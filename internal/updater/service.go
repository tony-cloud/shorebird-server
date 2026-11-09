package updater

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"golang.org/x/mod/semver"
)

// Installer installs a verified release.
type Installer interface {
	Install(context.Context, Source, *Release) error
}

// RollbackInstaller keeps the previous image of the running version and can
// restore it on an administrator's request.
type RollbackInstaller interface {
	RollbackInfo() (previousVersion string, ok bool)
	ManualRollback() error
}

// Status is the administrator-facing self-update state.
type Status struct {
	Settings
	Mode              string     `json:"mode"`
	ManagedBy         string     `json:"managed_by,omitempty"`
	UnavailableReason string     `json:"unavailable_reason,omitempty"`
	Platform          string     `json:"platform"`
	Repository        string     `json:"repository,omitempty"`
	CurrentVersion    string     `json:"current_version"`
	AvailableVersion  string     `json:"available_version,omitempty"`
	State             string     `json:"state"`
	LastCheck         *time.Time `json:"last_check,omitempty"`
	NextCheck         *time.Time `json:"next_check,omitempty"`
	Error             string     `json:"error_code,omitempty"`
	// JournalState is the update journal: trial, healthy or rolled_back.
	JournalState string `json:"journal_state,omitempty"`
	// RollbackVersion is the previous version a manual rollback would restore.
	RollbackVersion string `json:"rollback_version,omitempty"`
	// LastRollback is "manual" or "watchdog"; RolledBackVersion is the
	// version that rollback quarantined.
	LastRollback      string   `json:"last_rollback,omitempty"`
	RolledBackVersion string   `json:"rolled_back_version,omitempty"`
	DevelopmentTrust  bool     `json:"development_trust,omitempty"`
	TrustedKeyIDs     []string `json:"trusted_key_ids,omitempty"`
	InstallWritable   *bool    `json:"install_writable,omitempty"`
}

// Options configures an active Service.
type Options struct {
	ConfigPath string
	Version    string
	Source     Source
	Installer  Installer
	// Restart is called once an image was installed or rolled back; the
	// owner then shuts down and exits with UpdateExitCode.
	Restart    func()
	TempDir    string
	Trust      *Trust
	Platform   Platform
	Repository string
	// InstallWritable is evaluated for each status (nil: not reported).
	InstallWritable func() bool
}

// Service serializes manual and scheduled operations. Its context belongs to
// the server, not to the HTTP request that started an operation.
type Service struct {
	mu         sync.Mutex
	opts       Options
	status     Status
	release    *Release
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	autoCancel context.CancelFunc
}

// New creates the service of an active (supervised) installation.
func New(opts Options) (*Service, error) {
	settings, err := loadSettings(opts.ConfigPath)
	if err != nil {
		return nil, err
	}
	asset, _ := AssetName(opts.Platform)
	ctx, cancel := context.WithCancel(context.Background())
	status := Status{Settings: settings, Mode: ModeActive, Platform: asset, Repository: opts.Repository, CurrentVersion: opts.Version, State: "idle",
		DevelopmentTrust: opts.Trust.Development(), TrustedKeyIDs: opts.Trust.KeyIDs()}
	if files, ok := opts.Installer.(FileInstaller); ok {
		txn, e := files.loadTransaction()
		if e != nil {
			cancel()
			return nil, e
		}
		if txn != nil && txn.State == stateRolledBack {
			status.RolledBackVersion = txn.NewVersion
			if txn.Manual {
				status.LastRollback = "manual"
			} else {
				status.State = "error"
				status.Error = "update_rolled_back"
				status.LastRollback = "watchdog"
			}
		}
	}
	return &Service{opts: opts, status: status, ctx: ctx, cancel: cancel}, nil
}

// NewInactive creates a status-only service for a deployment that cannot
// self-update; every operation answers with the mode's error code.
func NewInactive(plan Plan, version string, platform Platform) *Service {
	ctx, cancel := context.WithCancel(context.Background())
	asset, err := AssetName(platform)
	if err != nil {
		asset = platform.GOOS + "-" + platform.GOARCH
	}
	return &Service{ctx: ctx, cancel: cancel, status: Status{Settings: DefaultSettings(), Mode: plan.Mode, ManagedBy: plan.ManagedBy,
		UnavailableReason: plan.Reason, Platform: asset, CurrentVersion: version, State: "idle"}}
}

// Active reports whether the service can change the installation.
func (s *Service) Active() bool { return s.status.Mode == ModeActive }

func (s *Service) inactiveError() error {
	switch s.status.Mode {
	case ModeActive:
		return nil
	case ModeManagedExternally:
		return errors.New("managed_externally")
	case ModeDisabled:
		return errors.New("self_update_disabled")
	}
	return errors.New("self_update_unavailable")
}

// Status returns a snapshot including the live journal state.
func (s *Service) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := s.status
	status.TrustedKeyIDs = append([]string(nil), s.status.TrustedKeyIDs...)
	if !s.Active() {
		return status
	}
	if status.AutoUpdate {
		next := time.Now().UTC()
		if status.LastCheck != nil {
			next = status.LastCheck.Add(time.Duration(status.CheckIntervalSeconds) * time.Second)
		}
		status.NextCheck = &next
	}
	if files, ok := s.opts.Installer.(FileInstaller); ok {
		status.JournalState = files.JournalState()
	}
	if !s.busy() {
		status.RollbackVersion = s.rollbackVersionLocked()
	}
	if s.opts.InstallWritable != nil {
		writable := s.opts.InstallWritable()
		status.InstallWritable = &writable
	}
	return status
}

func (s *Service) rollbackVersionLocked() string {
	if rollback, ok := s.opts.Installer.(RollbackInstaller); ok {
		if previous, ok := rollback.RollbackInfo(); ok {
			return previous
		}
	}
	return ""
}

func (s *Service) trialInProgress() bool {
	files, ok := s.opts.Installer.(FileInstaller)
	if !ok {
		return false
	}
	state := files.JournalState()
	return state == stateTrial || state == statePrepared
}

func (s *Service) quarantined(version string) bool {
	files, ok := s.opts.Installer.(FileInstaller)
	if !ok {
		return false
	}
	txn, err := files.loadTransaction()
	return err == nil && txn != nil && txn.State == stateRolledBack && txn.NewVersion == version
}

// Configure validates and atomically persists new settings.
func (s *Service) Configure(settings Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.inactiveError(); err != nil {
		return err
	}
	if err := settings.Validate(); err != nil {
		return err
	}
	if (settings.Channel != s.status.Channel || settings.UseMirror != s.status.UseMirror) && s.busy() {
		return errors.New("update_busy")
	}
	if err := saveSettings(s.opts.ConfigPath, settings); err != nil {
		return err
	}
	if settings.Channel != s.status.Channel {
		s.release = nil
		s.status.AvailableVersion = ""
	}
	s.status.Settings = settings
	// Cancelling before the replacement keeps a disabled automatic update
	// from proceeding; once replacement began, it finishes and restarts.
	if !settings.AutoUpdate && s.autoCancel != nil {
		s.autoCancel()
	}
	return nil
}

// Start runs the scheduler. Call it only after the supervisor acknowledged a
// healthy start, so a broken image never replaces another binary.
func (s *Service) Start() {
	if !s.Active() {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			s.checkDue(time.Now().UTC())
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// Close cancels running operations and waits for them.
func (s *Service) Close() { s.cancel(); s.wg.Wait() }

func (s *Service) busy() bool {
	switch s.status.State {
	case "checking", "verifying", "installing", "restarting":
		return true
	}
	return false
}

func (s *Service) checkDue(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.status.AutoUpdate || s.busy() || s.ctx.Err() != nil || s.trialInProgress() {
		return
	}
	if s.status.LastCheck != nil && now.Before(s.status.LastCheck.Add(time.Duration(s.status.CheckIntervalSeconds)*time.Second)) {
		return
	}
	s.beginLocked(true, nil, s.opts.Source, nil)
}

func (s *Service) preflightLocked() error {
	if err := s.inactiveError(); err != nil {
		return err
	}
	if s.busy() {
		return errors.New("update_busy")
	}
	if s.ctx.Err() != nil {
		return errors.New("update_cancelled")
	}
	return nil
}

// Check discovers the newest release of the selected channel now,
// independent of the automatic schedule.
func (s *Service) Check() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflightLocked(); err != nil {
		return err
	}
	s.beginLocked(false, nil, s.opts.Source, nil)
	return nil
}

// Install installs exactly the release found by the last check.
func (s *Service) Install(version string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflightLocked(); err != nil {
		return err
	}
	if s.release == nil || version != s.release.Version {
		return errors.New("check_required")
	}
	if s.trialInProgress() {
		return errors.New("update_trial_in_progress")
	}
	if s.quarantined(version) {
		return errors.New("version_quarantined")
	}
	s.beginLocked(false, s.release, s.opts.Source, nil)
	return nil
}

func (s *Service) beginLocked(automatic bool, release *Release, source Source, cleanup func()) {
	settings := s.status.Settings
	if configurable, ok := source.(interface{ WithSettings(Settings) Source }); ok {
		source = configurable.WithSettings(settings)
	}
	s.status.Error = ""
	s.status.State = "checking"
	if release != nil {
		s.status.State = "installing"
	} else {
		now := time.Now().UTC()
		s.status.LastCheck = &now
	}
	ctx, cancel := context.WithTimeout(s.ctx, 15*time.Minute)
	if automatic {
		s.autoCancel = cancel
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer cancel()
		if cleanup != nil {
			defer cleanup()
		}
		err := s.run(ctx, automatic, release, source, settings)
		s.mu.Lock()
		if automatic {
			s.autoCancel = nil
		}
		if err != nil {
			s.status.State = "error"
			s.status.Error = err.Error()
		} else if s.status.State != "restarting" {
			s.status.State = "idle"
		}
		restarting := s.status.State == "restarting"
		s.mu.Unlock()
		if restarting && s.opts.Restart != nil {
			s.opts.Restart()
		}
	}()
}

func (s *Service) run(ctx context.Context, automatic bool, release *Release, source Source, settings Settings) error {
	if release == nil {
		var err error
		release, err = source.Latest(ctx, s.status.CurrentVersion)
		s.mu.Lock()
		s.release = nil
		s.status.AvailableVersion = ""
		if err == nil && release != nil {
			// Enforced here as well so an alternate Source cannot downgrade.
			if !semver.IsValid(release.Version) || (settings.Channel != "dev" && semver.Prerelease(release.Version) != "") ||
				(semver.IsValid(s.status.CurrentVersion) && semver.Compare(release.Version, s.status.CurrentVersion) <= 0) {
				err = errors.New("invalid_release")
			} else {
				s.release = release
				s.status.AvailableVersion = release.Version
			}
		}
		enabled := s.status.AutoUpdate
		quarantined := release != nil && s.quarantined(release.Version)
		s.mu.Unlock()
		if err != nil {
			return err
		}
		if !automatic || !enabled || release == nil || quarantined {
			return nil
		}
	}
	if ctx.Err() != nil {
		return errors.New("update_cancelled")
	}
	s.mu.Lock()
	s.status.State = "installing"
	s.mu.Unlock()
	if err := s.opts.Installer.Install(ctx, source, release); err != nil {
		return err
	}
	s.mu.Lock()
	s.status.State = "restarting"
	s.status.AvailableVersion = release.Version
	s.mu.Unlock()
	return nil
}

// Upload verifies a signed update ZIP completely, then installs it in the
// background (202). A stable-channel ZIP is accepted on either channel; a
// dev-channel ZIP requires the dev channel. The version must be newer than
// the running one and not quarantined.
func (s *Service) Upload(reader io.Reader) (string, error) {
	s.mu.Lock()
	if err := s.preflightLocked(); err != nil {
		s.mu.Unlock()
		return "", err
	}
	if s.trialInProgress() {
		s.mu.Unlock()
		return "", errors.New("update_trial_in_progress")
	}
	previousState, previousError := s.status.State, s.status.Error
	s.status.State = "verifying"
	s.mu.Unlock()

	source, release, err := readZIP(reader, s.opts.TempDir, s.opts.Trust, s.opts.Platform)

	s.mu.Lock()
	defer s.mu.Unlock()
	fail := func(err error) (string, error) {
		if source != nil {
			source.Close()
		}
		s.status.State, s.status.Error = previousState, previousError
		return "", err
	}
	if err != nil {
		return fail(err)
	}
	version := release.Version
	if s.ctx.Err() != nil {
		return fail(errors.New("update_cancelled"))
	}
	if release.Channel == "dev" && s.status.Channel != "dev" {
		return fail(errors.New("dev_channel_required"))
	}
	if !semver.IsValid(s.status.CurrentVersion) || semver.Compare(version, s.status.CurrentVersion) <= 0 {
		return fail(errors.New("version_not_newer"))
	}
	if s.quarantined(version) {
		return fail(errors.New("version_quarantined"))
	}
	s.release = release
	s.status.AvailableVersion = version
	s.beginLocked(false, release, source, source.Close)
	return version, nil
}

func (s *Service) rollbackReadyLocked(currentVersion, rollbackVersion string) error {
	if err := s.preflightLocked(); err != nil {
		return err
	}
	previous := s.rollbackVersionLocked()
	if previous == "" {
		return errors.New("rollback_unavailable")
	}
	if currentVersion != s.status.CurrentVersion || rollbackVersion != previous {
		return errors.New("rollback_conflict")
	}
	return nil
}

// RollbackReady is a cheap precheck before the caller spends a password
// verification; Rollback repeats every check under the same lock.
func (s *Service) RollbackReady(currentVersion, rollbackVersion string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rollbackReadyLocked(currentVersion, rollbackVersion)
}

// Rollback restores the previous image of the running version once and
// restarts. A failure is reported and never retried automatically.
func (s *Service) Rollback(currentVersion, rollbackVersion string) error {
	s.mu.Lock()
	if err := s.rollbackReadyLocked(currentVersion, rollbackVersion); err != nil {
		s.mu.Unlock()
		return err
	}
	if err := s.opts.Installer.(RollbackInstaller).ManualRollback(); err != nil {
		code := "rollback_failed"
		if err.Error() == "rollback_unavailable" {
			code = "rollback_unavailable"
		}
		s.status.State = "error"
		s.status.Error = code
		s.mu.Unlock()
		return errors.New(code)
	}
	s.status.State = "restarting"
	s.status.Error = ""
	s.status.LastRollback = "manual"
	s.status.RolledBackVersion = currentVersion
	s.release = nil
	s.status.AvailableVersion = ""
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		if s.opts.Restart != nil {
			s.opts.Restart()
		}
	}()
	return nil
}
