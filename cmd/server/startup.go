package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/shorebird-server/internal/config"
	"github.com/shorebird-server/internal/maintenance"
	"github.com/shorebird-server/internal/updater"
	"github.com/shorebird-server/internal/version"
)

// selfUpdate is the startup decision and the paths the updater uses.
type selfUpdate struct {
	plan       updater.Plan
	executable string
	trust      *updater.Trust
	platform   updater.Platform
	stateDir   string
	configPath string
}

func resolveSelfUpdate(cfg *config.Config) selfUpdate {
	// Resolve before any replacement; Linux otherwise reports the renamed image.
	executable, exeErr := os.Executable()
	if exeErr == nil {
		executable, exeErr = filepath.EvalSymlinks(executable)
	}
	trust, trustErr := updater.CompiledTrust()
	su := selfUpdate{executable: executable, trust: trust, platform: updater.CurrentPlatform()}
	su.plan = updater.Decide(updater.ProcessEnvironment(), version.Versioned(), trustErr, exeErr, su.platform)
	su.stateDir = cfg.SelfUpdate.StateDir
	if su.stateDir == "" && exeErr == nil {
		su.stateDir = filepath.Dir(executable)
	}
	su.configPath = cfg.SelfUpdate.ConfigFile
	if su.configPath == "" {
		su.configPath = filepath.Join(su.stateDir, "server-update.json")
	}
	return su
}

func (su selfUpdate) installer() updater.FileInstaller {
	return updater.FileInstaller{Executable: su.executable, CurrentVersion: version.Current(), Trust: su.trust, Platform: su.platform}
}

func (su selfUpdate) secretPath() string {
	return filepath.Join(su.stateDir, "server-maintenance.secret")
}

func (su selfUpdate) localSecretPath() string {
	return filepath.Join(su.stateDir, "server-local-update.secret")
}

// createLocalSecret writes a fresh 256-bit secret for the local upload route
// (0600, service account) and returns it with its removal. The file is
// replaced at every core start, so a copy taken earlier stops working.
func createLocalSecret(path string) (string, func(), error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	secret := hex.EncodeToString(raw)
	_ = os.Remove(path)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", nil, err
	}
	_, err = f.WriteString(secret + "\n")
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		_ = os.Remove(path)
		return "", nil, err
	}
	return secret, func() { _ = os.Remove(path) }, nil
}

func watchdogOptions(cfg *config.Config) updater.WatchdogOptions {
	options := updater.DefaultWatchdogOptions()
	options.TrialPeriod = time.Duration(cfg.SelfUpdate.TrialSeconds) * time.Second
	options.StartupTimeout = time.Duration(cfg.SelfUpdate.StartupTimeoutSeconds) * time.Second
	return options
}

// runSupervisor is the watchdog parent of an active installation. It never
// serves the API itself; a supervisor failure (broken journal, failed
// rollback) waits in maintenance for the operator instead of exiting.
func runSupervisor(cfg *config.Config, su selfUpdate) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("Shorebird server %s: supervising %s (self-update active%s)", version.Current(), su.executable,
		map[bool]string{true: ", DEVELOPMENT-ONLY signing key trusted", false: ""}[su.trust.Development()])
	if su.trust.Development() {
		log.Print("SERVER_UPDATE_DEVELOPMENT_TRUST: this build accepts updates signed with the public DEVELOPMENT-ONLY key; never deploy it")
	}
	addr := fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port)
	attempts := 0
	for {
		err := updater.Supervise(ctx, su.installer(), os.Args[1:], watchdogOptions(cfg))
		if ctx.Err() != nil || err == nil {
			return 0
		}
		attempts++
		surface := maintenance.New(maintenance.Options{Addr: addr, SecretPath: su.secretPath(), Version: version.Current()})
		resume := surface.Serve(ctx, supervisorCause(err, su.executable, attempts))
		surface.Close()
		if resume == maintenance.ResumeStopped {
			return 0
		}
	}
}

func supervisorCause(err error, executable string, attempt int) maintenance.Cause {
	now := time.Now().UTC()
	journal := filepath.Base(executable) + ".update.json"
	cause := maintenance.Cause{Stage: "supervisor", Since: now, Attempts: attempt, Detail: err.Error()}
	switch {
	case strings.Contains(err.Error(), "invalid_update_journal"):
		cause.Code = "UPDATE_JOURNAL_INVALID"
		cause.Action = "Install the intended binary or restore the backup, move " + journal + " aside, then retry"
	case strings.HasPrefix(err.Error(), "rollback_failed"):
		cause.Code = "UPDATE_ROLLBACK_FAILED"
		cause.Action = "Restore the previous binary by hand (see " + journal + "), move the journal aside, then retry"
	case err.Error() == "update_restart_without_transaction":
		cause.Code = "UPDATE_RESTART_INVALID"
		cause.Action = "The server asked for an update restart without a journal change; check the preceding log lines"
		cause.Transient = true
	default:
		cause.Code = "UPDATE_JOURNAL_UNWRITABLE"
		cause.Action = "Make the executable directory writable for the service account, then retry"
		cause.Transient = true
	}
	if cause.Transient {
		next := now.Add(retryDelay(attempt))
		cause.NextRetry = &next
	}
	return cause
}

// startupFailure is a condition that keeps the core from starting.
type startupFailure struct {
	code, stage, action string
	transient           bool
	err                 error
}

func transientFailure(code, stage, action string, err error) *startupFailure {
	return &startupFailure{code: code, stage: stage, action: action, transient: true, err: err}
}

func operatorFailure(code, stage, action string, err error) *startupFailure {
	return &startupFailure{code: code, stage: stage, action: action, err: err}
}

func (f *startupFailure) detail() string {
	if f.err == nil {
		return ""
	}
	return f.err.Error()
}

// retryDelay is 5 s doubling to at most 5 min.
func retryDelay(attempt int) time.Duration {
	delay := 5 * time.Second
	for n := 1; n < attempt && delay < 5*time.Minute; n++ {
		delay *= 2
	}
	if delay > 5*time.Minute {
		delay = 5 * time.Minute
	}
	return delay
}

// setupUpdater builds the database-free updater service. A deployment that
// cannot self-update gets a status-only service; an unreadable settings file
// disables updates without stopping the patch server.
func setupUpdater(cfg *config.Config, su selfUpdate, restart chan struct{}) (*updater.Service, updater.Auditor) {
	current := version.Current()
	if su.plan.Mode != updater.ModeActive {
		return updater.NewInactive(su.plan, current, su.platform), updater.NewFileAuditor("")
	}
	auditor := updater.NewFileAuditor(filepath.Join(su.stateDir, "server-update-audit.jsonl"))
	mirror := cfg.SelfUpdate.MirrorURL
	if strings.EqualFold(mirror, "off") || strings.EqualFold(mirror, "none") {
		mirror = ""
	}
	source, err := updater.NewGitHubSource(updater.GitHubOptions{Repository: cfg.SelfUpdate.Repository, Token: cfg.SelfUpdate.GitHubToken,
		MirrorURL: mirror, TempDir: filepath.Dir(su.executable), Trust: su.trust, Platform: su.platform})
	if err != nil {
		log.Printf("UPDATER_CONFIG_INVALID: %v; fix SERVER_UPDATE_REPOSITORY/SERVER_UPDATE_MIRROR_URL and restart the service", err)
		return updater.NewInactive(updater.Plan{Mode: updater.ModeUnavailable, Reason: "updater_config_invalid"}, current, su.platform), auditor
	}
	service, err := updater.New(updater.Options{
		ConfigPath: su.configPath, Version: current, Source: source, Installer: su.installer(),
		Restart: func() {
			select {
			case restart <- struct{}{}:
			default:
			}
		},
		TempDir: filepath.Dir(su.executable), Trust: su.trust, Platform: su.platform, Repository: cfg.SelfUpdate.Repository,
		InstallWritable: func() bool { return updater.InstallWritable(su.executable) },
	})
	if err != nil {
		log.Printf("UPDATER_SETTINGS_INVALID: %v; fix or remove %s and check %s.update.json, then restart the service", err, su.configPath, su.executable)
		return updater.NewInactive(updater.Plan{Mode: updater.ModeUnavailable, Reason: "settings_invalid: " + err.Error()}, current, su.platform), auditor
	}
	if n := updater.SweepTemporaries(su.executable, 10*time.Minute); n > 0 {
		log.Printf("Self-update: removed %d stale temporary file(s) next to %s", n, filepath.Base(su.executable))
	}
	if !updater.InstallWritable(su.executable) {
		log.Printf("UPDATE_INSTALL_UNAVAILABLE: %s is not writable by the service account; every update fails with install_permission_denied until it is", filepath.Dir(su.executable))
	}
	return service, auditor
}

// runChild runs the core. Supervised, a core that cannot start stays up in
// maintenance until its cause clears; unsupervised it exits as before.
func runChild(ctx context.Context, cfg *config.Config, su selfUpdate) int {
	supervised := updater.IsSupervised()
	restart := make(chan struct{}, 1)
	service, auditor := setupUpdater(cfg, su, restart)
	defer service.Close()
	addr := fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port)
	surface := maintenance.New(maintenance.Options{Addr: addr, SecretPath: su.secretPath(), Version: version.Current(),
		Updater: service, Auditor: auditor, Restart: restart, Supervised: supervised})
	defer surface.Close()
	attempts := map[string]int{}
	var since = map[string]time.Time{}
	for {
		code, fail := runCore(ctx, &coreEnv{cfg: cfg, su: su, service: service, auditor: auditor, restart: restart, supervised: supervised, onReady: surface.Close})
		if fail == nil {
			return code
		}
		if ctx.Err() != nil {
			return 0
		}
		if !supervised {
			log.Printf("%s (stage %s): %s. Error: %s", fail.code, fail.stage, fail.action, maintenance.Redact(fail.detail()))
			return 1
		}
		attempts[fail.code]++
		if since[fail.code].IsZero() {
			since[fail.code] = time.Now().UTC()
		}
		cause := maintenance.Cause{Code: fail.code, Stage: fail.stage, Action: fail.action, Transient: fail.transient, Detail: fail.detail(),
			Since: since[fail.code], Attempts: attempts[fail.code]}
		if fail.transient {
			next := time.Now().UTC().Add(retryDelay(attempts[fail.code]))
			cause.NextRetry = &next
		}
		switch surface.Serve(ctx, cause) {
		case maintenance.ResumeStopped:
			return 0
		case maintenance.ResumeUpdate:
			log.Print("Maintenance: the uploaded update is installed; restarting into it")
			return updater.UpdateExitCode
		}
	}
}
