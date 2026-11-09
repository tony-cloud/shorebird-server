package updater

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeSource struct {
	mu      sync.Mutex
	release *Release
	err     error
	calls   int
	channel string
}

func (f *fakeSource) Latest(context.Context, string) (*Release, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.release, f.err
}
func (f *fakeSource) Download(context.Context, *Release, io.Writer) error { return nil }
func (f *fakeSource) WithSettings(s Settings) Source {
	f.mu.Lock()
	f.channel = s.Channel
	f.mu.Unlock()
	return f
}
func (f *fakeSource) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

type fakeInstaller struct {
	mu        sync.Mutex
	installed []string
	err       error
	previous  string
	rollbacks int
}

func (f *fakeInstaller) Install(_ context.Context, _ Source, r *Release) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.installed = append(f.installed, r.Version)
	return nil
}
func (f *fakeInstaller) RollbackInfo() (string, bool) { return f.previous, f.previous != "" }
func (f *fakeInstaller) ManualRollback() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rollbacks++
	f.previous = ""
	return nil
}

func newTestService(t *testing.T, version string, source Source, installer Installer, trust *Trust) (*Service, *atomic.Int32) {
	t.Helper()
	restarts := &atomic.Int32{}
	s, err := New(Options{ConfigPath: filepath.Join(t.TempDir(), "server-update.json"), Version: version, Source: source, Installer: installer,
		Restart: func() { restarts.Add(1) }, TempDir: t.TempDir(), Trust: trust, Platform: linuxAMD64})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, restarts
}

func waitState(t *testing.T, s *Service, want string) Status {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		status := s.Status()
		if status.State == want {
			return status
		}
		if time.Now().After(deadline) {
			t.Fatalf("state %q (error %q), want %q", status.State, status.Error, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSettingsPersistAndValidate(t *testing.T) {
	k := newTestKey(t)
	s, _ := newTestService(t, "v1.0.0", &fakeSource{}, &fakeInstaller{}, k.trust)
	if st := s.Status(); st.Channel != "stable" || st.CheckIntervalSeconds != 86400 || st.AutoUpdate || st.Mode != ModeActive {
		t.Fatalf("defaults %+v", st)
	}
	want := Settings{Channel: "dev", UseMirror: true, AutoUpdate: true, CheckIntervalSeconds: 3600}
	if err := s.Configure(want); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadSettings(s.opts.ConfigPath)
	if err != nil || loaded != want {
		t.Fatalf("persisted %+v %v", loaded, err)
	}
	if info, _ := os.Stat(s.opts.ConfigPath); info.Mode().Perm() != 0o600 {
		t.Fatalf("settings mode %v", info.Mode())
	}
	for _, bad := range []Settings{{Channel: "beta", CheckIntervalSeconds: 3600}, {Channel: "stable", CheckIntervalSeconds: 59}, {Channel: "stable", CheckIntervalSeconds: 8 * 86400}} {
		if err := s.Configure(bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	// A failed save leaves the live settings unchanged.
	s.opts.ConfigPath = filepath.Join(t.TempDir(), "missing", "server-update.json")
	if err := s.Configure(Settings{Channel: "stable", CheckIntervalSeconds: 600}); err == nil || err.Error() != "config_write_failed" {
		t.Fatalf("save into a missing directory: %v", err)
	}
	if s.Status().Settings != want {
		t.Fatal("live settings changed by a failed save")
	}
	// Unknown fields and trailing data in the file are refused.
	path := filepath.Join(t.TempDir(), "server-update.json")
	for _, data := range []string{`{"channel":"stable","check_interval_seconds":3600,"token":"x"}`, `{"channel":"stable","check_interval_seconds":3600} {}`, `null`} {
		_ = os.WriteFile(path, []byte(data), 0o600)
		if _, err := loadSettings(path); err == nil {
			t.Fatalf("loaded %s", data)
		}
	}
}

func TestManualCheckAndInstall(t *testing.T) {
	k := newTestKey(t)
	source := &fakeSource{release: k.release(t, "v1.1.0", "stable", linuxAMD64, []byte("bin"))}
	installer := &fakeInstaller{}
	s, restarts := newTestService(t, "v1.0.0", source, installer, k.trust)
	if err := s.Install("v1.1.0"); err == nil || err.Error() != "check_required" {
		t.Fatalf("install before check: %v", err)
	}
	if err := s.Check(); err != nil {
		t.Fatal(err)
	}
	status := waitState(t, s, "idle")
	if status.AvailableVersion != "v1.1.0" || status.LastCheck == nil || len(installer.installed) != 0 {
		t.Fatalf("manual check installed or missed: %+v", status)
	}
	if err := s.Install("v1.2.0"); err == nil || err.Error() != "check_required" {
		t.Fatalf("install of an unchecked version: %v", err)
	}
	if err := s.Install("v1.1.0"); err != nil {
		t.Fatal(err)
	}
	waitState(t, s, "restarting")
	if restarts.Load() != 1 || len(installer.installed) != 1 {
		t.Fatalf("restart %d installs %v", restarts.Load(), installer.installed)
	}
	if err := s.Check(); err == nil || err.Error() != "update_busy" {
		t.Fatalf("check while restarting: %v", err)
	}
}

func TestCheckRefusesDowngradeAndReportsErrors(t *testing.T) {
	k := newTestKey(t)
	source := &fakeSource{release: k.release(t, "v0.9.0", "stable", linuxAMD64, []byte("bin"))}
	s, _ := newTestService(t, "v1.0.0", source, &fakeInstaller{}, k.trust)
	_ = s.Check()
	if st := waitState(t, s, "error"); st.Error != "invalid_release" || st.AvailableVersion != "" {
		t.Fatalf("downgrade: %+v", st)
	}
	source.mu.Lock()
	source.release, source.err = nil, errors.New("release_request_failed")
	source.mu.Unlock()
	_ = s.Check()
	if st := waitState(t, s, "error"); st.Error != "release_request_failed" {
		t.Fatalf("%+v", st)
	}
}

func TestAutomaticScheduleUsesInterval(t *testing.T) {
	k := newTestKey(t)
	source := &fakeSource{release: k.release(t, "v1.1.0", "stable", linuxAMD64, []byte("bin"))}
	installer := &fakeInstaller{}
	s, restarts := newTestService(t, "v1.0.0", source, installer, k.trust)
	now := time.Now().UTC()
	s.checkDue(now)
	if source.count() != 0 {
		t.Fatal("checked while automatic updates are off")
	}
	if err := s.Configure(Settings{Channel: "stable", AutoUpdate: true, CheckIntervalSeconds: 3600}); err != nil {
		t.Fatal(err)
	}
	s.checkDue(now)
	waitState(t, s, "restarting")
	if restarts.Load() != 1 || len(installer.installed) != 1 {
		t.Fatal("automatic update did not install")
	}
	s.mu.Lock()
	s.status.State = "idle"
	s.mu.Unlock()
	s.checkDue(now.Add(30 * time.Minute))
	if source.count() != 1 {
		t.Fatal("checked again before the interval")
	}
	s.checkDue(now.Add(61 * time.Minute))
	waitState(t, s, "restarting")
	if source.count() != 2 {
		t.Fatal("interval elapsed without a check")
	}
}

func TestUploadRules(t *testing.T) {
	k := newTestKey(t)
	zipFor := func(version, channel string) []byte {
		return buildZIP(t, k.zipEntries(t, version, channel, linuxAMD64, []byte("binary "+version)))
	}
	t.Run("dev ZIP needs the dev channel", func(t *testing.T) {
		s, _ := newTestService(t, "v1.0.0", &fakeSource{}, &fakeInstaller{}, k.trust)
		if _, err := s.Upload(bytes.NewReader(zipFor("v1.1.0-dev.1", "dev"))); err == nil || err.Error() != "dev_channel_required" {
			t.Fatalf("err %v", err)
		}
		if st := s.Status(); st.State != "idle" || st.AvailableVersion != "" {
			t.Fatalf("refused upload changed state: %+v", st)
		}
		if err := s.Configure(Settings{Channel: "dev", CheckIntervalSeconds: 86400}); err != nil {
			t.Fatal(err)
		}
		if v, err := s.Upload(bytes.NewReader(zipFor("v1.1.0-dev.1", "dev"))); err != nil || v != "v1.1.0-dev.1" {
			t.Fatalf("dev upload: %v", err)
		}
		waitState(t, s, "restarting")
	})
	t.Run("stable ZIP on the stable channel", func(t *testing.T) {
		installer := &fakeInstaller{}
		s, restarts := newTestService(t, "v1.0.0", &fakeSource{}, installer, k.trust)
		if _, err := s.Upload(bytes.NewReader(zipFor("v1.1.0", "stable"))); err != nil {
			t.Fatal(err)
		}
		waitState(t, s, "restarting")
		if restarts.Load() != 1 || installer.installed[0] != "v1.1.0" {
			t.Fatal("upload not installed")
		}
		spooled, _ := filepath.Glob(filepath.Join(s.opts.TempDir, "*"))
		if len(spooled) != 0 {
			t.Fatalf("spooled upload left behind: %v", spooled)
		}
	})
	t.Run("version must be newer", func(t *testing.T) {
		s, _ := newTestService(t, "v1.1.0", &fakeSource{}, &fakeInstaller{}, k.trust)
		for _, v := range []string{"v1.1.0", "v1.0.9"} {
			if _, err := s.Upload(bytes.NewReader(zipFor(v, "stable"))); err == nil || err.Error() != "version_not_newer" {
				t.Fatalf("%s: %v", v, err)
			}
		}
	})
	t.Run("signature from another key", func(t *testing.T) {
		stranger := newTestKey(t)
		s, _ := newTestService(t, "v1.0.0", &fakeSource{}, &fakeInstaller{}, stranger.trust)
		if _, err := s.Upload(bytes.NewReader(zipFor("v1.1.0", "stable"))); err == nil || err.Error() != "untrusted_signer" {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("quarantined version", func(t *testing.T) {
		installer, _, _ := installedFixture(t, stateRolledBack)
		installer.CurrentVersion, installer.Trust, installer.Platform = "v1.0.0", k.trust, linuxAMD64
		s, _ := newTestService(t, "v1.0.0", &fakeSource{}, installer, k.trust)
		if st := s.Status(); st.State != "error" || st.Error != "update_rolled_back" || st.LastRollback != "watchdog" || st.RolledBackVersion != "v2.0.0" {
			t.Fatalf("status after watchdog rollback %+v", st)
		}
		if _, err := s.Upload(bytes.NewReader(zipFor("v2.0.0", "stable"))); err == nil || err.Error() != "version_quarantined" {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("upload during trial", func(t *testing.T) {
		installer, _, _ := installedFixture(t, stateTrial)
		installer.Trust, installer.Platform = k.trust, linuxAMD64
		s, _ := newTestService(t, "v2.0.0", &fakeSource{}, installer, k.trust)
		if st := s.Status(); st.JournalState != stateTrial || st.RollbackVersion != "v1.0.0" {
			t.Fatalf("status during trial %+v", st)
		}
		if _, err := s.Upload(bytes.NewReader(zipFor("v2.1.0", "stable"))); err == nil || err.Error() != "update_trial_in_progress" {
			t.Fatalf("err %v", err)
		}
	})
}

func TestServiceRollback(t *testing.T) {
	k := newTestKey(t)
	installer := &fakeInstaller{previous: "v1.0.0"}
	s, restarts := newTestService(t, "v1.1.0", &fakeSource{}, installer, k.trust)
	if st := s.Status(); st.RollbackVersion != "v1.0.0" {
		t.Fatalf("rollback offer %+v", st)
	}
	for _, tc := range [][2]string{{"v1.0.0", "v1.0.0"}, {"v1.1.0", "v0.9.0"}} {
		if err := s.RollbackReady(tc[0], tc[1]); err == nil || err.Error() != "rollback_conflict" {
			t.Fatalf("%v: %v", tc, err)
		}
	}
	if err := s.Rollback("v1.1.0", "v1.0.0"); err != nil {
		t.Fatal(err)
	}
	st := waitState(t, s, "restarting")
	if st.LastRollback != "manual" || st.RolledBackVersion != "v1.1.0" || installer.rollbacks != 1 {
		t.Fatalf("%+v", st)
	}
	waitFor(t, "restart", func() bool { return restarts.Load() == 1 })
	if err := s.Rollback("v1.1.0", "v1.0.0"); err == nil {
		t.Fatal("second rollback accepted")
	}
}

func TestServiceStatusAfterManualRollback(t *testing.T) {
	installer, _, _ := installedFixture(t, stateHealthy)
	if err := installer.ManualRollback(); err != nil {
		t.Fatal(err)
	}
	installer.CurrentVersion = "v1.0.0"
	s, _ := newTestService(t, "v1.0.0", &fakeSource{}, installer, newTestKey(t).trust)
	if st := s.Status(); st.State != "idle" || st.LastRollback != "manual" || st.RolledBackVersion != "v2.0.0" || st.Error != "" {
		t.Fatalf("%+v", st)
	}
}

func TestInactiveServiceRefusesEveryChange(t *testing.T) {
	for _, tc := range []struct {
		plan Plan
		want string
	}{
		{Plan{Mode: ModeManagedExternally, ManagedBy: "docker", Reason: "immutable_image"}, "managed_externally"},
		{Plan{Mode: ModeDisabled, Reason: "disabled_by_config"}, "self_update_disabled"},
		{Plan{Mode: ModeUnavailable, Reason: "unversioned_build"}, "self_update_unavailable"},
	} {
		s := NewInactive(tc.plan, "v1.0.0", linuxAMD64)
		st := s.Status()
		if st.Mode != tc.plan.Mode || st.ManagedBy != tc.plan.ManagedBy || st.UnavailableReason != tc.plan.Reason || st.Platform != "shorebird-server-linux-amd64" {
			t.Fatalf("status %+v", st)
		}
		errs := []error{s.Check(), s.Install("v1.1.0"), s.Configure(DefaultSettings()), s.RollbackReady("v1.0.0", "v0.9.0"), s.Rollback("v1.0.0", "v0.9.0")}
		_, uploadErr := s.Upload(bytes.NewReader(nil))
		errs = append(errs, uploadErr)
		for n, err := range errs {
			if err == nil || err.Error() != tc.want {
				t.Fatalf("%s op %d: %v", tc.plan.Mode, n, err)
			}
		}
		s.Start()
		s.Close()
	}
}

func TestAuditLogRotatesAndKeepsNewestFirst(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a := NewFileAuditor(path)
	a.MaxBytes = 600
	for n := 0; n < 10; n++ {
		a.Record(AuditEvent{Action: "server.update.check", Result: "ok", ActorID: n, Auth: "token"})
	}
	events, err := a.Recent(3)
	if err != nil || len(events) != 3 || events[0].ActorID != 9 || events[1].ActorID != 8 {
		t.Fatalf("%+v %v", events, err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatal("no rotation")
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode())
	}
	if events, err := NewFileAuditor("").Recent(5); err != nil || len(events) != 0 {
		t.Fatal("log-only auditor")
	}
}
