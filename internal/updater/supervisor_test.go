package updater

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fixtureModeEnv = "SHOREBIRD_TEST_WATCHDOG_MODE"

// TestWatchdogFixture is the supervised child: watchChild runs a copy of the
// test binary with -test.run=^TestWatchdogFixture$, so crash, hang and
// heartbeat behavior is real process supervision rather than a mock.
func TestWatchdogFixture(t *testing.T) {
	mode := os.Getenv(fixtureModeEnv)
	if mode == "" || !IsSupervised() {
		return
	}
	if path := os.Getenv("SHOREBIRD_TEST_FIXTURE_STARTS"); path != "" {
		f, _ := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		_, _ = f.WriteString("start\n")
		f.Close()
	}
	version := "v2.0.0"
	switch mode {
	case "crash":
		os.Exit(23)
	case "no_ack":
		time.Sleep(time.Minute)
		return
	case "exit_update":
		os.Exit(UpdateExitCode)
	case "wrong_version":
		version = "v99.0.0"
	}
	client := heartbeatClient()
	started := time.Now()
	for {
		report := heartbeatReport{Version: version}
		if mode == "maintenance" {
			report.Maintenance = "DATABASE_UNAVAILABLE"
		}
		if mode != "hang_after_ack" || time.Since(started) < 400*time.Millisecond {
			if code, err := postHeartbeat(context.Background(), client, report); err == nil && code == http.StatusConflict {
				os.Exit(0)
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func testWatchdogOptions() WatchdogOptions {
	return WatchdogOptions{StartupTimeout: time.Second, HeartbeatTimeout: 300 * time.Millisecond, StopTimeout: time.Second,
		TrialPeriod: time.Hour, RestartBackoffMin: 20 * time.Millisecond, RestartBackoffMax: 100 * time.Millisecond,
		Logf: func(string, ...any) {}}
}

// supervisedFixture installs a copy of the test binary as the "new" image
// (v2.0.0) over a non-starting v1.0.0 script, with the given journal state.
func supervisedFixture(t *testing.T, state string) (FileInstaller, string, string) {
	t.Helper()
	requireUnix(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	image, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "shorebird-server")
	if err := os.WriteFile(target, image, 0o755); err != nil {
		t.Fatal(err)
	}
	installer := FileInstaller{Executable: target, CurrentVersion: "v2.0.0"}
	if state == "" {
		return installer, "", ""
	}
	backup := filepath.Base(target) + ".previous-1"
	if err := os.WriteFile(filepath.Join(dir, backup), scriptBinary("v1.0.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	oldHash, _ := fileHash(filepath.Join(dir, backup))
	newHash, _ := fileHash(target)
	if err := installer.saveTransaction(&transaction{State: state, Previous: backup, OldVersion: "v1.0.0", NewVersion: "v2.0.0", OldHash: oldHash, NewHash: newHash}); err != nil {
		t.Fatal(err)
	}
	return installer, oldHash, newHash
}

type supervision struct {
	cancel context.CancelFunc
	done   chan error
}

func supervise(installer FileInstaller, options WatchdogOptions) *supervision {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	s := &supervision{cancel: cancel, done: make(chan error, 1)}
	go func() { s.done <- Supervise(ctx, installer, []string{"-test.run=^TestWatchdogFixture$"}, options) }()
	return s
}

func (s *supervision) stop(t *testing.T) error {
	t.Helper()
	s.cancel()
	select {
	case err := <-s.done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("supervisor did not stop")
		return nil
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func journalState(installer FileInstaller) string { return installer.JournalState() }

func TestWatchdogRollsBackFailedTrial(t *testing.T) {
	for _, mode := range []string{"crash", "no_ack", "hang_after_ack", "wrong_version", "maintenance"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv(fixtureModeEnv, mode)
			installer, oldHash, _ := supervisedFixture(t, stateTrial)
			s := supervise(installer, testWatchdogOptions())
			waitFor(t, "rollback", func() bool { return journalState(installer) == stateRolledBack })
			if err := s.stop(t); err != nil {
				t.Fatalf("supervisor: %v", err)
			}
			if hash, _ := fileHash(installer.Executable); hash != oldHash {
				t.Fatal("previous image not restored")
			}
			txn, _ := installer.loadTransaction()
			if txn.Manual {
				t.Fatal("watchdog rollback recorded as manual")
			}
			if v, _ := os.ReadFile(filepath.Join(filepath.Dir(installer.Executable), "VERSION")); string(v) != "v1.0.0\n" {
				t.Fatalf("VERSION %q", v)
			}
		})
	}
}

func TestWatchdogPromotesHealthyTrialAndStopsChild(t *testing.T) {
	t.Setenv(fixtureModeEnv, "healthy")
	starts := filepath.Join(t.TempDir(), "starts")
	t.Setenv("SHOREBIRD_TEST_FIXTURE_STARTS", starts)
	installer, _, newHash := supervisedFixture(t, stateTrial)
	options := testWatchdogOptions()
	options.TrialPeriod = 300 * time.Millisecond
	s := supervise(installer, options)
	waitFor(t, "healthy journal", func() bool { return journalState(installer) == stateHealthy })
	stopped := time.Now()
	if err := s.stop(t); err != nil {
		t.Fatalf("operator stop: %v", err)
	}
	if time.Since(stopped) > 5*time.Second {
		t.Fatal("child did not stop promptly")
	}
	if hash, _ := fileHash(installer.Executable); hash != newHash {
		t.Fatal("healthy image replaced")
	}
	if data, _ := os.ReadFile(starts); strings.Count(string(data), "start") != 1 {
		t.Fatalf("starts: %q", data)
	}
}

func TestWatchdogRestartsFailedHealthyImageWithoutRollback(t *testing.T) {
	t.Setenv(fixtureModeEnv, "crash")
	starts := filepath.Join(t.TempDir(), "starts")
	t.Setenv("SHOREBIRD_TEST_FIXTURE_STARTS", starts)
	installer, _, newHash := supervisedFixture(t, stateHealthy)
	s := supervise(installer, testWatchdogOptions())
	waitFor(t, "restarts", func() bool {
		data, _ := os.ReadFile(starts)
		return strings.Count(string(data), "start") >= 3
	})
	if err := s.stop(t); err != nil {
		t.Fatal(err)
	}
	if hash, _ := fileHash(installer.Executable); hash != newHash || journalState(installer) != stateHealthy {
		t.Fatal("a healthy image was rolled back after its trial")
	}
}

func TestWatchdogKeepsMaintenanceChildOutsideTrial(t *testing.T) {
	t.Setenv(fixtureModeEnv, "maintenance")
	starts := filepath.Join(t.TempDir(), "starts")
	t.Setenv("SHOREBIRD_TEST_FIXTURE_STARTS", starts)
	installer, _, _ := supervisedFixture(t, "")
	options := testWatchdogOptions()
	options.StartupTimeout = 500 * time.Millisecond
	s := supervise(installer, options)
	time.Sleep(2 * time.Second)
	if err := s.stop(t); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(starts); strings.Count(string(data), "start") != 1 {
		t.Fatalf("a child in maintenance was restarted: %q", data)
	}
}

func TestWatchdogRefusesUpdateRestartWithoutJournalChange(t *testing.T) {
	t.Setenv(fixtureModeEnv, "exit_update")
	installer, _, _ := supervisedFixture(t, "")
	s := supervise(installer, testWatchdogOptions())
	select {
	case err := <-s.done:
		if err == nil || err.Error() != "update_restart_without_transaction" {
			t.Fatalf("err %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("supervisor accepted an update restart without a journal")
	}
	s.cancel()
}

func TestWatchdogRefusesInvalidJournal(t *testing.T) {
	installer, _, _ := supervisedFixture(t, "")
	if err := os.WriteFile(installer.journalPath(), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Supervise(context.Background(), installer, nil, testWatchdogOptions()); err == nil || err.Error() != "invalid_update_journal" {
		t.Fatalf("err %v", err)
	}
}

func TestAcceptUpdateRestart(t *testing.T) {
	trial := &transaction{State: stateTrial, NewHash: "a"}
	healthy := &transaction{State: stateHealthy, NewHash: "a"}
	nextTrial := &transaction{State: stateTrial, NewHash: "b"}
	manual := &transaction{State: stateRolledBack, NewHash: "a", Manual: true}
	watchdog := &transaction{State: stateRolledBack, NewHash: "a"}
	for _, tc := range []struct {
		name           string
		previous, next *transaction
		want           bool
	}{
		{"first install", nil, trial, true},
		{"new trial after healthy", healthy, nextTrial, true},
		{"same trial again", trial, trial, false},
		{"manual rollback", healthy, manual, true},
		{"manual rollback already done", manual, manual, false},
		{"watchdog journal", healthy, watchdog, false},
		{"no journal", nil, nil, false},
		{"healthy unchanged", healthy, healthy, false},
	} {
		if got := acceptUpdateRestart(tc.previous, tc.next); got != tc.want {
			t.Errorf("%s: %v", tc.name, got)
		}
	}
}
