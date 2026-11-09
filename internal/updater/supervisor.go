package updater

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// UpdateExitCode is the child's exit status after it installed an update or
// performed a manual rollback; the supervisor then starts the new image.
const UpdateExitCode = 75

const (
	supervisedEnv    = "SHOREBIRD_SERVER_SUPERVISED"
	watchdogURLEnv   = "SHOREBIRD_SERVER_WATCHDOG"
	watchdogTokenEnv = "SHOREBIRD_SERVER_WATCHDOG_TOKEN"
)

// IsSupervised reports whether this process is the supervised server child.
func IsSupervised() bool { return os.Getenv(supervisedEnv) == "1" }

// WatchdogOptions are the supervisor's timing rules.
type WatchdogOptions struct {
	// StartupTimeout: a child must acknowledge a healthy start within this.
	StartupTimeout time.Duration
	// HeartbeatTimeout: an acknowledged child must keep reporting health.
	HeartbeatTimeout time.Duration
	// StopTimeout: grace period after asking a child to stop.
	StopTimeout time.Duration
	// TrialPeriod: an updated image must stay healthy this long after its
	// first healthy heartbeat before its journal moves from trial to healthy.
	// Until then any failure rolls it back.
	TrialPeriod time.Duration
	// RestartBackoff bounds the delay before restarting a failed child that is
	// not on trial.
	RestartBackoffMin, RestartBackoffMax time.Duration
	Logf                                 func(format string, args ...any)
}

// DefaultWatchdogOptions: 120 s to start, 60 s heartbeat timeout, 15 s stop
// grace, 5 min probation, restart backoff 1 s .. 60 s.
func DefaultWatchdogOptions() WatchdogOptions {
	return WatchdogOptions{StartupTimeout: 120 * time.Second, HeartbeatTimeout: 60 * time.Second, StopTimeout: 15 * time.Second,
		TrialPeriod: 5 * time.Minute, RestartBackoffMin: time.Second, RestartBackoffMax: time.Minute}
}

func (o WatchdogOptions) logf(format string, args ...any) {
	if o.Logf != nil {
		o.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// Supervise runs the server child and stays alive across replacements. It
// returns nil when ctx is cancelled (operator stop) and an error only for a
// condition it must not resolve by itself: an invalid journal, a failed
// rollback or an update restart without a matching journal change.
func Supervise(ctx context.Context, installer FileInstaller, args []string, options WatchdogOptions) error {
	backoff := options.RestartBackoffMin
	for {
		txn, err := installer.recoverTransaction()
		if err != nil {
			return err
		}
		expected := ""
		if txn != nil && (txn.State == stateTrial || txn.State == stateHealthy) {
			expected = txn.NewVersion
		}
		trialPeriod := time.Duration(-1)
		if txn != nil && txn.State == stateTrial {
			trialPeriod = options.TrialPeriod
			options.logf("update_trial: starting %s on probation (previous %s)", txn.NewVersion, txn.OldVersion)
		}
		promote := func() {
			current, err := installer.loadTransaction()
			if err != nil || current == nil || current.State != stateTrial || txn == nil || current.NewHash != txn.NewHash {
				return
			}
			current.State = stateHealthy
			if err := installer.saveTransaction(current); err != nil {
				options.logf("update_journal_unwritable: %v", err)
				return
			}
			options.logf("update_healthy: %s passed its trial", current.NewVersion)
		}
		started := time.Now()
		err = watchChild(ctx, installer.Executable, args, expected, trialPeriod, promote, options)
		if ctx.Err() != nil {
			return nil
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == UpdateExitCode {
			next, e := installer.loadTransaction()
			if e != nil {
				return e
			}
			if !acceptUpdateRestart(txn, next) {
				return errors.New("update_restart_without_transaction")
			}
			if next.State == stateRolledBack {
				options.logf("update_restart: manual rollback, starting %s (%s quarantined)", next.OldVersion, next.NewVersion)
			} else {
				options.logf("update_restart: starting %s on trial", next.NewVersion)
			}
			backoff = options.RestartBackoffMin
			continue
		}
		current, e := installer.loadTransaction()
		if e != nil {
			return e
		}
		if current != nil && current.State == stateTrial {
			options.logf("update_trial_failed: %s (%v); restoring %s", current.NewVersion, describeExit(err), current.OldVersion)
			if e := installer.Rollback(); e != nil {
				return fmt.Errorf("rollback_failed: %w", e)
			}
			options.logf("update_rolled_back: %s is quarantined, %s restored", current.NewVersion, current.OldVersion)
			backoff = options.RestartBackoffMin
			continue
		}
		if time.Since(started) > 10*time.Minute {
			backoff = options.RestartBackoffMin
		}
		options.logf("server_child_failed: %v; restarting in %s", describeExit(err), backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > options.RestartBackoffMax {
			backoff = options.RestartBackoffMax
		}
	}
}

func describeExit(err error) string {
	if err == nil {
		return "exited unexpectedly"
	}
	return err.Error()
}

// acceptUpdateRestart decides whether a child's UpdateExitCode follows a real
// journal change: a new trial image, or an administrator's manual rollback
// that the previous run had not already completed.
func acceptUpdateRestart(previous, next *transaction) bool {
	if next == nil {
		return false
	}
	switch {
	case next.State == stateTrial:
		return previous == nil || previous.NewHash != next.NewHash
	case next.State == stateRolledBack && next.Manual:
		return previous == nil || previous.State != stateRolledBack || previous.NewHash != next.NewHash
	}
	return false
}

type heartbeatReport struct {
	Version     string `json:"version"`
	Maintenance string `json:"maintenance,omitempty"`
}

func watchChild(ctx context.Context, executable string, args []string, version string, trialPeriod time.Duration, promote func(), options WatchdogOptions) error {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		listener.Close()
		return err
	}
	token := hex.EncodeToString(secret)
	var mu sync.Mutex
	var last, ackAt time.Time
	ack, stopping := false, false
	started := time.Now()
	server := &http.Server{ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/heartbeat" ||
			subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		mu.Lock()
		isStopping := stopping
		mu.Unlock()
		if isStopping || ctx.Err() != nil {
			w.WriteHeader(http.StatusConflict)
			return
		}
		var report heartbeatReport
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&report) != nil || report.Version == "" || (version != "" && report.Version != version) {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if report.Maintenance != "" {
			// A child in maintenance is alive but not healthy. Outside an
			// update it re-arms the startup window and stays up while its
			// causes are resolved; an updated image never earns this.
			if version == "" && !ack {
				started = time.Now()
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if !ack {
			ack = true
			ackAt = time.Now()
		}
		last = time.Now()
		w.WriteHeader(http.StatusNoContent)
	})
	go server.Serve(listener)
	defer server.Close()
	cmd := exec.Command(executable, args...)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, supervisedEnv+"=") && !strings.HasPrefix(entry, watchdogURLEnv+"=") && !strings.HasPrefix(entry, watchdogTokenEnv+"=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, supervisedEnv+"=1", watchdogURLEnv+"=http://"+listener.Addr().String(), watchdogTokenEnv+"="+token)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err = cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	mu.Lock()
	started = time.Now()
	mu.Unlock()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	kill := func() { _ = cmd.Process.Kill(); <-done }
	promoted := false
	for {
		select {
		case err := <-done:
			if err == nil {
				return errors.New("server child exited")
			}
			return err
		case <-ctx.Done():
			mu.Lock()
			stopping = true
			mu.Unlock()
			stopChild(cmd)
			select {
			case <-done:
			case <-time.After(options.StopTimeout):
				kill()
			}
			return nil
		case <-ticker.C:
			mu.Lock()
			healthy, seen, since, ackTime := ack, last, started, ackAt
			mu.Unlock()
			if (!healthy && time.Since(since) > options.StartupTimeout) || (healthy && time.Since(seen) > options.HeartbeatTimeout) {
				kill()
				if !healthy {
					return errors.New("server_startup_timeout")
				}
				return errors.New("server_heartbeat_timeout")
			}
			if trialPeriod >= 0 && healthy && !promoted && time.Since(ackTime) >= trialPeriod {
				promoted = true
				promote()
			}
		}
	}
}

func postHeartbeat(ctx context.Context, client *http.Client, report heartbeatReport) (int, error) {
	body, _ := json.Marshal(report)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, os.Getenv(watchdogURLEnv)+"/heartbeat", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+os.Getenv(watchdogTokenEnv))
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

func heartbeatClient() *http.Client {
	return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}
}

// Heartbeat acknowledges startup only after probe (HTTP health endpoint and
// database) succeeds, and keeps reporting while it does. ready runs once,
// after the supervisor accepted the first healthy heartbeat; stop runs when
// the supervisor is stopping.
func Heartbeat(ctx context.Context, probe func(context.Context) error, version string, stop, ready func()) {
	client := heartbeatClient()
	defer client.CloseIdleConnections()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	acknowledged := false
	for {
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		healthy := probe(probeCtx) == nil
		cancel()
		if healthy {
			code, err := postHeartbeat(ctx, client, heartbeatReport{Version: version})
			if err == nil && code == http.StatusNoContent && !acknowledged {
				acknowledged = true
				ready()
			}
			if err == nil && code == http.StatusConflict {
				stop()
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// MaintenanceHeartbeat keeps a child whose core could not start alive while
// it serves the maintenance surface. stop runs when the supervisor stops.
func MaintenanceHeartbeat(ctx context.Context, version, code string, stop func()) {
	client := heartbeatClient()
	defer client.CloseIdleConnections()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if status, err := postHeartbeat(ctx, client, heartbeatReport{Version: version, Maintenance: code}); err == nil && status == http.StatusConflict {
			stop()
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
