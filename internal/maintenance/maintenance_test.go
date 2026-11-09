package maintenance

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shorebird-server/internal/updater"
)

func TestRedact(t *testing.T) {
	for in, want := range map[string]string{
		"failed to connect to postgres://shorebird:hunter2@db:5432/x": "failed to connect to postgres://shorebird:REDACTED@db:5432/x",
		"dial: password=hunter2 host=db":                              "dial: password=REDACTED host=db",
		"plain error":                                                 "plain error",
	} {
		if got := Redact(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
	if got := Redact(strings.Repeat("x", 600)); len(got) != 515 {
		t.Fatalf("not bounded: %d", len(got))
	}
}

func TestMaintenanceSurface(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "server-maintenance.secret")
	auditPath := filepath.Join(dir, "audit.jsonl")
	inactive := updater.NewInactive(updater.Plan{Mode: updater.ModeUnavailable, Reason: "unversioned_build"}, "v1.0.0", updater.CurrentPlatform())
	s := New(Options{Addr: "127.0.0.1:0", SecretPath: secretPath, Version: "v1.0.0", Updater: inactive, Auditor: updater.NewFileAuditor(auditPath), Logf: func(string, ...any) {}})
	resumed := make(chan Resume, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		resumed <- s.Serve(ctx, Cause{Code: "DATABASE_UNAVAILABLE", Stage: "database", Action: "Start the database", Transient: true,
			Detail: "postgres://u:hunter2@db/x refused", Since: time.Now(), Attempts: 1})
	}()
	var secret []byte
	deadline := time.Now().Add(5 * time.Second)
	for len(secret) == 0 {
		secret, _ = os.ReadFile(secretPath)
		if time.Now().After(deadline) {
			t.Fatal("no secret file")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if info, _ := os.Stat(secretPath); info.Mode().Perm() != 0o600 {
		t.Fatalf("secret mode %v", info.Mode())
	}
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	request := func(method, path, auth, contentType, body string) (int, string) {
		req, _ := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(data)
	}
	if status, body := request(http.MethodGet, "/health", "", "", ""); status != http.StatusServiceUnavailable || !strings.Contains(body, `"DATABASE_UNAVAILABLE"`) {
		t.Fatalf("health: %d %s", status, body)
	}
	if status, body := request(http.MethodGet, "/api/v1/apps", "", "", ""); status != http.StatusServiceUnavailable || !strings.Contains(body, "SERVER_MAINTENANCE") {
		t.Fatalf("core route: %d %s", status, body)
	}
	key := strings.TrimSpace(string(secret))
	for _, auth := range []string{"", "wrong", key + "x"} {
		if status, _ := request(http.MethodGet, "/api/v1/server/maintenance", auth, "", ""); status != http.StatusUnauthorized {
			t.Fatalf("secret %q accepted: %d", auth, status)
		}
	}
	status, body := request(http.MethodGet, "/api/v1/server/maintenance", key, "", "")
	if status != http.StatusOK || !strings.Contains(body, "REDACTED") || strings.Contains(body, "hunter2") || !strings.Contains(body, `"updater"`) {
		t.Fatalf("report: %d %s", status, body)
	}
	if status, body := request(http.MethodPost, "/api/v1/server/maintenance/update", key, "application/zip", "PK"); status != http.StatusConflict || !strings.Contains(body, "self_update_unavailable") {
		t.Fatalf("update on an unavailable updater: %d %s", status, body)
	}
	if status, _ := request(http.MethodPost, "/api/v1/server/maintenance/retry", key, "", ""); status != http.StatusAccepted {
		t.Fatalf("retry: %d", status)
	}
	select {
	case r := <-resumed:
		if r != ResumeRetry {
			t.Fatalf("resume %v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("retry did not resume")
	}
	audit, _ := os.ReadFile(auditPath)
	if strings.Contains(string(audit), key) || !strings.Contains(string(audit), `"auth":"maintenance_secret"`) {
		t.Fatalf("audit: %s", audit)
	}
	s.Close()
	if _, err := os.Stat(secretPath); !os.IsNotExist(err) {
		t.Fatal("secret file kept after the episode")
	}
}

func TestMaintenanceAutomaticRetryAndUpdateRestart(t *testing.T) {
	dir := t.TempDir()
	restart := make(chan struct{}, 1)
	s := New(Options{Addr: "127.0.0.1:0", SecretPath: filepath.Join(dir, "secret"), Version: "v1.0.0", Restart: restart, Logf: func(string, ...any) {}})
	next := time.Now().Add(100 * time.Millisecond)
	if r := s.Serve(context.Background(), Cause{Code: "LISTEN_FAILED", Transient: true, NextRetry: &next}); r != ResumeRetry {
		t.Fatalf("automatic retry: %v", r)
	}
	restart <- struct{}{}
	if r := s.Serve(context.Background(), Cause{Code: "DATABASE_INIT_FAILED"}); r != ResumeUpdate {
		t.Fatalf("installed update: %v", r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := s.Serve(ctx, Cause{Code: "X"}); r != ResumeStopped {
		t.Fatalf("stop: %v", r)
	}
	s.Close()
}
