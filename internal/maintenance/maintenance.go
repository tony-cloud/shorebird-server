// Package maintenance keeps a supervised server reachable when its core cannot
// start: it reports why, offers a retry and accepts a signed update ZIP,
// authenticated by a per-episode secret file instead of the database.
package maintenance

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/shorebird-server/internal/updater"
)

// Cause is one reason the core could not start.
type Cause struct {
	Code      string     `json:"code"`
	Stage     string     `json:"stage"`
	Action    string     `json:"action"`
	Transient bool       `json:"transient"`
	Detail    string     `json:"detail,omitempty"`
	Since     time.Time  `json:"since"`
	Attempts  int        `json:"attempts"`
	NextRetry *time.Time `json:"next_retry,omitempty"`
}

// Resume tells the caller how maintenance ended.
type Resume int

const (
	// ResumeRetry: start the core again.
	ResumeRetry Resume = iota
	// ResumeUpdate: an uploaded update is installed; exit with UpdateExitCode.
	ResumeUpdate
	// ResumeStopped: the process is stopping.
	ResumeStopped
)

// Options configures the maintenance surface.
type Options struct {
	Addr       string
	SecretPath string
	Version    string
	Updater    *updater.Service
	Auditor    updater.Auditor
	// Restart receives a value when the updater installed an image.
	Restart <-chan struct{}
	// Supervised enables maintenance heartbeats to the supervisor.
	Supervised bool
	Logf       func(string, ...any)
}

// Surface is the maintenance HTTP surface of one maintenance episode.
type Surface struct {
	opts   Options
	mu     sync.Mutex
	cause  Cause
	secret string
	retry  chan struct{}
}

// New prepares a surface; the secret file is created on first use.
func New(opts Options) *Surface {
	if opts.Logf == nil {
		opts.Logf = log.Printf
	}
	return &Surface{opts: opts, retry: make(chan struct{}, 1)}
}

var (
	dsnCredential   = regexp.MustCompile(`(://[^/\s:@]*:)[^@\s]*@`)
	keyedCredential = regexp.MustCompile(`(?i)\b((?:password|passwd|pwd|secret|token|key)=)\S+`)
)

// Redact removes credentials that error texts may carry (DSNs, key=value).
func Redact(s string) string {
	s = dsnCredential.ReplaceAllString(s, "${1}REDACTED@")
	s = keyedCredential.ReplaceAllString(s, "${1}REDACTED")
	if len(s) > 512 {
		s = s[:512] + "..."
	}
	return s
}

func (s *Surface) ensureSecret() error {
	if s.secret != "" {
		return nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	secret := hex.EncodeToString(raw)
	_ = os.Remove(s.opts.SecretPath)
	f, err := os.OpenFile(s.opts.SecretPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(secret + "\n")
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		_ = os.Remove(s.opts.SecretPath)
		return err
	}
	s.secret = secret
	return nil
}

// Close ends the episode: the secret file is removed once the core is up.
func (s *Surface) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.secret != "" {
		_ = os.Remove(s.opts.SecretPath)
		s.secret = ""
	}
}

func (s *Surface) authorized(r *http.Request) bool {
	s.mu.Lock()
	secret := s.secret
	s.mu.Unlock()
	got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	return secret != "" && subtle.ConstantTimeCompare([]byte(got), []byte(secret)) == 1
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// Handler serves the maintenance routes.
func (s *Surface) Handler() http.Handler {
	mux := http.NewServeMux()
	codes := func() []string {
		s.mu.Lock()
		defer s.mu.Unlock()
		return []string{s.cause.Code}
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"code": "SERVER_MAINTENANCE", "causes": codes()})
	})
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "maintenance", "code": "SERVER_MAINTENANCE", "causes": codes()})
	})
	guard := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !s.authorized(r) {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"code": "MAINTENANCE_SECRET_INVALID"})
				return
			}
			next(w, r)
		}
	}
	mux.HandleFunc("GET /api/v1/server/maintenance", guard(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		cause := s.cause
		s.mu.Unlock()
		body := map[string]any{"version": s.opts.Version, "causes": []Cause{cause}}
		if s.opts.Updater != nil {
			body["updater"] = s.opts.Updater.Status()
		}
		writeJSON(w, http.StatusOK, body)
	}))
	mux.HandleFunc("POST /api/v1/server/maintenance/retry", guard(func(w http.ResponseWriter, r *http.Request) {
		select {
		case s.retry <- struct{}{}:
		default:
		}
		s.audit(r, "server.maintenance.retry", "ok", nil)
		writeJSON(w, http.StatusAccepted, map[string]any{"status": "retrying"})
	}))
	mux.HandleFunc("POST /api/v1/server/maintenance/update", guard(func(w http.ResponseWriter, r *http.Request) {
		if s.opts.Updater == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, updater.MaxZIPBytes))
			s.audit(r, "server.maintenance.update", "self_update_unavailable", nil)
			writeJSON(w, http.StatusConflict, map[string]any{"code": "self_update_unavailable"})
			return
		}
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(15 * time.Minute))
		body := http.MaxBytesReader(w, r.Body, updater.MaxZIPBytes)
		version, err := s.opts.Updater.Upload(body)
		if err != nil {
			_, _ = io.Copy(io.Discard, body)
			s.audit(r, "server.maintenance.update", err.Error(), nil)
			writeJSON(w, http.StatusConflict, map[string]any{"code": err.Error()})
			return
		}
		s.audit(r, "server.maintenance.update", "accepted", map[string]any{"version": version})
		writeJSON(w, http.StatusAccepted, s.opts.Updater.Status())
	}))
	return mux
}

func (s *Surface) audit(r *http.Request, action, result string, details map[string]any) {
	if s.opts.Auditor == nil {
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	s.opts.Auditor.Record(updater.AuditEvent{Action: action, Result: result, Auth: "maintenance_secret", RemoteAddr: host, Details: details})
}

// Serve stays in maintenance for cause until a retry is due or requested, an
// uploaded update is installed, or ctx ends.
func (s *Surface) Serve(ctx context.Context, cause Cause) Resume {
	s.mu.Lock()
	cause.Detail = Redact(cause.Detail)
	s.cause = cause
	err := s.ensureSecret()
	s.mu.Unlock()
	retryText := "retry with POST /api/v1/server/maintenance/retry or restart the service"
	if cause.NextRetry != nil {
		retryText = "automatic retry at " + cause.NextRetry.UTC().Format(time.RFC3339)
	}
	s.opts.Logf("SERVER MAINTENANCE %s (stage %s, attempt %d): %s. Error: %s. %s", cause.Code, cause.Stage, cause.Attempts, cause.Action, cause.Detail, retryText)
	if err != nil {
		s.opts.Logf("MAINTENANCE_SECRET_UNWRITABLE: cannot create %s (%v); the maintenance API is unavailable", s.opts.SecretPath, err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if s.opts.Supervised {
		go updater.MaintenanceHeartbeat(ctx, s.opts.Version, cause.Code, cancel)
	}
	var server *http.Server
	if listener, err := net.Listen("tcp", s.opts.Addr); err != nil {
		s.opts.Logf("maintenance surface unavailable on %s: %v", s.opts.Addr, err)
	} else {
		server = &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
		go server.Serve(listener)
	}
	defer func() {
		if server != nil {
			shutdownCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
			defer done()
			_ = server.Shutdown(shutdownCtx)
		}
	}()
	var timer <-chan time.Time
	if cause.NextRetry != nil {
		t := time.NewTimer(time.Until(*cause.NextRetry))
		defer t.Stop()
		timer = t.C
	}
	select {
	case <-ctx.Done():
		return ResumeStopped
	case <-s.retry:
		return ResumeRetry
	case <-timer:
		return ResumeRetry
	case <-s.opts.Restart:
		return ResumeUpdate
	}
}
