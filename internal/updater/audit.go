package updater

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"
)

// AuditEvent is one administrative self-update action. It never contains a
// password, token, maintenance secret or signature; Details carries only
// versions, channels and settings values.
type AuditEvent struct {
	Time       time.Time      `json:"time"`
	Action     string         `json:"action"`
	Result     string         `json:"result"`
	ActorID    int            `json:"actor_id,omitempty"`
	ActorEmail string         `json:"actor_email,omitempty"`
	Auth       string         `json:"auth"`
	RemoteAddr string         `json:"remote_addr,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
}

// Auditor records administrative actions.
type Auditor interface {
	Record(AuditEvent)
	Recent(limit int) ([]AuditEvent, error)
}

// FileAuditor appends JSON lines to a 0600 file in the update state directory
// and mirrors each line to the process log. The file rotates once at MaxBytes
// (one previous generation, <path>.1). A file is used rather than the
// database so that maintenance-mode uploads, which run without a database,
// are audited in the same place.
type FileAuditor struct {
	Path     string
	MaxBytes int64
	mu       sync.Mutex
}

// NewFileAuditor returns an auditor writing to path (1 MiB rotation); an
// empty path only logs.
func NewFileAuditor(path string) *FileAuditor { return &FileAuditor{Path: path, MaxBytes: 1 << 20} }

func (a *FileAuditor) Record(event AuditEvent) {
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	line, err := json.Marshal(event)
	if err != nil {
		return
	}
	log.Printf("audit server_update %s", line)
	if a.Path == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if info, err := os.Stat(a.Path); err == nil && info.Size()+int64(len(line))+1 > a.MaxBytes {
		_ = os.Rename(a.Path, a.Path+".1")
	}
	f, err := os.OpenFile(a.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("audit_unwritable: %s", err)
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
}

// Recent returns up to limit newest events, newest first.
func (a *FileAuditor) Recent(limit int) ([]AuditEvent, error) {
	if a.Path == "" {
		return nil, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var events []AuditEvent
	for _, path := range []string{a.Path, a.Path + ".1"} {
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var chunk []AuditEvent
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 64<<10), 1<<20)
		for scanner.Scan() {
			var e AuditEvent
			if json.Unmarshal(scanner.Bytes(), &e) == nil {
				chunk = append(chunk, e)
			}
		}
		for n := len(chunk) - 1; n >= 0 && len(events) < limit; n-- {
			events = append(events, chunk[n])
		}
		if len(events) >= limit {
			break
		}
	}
	return events, nil
}
