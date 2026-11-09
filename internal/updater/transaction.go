package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Journal states. prepared: the replacement is about to happen. trial: the new
// image is installed and on probation. healthy: it passed probation.
// rolled_back: the previous image was restored (NewVersion is quarantined).
const (
	statePrepared   = "prepared"
	stateTrial      = "trial"
	stateHealthy    = "healthy"
	stateRolledBack = "rolled_back"
)

// transaction is the durable <executable>.update.json journal. Both images are
// bound by hash, so the supervisor can always tell which one is installed.
type transaction struct {
	State      string `json:"state"`
	Previous   string `json:"previous"`
	OldVersion string `json:"old_version"`
	NewVersion string `json:"new_version"`
	OldHash    string `json:"old_hash"`
	NewHash    string `json:"new_hash"`
	// Manual marks a rollback requested by an administrator rather than the
	// watchdog. Both quarantine NewVersion.
	Manual bool `json:"manual,omitempty"`
	// UpdatedAt is informational (status output).
	UpdatedAt time.Time `json:"updated_at"`
}

func fileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	_, err = io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), err
}

func (i FileInstaller) journalPath() string { return i.Executable + ".update.json" }

func (i FileInstaller) loadTransaction() (*transaction, error) {
	f, err := os.Open(i.journalPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("invalid_update_journal")
	}
	defer f.Close()
	data, err := readBounded(f, 16384)
	if err != nil {
		return nil, errors.New("invalid_update_journal")
	}
	var t transaction
	if json.Unmarshal(data, &t) != nil || filepath.Base(t.Previous) != t.Previous ||
		!strings.HasPrefix(t.Previous, filepath.Base(i.Executable)+".previous-") || len(t.OldHash) != 64 || len(t.NewHash) != 64 {
		return nil, errors.New("invalid_update_journal")
	}
	switch t.State {
	case statePrepared, stateTrial, stateHealthy, stateRolledBack:
	default:
		return nil, errors.New("invalid_update_journal")
	}
	return &t, nil
}

func (i FileInstaller) saveTransaction(t *transaction) error {
	t.UpdatedAt = time.Now().UTC()
	data, err := json.Marshal(t)
	if err != nil {
		return err
	}
	return writeFileAtomic(i.journalPath(), data, 0o600)
}

// recoverTransaction resolves a power or process interruption around a
// replacement, and archives a finished journal that no longer matches the
// installed executable (an operator installed a binary by hand).
func (i FileInstaller) recoverTransaction() (*transaction, error) {
	t, err := i.loadTransaction()
	if err != nil || t == nil {
		return t, err
	}
	hash, err := fileHash(i.Executable)
	if t.State != statePrepared {
		if err == nil && hash == t.NewHash && t.State != stateRolledBack {
			return t, nil
		}
		if err == nil && hash == t.OldHash {
			if t.State != stateRolledBack {
				t.State = stateRolledBack
				if e := writeVersion(i.versionPath(), t.OldVersion); e != nil {
					return nil, e
				}
				return t, i.saveTransaction(t)
			}
			return t, nil
		}
		if err == nil && (t.State == stateHealthy || t.State == stateRolledBack) {
			stale := fmt.Sprintf("%s.stale-%d", i.journalPath(), time.Now().Unix())
			if e := os.Rename(i.journalPath(), stale); e != nil {
				return nil, e
			}
			log.Printf("update_journal_archived: %s (the installed executable matches neither journal image)", filepath.Base(stale))
			return nil, nil
		}
		return nil, errors.New("invalid_update_journal")
	}
	if err == nil && hash == t.NewHash {
		t.State = stateTrial
		return t, i.saveTransaction(t)
	}
	if err == nil && hash == t.OldHash {
		t.State = stateRolledBack
		return t, i.saveTransaction(t)
	}
	// The original may have been moved aside just before the process stopped.
	backup := filepath.Join(filepath.Dir(i.Executable), t.Previous)
	if old, e := fileHash(backup); e != nil || old != t.OldHash {
		return nil, errors.New("rollback_failed")
	}
	if _, e := os.Stat(i.Executable); e == nil {
		return nil, errors.New("rollback_failed")
	}
	if e := os.Rename(backup, i.Executable); e != nil {
		return nil, e
	}
	t.State = stateRolledBack
	if e := writeVersion(i.versionPath(), t.OldVersion); e != nil {
		return nil, e
	}
	return t, i.saveTransaction(t)
}
