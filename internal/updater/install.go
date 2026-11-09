package updater

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// FileInstaller replaces the server executable in place. The new image is
// staged next to the executable (same filesystem), verified against the signed
// manifest, probed with --version and swapped with two renames under a durable
// journal. The previous image is kept as <executable>.previous-<nanos>.
type FileInstaller struct {
	Executable     string
	CurrentVersion string
	Trust          *Trust
	Platform       Platform
}

func (i FileInstaller) versionPath() string {
	return filepath.Join(filepath.Dir(i.Executable), "VERSION")
}

// Install installs a verified release as a trial image. The caller restarts
// the process; the supervisor then runs the new image on probation.
func (i FileInstaller) Install(ctx context.Context, source Source, release *Release) error {
	if err := verifyRelease(i.Trust, release, i.Platform); err != nil {
		return err
	}
	prior, err := i.loadTransaction()
	if err != nil {
		return err
	}
	if prior != nil && (prior.State == stateTrial || prior.State == statePrepared) {
		return errors.New("update_trial_in_progress")
	}
	if prior != nil && prior.State == stateRolledBack && prior.NewVersion == release.Version {
		return errors.New("version_quarantined")
	}
	f, err := os.CreateTemp(filepath.Dir(i.Executable), ".shorebird-server-staged-*")
	if err != nil {
		return errors.New("install_permission_denied")
	}
	staged := f.Name()
	defer os.Remove(staged)
	if err = f.Chmod(0o755); err == nil {
		err = source.Download(ctx, release, f)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		if ctx.Err() != nil {
			return errors.New("update_cancelled")
		}
		return err
	}
	if closeErr != nil {
		return errors.New("download_failed")
	}
	newHash, err := fileHash(staged)
	if err != nil || newHash != fmt.Sprintf("%x", release.Checksum) {
		return errors.New("checksum_mismatch")
	}
	// A binary with another platform or embedded version must never replace
	// the running server. --version exits before reading any configuration.
	probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(probeCtx, staged, "--version")
	output := &limitedOutput{limit: 256}
	cmd.Stdout = output
	cmd.Stderr = io.Discard
	cmd.Env = probeEnvironment()
	if cmd.Run() != nil || strings.TrimSpace(string(output.data)) != release.Version {
		return errors.New("binary_version_mismatch")
	}
	if ctx.Err() != nil {
		return errors.New("update_cancelled")
	}
	oldHash, err := fileHash(i.Executable)
	if err != nil {
		return errors.New("install_failed")
	}
	backupName := filepath.Base(i.Executable) + fmt.Sprintf(".previous-%d", time.Now().UnixNano())
	backup := filepath.Join(filepath.Dir(i.Executable), backupName)
	txn := &transaction{State: statePrepared, Previous: backupName, OldVersion: i.CurrentVersion, NewVersion: release.Version, OldHash: oldHash, NewHash: newHash}
	if err = i.saveTransaction(txn); err != nil {
		return errors.New("install_permission_denied")
	}
	if err = os.Rename(i.Executable, backup); err != nil {
		i.restoreJournal(prior)
		return errors.New("install_permission_denied")
	}
	if err = os.Rename(staged, i.Executable); err != nil {
		if os.Rename(backup, i.Executable) != nil {
			return errors.New("rollback_failed")
		}
		i.restoreJournal(prior)
		return errors.New("install_failed")
	}
	_ = syncDir(filepath.Dir(i.Executable))
	txn.State = stateTrial
	if err = i.saveTransaction(txn); err != nil {
		if i.restorePrevious(txn, txn.OldVersion) != nil {
			return errors.New("rollback_failed")
		}
		return errors.New("install_failed")
	}
	// The previous journal's backup is superseded. A locked file (Windows) is
	// left for the operator.
	if prior != nil && prior.Previous != backupName {
		_ = os.Remove(filepath.Join(filepath.Dir(i.Executable), prior.Previous))
	}
	// VERSION is advisory; the executable's embedded version is authoritative.
	if err = writeVersion(i.versionPath(), release.Version); err != nil {
		if i.restorePrevious(txn, txn.OldVersion) != nil {
			return errors.New("rollback_failed")
		}
		return errors.New("version_write_failed")
	}
	return nil
}

// restoreJournal puts the previous journal back after a replacement that
// never happened, so its quarantine and rollback information survive.
func (i FileInstaller) restoreJournal(prior *transaction) {
	if prior == nil {
		_ = os.Remove(i.journalPath())
		return
	}
	_ = i.saveTransaction(prior)
}

// probeEnvironment keeps the supervisor's control variables away from the
// --version probe.
func probeEnvironment() []string {
	var env []string
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, supervisedEnv+"=") && !strings.HasPrefix(entry, watchdogURLEnv+"=") && !strings.HasPrefix(entry, watchdogTokenEnv+"=") {
			env = append(env, entry)
		}
	}
	return env
}

type limitedOutput struct {
	data  []byte
	limit int
}

func (w *limitedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := w.limit - len(w.data); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		w.data = append(w.data, p...)
	}
	return n, nil
}

func writeVersion(path, version string) error {
	return writeFileAtomic(path, []byte(version+"\n"), 0o644)
}

// Rollback restores the hash-bound previous image after a failed trial and
// quarantines the failed version (watchdog path).
func (i FileInstaller) Rollback() error {
	txn, err := i.loadTransaction()
	if err != nil || txn == nil {
		return errors.New("rollback_failed")
	}
	return i.restorePrevious(txn, txn.OldVersion)
}

// RollbackInfo reports the version a manual rollback would restore. It only
// inspects the journal and the presence of the backup; ManualRollback verifies
// both hashes before replacing anything.
func (i FileInstaller) RollbackInfo() (string, bool) {
	txn, err := i.loadTransaction()
	if err != nil || txn == nil || !i.manualRollbackJournal(txn) {
		return "", false
	}
	info, err := os.Stat(filepath.Join(filepath.Dir(i.Executable), txn.Previous))
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	return txn.OldVersion, true
}

// ManualRollback restores the previous image of the running, installed
// version and quarantines it exactly like a watchdog rollback. The caller
// restarts the process; the supervisor runs the restored image without a trial.
func (i FileInstaller) ManualRollback() error {
	txn, err := i.loadTransaction()
	if err != nil || txn == nil || !i.manualRollbackJournal(txn) {
		return errors.New("rollback_unavailable")
	}
	hash, err := fileHash(i.Executable)
	if err != nil || hash != txn.NewHash {
		return errors.New("rollback_unavailable")
	}
	txn.Manual = true
	if err := i.restorePrevious(txn, txn.OldVersion); err != nil {
		return errors.New("rollback_failed")
	}
	return nil
}

func (i FileInstaller) manualRollbackJournal(txn *transaction) bool {
	return (txn.State == stateTrial || txn.State == stateHealthy) && i.CurrentVersion != "" && txn.NewVersion == i.CurrentVersion && txn.OldVersion != ""
}

func (i FileInstaller) restorePrevious(txn *transaction, old string) error {
	previous := filepath.Join(filepath.Dir(i.Executable), txn.Previous)
	hash, err := fileHash(previous)
	if err != nil || hash != txn.OldHash {
		return errors.New("rollback_failed")
	}
	failed := i.Executable + fmt.Sprintf(".failed-%d", time.Now().UnixNano())
	if err := os.Rename(i.Executable, failed); err != nil {
		return err
	}
	if err := os.Rename(previous, i.Executable); err != nil {
		_ = os.Rename(failed, i.Executable)
		return err
	}
	_ = syncDir(filepath.Dir(i.Executable))
	// A locked image (Windows: the running child) stays for the operator.
	_ = os.Remove(failed)
	if err = writeVersion(i.versionPath(), old); err != nil {
		return err
	}
	txn.State = stateRolledBack
	return i.saveTransaction(txn)
}

// JournalState returns the current journal state ("" without a journal).
func (i FileInstaller) JournalState() string {
	txn, err := i.loadTransaction()
	if err != nil {
		return "invalid"
	}
	if txn == nil {
		return ""
	}
	return txn.State
}

// SweepTemporaries removes staging, download, upload and write temporaries
// that a crashed process left next to the executable. Only files older than
// minAge are removed, so a concurrent journal write is never touched.
func SweepTemporaries(executable string, minAge time.Duration) int {
	removed := 0
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(executable), ".shorebird-server-*"))
	for _, path := range matches {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || time.Since(info.ModTime()) < minAge {
			continue
		}
		if os.Remove(path) == nil {
			removed++
		}
	}
	return removed
}
