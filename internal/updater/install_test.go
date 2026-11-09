package updater

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func installFixture(t *testing.T) (FileInstaller, testKey, string) {
	t.Helper()
	requireUnix(t)
	k := newTestKey(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "shorebird-server")
	if err := os.WriteFile(target, scriptBinary("v1.0.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	return FileInstaller{Executable: target, CurrentVersion: "v1.0.0", Trust: k.trust, Platform: linuxAMD64}, k, dir
}

func TestInstallKeepsHashBoundPreviousImage(t *testing.T) {
	installer, k, dir := installFixture(t)
	oldHash, _ := fileHash(installer.Executable)
	binary := scriptBinary("v1.1.0")
	release := k.release(t, "v1.1.0", "stable", linuxAMD64, binary)
	if err := installer.Install(context.Background(), bytesSource{binary}, release); err != nil {
		t.Fatal(err)
	}
	txn, err := installer.loadTransaction()
	if err != nil || txn.State != stateTrial || txn.OldVersion != "v1.0.0" || txn.NewVersion != "v1.1.0" || txn.OldHash != oldHash {
		t.Fatalf("journal %+v %v", txn, err)
	}
	if hash, _ := fileHash(installer.Executable); hash != txn.NewHash {
		t.Fatal("new image not installed")
	}
	if hash, _ := fileHash(filepath.Join(dir, txn.Previous)); hash != oldHash {
		t.Fatal("previous image not kept")
	}
	if v, _ := os.ReadFile(filepath.Join(dir, "VERSION")); string(v) != "v1.1.0\n" {
		t.Fatalf("VERSION %q", v)
	}
	if info, _ := os.Stat(installer.journalPath()); info.Mode().Perm() != 0o600 {
		t.Fatalf("journal mode %v", info.Mode())
	}
	// A second install during the trial is refused.
	next := scriptBinary("v1.2.0")
	if err := installer.Install(context.Background(), bytesSource{next}, k.release(t, "v1.2.0", "stable", linuxAMD64, next)); err == nil || err.Error() != "update_trial_in_progress" {
		t.Fatalf("install during trial: %v", err)
	}
}

func TestInstallRefusals(t *testing.T) {
	installer, k, dir := installFixture(t)
	before, _ := fileHash(installer.Executable)
	// The embedded version must match the signed manifest.
	liar := scriptBinary("v9.9.9")
	if err := installer.Install(context.Background(), bytesSource{liar}, k.release(t, "v1.1.0", "stable", linuxAMD64, liar)); err == nil || err.Error() != "binary_version_mismatch" {
		t.Fatalf("version probe: %v", err)
	}
	// A source delivering other bytes than signed is refused before probing.
	good := scriptBinary("v1.1.0")
	err := installer.Install(context.Background(), bytesSource{scriptBinary("v1.1.1")}, k.release(t, "v1.1.0", "stable", linuxAMD64, good))
	if err == nil || err.Error() != "checksum_mismatch" {
		t.Fatalf("hash: %v", err)
	}
	// A release object whose fields differ from its signed manifest.
	forged := k.release(t, "v1.1.0", "stable", linuxAMD64, good)
	forged.Version = "v1.5.0"
	if err := installer.Install(context.Background(), bytesSource{good}, forged); err == nil || err.Error() != "invalid_release" {
		t.Fatalf("forged release: %v", err)
	}
	// A release for another platform.
	other := k.release(t, "v1.1.0", "stable", Platform{"linux", "arm64"}, good)
	if err := installer.Install(context.Background(), bytesSource{good}, other); err == nil || err.Error() != "wrong_platform" {
		t.Fatalf("other platform: %v", err)
	}
	if after, _ := fileHash(installer.Executable); after != before {
		t.Fatal("a refused install changed the executable")
	}
	if _, err := os.Stat(installer.journalPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused install wrote a journal")
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, ".shorebird-server-*"))
	if len(leftovers) != 0 {
		t.Fatalf("staging files left: %v", leftovers)
	}
}

func TestInstallPermissionDenied(t *testing.T) {
	installer, k, dir := installFixture(t)
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o755)
	binary := scriptBinary("v1.1.0")
	if err := installer.Install(context.Background(), bytesSource{binary}, k.release(t, "v1.1.0", "stable", linuxAMD64, binary)); err == nil || err.Error() != "install_permission_denied" {
		t.Fatalf("read-only directory: %v", err)
	}
	if InstallWritable(installer.Executable) {
		t.Fatal("InstallWritable on a read-only directory")
	}
}

func TestQuarantinedVersionIsNotReinstalled(t *testing.T) {
	installer, k, _ := installFixture(t)
	binary := scriptBinary("v1.1.0")
	release := k.release(t, "v1.1.0", "stable", linuxAMD64, binary)
	if err := installer.Install(context.Background(), bytesSource{binary}, release); err != nil {
		t.Fatal(err)
	}
	if err := installer.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := installer.Install(context.Background(), bytesSource{binary}, release); err == nil || err.Error() != "version_quarantined" {
		t.Fatalf("reinstall of a rolled back version: %v", err)
	}
	// A newer signed version clears the quarantine by installing normally.
	newer := scriptBinary("v1.2.0")
	if err := installer.Install(context.Background(), bytesSource{newer}, k.release(t, "v1.2.0", "stable", linuxAMD64, newer)); err != nil {
		t.Fatalf("newer version after quarantine: %v", err)
	}
}

func TestRecoverTransaction(t *testing.T) {
	t.Run("prepared with new image becomes trial", func(t *testing.T) {
		installer, _, _ := installedFixture(t, statePrepared)
		txn, err := installer.recoverTransaction()
		if err != nil || txn.State != stateTrial {
			t.Fatalf("%+v %v", txn, err)
		}
	})
	t.Run("prepared with executable moved aside restores previous", func(t *testing.T) {
		installer, oldHash, _ := installedFixture(t, statePrepared)
		if err := os.Remove(installer.Executable); err != nil {
			t.Fatal(err)
		}
		txn, err := installer.recoverTransaction()
		if err != nil || txn.State != stateRolledBack {
			t.Fatalf("%+v %v", txn, err)
		}
		if hash, _ := fileHash(installer.Executable); hash != oldHash {
			t.Fatal("previous image not restored")
		}
	})
	t.Run("trial whose previous image is installed is rolled back", func(t *testing.T) {
		installer, _, _ := installedFixture(t, stateTrial)
		txn, _ := installer.loadTransaction()
		previous := filepath.Join(filepath.Dir(installer.Executable), txn.Previous)
		if err := os.Rename(previous, installer.Executable); err != nil {
			t.Fatal(err)
		}
		got, err := installer.recoverTransaction()
		if err != nil || got.State != stateRolledBack {
			t.Fatalf("%+v %v", got, err)
		}
	})
	t.Run("stale finished journal is archived", func(t *testing.T) {
		installer, _, _ := installedFixture(t, stateHealthy)
		if err := os.WriteFile(installer.Executable, scriptBinary("v3.0.0-by-hand"), 0o755); err != nil {
			t.Fatal(err)
		}
		txn, err := installer.recoverTransaction()
		if err != nil || txn != nil {
			t.Fatalf("stale journal: %+v %v", txn, err)
		}
		archived, _ := filepath.Glob(installer.journalPath() + ".stale-*")
		if len(archived) != 1 {
			t.Fatalf("archived journals %v", archived)
		}
		if _, err := os.Stat(installer.journalPath()); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("journal not moved aside")
		}
	})
	t.Run("unfinished trial with unknown image refuses to start", func(t *testing.T) {
		installer, _, _ := installedFixture(t, stateTrial)
		if err := os.WriteFile(installer.Executable, scriptBinary("v3.0.0-by-hand"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := installer.recoverTransaction(); err == nil || err.Error() != "invalid_update_journal" {
			t.Fatalf("unknown image during trial: %v", err)
		}
	})
	t.Run("malformed journal", func(t *testing.T) {
		installer, _, _ := installedFixture(t, stateTrial)
		for _, data := range []string{`{`, `{"state":"other","previous":"shorebird-server.previous-1","old_hash":"` + strings.Repeat("a", 64) + `","new_hash":"` + strings.Repeat("b", 64) + `"}`,
			`{"state":"trial","previous":"../etc/passwd","old_hash":"` + strings.Repeat("a", 64) + `","new_hash":"` + strings.Repeat("b", 64) + `"}`} {
			if err := os.WriteFile(installer.journalPath(), []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := installer.loadTransaction(); err == nil || err.Error() != "invalid_update_journal" {
				t.Fatalf("journal %s: %v", data, err)
			}
		}
	})
}

func TestManualRollbackRestoresPreviousAndQuarantines(t *testing.T) {
	for _, state := range []string{stateTrial, stateHealthy} {
		t.Run(state, func(t *testing.T) {
			installer, oldHash, _ := installedFixture(t, state)
			if previous, ok := installer.RollbackInfo(); !ok || previous != "v1.0.0" {
				t.Fatalf("rollback info %q %v", previous, ok)
			}
			if err := installer.ManualRollback(); err != nil {
				t.Fatal(err)
			}
			if hash, _ := fileHash(installer.Executable); hash != oldHash {
				t.Fatal("previous image not restored")
			}
			txn, err := installer.loadTransaction()
			if err != nil || txn.State != stateRolledBack || !txn.Manual {
				t.Fatalf("journal %+v %v", txn, err)
			}
			if v, _ := os.ReadFile(filepath.Join(filepath.Dir(installer.Executable), "VERSION")); string(v) != "v1.0.0\n" {
				t.Fatalf("VERSION %q", v)
			}
			if _, ok := installer.RollbackInfo(); ok {
				t.Fatal("rollback offered twice")
			}
		})
	}
}

func TestManualRollbackRefusals(t *testing.T) {
	t.Run("running another version", func(t *testing.T) {
		installer, _, _ := installedFixture(t, stateHealthy)
		installer.CurrentVersion = "v1.0.0"
		if _, ok := installer.RollbackInfo(); ok {
			t.Fatal("offered")
		}
		if err := installer.ManualRollback(); err == nil || err.Error() != "rollback_unavailable" {
			t.Fatal(err)
		}
	})
	t.Run("executable replaced by hand", func(t *testing.T) {
		installer, _, _ := installedFixture(t, stateHealthy)
		_ = os.WriteFile(installer.Executable, scriptBinary("v2.0.0"+" "), 0o755)
		if err := installer.ManualRollback(); err == nil || err.Error() != "rollback_unavailable" {
			t.Fatal(err)
		}
	})
	t.Run("previous image missing", func(t *testing.T) {
		installer, _, _ := installedFixture(t, stateHealthy)
		txn, _ := installer.loadTransaction()
		_ = os.Remove(filepath.Join(filepath.Dir(installer.Executable), txn.Previous))
		if _, ok := installer.RollbackInfo(); ok {
			t.Fatal("offered without backup")
		}
	})
	t.Run("previous image tampered", func(t *testing.T) {
		installer, _, newHash := installedFixture(t, stateHealthy)
		txn, _ := installer.loadTransaction()
		_ = os.WriteFile(filepath.Join(filepath.Dir(installer.Executable), txn.Previous), []byte("evil"), 0o755)
		if err := installer.ManualRollback(); err == nil || err.Error() != "rollback_failed" {
			t.Fatal(err)
		}
		if hash, _ := fileHash(installer.Executable); hash != newHash {
			t.Fatal("running image replaced by a tampered backup")
		}
	})
	t.Run("after rollback", func(t *testing.T) {
		installer, _, _ := installedFixture(t, stateRolledBack)
		if err := installer.ManualRollback(); err == nil || err.Error() != "rollback_unavailable" {
			t.Fatal(err)
		}
	})
}

func TestSweepTemporaries(t *testing.T) {
	dir := t.TempDir()
	executable := filepath.Join(dir, "shorebird-server")
	old := time.Now().Add(-time.Hour)
	for _, name := range []string{".shorebird-server-staged-1", ".shorebird-server-upload-2.zip", ".shorebird-server-write-3"} {
		path := filepath.Join(dir, name)
		_ = os.WriteFile(path, []byte("x"), 0o600)
		_ = os.Chtimes(path, old, old)
	}
	fresh := filepath.Join(dir, ".shorebird-server-write-4")
	_ = os.WriteFile(fresh, []byte("x"), 0o600)
	keep := filepath.Join(dir, "shorebird-server.previous-1")
	_ = os.WriteFile(keep, []byte("x"), 0o600)
	_ = os.Chtimes(keep, old, old)
	if n := SweepTemporaries(executable, 10*time.Minute); n != 3 {
		t.Fatalf("removed %d", n)
	}
	for _, path := range []string{fresh, keep} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s removed", filepath.Base(path))
		}
	}
}
