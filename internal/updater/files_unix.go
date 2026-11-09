//go:build !windows

package updater

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// replaceFile renames from over to and syncs the directory entry.
func replaceFile(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return err
	}
	return syncDir(filepath.Dir(to))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// stopChild asks the supervised child to shut down gracefully.
func stopChild(cmd *exec.Cmd) { _ = cmd.Process.Signal(syscall.SIGTERM) }
