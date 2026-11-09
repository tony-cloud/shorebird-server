package updater

import (
	"os"
	"os/exec"
)

// replaceFile renames from over to (MoveFileEx with MOVEFILE_REPLACE_EXISTING).
func replaceFile(from, to string) error { return os.Rename(from, to) }

func syncDir(string) error { return nil }

// stopChild relies on the heartbeat: a stopping supervisor answers the
// child's next heartbeat with 409 and the child shuts down by itself.
func stopChild(*exec.Cmd) {}
