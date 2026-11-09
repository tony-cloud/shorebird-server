package updater

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// Self-update modes reported in the status.
const (
	// ModeActive: this process is supervised and can replace its executable.
	ModeActive = "active"
	// ModeManagedExternally: the binary belongs to an immutable image
	// (Docker, Kubernetes, ...). Updates replace the image, never the binary.
	ModeManagedExternally = "managed_externally"
	// ModeDisabled: the operator turned self-update off (SERVER_SELF_UPDATE=off).
	ModeDisabled = "disabled"
	// ModeUnavailable: this build cannot self-update (see UnavailableReason).
	ModeUnavailable = "unavailable"
)

// ManagedExternallyEnv explicitly marks an externally managed deployment.
// The Docker image sets it; its value names the manager (for example "docker").
const ManagedExternallyEnv = "SHOREBIRD_SERVER_MANAGED_EXTERNALLY"

// Environment is what mode detection reads; tests replace it.
type Environment struct {
	Getenv func(string) string
	// Root is the filesystem root for container probes ("/" in production).
	Root string
	GOOS string
}

// ProcessEnvironment is the real environment of this process.
func ProcessEnvironment() Environment {
	return Environment{Getenv: os.Getenv, Root: "/", GOOS: runtime.GOOS}
}

var managerPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,31}$`)

// DetectContainer names the external manager of this process, or "".
// The explicit marker always wins; the heuristics cover images that do not
// set it (Docker, Podman, Kubernetes, containerd).
func DetectContainer(env Environment) string {
	if marker := strings.ToLower(strings.TrimSpace(env.Getenv(ManagedExternallyEnv))); marker != "" {
		if marker == "0" || marker == "false" || marker == "no" {
			return ""
		}
		if !managerPattern.MatchString(marker) || marker == "1" || marker == "true" || marker == "yes" {
			return "external"
		}
		return marker
	}
	if env.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return "kubernetes"
	}
	switch env.Getenv("container") {
	case "docker", "podman", "oci":
		return env.Getenv("container")
	}
	if env.GOOS != "linux" {
		return ""
	}
	exists := func(path string) bool {
		_, err := os.Stat(filepath.Join(env.Root, path))
		return err == nil
	}
	if exists(".dockerenv") {
		return "docker"
	}
	if exists("run/.containerenv") {
		return "podman"
	}
	read := func(path string) string {
		f, err := os.Open(filepath.Join(env.Root, path))
		if err != nil {
			return ""
		}
		defer f.Close()
		data, _ := readBounded(f, 1<<20)
		return string(data)
	}
	cgroup := read("proc/1/cgroup")
	for _, marker := range []string{"kubepods", "docker", "containerd", "libpod"} {
		if strings.Contains(cgroup, marker) {
			return "container"
		}
	}
	if mounts := read("proc/self/mountinfo"); strings.Contains(mounts, "/docker/containers/") || strings.Contains(mounts, "/containers/storage/overlay") {
		return "container"
	}
	return ""
}

// Plan is the startup decision about self-update.
type Plan struct {
	Mode      string
	ManagedBy string
	Reason    string
}

// Decide chooses the self-update mode. SERVER_SELF_UPDATE=off disables it;
// =on skips the container heuristics (not the explicit marker) for mutable
// containers such as LXC. Unversioned builds, builds without a compiled
// signing key and unsupported platforms are unavailable.
func Decide(env Environment, versioned bool, trustErr, executableErr error, platform Platform) Plan {
	setting := strings.ToLower(strings.TrimSpace(env.Getenv("SERVER_SELF_UPDATE")))
	switch setting {
	case "off", "false", "0", "disabled":
		return Plan{Mode: ModeDisabled, Reason: "disabled_by_config"}
	}
	probe := env
	if setting == "on" || setting == "true" || setting == "1" {
		explicit := env.Getenv(ManagedExternallyEnv)
		probe = Environment{Getenv: func(k string) string {
			if k == ManagedExternallyEnv {
				return explicit
			}
			return ""
		}, Root: env.Root, GOOS: "none"}
	}
	if manager := DetectContainer(probe); manager != "" {
		return Plan{Mode: ModeManagedExternally, ManagedBy: manager, Reason: "immutable_image"}
	}
	if !versioned {
		return Plan{Mode: ModeUnavailable, Reason: "unversioned_build"}
	}
	if trustErr != nil {
		return Plan{Mode: ModeUnavailable, Reason: trustErr.Error()}
	}
	if _, err := AssetName(platform); err != nil {
		return Plan{Mode: ModeUnavailable, Reason: "unsupported_platform"}
	}
	if executableErr != nil {
		return Plan{Mode: ModeUnavailable, Reason: "executable_unresolved"}
	}
	return Plan{Mode: ModeActive}
}

// InstallWritable reports whether the executable's directory accepts the
// staged image, journal and backup (it must be writable by the service user).
func InstallWritable(executable string) bool {
	f, err := os.CreateTemp(filepath.Dir(executable), ".shorebird-server-probe-*")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	return os.Remove(name) == nil
}
