package updater

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func fakeEnvironment(t *testing.T, vars map[string]string, files map[string]string) Environment {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return Environment{Getenv: func(k string) string { return vars[k] }, Root: root, GOOS: "linux"}
}

func TestDockerAndContainerDetection(t *testing.T) {
	for _, tc := range []struct {
		name  string
		vars  map[string]string
		files map[string]string
		want  string
	}{
		{"bare host", nil, map[string]string{"proc/1/cgroup": "0::/init.scope\n"}, ""},
		{"explicit marker (Dockerfile)", map[string]string{ManagedExternallyEnv: "docker"}, nil, "docker"},
		{"explicit marker true", map[string]string{ManagedExternallyEnv: "1"}, nil, "external"},
		{"marker with odd value", map[string]string{ManagedExternallyEnv: "My Platform!"}, nil, "external"},
		{"marker false disables the marker only", map[string]string{ManagedExternallyEnv: "false"}, nil, ""},
		{"dockerenv", nil, map[string]string{".dockerenv": ""}, "docker"},
		{"podman", nil, map[string]string{"run/.containerenv": ""}, "podman"},
		{"kubernetes env", map[string]string{"KUBERNETES_SERVICE_HOST": "10.0.0.1"}, nil, "kubernetes"},
		{"container env", map[string]string{"container": "podman"}, nil, "podman"},
		{"cgroup v1 docker", nil, map[string]string{"proc/1/cgroup": "12:pids:/docker/0123abcd\n"}, "container"},
		{"cgroup kubepods", nil, map[string]string{"proc/1/cgroup": "0::/kubepods/besteffort/pod1\n"}, "container"},
		{"cgroup v2 overlay mountinfo", nil, map[string]string{"proc/self/mountinfo": "1 0 0:1 / / rw - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l,upperdir=x\n2 1 0:2 /var/lib/docker/containers/abc/hostname /etc/hostname rw\n"}, "container"},
	} {
		if got := DetectContainer(fakeEnvironment(t, tc.vars, tc.files)); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	// File probes are Linux-only.
	env := fakeEnvironment(t, nil, map[string]string{".dockerenv": ""})
	env.GOOS = "darwin"
	if got := DetectContainer(env); got != "" {
		t.Fatalf("darwin: %q", got)
	}
}

func TestDecideMode(t *testing.T) {
	host := func(vars map[string]string) Environment { return fakeEnvironment(t, vars, nil) }
	docker := func(vars map[string]string) Environment {
		return fakeEnvironment(t, vars, map[string]string{".dockerenv": ""})
	}
	for _, tc := range []struct {
		name      string
		env       Environment
		versioned bool
		trustErr  error
		exeErr    error
		platform  Platform
		want      Plan
	}{
		{"active", host(nil), true, nil, nil, linuxAMD64, Plan{Mode: ModeActive}},
		{"docker", docker(nil), true, nil, nil, linuxAMD64, Plan{Mode: ModeManagedExternally, ManagedBy: "docker", Reason: "immutable_image"}},
		{"docker wins over unversioned", docker(nil), false, nil, nil, linuxAMD64, Plan{Mode: ModeManagedExternally, ManagedBy: "docker", Reason: "immutable_image"}},
		{"off", docker(map[string]string{"SERVER_SELF_UPDATE": "off"}), true, nil, nil, linuxAMD64, Plan{Mode: ModeDisabled, Reason: "disabled_by_config"}},
		{"on skips heuristics", docker(map[string]string{"SERVER_SELF_UPDATE": "on"}), true, nil, nil, linuxAMD64, Plan{Mode: ModeActive}},
		{"on keeps the explicit marker", host(map[string]string{"SERVER_SELF_UPDATE": "on", ManagedExternallyEnv: "docker"}), true, nil, nil, linuxAMD64,
			Plan{Mode: ModeManagedExternally, ManagedBy: "docker", Reason: "immutable_image"}},
		{"unversioned", host(nil), false, nil, nil, linuxAMD64, Plan{Mode: ModeUnavailable, Reason: "unversioned_build"}},
		{"no pinned key", host(nil), true, errors.New("trust_unconfigured"), nil, linuxAMD64, Plan{Mode: ModeUnavailable, Reason: "trust_unconfigured"}},
		{"platform", host(nil), true, nil, nil, Platform{"freebsd", "amd64"}, Plan{Mode: ModeUnavailable, Reason: "unsupported_platform"}},
		{"executable", host(nil), true, nil, errors.New("x"), linuxAMD64, Plan{Mode: ModeUnavailable, Reason: "executable_unresolved"}},
	} {
		if got := Decide(tc.env, tc.versioned, tc.trustErr, tc.exeErr, tc.platform); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}
