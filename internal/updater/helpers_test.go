package updater

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type testKey struct {
	private ed25519.PrivateKey
	public  string
	trust   *Trust
}

func newTestKey(t *testing.T) testKey {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(public)
	trust, err := NewTrust(encoded, false)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{private: private, public: encoded, trust: trust}
}

var linuxAMD64 = Platform{"linux", "amd64"}

// scriptBinary is an executable "server" that answers --version.
func scriptBinary(version string) []byte {
	return []byte("#!/bin/sh\nif [ \"$1\" = --version ]; then echo " + version + "; exit 0; fi\nsleep 60\n")
}

func requireUnix(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("script fixtures need a POSIX shell")
	}
}

// signedRelease builds a verified Release for a binary.
func (k testKey) release(t *testing.T, version, channel string, platform Platform, binary []byte) *Release {
	t.Helper()
	manifest, err := BuildManifest(version, channel, platform, binary)
	if err != nil {
		t.Fatal(err)
	}
	r, err := verifyManifest(k.trust, manifest, EncodeSignature(k.private, manifest), platform)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// zipEntries returns the standard ZIP layout for a signed binary.
func (k testKey) zipEntries(t *testing.T, version, channel string, platform Platform, binary []byte) map[string][]byte {
	t.Helper()
	manifest, err := BuildManifest(version, channel, platform, binary)
	if err != nil {
		t.Fatal(err)
	}
	name, _ := AssetName(platform)
	return map[string][]byte{name: binary, name + ".manifest.json": manifest, name + ".sig": EncodeSignature(k.private, manifest), "VERSION": []byte(version + "\n")}
}

func buildZIP(t *testing.T, entries map[string][]byte, extra ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	write := func(name string, data []byte) {
		w, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range entries {
		write(name, data)
	}
	for _, name := range extra {
		write(name, []byte("x"))
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type bytesSource struct{ binary []byte }

func (b bytesSource) Latest(context.Context, string) (*Release, error) { return nil, nil }
func (b bytesSource) Download(_ context.Context, _ *Release, w io.Writer) error {
	_, err := w.Write(b.binary)
	return err
}

// installedFixture lays out an executable at v2 (trial or healthy) with its
// hash-bound v1 backup, as a successful install leaves it.
func installedFixture(t *testing.T, state string) (FileInstaller, string, string) {
	t.Helper()
	requireUnix(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "shorebird-server")
	backup := filepath.Base(target) + ".previous-1"
	if err := os.WriteFile(target, scriptBinary("v2.0.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, backup), scriptBinary("v1.0.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	installer := FileInstaller{Executable: target, CurrentVersion: "v2.0.0"}
	oldHash, _ := fileHash(filepath.Join(dir, backup))
	newHash, _ := fileHash(target)
	if err := installer.saveTransaction(&transaction{State: state, Previous: backup, OldVersion: "v1.0.0", NewVersion: "v2.0.0", OldHash: oldHash, NewHash: newHash}); err != nil {
		t.Fatal(err)
	}
	return installer, oldHash, newHash
}

func filepathGlob(dir string) ([]string, error) { return filepath.Glob(filepath.Join(dir, "*")) }
