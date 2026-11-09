package updater

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// MaxZIPBytes bounds an uploaded update ZIP.
const MaxZIPBytes = maxBinaryBytes + (2 << 20)

// zipSource serves the binary of an already verified ZIP spooled to disk.
type zipSource struct{ path string }

func (s *zipSource) Latest(context.Context, string) (*Release, error) {
	return nil, errors.New("check_required")
}

func (s *zipSource) Download(ctx context.Context, r *Release, w io.Writer) error {
	if ctx.Err() != nil {
		return errors.New("update_cancelled")
	}
	z, err := zip.OpenReader(s.path)
	if err != nil {
		return errors.New("invalid_zip")
	}
	defer z.Close()
	for _, f := range z.File {
		if f.Name != r.AssetName {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return errors.New("invalid_zip")
		}
		defer rc.Close()
		h := sha256.New()
		n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(rc, r.Size+1))
		if err != nil || n != r.Size || [sha256.Size]byte(h.Sum(nil)) != r.Checksum {
			return errors.New("checksum_mismatch")
		}
		return nil
	}
	return errors.New("invalid_zip")
}

// Close removes the spooled ZIP.
func (s *zipSource) Close() { _ = os.Remove(s.path) }

// readZIP spools a bounded ZIP to tempDir and verifies it completely (layout,
// signature, platform, version file, size and hash of the binary) before it
// is offered for installation. No entry is ever extracted to a path.
func readZIP(reader io.Reader, tempDir string, trust *Trust, platform Platform) (*zipSource, *Release, error) {
	f, err := os.CreateTemp(tempDir, ".shorebird-server-upload-*.zip")
	if err != nil {
		return nil, nil, errors.New("install_permission_denied")
	}
	path := f.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(path)
		}
	}()
	n, err := io.Copy(f, io.LimitReader(reader, MaxZIPBytes+1))
	closeErr := f.Close()
	if err != nil || closeErr != nil || n > MaxZIPBytes || n == 0 {
		return nil, nil, errors.New("invalid_zip")
	}
	z, err := zip.OpenReader(path)
	if err != nil {
		return nil, nil, errors.New("invalid_zip")
	}
	defer z.Close()
	name, err := AssetName(platform)
	if err != nil {
		return nil, nil, err
	}
	limits := map[string]int64{name: maxBinaryBytes, "VERSION": maxVersionBytes, name + ".manifest.json": maxManifestBytes, name + ".sig": maxSignatureBytes}
	files := map[string]*zip.File{}
	foreignBinary := false
	for _, entry := range z.File {
		limit, ok := limits[entry.Name]
		if !ok {
			if strings.HasPrefix(entry.Name, Product+"-") {
				foreignBinary = true
			}
			continue
		}
		if files[entry.Name] != nil || !entry.Mode().IsRegular() || entry.UncompressedSize64 > uint64(limit) {
			return nil, nil, errors.New("invalid_zip")
		}
		files[entry.Name] = entry
	}
	if len(files) != len(limits) || len(z.File) != len(limits) {
		if foreignBinary && files[name] == nil {
			// A complete ZIP for another platform: say so instead of invalid_zip.
			return nil, nil, errors.New("wrong_platform")
		}
		return nil, nil, errors.New("invalid_zip")
	}
	read := func(key string) ([]byte, error) {
		rc, err := files[key].Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return readBounded(rc, limits[key])
	}
	manifest, err := read(name + ".manifest.json")
	if err != nil {
		return nil, nil, errors.New("invalid_zip")
	}
	sig, err := read(name + ".sig")
	if err != nil {
		return nil, nil, errors.New("invalid_zip")
	}
	release, err := verifyManifest(trust, manifest, sig, platform)
	if err != nil {
		return nil, nil, err
	}
	version, err := read("VERSION")
	if err != nil || strings.TrimSpace(string(version)) != release.Version {
		return nil, nil, errors.New("version_mismatch")
	}
	source := &zipSource{path: path}
	if err := source.Download(context.Background(), release, io.Discard); err != nil {
		return nil, nil, err
	}
	keep = true
	return source, release, nil
}

// VerifyZIPFile verifies an update ZIP exactly as an upload would be checked
// (release tooling and CI). It returns the signed version and channel.
func VerifyZIPFile(path string, trust *Trust, platform Platform) (version, channel string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	dir, err := os.MkdirTemp(filepath.Dir(path), ".verify-*")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(dir)
	source, release, err := readZIP(f, dir, trust, platform)
	if err != nil {
		return "", "", err
	}
	source.Close()
	return release.Version, release.Channel, nil
}
