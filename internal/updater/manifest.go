package updater

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"runtime"

	"golang.org/x/mod/semver"
)

// Product names the signed artifact family; a manifest for another product
// signed with the same key is refused.
const Product = "shorebird-server"

const (
	maxBinaryBytes   = 128 << 20
	maxManifestBytes = 16 << 10
	maxVersionBytes  = 128
)

// Manifest is signed as exact bytes before anything in it is trusted.
type Manifest struct {
	Product string `json:"product"`
	Version string `json:"version"`
	Channel string `json:"channel"`
	GOOS    string `json:"goos"`
	GOARCH  string `json:"goarch"`
	Asset   string `json:"asset"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
}

// Release is one verified update for this platform.
type Release struct {
	Version   string
	AssetName string
	Size      int64
	Checksum  [sha256.Size]byte
	Channel   string
	manifest  []byte
	signature []byte
	assetID   int64
}

// Platform is the GOOS/GOARCH pair a binary runs on.
type Platform struct{ GOOS, GOARCH string }

// CurrentPlatform is the platform of the running binary.
func CurrentPlatform() Platform { return Platform{runtime.GOOS, runtime.GOARCH} }

var supportedPlatforms = map[Platform]bool{
	{"linux", "amd64"}: true, {"linux", "arm64"}: true,
	{"darwin", "amd64"}: true, {"darwin", "arm64"}: true,
	{"windows", "amd64"}: true,
}

// AssetName is the release asset (and ZIP entry) name of the server binary
// for a platform, matching the CI artifact names (shorebird-server-<goos>-<goarch>).
func AssetName(p Platform) (string, error) {
	if !supportedPlatforms[p] {
		return "", errors.New("unsupported_platform")
	}
	name := Product + "-" + p.GOOS + "-" + p.GOARCH
	if p.GOOS == "windows" {
		name += ".exe"
	}
	return name, nil
}

// verifyManifest verifies the signature, then the manifest fields, for the
// given platform. Stable manifests may not carry a prerelease version.
func verifyManifest(trust *Trust, data, sig []byte, platform Platform) (*Release, error) {
	if err := trust.Verify(data, sig); err != nil {
		return nil, err
	}
	name, err := AssetName(platform)
	if err != nil {
		return nil, err
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(&m) != nil {
		return nil, errors.New("invalid_release")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, errors.New("invalid_release")
	}
	if m.Product != Product || !semver.IsValid(m.Version) || semver.Build(m.Version) != "" || m.Size <= 0 || m.Size > maxBinaryBytes ||
		(m.Channel != "stable" && m.Channel != "dev") || (m.Channel == "stable" && semver.Prerelease(m.Version) != "") ||
		(m.Channel == "dev" && semver.Prerelease(m.Version) == "") {
		return nil, errors.New("invalid_release")
	}
	if m.GOOS != platform.GOOS || m.GOARCH != platform.GOARCH || m.Asset != name {
		return nil, errors.New("wrong_platform")
	}
	sum, err := hex.DecodeString(m.SHA256)
	if err != nil || len(sum) != sha256.Size || hex.EncodeToString(sum) != m.SHA256 {
		return nil, errors.New("invalid_release")
	}
	r := &Release{Version: m.Version, AssetName: m.Asset, Size: m.Size, Channel: m.Channel,
		manifest: append([]byte(nil), data...), signature: append([]byte(nil), sig...)}
	copy(r.Checksum[:], sum)
	return r, nil
}

// verifyRelease re-verifies a release object before it is installed, so an
// alternate Source cannot hand the installer unsigned fields.
func verifyRelease(trust *Trust, r *Release, platform Platform) error {
	if r == nil {
		return errors.New("invalid_release")
	}
	checked, err := verifyManifest(trust, r.manifest, r.signature, platform)
	if err != nil {
		return err
	}
	if checked.Version != r.Version || checked.Size != r.Size || checked.Checksum != r.Checksum || checked.Channel != r.Channel || checked.AssetName != r.AssetName {
		return errors.New("invalid_release")
	}
	return nil
}

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("invalid_release")
	}
	return data, nil
}

// BuildManifest returns canonical manifest bytes (tooling and tests).
func BuildManifest(version, channel string, platform Platform, binary []byte) ([]byte, error) {
	name, err := AssetName(platform)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(binary)
	return json.Marshal(Manifest{Product: Product, Version: version, Channel: channel, GOOS: platform.GOOS, GOARCH: platform.GOARCH,
		Asset: name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(binary))})
}
