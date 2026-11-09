package updater

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseTrustedKeys(t *testing.T) {
	k := newTestKey(t)
	other := newTestKey(t)
	if _, err := ParseTrustedKeys(k.public+","+other.public, false); err != nil {
		t.Fatalf("two keys (rotation): %v", err)
	}
	for _, tc := range []struct {
		name, list string
		allowDev   bool
		want       string
	}{
		{"empty", "", false, "trust_unconfigured"},
		{"blank entries", " , ", false, "trust_unconfigured"},
		{"not base64", "not-a-key", false, "trust_malformed"},
		{"short key", base64.StdEncoding.EncodeToString([]byte("short")), false, "trust_malformed"},
		{"duplicate", k.public + "," + k.public, false, "trust_malformed"},
		{"one bad entry poisons the list", k.public + ",bad", false, "trust_malformed"},
		{"development key without allowance", DevelopmentPublicKey, false, "development_key_refused"},
	} {
		if _, err := ParseTrustedKeys(tc.list, tc.allowDev); err == nil || err.Error() != tc.want {
			t.Errorf("%s: err %v, want %s", tc.name, err, tc.want)
		}
	}
	trust, err := NewTrust(DevelopmentPublicKey, true)
	if err != nil || !trust.Development() {
		t.Fatalf("development trust: %v", err)
	}
	if k.trust.Development() {
		t.Fatal("a production key is reported as development trust")
	}
	if ids := k.trust.KeyIDs(); len(ids) != 1 || !strings.HasPrefix(ids[0], "sha256:") || len(ids[0]) != 71 {
		t.Fatalf("key ids %v", ids)
	}
}

func TestCompiledTrustDefaultsToUnavailable(t *testing.T) {
	if TrustedKeys != "" {
		t.Skip("test binary linked with a pinned key")
	}
	if _, err := CompiledTrust(); err == nil || err.Error() != "trust_unconfigured" {
		t.Fatalf("unpinned build: %v", err)
	}
}

func TestSignatureRejects(t *testing.T) {
	k := newTestKey(t)
	manifest, _ := BuildManifest("v1.2.3", "stable", linuxAMD64, []byte("binary"))
	good := EncodeSignature(k.private, manifest)
	if err := k.trust.Verify(manifest, good); err != nil {
		t.Fatalf("valid signature: %v", err)
	}
	var file SignatureFile
	_ = json.Unmarshal(good, &file)
	rawDomainless := ed25519.Sign(k.private, manifest)
	stranger := newTestKey(t)
	cases := map[string]struct {
		manifest, sig []byte
		want          string
	}{
		"tampered manifest":   {bytes.Replace(manifest, []byte("v1.2.3"), []byte("v1.2.4"), 1), good, "signature_invalid"},
		"unknown signer":      {manifest, EncodeSignature(stranger.private, manifest), "untrusted_signer"},
		"no domain":           {manifest, mustJSON(SignatureFile{KeyID: file.KeyID, Signature: base64.StdEncoding.EncodeToString(rawDomainless)}), "signature_invalid"},
		"extra field":         {manifest, []byte(`{"key_id":"` + file.KeyID + `","signature":"` + file.Signature + `","x":1}`), "signature_invalid"},
		"trailing data":       {manifest, append(append([]byte(nil), good...), []byte(` {}`)...), "signature_invalid"},
		"short signature":     {manifest, mustJSON(SignatureFile{KeyID: file.KeyID, Signature: base64.StdEncoding.EncodeToString([]byte("abc"))}), "signature_invalid"},
		"raw base64 not json": {manifest, []byte(file.Signature), "signature_invalid"},
		"oversized":           {manifest, bytes.Repeat([]byte(" "), maxSignatureBytes+1), "signature_invalid"},
	}
	for name, tc := range cases {
		if err := k.trust.Verify(tc.manifest, tc.sig); err == nil || err.Error() != tc.want {
			t.Errorf("%s: err %v, want %s", name, err, tc.want)
		}
	}
	if err := (*Trust)(nil).Verify(manifest, good); err == nil || err.Error() != "trust_unconfigured" {
		t.Fatalf("nil trust: %v", err)
	}
}

func mustJSON(v any) []byte {
	data, _ := json.Marshal(v)
	return data
}

func TestManifestRules(t *testing.T) {
	k := newTestKey(t)
	sign := func(m Manifest) error {
		data := mustJSON(m)
		_, err := verifyManifest(k.trust, data, EncodeSignature(k.private, data), linuxAMD64)
		return err
	}
	base := Manifest{Product: Product, Version: "v1.2.3", Channel: "stable", GOOS: "linux", GOARCH: "amd64", Asset: "shorebird-server-linux-amd64",
		SHA256: strings.Repeat("ab", 32), Size: 10}
	if err := sign(base); err != nil {
		t.Fatalf("valid manifest: %v", err)
	}
	mutate := func(f func(*Manifest)) Manifest { m := base; f(&m); return m }
	for name, tc := range map[string]struct {
		m    Manifest
		want string
	}{
		"other product":          {mutate(func(m *Manifest) { m.Product = "dali-toolkit-server" }), "invalid_release"},
		"stable with prerelease": {mutate(func(m *Manifest) { m.Version = "v1.2.3-dev.1" }), "invalid_release"},
		"dev without prerelease": {mutate(func(m *Manifest) { m.Channel = "dev" }), "invalid_release"},
		"unknown channel":        {mutate(func(m *Manifest) { m.Channel = "beta" }), "invalid_release"},
		"build metadata":         {mutate(func(m *Manifest) { m.Version = "v1.2.3+x" }), "invalid_release"},
		"not semver":             {mutate(func(m *Manifest) { m.Version = "1.2.3" }), "invalid_release"},
		"zero size":              {mutate(func(m *Manifest) { m.Size = 0 }), "invalid_release"},
		"oversized":              {mutate(func(m *Manifest) { m.Size = maxBinaryBytes + 1 }), "invalid_release"},
		"uppercase hash":         {mutate(func(m *Manifest) { m.SHA256 = strings.Repeat("AB", 32) }), "invalid_release"},
		"short hash":             {mutate(func(m *Manifest) { m.SHA256 = "abcd" }), "invalid_release"},
		"wrong goos":             {mutate(func(m *Manifest) { m.GOOS = "darwin" }), "wrong_platform"},
		"wrong goarch":           {mutate(func(m *Manifest) { m.GOARCH = "arm64" }), "wrong_platform"},
		"wrong asset":            {mutate(func(m *Manifest) { m.Asset = "shorebird-server-linux-arm64" }), "wrong_platform"},
	} {
		if err := sign(tc.m); err == nil || err.Error() != tc.want {
			t.Errorf("%s: err %v, want %s", name, err, tc.want)
		}
	}
	unknown := []byte(`{"product":"shorebird-server","version":"v1.2.3","channel":"stable","goos":"linux","goarch":"amd64","asset":"shorebird-server-linux-amd64","sha256":"` + strings.Repeat("ab", 32) + `","size":10,"url":"https://evil"}`)
	if _, err := verifyManifest(k.trust, unknown, EncodeSignature(k.private, unknown), linuxAMD64); err == nil || err.Error() != "invalid_release" {
		t.Fatalf("unknown manifest field: %v", err)
	}
}

func TestAssetNames(t *testing.T) {
	for p, want := range map[Platform]string{
		{"linux", "amd64"}: "shorebird-server-linux-amd64", {"linux", "arm64"}: "shorebird-server-linux-arm64",
		{"darwin", "arm64"}: "shorebird-server-darwin-arm64", {"windows", "amd64"}: "shorebird-server-windows-amd64.exe",
	} {
		if got, err := AssetName(p); err != nil || got != want {
			t.Errorf("%v: %q %v", p, got, err)
		}
	}
	if _, err := AssetName(Platform{"freebsd", "amd64"}); err == nil {
		t.Fatal("unsupported platform accepted")
	}
}

func TestZIPVerification(t *testing.T) {
	k := newTestKey(t)
	binary := []byte("server binary v1.3.0")
	name, _ := AssetName(linuxAMD64)
	dir := t.TempDir()
	read := func(data []byte, trust *Trust, platform Platform) error {
		source, _, err := readZIP(bytes.NewReader(data), dir, trust, platform)
		if source != nil {
			source.Close()
		}
		return err
	}
	good := k.zipEntries(t, "v1.3.0", "stable", linuxAMD64, binary)
	source, release, err := readZIP(bytes.NewReader(buildZIP(t, good)), dir, k.trust, linuxAMD64)
	if err != nil || release.Version != "v1.3.0" || release.Channel != "stable" {
		t.Fatalf("valid ZIP: %v", err)
	}
	var out bytes.Buffer
	if err := source.Download(t.Context(), release, &out); err != nil || !bytes.Equal(out.Bytes(), binary) {
		t.Fatalf("download from verified ZIP: %v", err)
	}
	source.Close()

	with := func(f func(map[string][]byte)) map[string][]byte {
		entries := map[string][]byte{}
		for key, value := range good {
			entries[key] = value
		}
		f(entries)
		return entries
	}
	stranger := newTestKey(t)
	wrongSize, _ := BuildManifest("v1.3.0", "stable", linuxAMD64, append([]byte("x"), binary...))
	for nameCase, tc := range map[string]struct {
		data []byte
		want string
	}{
		"signature from unknown key": {buildZIP(t, with(func(e map[string][]byte) {
			e[name+".sig"] = EncodeSignature(stranger.private, e[name+".manifest.json"])
		})), "untrusted_signer"},
		"tampered binary (hash)": {buildZIP(t, with(func(e map[string][]byte) { e[name] = []byte("server binary v1.3.X") })), "checksum_mismatch"},
		"wrong size": {buildZIP(t, with(func(e map[string][]byte) {
			e[name+".manifest.json"] = wrongSize
			e[name+".sig"] = EncodeSignature(k.private, wrongSize)
		})), "checksum_mismatch"},
		"VERSION disagrees": {buildZIP(t, with(func(e map[string][]byte) { e["VERSION"] = []byte("v9.9.9\n") })), "version_mismatch"},
		"extra entry":       {buildZIP(t, good, "README"), "invalid_zip"},
		"nested path":       {buildZIP(t, good, "dir/"+name), "invalid_zip"},
		"missing VERSION":   {buildZIP(t, with(func(e map[string][]byte) { delete(e, "VERSION") })), "invalid_zip"},
		"not a zip":         {[]byte("PK not really"), "invalid_zip"},
		"empty":             {nil, "invalid_zip"},
		"other platform":    {buildZIP(t, k.zipEntries(t, "v1.3.0", "stable", Platform{"linux", "arm64"}, binary)), "wrong_platform"},
	} {
		if err := read(tc.data, k.trust, linuxAMD64); err == nil || err.Error() != tc.want {
			t.Errorf("%s: err %v, want %s", nameCase, err, tc.want)
		}
	}
	if err := read(buildZIP(t, good), k.trust, Platform{"darwin", "arm64"}); err == nil || err.Error() != "wrong_platform" {
		t.Fatalf("ZIP for another platform: %v", err)
	}
	// Duplicate entries are refused even when both copies are identical.
	dup := buildZIP(t, good, name)
	if err := read(dup, k.trust, linuxAMD64); err == nil || err.Error() != "invalid_zip" {
		t.Fatalf("duplicate entry: %v", err)
	}
	entries, _ := filepathGlob(dir)
	if len(entries) != 0 {
		t.Fatalf("refused uploads left spool files: %v", entries)
	}
}
