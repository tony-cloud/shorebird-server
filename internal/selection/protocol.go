// Package selection implements the immutable signed selection protocol v2.
package selection

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"unicode/utf8"

	"github.com/google/uuid"
)

const MaxJSON = 64 << 10

var identifier = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
var hash = regexp.MustCompile(`^[0-9a-f]{64}$`)

func Identifier(s string) bool { return identifier.MatchString(s) }
func Hash(s string) bool       { return hash.MatchString(s) }
func Text(s string, max int) bool {
	if len(s) < 1 || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
func Decimal(s string, min, max int64) (int64, error) {
	n, e := strconv.ParseInt(s, 10, 64)
	if e != nil || n < min || n > max || strconv.FormatInt(n, 10) != s {
		return 0, fmt.Errorf("invalid canonical decimal")
	}
	return n, nil
}
func Platform(s string) bool {
	return s == "android" || s == "ios" || s == "macos" || s == "windows" || s == "linux"
}
func Arch(s string) bool { return s == "arm" || s == "aarch64" || s == "x86" || s == "x86_64" }
func UUID4(s string) bool {
	u, e := uuid.Parse(s)
	return e == nil && u.Version() == 4 && u.Variant() == uuid.RFC4122 && u.String() == s
}
func ClientHash(s string) string { v := sha256.Sum256([]byte(s)); return hex.EncodeToString(v[:]) }

type Scope struct {
	AppID            string  `json:"app_id"`
	ReleaseVersion   string  `json:"release_version"`
	Platform         string  `json:"platform"`
	Arch             string  `json:"arch"`
	ClientIDHash     string  `json:"client_id_hash,omitempty"`
	BaseArtifactHash string  `json:"base_artifact_hash"`
	HostABIHash      *string `json:"host_abi_hash"`
	RuntimeProfile   string  `json:"runtime_profile"`
}

func (s Scope) Validate(installation bool) error {
	u, e := uuid.Parse(s.AppID)
	if e != nil || u.String() != s.AppID || !Text(s.ReleaseVersion, 256) || !Platform(s.Platform) || !Arch(s.Arch) || !Hash(s.BaseArtifactHash) || (installation && !Hash(s.ClientIDHash)) {
		return fmt.Errorf("invalid selection scope")
	}
	switch s.RuntimeProfile {
	case "native-aot", "interpreter-body", "interpreter-structural":
		if s.HostABIHash != nil {
			return fmt.Errorf("unexpected host ABI")
		}
	case "interpreter-full":
		if s.HostABIHash == nil || !Hash(*s.HostABIHash) {
			return fmt.Errorf("missing host ABI")
		}
	default:
		return fmt.Errorf("invalid runtime profile")
	}
	return nil
}

type Target struct {
	Kind          string  `json:"kind"`
	PatchNumber   *string `json:"patch_number"`
	ArtifactHash  *string `json:"artifact_hash"`
	Encryption    string  `json:"encryption"`
	ArtifactKeyID *string `json:"artifact_key_id"`
}
type Fallback struct {
	Kind        string `json:"kind"`
	VariantID   string `json:"variant_id"`
	LicenseType string `json:"license_type"`
}
type Descriptor struct {
	Epoch               string   `json:"epoch"`
	Scope               Scope    `json:"scope"`
	Channel             string   `json:"channel"`
	VariantID           string   `json:"variant_id"`
	LicenseType         string   `json:"license_type"`
	EntitlementRevision string   `json:"entitlement_revision"`
	Target              Target   `json:"target"`
	NotBefore           string   `json:"not_before"`
	OfflineValidUntil   *string  `json:"offline_valid_until"`
	Fallback            Fallback `json:"fallback"`
}

func (d Descriptor) Validate() error {
	if _, e := Decimal(d.Epoch, 1, 9223372036854775807); e != nil {
		return e
	}
	if e := d.Scope.Validate(true); e != nil {
		return e
	}
	if !Identifier(d.Channel) || !Identifier(d.VariantID) || !Identifier(d.LicenseType) || !Text(d.EntitlementRevision, 128) || d.Fallback != (Fallback{"base", "free", "free"}) {
		return fmt.Errorf("invalid selection identity")
	}
	n, e := Decimal(d.NotBefore, 0, 253402300799)
	if e != nil {
		return e
	}
	if d.OfflineValidUntil != nil {
		v, e := Decimal(*d.OfflineValidUntil, 0, 253402300799)
		if e != nil || v <= n {
			return fmt.Errorf("invalid lease")
		}
	}
	t := d.Target
	switch t.Kind {
	case "base":
		if d.VariantID != "free" || d.LicenseType != "free" || t.PatchNumber != nil || t.ArtifactHash != nil || t.ArtifactKeyID != nil || t.Encryption != "none" {
			return fmt.Errorf("invalid base target")
		}
	case "patch":
		if t.PatchNumber == nil || t.ArtifactHash == nil || !Hash(*t.ArtifactHash) {
			return fmt.Errorf("invalid patch target")
		}
		if _, e := Decimal(*t.PatchNumber, 1, 2147483647); e != nil {
			return e
		}
		if d.Scope.RuntimeProfile == "native-aot" {
			if t.Encryption != "transport-aes-256-gcm" || t.ArtifactKeyID != nil {
				return fmt.Errorf("invalid native encryption")
			}
		} else {
			if t.Encryption != "artifact-aes-256-gcm" || t.ArtifactKeyID == nil || !Text(*t.ArtifactKeyID, 128) {
				return fmt.Errorf("invalid interpreter encryption")
			}
		}
	default:
		return fmt.Errorf("invalid target kind")
	}
	return nil
}
func (d Descriptor) Canonical() ([]byte, error) {
	if e := d.Validate(); e != nil {
		return nil, e
	}
	b := bytes.NewBufferString("shorebird-selection-v2\x00\x01")
	values := []*string{&d.Epoch, &d.Scope.AppID, &d.Scope.ReleaseVersion, &d.Scope.Platform, &d.Scope.Arch, &d.Scope.ClientIDHash, &d.Scope.BaseArtifactHash, d.Scope.HostABIHash, &d.Scope.RuntimeProfile, &d.Channel, &d.VariantID, &d.LicenseType, &d.EntitlementRevision, &d.Target.Kind, d.Target.PatchNumber, d.Target.ArtifactHash, &d.Target.Encryption, d.Target.ArtifactKeyID, &d.NotBefore, d.OfflineValidUntil, &d.Fallback.Kind, &d.Fallback.VariantID, &d.Fallback.LicenseType}
	for _, v := range values {
		if v == nil {
			b.WriteByte(0)
		} else {
			b.WriteByte(1)
			_ = binary.Write(b, binary.BigEndian, uint32(len(*v)))
			b.WriteString(*v)
		}
	}
	return b.Bytes(), nil
}
func (d Descriptor) Digest() (string, error) {
	b, e := d.Canonical()
	if e != nil {
		return "", e
	}
	return ClientHash(string(b)), nil
}
func Base(scope Scope, channel, epoch, revision, now string) Descriptor {
	return Descriptor{epoch, scope, channel, "free", "free", revision, Target{Kind: "base", Encryption: "none"}, now, nil, Fallback{"base", "free", "free"}}
}

// StrictJSON rejects duplicate/unknown keys, malformed UTF-8, unpaired JSON
// surrogates and trailing values. Required fields are checked by ExactKeys.
func StrictJSON(data []byte, dst any) error {
	if len(data) > MaxJSON || !utf8.Valid(data) || !validSurrogates(data) {
		return fmt.Errorf("JSON exceeds limit or is not UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if e := uniqueValue(dec); e != nil {
		return e
	}
	if _, e := dec.Token(); e != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	dec = json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
func uniqueValue(d *json.Decoder) error {
	t, e := d.Token()
	if e != nil {
		return e
	}
	if token, ok := t.(json.Delim); ok {
		switch token {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return fmt.Errorf("duplicate JSON key")
				}
				seen[s] = true
				if e := uniqueValue(d); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e := uniqueValue(d); e != nil {
					return e
				}
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter")
		}
		_, e = d.Token()
		return e
	}
	return nil
}
func ExactKeys(data []byte, names ...string) error {
	var m map[string]json.RawMessage
	if e := json.Unmarshal(data, &m); e != nil {
		return e
	}
	if len(m) != len(names) {
		return fmt.Errorf("all fields are required")
	}
	for _, k := range names {
		if _, ok := m[k]; !ok {
			return fmt.Errorf("missing %s", k)
		}
	}
	return nil
}

// encoding/json replaces lone surrogates; reject them before that lossy step.
func validSurrogates(data []byte) bool {
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		v, e := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if e != nil {
			return false
		}
		i += 4
		if v >= 0xdc00 && v <= 0xdfff {
			return false
		}
		if v >= 0xd800 && v <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			lo, e := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if e != nil || lo < 0xdc00 || lo > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
func (t *Target) UnmarshalJSON(data []byte) error {
	type alias Target
	var value alias
	if e := StrictJSON(data, &value); e != nil {
		return e
	}
	if e := ExactKeys(data, "kind", "patch_number", "artifact_hash", "encryption", "artifact_key_id"); e != nil {
		return e
	}
	*t = Target(value)
	return nil
}
