package updater

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// Update signing trust.
//
// The server pins the Ed25519 public keys that may sign its own update
// manifests. They are compiled in with -ldflags (never read at run time), so
// neither the environment, the settings file nor a mirror can change who is
// trusted:
//
//	-X github.com/shorebird-server/internal/updater.TrustedKeys=<b64>[,<b64>...]
//
// More than one key allows a rotation: release N+1 pins both the old and the
// new key, later releases pin only the new one. The key is deliberately not a
// role of the P4 release root (docs/SELF_UPDATE.md, "Signing key").
var TrustedKeys = ""

// DevelopmentTrust must be "allowed" (link time) for the binary to accept the
// committed DEVELOPMENT-ONLY key. Release builds never set it.
var DevelopmentTrust = ""

// DevelopmentPublicKey is the public half of signing/server-update.DEVELOPMENT-ONLY.pem.
// Its private key is committed on purpose and protects nothing.
const DevelopmentPublicKey = "a0ZEK+btwcAvqSxqsi4jT7YFIVj9AecHhANwfESYE4w="

// SignatureDomain separates update signatures from every other signature
// made with Ed25519 in this workspace (the P4 domains end in ".v2:").
const SignatureDomain = "open-shorebird.server-update-signature.v1:"

const maxSignatureBytes = 1024

type trustedKey struct {
	id  string
	key ed25519.PublicKey
}

// KeyID is "sha256:" plus the lowercase hex SHA-256 of the raw public key,
// the same convention as the P4 release-root documents.
func KeyID(key ed25519.PublicKey) string {
	sum := sha256.Sum256(key)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ParseTrustedKeys decodes a comma-separated list of base64 Ed25519 public
// keys. Malformed or duplicate entries make the whole list invalid: a
// partially understood pin must not silently drop a rotation key.
func ParseTrustedKeys(list string, allowDevelopment bool) ([]trustedKey, error) {
	var keys []trustedKey
	seen := map[string]bool{}
	for _, entry := range strings.Split(list, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(entry)
		if err != nil || len(raw) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(raw) != entry {
			return nil, errors.New("trust_malformed")
		}
		if entry == DevelopmentPublicKey && !allowDevelopment {
			return nil, errors.New("development_key_refused")
		}
		key := ed25519.PublicKey(raw)
		id := KeyID(key)
		if seen[id] {
			return nil, errors.New("trust_malformed")
		}
		seen[id] = true
		keys = append(keys, trustedKey{id: id, key: key})
	}
	if len(keys) == 0 {
		return nil, errors.New("trust_unconfigured")
	}
	return keys, nil
}

// Trust is the compiled set of update signing keys.
type Trust struct {
	keys        []trustedKey
	development bool
}

// CompiledTrust returns the link-time trust, or why self-update is unavailable.
func CompiledTrust() (*Trust, error) {
	return NewTrust(TrustedKeys, DevelopmentTrust == "allowed")
}

// NewTrust builds a trust set from an explicit key list (tests and tools).
func NewTrust(list string, allowDevelopment bool) (*Trust, error) {
	keys, err := ParseTrustedKeys(list, allowDevelopment)
	if err != nil {
		return nil, err
	}
	t := &Trust{keys: keys}
	for _, k := range keys {
		if base64.StdEncoding.EncodeToString(k.key) == DevelopmentPublicKey {
			t.development = true
		}
	}
	return t, nil
}

// Development reports whether the committed DEVELOPMENT-ONLY key is trusted.
func (t *Trust) Development() bool { return t != nil && t.development }

// KeyIDs lists the pinned key IDs (status output; public information).
func (t *Trust) KeyIDs() []string {
	if t == nil {
		return nil
	}
	ids := make([]string, 0, len(t.keys))
	for _, k := range t.keys {
		ids = append(ids, k.id)
	}
	return ids
}

// SignatureFile is the content of <asset>.sig.
type SignatureFile struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// SignedMessage is what a key signs for a manifest: the domain and the
// lowercase hex SHA-256 of the exact manifest bytes.
func SignedMessage(manifest []byte) []byte {
	sum := sha256.Sum256(manifest)
	return []byte(SignatureDomain + hex.EncodeToString(sum[:]))
}

// EncodeSignature produces canonical <asset>.sig bytes.
func EncodeSignature(key ed25519.PrivateKey, manifest []byte) []byte {
	sig := ed25519.Sign(key, SignedMessage(manifest))
	public := key.Public().(ed25519.PublicKey)
	data, _ := json.Marshal(SignatureFile{KeyID: KeyID(public), Signature: base64.StdEncoding.EncodeToString(sig)})
	return data
}

// Verify checks a signature file over the exact manifest bytes. Nothing in the
// manifest is parsed before this succeeds.
func (t *Trust) Verify(manifest, signature []byte) error {
	if t == nil || len(t.keys) == 0 {
		return errors.New("trust_unconfigured")
	}
	if len(signature) > maxSignatureBytes {
		return errors.New("signature_invalid")
	}
	var file SignatureFile
	dec := json.NewDecoder(bytes.NewReader(signature))
	dec.DisallowUnknownFields()
	if dec.Decode(&file) != nil {
		return errors.New("signature_invalid")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return errors.New("signature_invalid")
	}
	sig, err := base64.StdEncoding.DecodeString(file.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(sig) != file.Signature {
		return errors.New("signature_invalid")
	}
	for _, k := range t.keys {
		if k.id != file.KeyID {
			continue
		}
		if !ed25519.Verify(k.key, SignedMessage(manifest), sig) {
			return errors.New("signature_invalid")
		}
		return nil
	}
	return errors.New("untrusted_signer")
}
