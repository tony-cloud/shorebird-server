package selection

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestSharedGoldenEncodingAndSignatures(t *testing.T) {
	data, e := os.ReadFile("../../testdata/variant_selection_v2.json")
	if e != nil {
		t.Fatal(e)
	}
	var golden struct {
		Signature struct {
			Public string `json:"public_key_der_base64"`
		} `json:"signature"`
		Descriptors map[string]struct {
			Descriptor      Descriptor `json:"descriptor"`
			CanonicalHex    string     `json:"canonical_hex"`
			CanonicalBase64 string     `json:"canonical_base64"`
			Digest          string     `json:"sha256"`
		} `json:"descriptors"`
		Vectors []struct {
			ID          string `json:"id"`
			Payload     string `json:"signed_payload_utf8"`
			PayloadHash string `json:"signed_payload_sha256"`
			Response    struct {
				Authentication struct {
					Payload   string `json:"payload"`
					Signature string `json:"signature"`
				} `json:"authentication"`
			} `json:"response"`
			Expected struct {
				SignatureValid bool `json:"signature_valid"`
			} `json:"expected"`
		} `json:"vectors"`
	}
	if e = json.Unmarshal(data, &golden); e != nil {
		t.Fatal(e)
	}
	pubBytes, e := base64.StdEncoding.DecodeString(golden.Signature.Public)
	if e != nil {
		t.Fatal(e)
	}
	pub, e := x509.ParsePKCS1PublicKey(pubBytes)
	if e != nil {
		t.Fatal(e)
	}
	for name, v := range golden.Descriptors {
		t.Run(name, func(t *testing.T) {
			canonical, e := v.Descriptor.Canonical()
			if e != nil {
				t.Fatal(e)
			}
			if hex.EncodeToString(canonical) != v.CanonicalHex || base64.StdEncoding.EncodeToString(canonical) != v.CanonicalBase64 {
				t.Fatal("canonical byte mismatch")
			}
			digest, e := v.Descriptor.Digest()
			if e != nil || digest != v.Digest {
				t.Fatalf("digest %s want %s: %v", digest, v.Digest, e)
			}
		})
	}
	for _, v := range golden.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			payload, e := base64.StdEncoding.DecodeString(v.Response.Authentication.Payload)
			if e != nil {
				t.Fatal(e)
			}
			if string(payload) != v.Payload || ClientHash(string(payload)) != v.PayloadHash {
				t.Fatal("exact signed bytes changed")
			}
			sig, e := base64.StdEncoding.DecodeString(v.Response.Authentication.Signature)
			if e != nil {
				t.Fatal(e)
			}
			digest := sha256.Sum256(payload)
			valid := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig) == nil
			if valid != v.Expected.SignatureValid {
				t.Fatalf("signature valid=%v", valid)
			}
		})
	}
}
func TestStrictJSONAndCanonicalDecimals(t *testing.T) {
	for _, body := range []string{`{"a":"x","a":"y"}`, `{"a":"x","unknown":null}`, `{"a":"\ud800"}`, `{"a":"\udfff"}`, `{"a":"x"} {}`, strings.Repeat(" ", MaxJSON+1) + `{}`} {
		var dst struct {
			A string `json:"a"`
		}
		if StrictJSON([]byte(body), &dst) == nil {
			t.Fatalf("accepted %s", body[:min(100, len(body))])
		}
	}
	for _, s := range []string{"01", "-1", "+1", "9223372036854775808", "1.0", "1e1"} {
		if _, e := Decimal(s, 0, 9223372036854775807); e == nil {
			t.Fatalf("accepted %s", s)
		}
	}
	if n, e := Decimal("9223372036854775807", 0, 9223372036854775807); e != nil || n != 9223372036854775807 {
		t.Fatal("64-bit epoch rejected")
	}
}
