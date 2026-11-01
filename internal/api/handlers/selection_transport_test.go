package handlers

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func testCompressInterpreterBipatch(t *testing.T, data []byte) []byte {
	t.Helper()
	w, e := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	return w.EncodeAll(data, nil)
}
func TestProductionInterpreterTransportFixture(t *testing.T) {
	transport, e := os.ReadFile("../../../testdata/interpreter_transport/transport.patch")
	if e != nil {
		t.Fatal(e)
	}
	want, e := os.ReadFile("../../../testdata/interpreter_transport/envelope.json")
	if e != nil {
		t.Fatal(e)
	}
	manifestData, e := os.ReadFile("../../../testdata/interpreter_transport/manifest.json")
	if e != nil {
		t.Fatal(e)
	}
	var manifest struct {
		Installed  string `json:"installed_envelope_sha256"`
		Compressed string `json:"compressed_transport_sha256"`
	}
	if e = json.Unmarshal(manifestData, &manifest); e != nil {
		t.Fatal(e)
	}
	if sha256Hex(transport) != manifest.Compressed || sha256Hex(want) != manifest.Installed || manifest.Compressed == manifest.Installed {
		t.Fatal("fixture lost installed/transport hash distinction")
	}
	got, e := reconstructInterpreterTransport(transport)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("production transport reconstructed different envelope")
	}
	// The live production encoder is optional for standalone clones. When present,
	// the HTTP fixtures also invoke it for each generated app/variant envelope.
	if os.Getenv("SHOREBIRD_TEST_PATCH_ENCODER") != "" {
		live := interpreterTestTransport(t, want)
		got, e := reconstructInterpreterTransport(live)
		if e != nil || !bytes.Equal(got, want) {
			t.Fatalf("live production encoder: %v", e)
		}
	}
}
func TestInterpreterTransportRejectsMalformedRepresentations(t *testing.T) {
	validRaw := append(append([]byte(nil), interpreterBipatchHeader...), 0, 2, '{', '}', 0)
	valid := testCompressInterpreterBipatch(t, validRaw)
	oversizedFrame := []byte{0x28, 0xb5, 0x2f, 0xfd, 0xe0}
	oversizedFrame = binary.LittleEndian.AppendUint64(oversizedFrame, uint64(maxInterpreterDecodedTransportBytes)+1)
	oversizedFrame = append(oversizedFrame, 1, 0, 0)
	hugeWindow := []byte{0x28, 0xb5, 0x2f, 0xfd, 0, 0xff, 1, 0, 0}
	compressedCases := map[string][]byte{"dictionary frame": {0x28, 0xb5, 0x2f, 0xfd, 0x21, 1, 0, 1, 0, 0}, "declared decoded size cap": oversizedFrame, "declared decoder window cap": hugeWindow, "reserved block type": {0x28, 0xb5, 0x2f, 0xfd, 0x20, 0, 7, 0, 0}, "raw JSON": []byte(`{"format":"open-aot-vmcode-encrypted-v1"}`), "truncated header": valid[:3], "truncated block": valid[:len(valid)-1], "trailing compressed byte": append(append([]byte(nil), valid...), 0), "concatenated frames": append(append([]byte(nil), valid...), valid...), "skippable frame": {0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0}}
	for name, data := range compressedCases {
		t.Run(name, func(t *testing.T) {
			if _, e := reconstructInterpreterTransport(data); e == nil {
				t.Fatal("accepted malformed transport")
			}
		})
	}
	rawCases := map[string][]byte{
		"wrong bipatch version": append([]byte{0xdf, 0xb1, 0, 0, 1, 0x10, 0, 0}, validRaw[8:]...),
		"base dependent add":    append(append([]byte(nil), interpreterBipatchHeader...), 1, 0, 2, '{', '}', 0),
		"missing literal":       append(append([]byte(nil), interpreterBipatchHeader...), 0, 0, 0),
		"truncated literal":     append(append([]byte(nil), interpreterBipatchHeader...), 0, 2, '{'),
		"missing seek":          validRaw[:len(validRaw)-1],
		"nonzero seek":          append(append([]byte(nil), validRaw[:len(validRaw)-1]...), 2),
		"second instruction":    append(append([]byte(nil), validRaw...), 0, 1, 'x', 0),
		"trailing decoded byte": append(append([]byte(nil), validRaw...), 0xff),
		"overlong zero":         append(append([]byte(nil), interpreterBipatchHeader...), 0x80, 0, 2, '{', '}', 0),
	}
	overflow := append(append([]byte(nil), interpreterBipatchHeader...), 0)
	overflow = append(overflow, bytes.Repeat([]byte{0xff}, 10)...)
	rawCases["overflow copy integer"] = overflow
	oversized := append(append([]byte(nil), interpreterBipatchHeader...), 0)
	oversized = binary.AppendUvarint(oversized, uint64(maxInterpreterArtifactBytes)+1)
	rawCases["oversized installed artifact"] = oversized
	huge := append(append([]byte(nil), interpreterBipatchHeader...), 0)
	huge = binary.AppendUvarint(huge, math.MaxUint64)
	rawCases["allocation integer overflow"] = huge
	for name, raw := range rawCases {
		t.Run(name, func(t *testing.T) {
			if _, e := reconstructInterpreterTransport(testCompressInterpreterBipatch(t, raw)); e == nil {
				t.Fatal("accepted unsupported bipatch")
			}
		})
	}
}

func TestInterpreterTransportProductionVarintAndBlockBoundaries(t *testing.T) {
	for _, size := range []int{1, 127, 128, 16383, 16384, 131072} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			envelope := bytes.Repeat([]byte("x"), size)
			transport := interpreterTestTransport(t, envelope)
			decoded, e := reconstructInterpreterTransport(transport)
			if e != nil || !bytes.Equal(decoded, envelope) {
				t.Fatalf("size %d: %v", size, e)
			}
		})
	}
}
