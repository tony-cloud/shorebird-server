package handlers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
)

// Interpreter publishers use patch::make_patch(empty_base, encrypted_envelope):
// one zstd frame containing bipatch v1 and exactly one literal-only control.
// These are independent limits: neither compressed nor reconstructed bytes may
// exceed 128 MiB, and the bipatch framing may consume at most 32 further bytes.
const maxInterpreterArtifactBytes int64 = 128 << 20
const maxInterpreterDecodedTransportBytes = maxInterpreterArtifactBytes + 32

var interpreterBipatchHeader = []byte{0xdf, 0xb1, 0, 0, 0, 0x10, 0, 0}

func reconstructInterpreterTransport(compressed []byte) ([]byte, error) {
	if len(compressed) == 0 || int64(len(compressed)) > maxEncryptedPatchTransportBytes {
		return nil, fmt.Errorf("interpreter compressed transport exceeds limit")
	}
	if e := singleInterpreterZstdFrame(compressed); e != nil {
		return nil, e
	}
	decoder, e := zstd.NewReader(bytes.NewReader(compressed), zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true), zstd.WithDecoderMaxMemory(uint64(maxInterpreterDecodedTransportBytes)), zstd.WithDecoderMaxWindow(uint64(maxInterpreterDecodedTransportBytes)))
	if e != nil {
		return nil, e
	}
	defer decoder.Close()
	decoded, e := readBoundedPatchBytes(decoder, maxInterpreterDecodedTransportBytes)
	if e != nil {
		return nil, e
	}
	if !bytes.HasPrefix(decoded, interpreterBipatchHeader) {
		return nil, fmt.Errorf("invalid interpreter bipatch header")
	}
	r := bytes.NewReader(decoded[len(interpreterBipatchHeader):])
	add, e := canonicalTransportUvarint(r)
	if e != nil || add != 0 {
		return nil, fmt.Errorf("interpreter transport must not read a base artifact")
	}
	count, e := canonicalTransportUvarint(r)
	if e != nil || count == 0 || count > uint64(maxInterpreterArtifactBytes) || count > uint64(r.Len()) {
		return nil, fmt.Errorf("invalid interpreter literal size")
	}
	start := len(decoded) - r.Len()
	artifact := decoded[start : start+int(count)]
	if _, e = r.Seek(int64(count), io.SeekCurrent); e != nil {
		return nil, e
	}
	seek, e := canonicalTransportUvarint(r)
	if e != nil || seek != 0 || r.Len() != 0 {
		return nil, fmt.Errorf("interpreter transport must contain exactly one literal control")
	}
	return artifact, nil
}
func canonicalTransportUvarint(r *bytes.Reader) (uint64, error) {
	before := r.Len()
	n, e := binary.ReadUvarint(r)
	if e != nil {
		return 0, e
	}
	var encoded [binary.MaxVarintLen64]byte
	if binary.PutUvarint(encoded[:], n) != before-r.Len() {
		return 0, fmt.Errorf("noncanonical transport integer")
	}
	return n, nil
}

// Check the exact frame boundary before decompression; concatenated/skippable
// frames and trailing bytes cannot masquerade as this single-frame transport.
func singleInterpreterZstdFrame(data []byte) error {
	var header zstd.Header
	if e := header.Decode(data); e != nil {
		return e
	}
	if header.Skippable || header.DictionaryID != 0 || header.WindowSize > uint64(maxInterpreterDecodedTransportBytes) || (header.HasFCS && header.FrameContentSize > uint64(maxInterpreterDecodedTransportBytes)) {
		return fmt.Errorf("unsupported interpreter zstd frame")
	}
	offset := header.HeaderSize
	for {
		if len(data)-offset < 3 {
			return io.ErrUnexpectedEOF
		}
		block := uint32(data[offset]) | uint32(data[offset+1])<<8 | uint32(data[offset+2])<<16
		offset += 3
		kind, size := block>>1&3, int(block>>3)
		if kind == 3 {
			return fmt.Errorf("reserved zstd block type")
		}
		if kind == 1 {
			size = 1
		}
		if size > len(data)-offset {
			return io.ErrUnexpectedEOF
		}
		offset += size
		if block&1 != 0 {
			break
		}
	}
	if header.HasCheckSum {
		if len(data)-offset < 4 {
			return io.ErrUnexpectedEOF
		}
		offset += 4
	}
	if offset != len(data) {
		return fmt.Errorf("trailing interpreter zstd data")
	}
	return nil
}
