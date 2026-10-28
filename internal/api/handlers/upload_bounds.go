package handlers

import (
	"errors"
	"io"
)

var errUploadSizeMismatch = errors.New("upload does not match the granted byte size")

// exactUploadReader withholds the final byte until EOF is checked. Storage
// clients reading exactly Content-Length cannot commit an oversized payload.
type exactUploadReader struct {
	reader    io.Reader
	remaining int64
}

func (r *exactUploadReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.remaining == 0 {
		return 0, io.EOF
	}
	if r.remaining == 1 {
		var tail [2]byte
		n, err := io.ReadFull(r.reader, tail[:])
		if n != 1 || err != io.ErrUnexpectedEOF {
			return 0, errUploadSizeMismatch
		}
		p[0] = tail[0]
		r.remaining = 0
		return 1, nil
	}
	limit := r.remaining - 1
	if int64(len(p)) > limit {
		p = p[:int(limit)]
	}
	n, err := r.reader.Read(p)
	r.remaining -= int64(n)
	if err == io.EOF {
		return n, errUploadSizeMismatch
	}
	return n, err
}
