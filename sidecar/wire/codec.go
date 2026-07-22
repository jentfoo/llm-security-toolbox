package wire

import (
	"encoding/binary"
	"fmt"
	"io"
)

// MaxFrameBytes bounds a single message on both read and write. A frame whose
// length prefix exceeds it is rejected as oversized rather than allocated.
const MaxFrameBytes uint64 = 128 << 20 // 128 MiB

// WriteFrame writes payload as a 4-byte big-endian length prefix followed by the
// payload bytes.
func WriteFrame(w io.Writer, payload []byte) error {
	if uint64(len(payload)) > MaxFrameBytes {
		return NewError(CodeOversizedMessage,
			fmt.Sprintf("message of %d bytes exceeds frame ceiling", len(payload)))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame reads one length-prefixed message. Returns the underlying read error
// (e.g. io.EOF) on a closed connection.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if uint64(n) > MaxFrameBytes {
		return nil, NewError(CodeOversizedMessage,
			fmt.Sprintf("frame of %d bytes exceeds frame ceiling", n))
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
