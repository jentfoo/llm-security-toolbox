package sidecar

import "bytes"

// Reassembler accumulates stream_deliver chunks until a complete protocol frame
// is buffered. Inbound chunks are raw transport bytes that may split or coalesce
// frames; an adapter appends each chunk and drains whole frames via Next.
type Reassembler struct {
	buf []byte
}

// Append adds a delivered chunk to the buffer.
func (r *Reassembler) Append(data []byte) { r.buf = append(r.buf, data...) }

// Buffered reports the number of bytes held but not yet drained.
func (r *Reassembler) Buffered() int { return len(r.buf) }

// Next extracts the leading complete frame. split inspects the buffered bytes and
// returns the frame length and true when a whole frame is present; Next then
// returns a copy of those bytes and advances. It returns false when no complete
// frame is buffered or split reports an invalid length.
func (r *Reassembler) Next(split func(buf []byte) (n int, ok bool)) ([]byte, bool) {
	n, ok := split(r.buf)
	if !ok || n <= 0 || n > len(r.buf) {
		return nil, false
	}
	frame := bytes.Clone(r.buf[:n])
	r.buf = append(r.buf[:0], r.buf[n:]...)
	return frame, true
}
