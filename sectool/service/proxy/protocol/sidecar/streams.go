package sidecar

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/go-analyze/bulk"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// streamReadBuf is the per-read chunk size delivered to the sidecar. Chunks are
// raw transport bytes, not aligned to protocol frames; the sidecar reassembles.
const streamReadBuf = 32 * 1024

// streamSet tracks a sidecar's open byte streams so writes, proactive output, and
// teardown can reach the right socket.
type streamSet struct {
	next atomic.Uint64

	mu      sync.Mutex
	streams map[string]net.Conn
}

func newStreamSet() *streamSet {
	return &streamSet{streams: map[string]net.Conn{}}
}

func (ss *streamSet) add(conn net.Conn) string {
	id := "s" + strconv.FormatUint(ss.next.Add(1), 10)
	ss.mu.Lock()
	ss.streams[id] = conn
	ss.mu.Unlock()
	return id
}

func (ss *streamSet) remove(id string) {
	ss.mu.Lock()
	delete(ss.streams, id)
	ss.mu.Unlock()
}

func (ss *streamSet) conn(id string) net.Conn {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.streams[id]
}

// applyWrites writes each entry to its named stream's socket. A write may target
// a different stream than the event arrived on. It returns the first write error
// so the caller can tear the stream down; an unknown stream_id is skipped, not an
// error.
func (ss *streamSet) applyWrites(writes []wire.StreamWrite) error {
	for _, w := range writes {
		c := ss.conn(w.StreamID)
		if c == nil {
			continue
		}
		if _, err := c.Write(w.Data); err != nil {
			return err
		}
	}
	return nil
}

// serveClient runs one claimed client-facing connection through the event model:
// stream_open, then ordered stream_deliver per inbound chunk awaiting each reply,
// then stream_ended on close. The caller owns closing the socket.
func (ss *streamSet) serveClient(ctx context.Context, rec *Record, c *protocol.EarlyClaimCtx) {
	id := ss.add(c.ClientConn)
	defer ss.remove(id)

	host, path := openInfo(c)
	ss.runClient(ctx, rec, id, c.ClientReader, wire.StreamOpenParams{
		StreamID:     id,
		Host:         host,
		Path:         path,
		MatchedClaim: rec.Name,
		PeerAddr:     c.ClientConn.RemoteAddr().String(),
	})
}

// serveUpgrade runs a post-upgrade client connection through the event model,
// carrying the captured triggering request's flow_id and headers on stream_open so
// the sidecar can drive a handshake embedded in the upgrade request.
func (ss *streamSet) serveUpgrade(ctx context.Context, rec *Record, conns protocol.UpgradeConns, reqFlowID string, reqHeaders []wire.Header, host, path string) {
	id := ss.add(conns.ClientConn)
	defer ss.remove(id)

	ss.runClient(ctx, rec, id, conns.ClientReader, wire.StreamOpenParams{
		StreamID:       id,
		Host:           host,
		Path:           path,
		MatchedClaim:   rec.Name,
		PeerAddr:       conns.ClientConn.RemoteAddr().String(),
		RequestFlowID:  reqFlowID,
		RequestHeaders: reqHeaders,
	})
}

// runClient opens the stream, applies any opening writes, and pumps inbound bytes,
// emitting stream_ended on exit. The caller registered the socket and owns closing
// it.
func (ss *streamSet) runClient(ctx context.Context, rec *Record, id string, r io.Reader, open wire.StreamOpenParams) {
	var res wire.StreamResult
	if err := rec.peer.Call(ctx, wire.MethodStreamOpen, open, &res); err != nil {
		return
	}
	// Stream established: notify the sidecar whenever the loop exits; a peer disconnect
	// makes notify a no-op, but a mid-stream RPC error or normal EOF must still release
	// the sidecar's per-stream state
	defer ss.notifyEnded(rec, id)
	if ss.applyWrites(res.Writes) != nil {
		return
	}
	ss.pump(ctx, rec, id, r)
}

// serveUpstream runs a dialed upstream socket through the event model. The dial
// reply already announced the stream, so there is no stream_open; inbound upstream
// bytes deliver as stream_deliver and stream_ended fires on close. The caller
// registered the socket via add; this releases it on exit.
func (ss *streamSet) serveUpstream(ctx context.Context, rec *Record, id string, conn net.Conn) {
	defer ss.remove(id)
	defer ss.notifyEnded(rec, id)
	ss.pump(ctx, rec, id, conn)
}

// pump delivers inbound bytes from r as ordered stream_deliver events, awaiting
// each reply and applying its writes before reading the next chunk.
func (ss *streamSet) pump(ctx context.Context, rec *Record, id string, r io.Reader) {
	buf := make([]byte, streamReadBuf)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			var dres wire.StreamResult
			if derr := rec.peer.Call(ctx, wire.MethodStreamDeliver, wire.StreamDeliverParams{
				StreamID: id,
				Data:     buf[:n],
			}, &dres); derr != nil {
				return
			}
			if ss.applyWrites(dres.Writes) != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// notifyEnded tells the sidecar a stream closed so it can close the paired stream.
func (ss *streamSet) notifyEnded(rec *Record, id string) {
	_ = rec.peer.Notify(wire.MethodStreamEnded, wire.StreamEndedParams{StreamID: id, Reason: "closed"})
}

// closeStream closes the named stream's socket on the sidecar's request.
func (ss *streamSet) closeStream(id string) {
	if c := ss.conn(id); c != nil {
		_ = c.Close()
	}
}

// streamWrite writes proactive bytes to an open stream. An unknown stream_id is a
// transport error.
func (ss *streamSet) streamWrite(id string, data []byte) *wire.Error {
	c := ss.conn(id)
	if c == nil {
		return wire.NewError(wire.CodeUnknownStream, "stream_write: unknown stream_id").
			WithData(&wire.ErrorData{StreamID: id})
	}
	_, _ = c.Write(data)
	return nil
}

// closeAll closes every open stream, unblocking their read loops.
func (ss *streamSet) closeAll() {
	ss.mu.Lock()
	conns := bulk.MapValuesSlice(ss.streams)
	ss.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

// openInfo derives the stream_open host/path. An early_claim has no HTTP request,
// so host comes from the CONNECT target when TLS-terminated and path is empty.
func openInfo(c *protocol.EarlyClaimCtx) (host, path string) {
	if c.Target != nil {
		host = c.Target.Hostname
	}
	return host, ""
}
