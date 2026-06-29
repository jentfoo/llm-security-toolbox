package proxy

import (
	"bytes"
	"cmp"
	"log"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-appsec/toolbox/sectool/service/ids"
	"github.com/go-appsec/toolbox/sectool/service/store"
)

const (
	historyKeyPrefix  = "proxy:history:f:"
	historyPayloadSuf = ":p"
)

func historyMetaKey(flowID string) string {
	return historyKeyPrefix + flowID
}

func historyPayloadKey(flowID string) string {
	return historyKeyPrefix + flowID + historyPayloadSuf
}

// orderedFlow is the in-memory ordering record for a stored history entry.
type orderedFlow struct {
	flowID    string
	timestamp time.Time
}

// lessOrder is the canonical (timestamp, flow_id) order. flow_id breaks ties so
// same-instant captures sort deterministically across recovery and platform clock resolution.
func lessOrder(aTime time.Time, aID string, bTime time.Time, bID string) bool {
	if !aTime.Equal(bTime) {
		return aTime.Before(bTime)
	}
	return aID < bID
}

// HistoryStore provides typed access to proxy history backed by store.Storage.
// Entries are keyed by flow_id; merge ordering uses (Timestamp, FlowID).
type HistoryStore struct {
	mu              sync.RWMutex
	storage         store.Storage
	flowOrder       []orderedFlow        // ordered by (timestamp, flowID) ascending
	timestampByFlow map[string]time.Time // flow_id -> timestamp, for cursor resolution
	captureFilter   atomic.Value         // stores CaptureFilter
}

// newHistoryStore creates a history store using the provided storage backend.
// Recovers in-memory ordering by scanning meta keys.
func newHistoryStore(storage store.Storage) *HistoryStore {
	h := &HistoryStore{
		storage:         storage,
		timestampByFlow: make(map[string]time.Time),
	}
	h.recover()
	return h
}

// recover rebuilds in-memory order from persisted meta keys.
func (h *HistoryStore) recover() {
	for _, key := range h.storage.KeySet() {
		if !strings.HasPrefix(key, historyKeyPrefix) || strings.HasSuffix(key, historyPayloadSuf) {
			continue
		}
		data, found, err := h.storage.Get(key)
		if err != nil || !found {
			continue
		}
		var meta HistoryMeta
		if err := store.Deserialize(data, &meta); err != nil {
			log.Printf("proxy: history recover deserialize error %s: %v", key, err)
			continue
		}
		if meta.FlowID == "" {
			continue
		}
		ts := meta.Timestamp.UTC()
		h.flowOrder = append(h.flowOrder, orderedFlow{flowID: meta.FlowID, timestamp: ts})
		h.timestampByFlow[meta.FlowID] = ts
	}
	slices.SortFunc(h.flowOrder, func(a, b orderedFlow) int {
		return cmp.Or(a.timestamp.Compare(b.timestamp), cmp.Compare(a.flowID, b.flowID))
	})
}

// Store mints a flow_id, assigns it to flow, persists, and returns the flow_id.
// flow.StartedAt must be set by the caller. Child flows (ParentFlowID set) are
// stored payload-only: no meta key and absent from the listing order.
func (h *HistoryStore) Store(flow *Flow) string {
	h.mu.Lock()
	defer h.mu.Unlock()

	flowID := h.mintUniqueFlowIDLocked()
	flow.FlowID = flowID
	ts := flow.StartedAt.UTC()
	flow.StartedAt = ts

	h.writePayloadLocked(flow)
	if flow.ParentFlowID != "" {
		return flowID
	}
	h.writeMetaLocked(flow)
	h.insertOrderLocked(orderedFlow{flowID: flowID, timestamp: ts})
	h.timestampByFlow[flowID] = ts
	return flowID
}

// mintUniqueFlowIDLocked generates a flow_id, retrying on collision. Caller must hold mu.
// Probes the payload key so child flows (which have no meta key) are also covered.
func (h *HistoryStore) mintUniqueFlowIDLocked() string {
	for {
		candidate := ids.Generate(ids.DefaultLength)
		if _, exists := h.timestampByFlow[candidate]; exists {
			continue
		} else if _, found, _ := h.storage.Get(historyPayloadKey(candidate)); found {
			continue
		}
		return candidate
	}
}

// writePayloadLocked serializes and writes the payload key for a flow. Caller must hold mu.
func (h *HistoryStore) writePayloadLocked(flow *Flow) {
	payloadData, err := store.Serialize(flow)
	if err != nil {
		log.Printf("proxy: serialize history flow %s: %v", flow.FlowID, err)
		return
	}
	if err := h.storage.Set(historyPayloadKey(flow.FlowID), payloadData); err != nil {
		log.Printf("proxy: save history payload %s: %v", flow.FlowID, err)
	}
}

// writeMetaLocked serializes and writes the meta key for a flow. Caller must hold mu.
// Must run after writePayloadLocked: a torn write leaves an invisible orphan payload.
func (h *HistoryStore) writeMetaLocked(flow *Flow) {
	meta := flow.extractMeta()
	metaData, err := store.Serialize(&meta)
	if err != nil {
		log.Printf("proxy: serialize history meta %s: %v", flow.FlowID, err)
		return
	}
	if err := h.storage.Set(historyMetaKey(flow.FlowID), metaData); err != nil {
		log.Printf("proxy: save history meta %s: %v", flow.FlowID, err)
	}
}

// insertOrderLocked inserts e into flowOrder, preserving (timestamp, flowID) ascending order.
// Caller must hold mu.
func (h *HistoryStore) insertOrderLocked(e orderedFlow) {
	idx := sort.Search(len(h.flowOrder), func(i int) bool {
		return !lessOrder(h.flowOrder[i].timestamp, h.flowOrder[i].flowID, e.timestamp, e.flowID)
	})
	h.flowOrder = slices.Insert(h.flowOrder, idx, e)
}

// Get retrieves a flow by flow_id.
func (h *HistoryStore) Get(flowID string) (*Flow, bool) {
	data, found, err := h.storage.Get(historyPayloadKey(flowID))
	if err != nil || !found {
		return nil, false
	}
	var flow Flow
	if err := store.Deserialize(data, &flow); err != nil {
		return nil, false
	}
	// msgpack timestamps lose timezone info; normalize to UTC
	flow.StartedAt = flow.StartedAt.UTC()
	flow.CompletedAt = flow.CompletedAt.UTC()
	return &flow, true
}

// GetMeta retrieves lightweight metadata for an entry by flow_id.
func (h *HistoryStore) GetMeta(flowID string) (*HistoryMeta, bool) {
	data, found, err := h.storage.Get(historyMetaKey(flowID))
	if err != nil || !found {
		return nil, false
	}
	var meta HistoryMeta
	if err := store.Deserialize(data, &meta); err != nil {
		return nil, false
	}
	meta.Timestamp = meta.Timestamp.UTC()
	return &meta, true
}

// Page returns up to count flows strictly after afterFlowID, ordered oldest-first.
func (h *HistoryStore) Page(count int, afterFlowID string) []*Flow {
	if count <= 0 {
		return nil
	}
	flowIDs := h.pageFlowIDs(count, afterFlowID)
	flows := make([]*Flow, 0, len(flowIDs))
	for _, fid := range flowIDs {
		if f, ok := h.Get(fid); ok {
			flows = append(flows, f)
		}
	}
	return flows
}

// PageMeta returns up to count meta entries strictly after afterFlowID, ordered oldest-first.
func (h *HistoryStore) PageMeta(count int, afterFlowID string) []HistoryMeta {
	if count <= 0 {
		return nil
	}
	flowIDs := h.pageFlowIDs(count, afterFlowID)
	metas := make([]HistoryMeta, 0, len(flowIDs))
	for _, fid := range flowIDs {
		if m, ok := h.GetMeta(fid); ok {
			metas = append(metas, *m)
		}
	}
	return metas
}

// pageFlowIDs returns up to count flow IDs after afterFlowID, oldest-first.
// Copies the slice while holding the lock so a concurrent Store cannot realloc the backing array.
func (h *HistoryStore) pageFlowIDs(count int, afterFlowID string) []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var startIdx int
	if afterFlowID != "" {
		if ts, ok := h.timestampByFlow[afterFlowID]; ok {
			startIdx = sort.Search(len(h.flowOrder), func(i int) bool {
				return lessOrder(ts, afterFlowID, h.flowOrder[i].timestamp, h.flowOrder[i].flowID)
			})
		}
	}
	end := min(startIdx+count, len(h.flowOrder))
	if startIdx >= end {
		return nil
	}
	flowIDs := make([]string, 0, end-startIdx)
	for i := startIdx; i < end; i++ {
		flowIDs = append(flowIDs, h.flowOrder[i].flowID)
	}
	return flowIDs
}

// Count returns the number of entries currently stored.
func (h *HistoryStore) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return len(h.flowOrder)
}

// Delete removes entries by flow_id. Idempotent; unknown ids are skipped.
// Returns the number of entries actually removed.
func (h *HistoryStore) Delete(flowIDs ...string) int {
	h.mu.Lock()
	defer h.mu.Unlock()

	var deleted int
	for _, fid := range flowIDs {
		ts, ok := h.timestampByFlow[fid]
		if !ok {
			continue
		}
		if err := h.storage.Delete(historyMetaKey(fid)); err != nil {
			log.Printf("proxy: delete history meta %s: %v", fid, err)
			continue
		}
		if err := h.storage.Delete(historyPayloadKey(fid)); err != nil {
			log.Printf("proxy: delete history payload %s: %v", fid, err)
		}
		delete(h.timestampByFlow, fid)
		idx := sort.Search(len(h.flowOrder), func(i int) bool {
			return !lessOrder(h.flowOrder[i].timestamp, h.flowOrder[i].flowID, ts, fid)
		})
		if idx < len(h.flowOrder) && h.flowOrder[idx].flowID == fid {
			h.flowOrder = slices.Delete(h.flowOrder, idx, idx+1)
		}
		deleted++
	}
	return deleted
}

// Close closes the underlying storage.
func (h *HistoryStore) Close() {
	_ = h.storage.Close()
}

// extractMeta builds HistoryMeta from a Flow using its accessor methods.
func (f *Flow) extractMeta() HistoryMeta {
	return HistoryMeta{
		FlowID:      f.FlowID,
		Protocol:    f.ProtocolTag,
		Scheme:      f.Scheme,
		Port:        f.Port,
		Method:      f.GetMethod(),
		Host:        f.GetHost(),
		Path:        f.getFullPath(),
		Status:      f.GetStatusCode(),
		ContentType: f.GetResponseHeader("content-type"),
		RespLen:     f.responseBodyLen(),
		Timestamp:   f.StartedAt,
		Duration:    f.CompletedAt.Sub(f.StartedAt),
	}
}

// isH2 reports whether the flow's request side carries folded HTTP/2 pseudo-headers.
func (f *Flow) isH2() bool { return f.ProtocolTag == protocolH2 }

// getFullPath returns path including query string for summary/meta display.
// For HTTP/1.1, concatenates Path + "?" + Query when Query is non-empty.
// For H2, :path already includes the query.
func (f *Flow) getFullPath() string {
	if f.Request == nil {
		return ""
	}
	if f.isH2() {
		return f.Request.GetHeader(":path")
	}
	if f.Request.Query != "" {
		return f.Request.Path + "?" + f.Request.Query
	}
	return f.Request.Path
}

// responseBodyLen returns the length of the response body.
func (f *Flow) responseBodyLen() int {
	if f.Response != nil {
		return len(f.Response.Body)
	}
	return 0
}

// FormatRequest returns the request in wire-compatible format.
// For HTTP/1.1, uses SerializeRaw to preserve anomalies like bare-LF.
// For HTTP/2, rebuilds HTTP/1.1-style text from the folded pseudo-headers.
func (f *Flow) FormatRequest(buf *bytes.Buffer) []byte {
	if f.Request == nil {
		return nil
	}
	if f.isH2() {
		return formatH2Request(buf, f.Request)
	}
	return f.Request.toRawRequest().SerializeRaw(buf)
}

// FormatResponse returns the response in wire-compatible format.
// For HTTP/1.1, uses SerializeRaw to preserve anomalies like bare-LF.
// For HTTP/2, rebuilds HTTP/1.1-style text from the folded pseudo-headers.
func (f *Flow) FormatResponse(buf *bytes.Buffer) []byte {
	if f.Response == nil {
		return nil
	}
	if f.isH2() {
		return formatH2Response(buf, f.Response)
	}
	return f.Response.toRawResponse().SerializeRaw(buf)
}

// FormatInterimResponses returns each 1xx response in wire form (HTTP/1.1 only).
func (f *Flow) FormatInterimResponses(buf *bytes.Buffer) []string {
	if len(f.InterimResponses) == 0 {
		return nil
	}
	out := make([]string, 0, len(f.InterimResponses))
	for _, ir := range f.InterimResponses {
		out = append(out, string(ir.toRawResponse().SerializeRaw(buf)))
	}
	return out
}

// GetMethod returns the request method.
func (f *Flow) GetMethod() string {
	if f.Request == nil {
		return ""
	}
	if f.isH2() {
		return f.Request.GetHeader(":method")
	}
	return f.Request.Method
}

// GetPath returns the URL path without query string.
// For H2, strips the query portion since :path includes it.
func (f *Flow) GetPath() string {
	if f.Request == nil {
		return ""
	}
	if f.isH2() {
		path := f.Request.GetHeader(":path")
		if idx := strings.IndexByte(path, '?'); idx >= 0 {
			return path[:idx]
		}
		return path
	}
	return f.Request.Path
}

// GetHost returns the request host.
func (f *Flow) GetHost() string {
	if f.Request == nil {
		return ""
	}
	if f.isH2() {
		return f.Request.GetHeader(":authority")
	}
	return f.Request.GetHeader("Host")
}

// GetStatusCode returns the response status code.
func (f *Flow) GetStatusCode() int {
	if f.Response != nil {
		return f.Response.StatusCode
	}
	return 0
}

// GetRequestHeader returns a request header value (case-insensitive).
func (f *Flow) GetRequestHeader(name string) string {
	if f.Request != nil {
		return f.Request.GetHeader(name)
	}
	return ""
}

// GetResponseHeader returns a response header value (case-insensitive).
func (f *Flow) GetResponseHeader(name string) string {
	if f.Response != nil {
		return f.Response.GetHeader(name)
	}
	return ""
}

// isPseudoOrStreamHeader reports headers that must not be re-emitted when
// rebuilding HTTP/1.1-style text: HTTP/2 pseudo-headers and the synthetic stream id.
func isPseudoOrStreamHeader(name string) bool {
	return strings.HasPrefix(name, ":") || strings.EqualFold(name, headerStreamID)
}

// formatH2Request rebuilds an HTTP/1.1-style request from a folded HTTP/2 Message
// for display and replay. The HTTP/1.1 version keeps it parseable by the standard
// parser; pseudo-headers and the stream id are reconstructed into the request line
// and host, never re-emitted as headers.
func formatH2Request(buf *bytes.Buffer, req *Message) []byte {
	buf.Reset()

	buf.WriteString(req.GetHeader(":method"))
	buf.WriteByte(' ')
	buf.WriteString(req.GetHeader(":path"))
	buf.WriteString(" HTTP/1.1\r\n")

	buf.WriteString("host: ")
	buf.WriteString(req.GetHeader(":authority"))
	buf.WriteString("\r\n")

	for _, h := range req.Headers {
		if isPseudoOrStreamHeader(h.Name) {
			continue
		}
		buf.WriteString(h.Name)
		buf.WriteString(": ")
		buf.WriteString(h.Value)
		buf.WriteString("\r\n")
	}

	buf.WriteString("\r\n")
	buf.Write(req.Body)

	return buf.Bytes()
}

// formatH2Response rebuilds an HTTP/1.1-style response from a folded HTTP/2 Message.
func formatH2Response(buf *bytes.Buffer, resp *Message) []byte {
	buf.Reset()

	buf.WriteString("HTTP/2 ")
	buf.WriteString(strconv.Itoa(resp.StatusCode))
	text := http.StatusText(resp.StatusCode)
	if text != "" {
		buf.WriteByte(' ')
		buf.WriteString(text)
	}
	buf.WriteString("\r\n")

	for _, h := range resp.Headers {
		if isPseudoOrStreamHeader(h.Name) {
			continue
		}
		buf.WriteString(h.Name)
		buf.WriteString(": ")
		buf.WriteString(h.Value)
		buf.WriteString("\r\n")
	}

	buf.WriteString("\r\n")
	buf.Write(resp.Body)

	return buf.Bytes()
}
