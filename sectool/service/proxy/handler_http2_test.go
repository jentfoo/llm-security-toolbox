package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-harden/llm-security-toolbox/sectool/service/store"
)

func TestNewHTTP2Handler(t *testing.T) {
	t.Parallel()

	history := NewHistoryStore(store.NewMemStorage())
	handler := NewHTTP2Handler(history, 1024*1024)

	require.NotNil(t, handler)
	assert.Equal(t, 1024*1024, handler.maxBodyBytes)
	assert.Nil(t, handler.ruleApplier)
}

func TestHTTP2Handler_SetRuleApplier(t *testing.T) {
	t.Parallel()

	history := NewHistoryStore(store.NewMemStorage())
	handler := NewHTTP2Handler(history, 1024*1024)

	// Initially nil
	assert.Nil(t, handler.ruleApplier)

	// Set rule applier
	applier := &h2MockRuleApplier{}
	handler.SetRuleApplier(applier)

	assert.Equal(t, applier, handler.ruleApplier)
}

func TestStreamTracker(t *testing.T) {
	t.Parallel()

	tracker := newStreamTracker()

	// Get non-existent stream
	_, exists := tracker.get(1)
	assert.False(t, exists)

	// Create stream
	stream := tracker.getOrCreate(1)
	require.NotNil(t, stream)
	assert.Equal(t, uint32(1), stream.id)
	assert.Equal(t, streamOpen, stream.state)

	// Get existing stream
	stream2, exists := tracker.get(1)
	assert.True(t, exists)
	assert.Equal(t, stream, stream2)

	// Create another stream
	stream3 := tracker.getOrCreate(3)
	assert.Equal(t, uint32(3), stream3.id)

	// List all streams
	all := tracker.all()
	assert.Len(t, all, 2)

	// Remove stream
	tracker.remove(1)
	_, exists = tracker.get(1)
	assert.False(t, exists)

	// Remaining stream still there
	_, exists = tracker.get(3)
	assert.True(t, exists)
}

func TestStreamTracker_GetOrCreate(t *testing.T) {
	t.Parallel()

	tracker := newStreamTracker()

	// First call creates
	s1 := tracker.getOrCreate(5)
	assert.NotNil(t, s1)
	assert.Equal(t, uint32(5), s1.id)

	// Second call returns same
	s2 := tracker.getOrCreate(5)
	assert.Equal(t, s1, s2)
}

func TestH2Stream_InitialState(t *testing.T) {
	t.Parallel()

	tracker := newStreamTracker()
	stream := tracker.getOrCreate(1)

	assert.Equal(t, streamOpen, stream.state)
	assert.WithinDuration(t, time.Now(), stream.startTime, time.Second)
	assert.WithinDuration(t, time.Now(), stream.lastActivity, time.Second)
	assert.Equal(t, int32(initialWindowSize), stream.window)
	assert.False(t, stream.reqBodyComplete)
	assert.False(t, stream.respBodyComplete)
}

func TestHistoryEntry_FormatH2Request(t *testing.T) {
	t.Parallel()

	entry := &HistoryEntry{
		Protocol: "h2",
		H2Request: &H2RequestData{
			Method:    "GET",
			Scheme:    "https",
			Authority: "example.com",
			Path:      "/test",
			Headers: []Header{
				{Name: "user-agent", Value: "test/1.0"},
			},
			Body: []byte("request body"),
		},
	}

	formatted := entry.FormatRequest()
	// FormatRequest uses HTTP/1.1 for parser compatibility; actual protocol is tracked in entry.Protocol
	assert.Contains(t, string(formatted), "GET /test HTTP/1.1")
	assert.Contains(t, string(formatted), "host: example.com")
	assert.Contains(t, string(formatted), "user-agent: test/1.0")
	assert.Contains(t, string(formatted), "request body")
}

func TestHistoryEntry_FormatH2Response(t *testing.T) {
	t.Parallel()

	entry := &HistoryEntry{
		Protocol: "h2",
		H2Response: &H2ResponseData{
			StatusCode: 200,
			Headers: []Header{
				{Name: "content-type", Value: "text/plain"},
			},
			Body: []byte("response body"),
		},
	}

	formatted := entry.FormatResponse()
	assert.Contains(t, string(formatted), "HTTP/2 200 OK")
	assert.Contains(t, string(formatted), "content-type: text/plain")
	assert.Contains(t, string(formatted), "response body")
}

func TestHistoryEntry_GetMethods_H2(t *testing.T) {
	t.Parallel()

	entry := &HistoryEntry{
		Protocol: "h2",
		H2Request: &H2RequestData{
			Method:    "POST",
			Authority: "api.example.com",
			Path:      "/v1/data",
			Headers: []Header{
				{Name: "content-type", Value: "application/json"},
			},
		},
		H2Response: &H2ResponseData{
			StatusCode: 201,
			Headers: []Header{
				{Name: "location", Value: "/v1/data/123"},
			},
		},
	}

	assert.Equal(t, "POST", entry.GetMethod())
	assert.Equal(t, "/v1/data", entry.GetPath())
	assert.Equal(t, "api.example.com", entry.GetHost())
	assert.Equal(t, 201, entry.GetStatusCode())
	assert.Equal(t, "application/json", entry.GetRequestHeader("content-type"))
	assert.Equal(t, "/v1/data/123", entry.GetResponseHeader("location"))
}

func TestHistoryEntry_GetMethods_HTTP1(t *testing.T) {
	t.Parallel()

	entry := &HistoryEntry{
		Protocol: "http/1.1",
		Request: &RawHTTP1Request{
			Method: "GET",
			Path:   "/index.html",
			Headers: []Header{
				{Name: "Host", Value: "www.example.com"},
				{Name: "Accept", Value: "text/html"},
			},
		},
		Response: &RawHTTP1Response{
			StatusCode: 200,
			Headers: []Header{
				{Name: "Content-Type", Value: "text/html"},
			},
		},
	}

	assert.Equal(t, "GET", entry.GetMethod())
	assert.Equal(t, "/index.html", entry.GetPath())
	assert.Equal(t, "www.example.com", entry.GetHost())
	assert.Equal(t, 200, entry.GetStatusCode())
	assert.Equal(t, "text/html", entry.GetRequestHeader("accept"))
	assert.Equal(t, "text/html", entry.GetResponseHeader("content-type"))
}

func TestHistoryEntry_FormatRequest_NilData(t *testing.T) {
	t.Parallel()

	// H2 entry with nil H2Request
	entry := &HistoryEntry{
		Protocol: "h2",
	}
	assert.Nil(t, entry.FormatRequest())

	// HTTP/1.1 entry with nil Request
	entry2 := &HistoryEntry{
		Protocol: "http/1.1",
	}
	assert.Nil(t, entry2.FormatRequest())
}

func TestHistoryEntry_FormatResponse_NilData(t *testing.T) {
	t.Parallel()

	// H2 entry with nil H2Response
	entry := &HistoryEntry{
		Protocol: "h2",
	}
	assert.Nil(t, entry.FormatResponse())

	// HTTP/1.1 entry with nil Response
	entry2 := &HistoryEntry{
		Protocol: "http/1.1",
	}
	assert.Nil(t, entry2.FormatResponse())
}

// h2MockRuleApplier is a mock implementation for testing
type h2MockRuleApplier struct {
	hasReqBodyRules  bool
	hasRespBodyRules bool
	reqHeaderMod     func([]Header) []Header
	respHeaderMod    func([]Header) []Header
	reqBodyMod       func([]byte) []byte
	respBodyMod      func([]byte) []byte
}

func (m *h2MockRuleApplier) ApplyRequestRules(req *RawHTTP1Request) *RawHTTP1Request {
	if m.reqHeaderMod != nil {
		req.Headers = m.reqHeaderMod(req.Headers)
	}
	if m.reqBodyMod != nil {
		req.Body = m.reqBodyMod(req.Body)
	}
	return req
}

func (m *h2MockRuleApplier) ApplyResponseRules(resp *RawHTTP1Response) *RawHTTP1Response {
	if m.respHeaderMod != nil {
		resp.Headers = m.respHeaderMod(resp.Headers)
	}
	if m.respBodyMod != nil {
		resp.Body = m.respBodyMod(resp.Body)
	}
	return resp
}

func (m *h2MockRuleApplier) ApplyWSRules(payload []byte, direction string) []byte {
	return payload
}

func (m *h2MockRuleApplier) HasBodyRules(isRequest bool) bool {
	if isRequest {
		return m.hasReqBodyRules
	}
	return m.hasRespBodyRules
}

func (m *h2MockRuleApplier) ApplyRequestBodyOnlyRules(body []byte) []byte {
	if m.reqBodyMod != nil {
		return m.reqBodyMod(body)
	}
	return body
}

func (m *h2MockRuleApplier) ApplyResponseBodyOnlyRules(body []byte, headers []Header) []byte {
	if m.respBodyMod != nil {
		return m.respBodyMod(body)
	}
	return body
}

func TestApplyBodyRules_RequestWithHeaders(t *testing.T) {
	t.Parallel()

	history := NewHistoryStore(store.NewMemStorage())
	handler := NewHTTP2Handler(history, 1024)

	// Set up rule applier that modifies body
	applier := &h2MockRuleApplier{
		reqBodyMod: func(body []byte) []byte {
			return append(body, []byte("-modified")...)
		},
	}
	handler.SetRuleApplier(applier)

	// Create a proxy with the handler
	stream := &h2Stream{
		id:         1,
		method:     "POST",
		path:       "/test",
		reqHeaders: []Header{{Name: "content-type", Value: "text/plain"}},
	}
	stream.reqBodyFull.WriteString("hello")

	// Create a minimal proxy for testing
	p := &h2Proxy{handler: handler}

	// Apply body rules
	result := p.applyBodyRules(stream, stream.reqBodyFull.Bytes(), true)
	assert.Equal(t, "hello-modified", string(result))
}

func TestApplyBodyRules_ResponseUsesBodyOnlyMethod(t *testing.T) {
	t.Parallel()

	history := NewHistoryStore(store.NewMemStorage())
	handler := NewHTTP2Handler(history, 1024)

	// Track whether the body-only method or full method is called
	var bodyOnlyCalled bool
	var fullMethodCalled bool
	applier := &h2MockRuleApplier{
		respBodyMod: func(body []byte) []byte {
			// This is called by ApplyResponseBodyOnlyRules
			bodyOnlyCalled = true
			return append(body, []byte("-modified")...)
		},
		respHeaderMod: func(headers []Header) []Header {
			// This would be called by ApplyResponseRules (should NOT be called)
			fullMethodCalled = true
			return headers
		},
	}
	handler.SetRuleApplier(applier)

	stream := &h2Stream{
		id:          1,
		statusCode:  200,
		respHeaders: []Header{{Name: "content-type", Value: "text/plain"}},
	}
	stream.respBodyFull.WriteString("test body")

	p := &h2Proxy{handler: handler}

	// Apply body rules
	result := p.applyBodyRules(stream, stream.respBodyFull.Bytes(), false)

	// Body should be modified via the body-only method
	assert.Equal(t, "test body-modified", string(result))

	// IMPORTANT: We now use ApplyResponseBodyOnlyRules which only applies body rules.
	// This ensures header rules aren't re-applied (they were already applied in processHeaders).
	// The body-only method should be called, not the full ApplyResponseRules method.
	assert.True(t, bodyOnlyCalled, "body-only rule application should be used")
	assert.False(t, fullMethodCalled, "full rule application (with header rules) should NOT be called")
}

func TestCopyToHistoryBuffer_RespectLimit(t *testing.T) {
	t.Parallel()

	history := NewHistoryStore(store.NewMemStorage())
	handler := NewHTTP2Handler(history, 10) // 10 byte limit

	stream := &h2Stream{id: 1}
	p := &h2Proxy{handler: handler}

	// Write 15 bytes
	p.copyToHistoryBuffer(stream, []byte("hello"), true)
	p.copyToHistoryBuffer(stream, []byte("worldextra"), true)

	// Should be limited to 10 bytes
	assert.Equal(t, 10, stream.reqBody.Len())
	assert.Equal(t, "helloworld", stream.reqBody.String())
}

func TestCopyToFullBuffer_NoOverflow(t *testing.T) {
	t.Parallel()

	history := NewHistoryStore(store.NewMemStorage())
	handler := NewHTTP2Handler(history, 1024)

	stream := &h2Stream{id: 1}
	p := &h2Proxy{handler: handler}

	// Write small amount - no overflow
	overflow := p.copyToFullBuffer(stream, []byte("hello"), true)
	assert.False(t, overflow)
	assert.False(t, stream.reqBodyOverflow)
	assert.Equal(t, "hello", stream.reqBodyFull.String())
}

func TestCopyToFullBuffer_Overflow(t *testing.T) {
	t.Parallel()

	history := NewHistoryStore(store.NewMemStorage())
	handler := NewHTTP2Handler(history, 1024)

	stream := &h2Stream{id: 1}
	p := &h2Proxy{handler: handler}

	// Verify the overflow flag mechanism (maxBodyBytes = 1024 for this test)
	stream.reqBodyOverflow = true // simulate already overflowed

	overflow := p.copyToFullBuffer(stream, []byte("more data"), true)
	assert.True(t, overflow)
}

func TestUpdateHistoryWithModifiedBody(t *testing.T) {
	t.Parallel()

	history := NewHistoryStore(store.NewMemStorage())
	handler := NewHTTP2Handler(history, 5) // 5 byte limit

	stream := &h2Stream{id: 1}
	stream.reqBody.WriteString("original")

	p := &h2Proxy{handler: handler}

	// Update with body larger than limit
	p.updateHistoryWithModifiedBody(stream, []byte("new body content"), true)

	// Should be truncated to limit
	assert.Equal(t, 5, stream.reqBody.Len())
	assert.Equal(t, "new b", stream.reqBody.String())
}

func TestStoreStreamInHistory(t *testing.T) {
	t.Parallel()

	history := NewHistoryStore(store.NewMemStorage())
	handler := NewHTTP2Handler(history, 1024)

	stream := &h2Stream{
		id:          1,
		state:       streamClosed,
		method:      "GET",
		scheme:      "https",
		authority:   "test.example.com",
		path:        "/api/v1",
		statusCode:  200,
		startTime:   time.Now().Add(-100 * time.Millisecond),
		reqHeaders:  []Header{{Name: "user-agent", Value: "test"}},
		respHeaders: []Header{{Name: "content-type", Value: "application/json"}},
	}
	stream.reqBody.WriteString("request body")
	stream.respBody.WriteString(`{"ok": true}`)

	p := &h2Proxy{
		handler: handler,
		streams: newStreamTracker(),
	}

	p.storeStreamInHistory(stream)

	// Verify entry was stored
	assert.Equal(t, 1, history.Count())

	entry, ok := history.Get(0)
	require.True(t, ok)
	assert.Equal(t, "h2", entry.Protocol)
	assert.Equal(t, uint32(1), entry.H2StreamID)
	require.NotNil(t, entry.H2Request)
	assert.Equal(t, "GET", entry.H2Request.Method)
	assert.Equal(t, "https", entry.H2Request.Scheme)
	assert.Equal(t, "test.example.com", entry.H2Request.Authority)
	assert.Equal(t, "/api/v1", entry.H2Request.Path)
	assert.Equal(t, "request body", string(entry.H2Request.Body))
	require.NotNil(t, entry.H2Response)
	assert.Equal(t, 200, entry.H2Response.StatusCode)
	assert.Equal(t, `{"ok": true}`, string(entry.H2Response.Body))
}

func TestH2Conn_FlowControl_ConsumeWindow(t *testing.T) {
	t.Parallel()

	// Create a mock connection - we only need the flow control logic
	h := &h2Conn{
		initialWindowSize: 65535,
		recvWindowConn:    65535,
		recvWindowStream:  make(map[uint32]int32),
	}

	// Consume some data on stream 1
	err := h.consumeRecvWindow(1, 1000)
	require.NoError(t, err)
	assert.Equal(t, int32(65535-1000), h.recvWindowConn)
	assert.Equal(t, int32(65535-1000), h.recvWindowStream[1])

	// Consume more
	err = h.consumeRecvWindow(1, 2000)
	require.NoError(t, err)
	assert.Equal(t, int32(65535-3000), h.recvWindowConn)
}

func TestH2Conn_FlowControl_ConsumeWindow_Violation(t *testing.T) {
	t.Parallel()

	t.Run("connection_level_violation", func(t *testing.T) {
		h := &h2Conn{
			initialWindowSize: 65535,
			recvWindowConn:    1000, // small window
			recvWindowStream:  make(map[uint32]int32),
		}

		// Try to consume more than connection window allows
		err := h.consumeRecvWindow(1, 2000)
		require.Error(t, err)

		var fcErr *FlowControlError
		require.ErrorAs(t, err, &fcErr)
		assert.Equal(t, uint32(0), fcErr.StreamID) // 0 indicates connection-level

		// Window should not have changed
		assert.Equal(t, int32(1000), h.recvWindowConn)
	})

	t.Run("stream_level_violation", func(t *testing.T) {
		h := &h2Conn{
			initialWindowSize: 65535,
			recvWindowConn:    65535,
			recvWindowStream:  map[uint32]int32{1: 500}, // small stream window
		}

		// Try to consume more than stream window allows
		err := h.consumeRecvWindow(1, 1000)
		require.Error(t, err)

		var fcErr *FlowControlError
		require.ErrorAs(t, err, &fcErr)
		assert.Equal(t, uint32(1), fcErr.StreamID)

		// Windows should not have changed
		assert.Equal(t, int32(65535), h.recvWindowConn)
		assert.Equal(t, int32(500), h.recvWindowStream[1])
	})
}

func TestH2Conn_FlowControl_NeedsWindowUpdate(t *testing.T) {
	t.Parallel()

	h := &h2Conn{
		initialWindowSize: 65535,
		recvWindowConn:    65535,
		recvWindowStream:  make(map[uint32]int32),
	}

	// Initially no update needed
	connUp, streamUp := h.needsWindowUpdate(1)
	assert.Equal(t, uint32(0), connUp)
	assert.Equal(t, uint32(0), streamUp)

	// Consume enough to trigger update (below 50% threshold)
	_ = h.consumeRecvWindow(1, 40000)

	connUp, streamUp = h.needsWindowUpdate(1)
	assert.Positive(t, connUp)
	assert.Positive(t, streamUp)

	// Window should be replenished after needsWindowUpdate
	assert.Equal(t, int32(65535), h.recvWindowConn)
	assert.Equal(t, int32(65535), h.recvWindowStream[1])
}

func TestH2Conn_FlowControl_RemoveStream(t *testing.T) {
	t.Parallel()

	h := &h2Conn{
		initialWindowSize: 65535,
		recvWindowConn:    65535,
		recvWindowStream:  make(map[uint32]int32),
	}

	// Create some stream windows
	_ = h.consumeRecvWindow(1, 1000)
	_ = h.consumeRecvWindow(3, 500)
	assert.Len(t, h.recvWindowStream, 2)

	// Remove stream 1
	h.removeStreamWindow(1)
	assert.Len(t, h.recvWindowStream, 1)
	_, ok := h.recvWindowStream[1]
	assert.False(t, ok)
	_, ok = h.recvWindowStream[3]
	assert.True(t, ok)
}

func TestH2Conn_Close_OnlyOnce(t *testing.T) {
	t.Parallel()

	h := &h2Conn{
		closeCh: make(chan struct{}),
	}

	// Close should work
	h.close()
	select {
	case <-h.closeCh:
		// expected
	default:
		t.Fatal("closeCh should be closed")
	}

	// Close again should not panic
	h.close()
}

func TestH2Conn_EnqueueWrite_AfterClose(t *testing.T) {
	t.Parallel()

	h := &h2Conn{
		writeCh: make(chan []byte), // unbuffered channel
		closeCh: make(chan struct{}),
	}

	// Close the connection
	h.close()

	// With unbuffered channel and closed closeCh, enqueueWrite should
	// return false (can't write to unbuffered channel, so picks closeCh)
	ok := h.enqueueWrite(context.Background(), []byte("test"))
	assert.False(t, ok)
}

func TestH2Conn_FlowCtrlWait_SignaledOnUpdate(t *testing.T) {
	t.Parallel()

	h := &h2Conn{
		initialWindowSize: 65535,
		sendWindowConn:    0, // blocked
		sendWindowStream:  make(map[uint32]int32),
		flowCtrlCh:        make(chan struct{}),
	}

	// Get the wait channel
	waitCh := h.flowCtrlWait()

	// Channel should be open (not signaled yet)
	select {
	case <-waitCh:
		t.Fatal("channel should not be closed yet")
	default:
		// expected
	}

	// Update send window - this should signal waiters
	h.updateSendWindow(0, 1000)

	// Channel should now be closed (signaled)
	select {
	case <-waitCh:
		// expected - channel was closed
	default:
		t.Fatal("channel should be closed after updateSendWindow")
	}

	// New wait channel should be open
	waitCh2 := h.flowCtrlWait()
	select {
	case <-waitCh2:
		t.Fatal("new channel should not be closed")
	default:
		// expected
	}
}

func TestH2Conn_FlowCtrlWait_SignaledOnSettingsIncrease(t *testing.T) {
	t.Parallel()

	h := &h2Conn{
		initialWindowSize: 65535,
		sendWindowConn:    65535,
		sendWindowStream:  make(map[uint32]int32),
		flowCtrlCh:        make(chan struct{}),
	}

	// Create a stream window
	h.initStreamSendWindow(1)

	// Get the wait channel
	waitCh := h.flowCtrlWait()

	// Increase window via settings
	h.updateSendWindowFromSettings(131070)

	// Channel should be signaled
	select {
	case <-waitCh:
		// expected
	default:
		t.Fatal("channel should be closed after settings increase")
	}
}

func TestH2Conn_FlowCtrlWait_NotSignaledOnSettingsDecrease(t *testing.T) {
	t.Parallel()

	h := &h2Conn{
		initialWindowSize: 65535,
		sendWindowConn:    65535,
		sendWindowStream:  make(map[uint32]int32),
		flowCtrlCh:        make(chan struct{}),
	}

	// Create a stream window
	h.initStreamSendWindow(1)

	// Get the wait channel
	waitCh := h.flowCtrlWait()

	// Decrease window via settings
	h.updateSendWindowFromSettings(32768)

	// Channel should NOT be signaled (no point waking waiters if window decreased)
	select {
	case <-waitCh:
		t.Fatal("channel should not be closed on settings decrease")
	default:
		// expected
	}
}

func TestHTTP2Proxy_EndToEnd(t *testing.T) {
	t.Parallel()

	// Start HTTP/2 test server
	testServer := newHTTP2TestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Protocol", r.Proto)
		w.Header().Set("X-Test-Header", "h2-success")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("Hello from HTTP/2 server"))
	})
	t.Cleanup(testServer.Close)

	// Start proxy
	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024)
	require.NoError(t, err)
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Shutdown(t.Context()) })

	// Create CA cert pool with proxy's CA
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(proxy.CertManager().CACert())

	// Create HTTP client with proxy and HTTP/2 enabled
	transport := &http.Transport{
		Proxy: http.ProxyURL(mustParseURL(t, "http://"+proxy.Addr())),
		TLSClientConfig: &tls.Config{
			RootCAs:            caCertPool,
			InsecureSkipVerify: true, // test server uses self-signed cert
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Transport: transport}

	// Make HTTPS request through proxy
	resp, err := client.Get(testServer.URL + "/test")
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "h2-success", resp.Header.Get("X-Test-Header"))
	assert.Equal(t, "Hello from HTTP/2 server", string(body))

	// Client should have used HTTP/2
	assert.Equal(t, 2, resp.ProtoMajor)

	// Wait for history to be stored and verify HTTP/2 entry
	time.Sleep(100 * time.Millisecond)
	require.GreaterOrEqual(t, proxy.History().Count(), 1)

	entry, ok := proxy.History().Get(0)
	require.True(t, ok)
	assert.Equal(t, "h2", entry.Protocol)
	require.NotNil(t, entry.H2Request)
	assert.Equal(t, "GET", entry.H2Request.Method)
	assert.Contains(t, entry.H2Request.Path, "/test")
	require.NotNil(t, entry.H2Response)
	assert.Equal(t, 200, entry.H2Response.StatusCode)
	assert.Contains(t, string(entry.H2Response.Body), "Hello from HTTP/2 server")
}

func TestHTTP2Proxy_HeaderRules(t *testing.T) {
	t.Parallel()

	// Test server that echoes a header
	var receivedHeader string
	testServer := newHTTP2TestServer(t, func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-Injected")
		w.WriteHeader(200)
	})
	t.Cleanup(testServer.Close)

	// Start proxy
	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024)
	require.NoError(t, err)
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Shutdown(t.Context()) })

	// Set up rule applier that adds a header
	applier := &h2MockRuleApplier{
		reqHeaderMod: func(headers []Header) []Header {
			return append(headers, Header{Name: "x-injected", Value: "rule-applied"})
		},
	}
	proxy.SetRuleApplier(applier)

	// Create client with proxy
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(proxy.CertManager().CACert())

	transport := &http.Transport{
		Proxy: http.ProxyURL(mustParseURL(t, "http://"+proxy.Addr())),
		TLSClientConfig: &tls.Config{
			RootCAs:            caCertPool,
			InsecureSkipVerify: true,
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Transport: transport}

	// Make request
	resp, err := client.Get(testServer.URL + "/test")
	require.NoError(t, err)
	_ = resp.Body.Close()

	// Verify rule was applied - server received the injected header
	assert.Equal(t, "rule-applied", receivedHeader)

	// Verify HTTP/2 was used
	assert.Equal(t, 2, resp.ProtoMajor)
}

// newHTTP2TestServer creates an HTTP/2-enabled test server
func newHTTP2TestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()

	server := httptest.NewUnstartedServer(handler)

	// Enable HTTP/2 via TLS ALPN
	server.TLS = &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
	}
	server.StartTLS()

	return server
}
