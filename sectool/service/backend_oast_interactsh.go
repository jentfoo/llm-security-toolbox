package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-analyze/bulk"
	"github.com/go-appsec/interactsh-lite/oobclient"

	"github.com/go-appsec/toolbox/sectool/service/ids"
)

const (
	// interactshPollInterval is how often the interactsh client polls the server.
	interactshPollInterval = 4 * time.Second
	// clientCloseTimeout is how long to wait when closing clients.
	clientCloseTimeout = 10 * time.Second
	// clientCleanupInterval is how often to check for idle clients with no active sessions.
	clientCleanupInterval = 120 * time.Second
	// maxLabelPrefixLen is the maximum label length to use as a domain prefix.
	maxLabelPrefixLen = 16
	// correlationIdNonceLength is the per-URL nonce length passed to the interactsh client.
	correlationIdNonceLength = 8
)

// dnsLabelRe matches a valid DNS label: alphanumeric with at most one interior hyphen.
var dnsLabelRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)?$`)

// structuredDomainSuffixes are server hosts that support the structured
// domain format (correlationID.sessionID.serverHost).
var structuredDomainSuffixes = [...]string{"oastsrv.net", "oastlab.net"}

// isInteractLiteHost reports whether the server host uses the structured domain format.
func isInteractLiteHost(serverHost string) bool {
	return slices.ContainsFunc(structuredDomainSuffixes[:], func(suffix string) bool {
		return serverHost == suffix || strings.HasSuffix(serverHost, "."+suffix)
	})
}

// InteractshBackend implements OastBackend using Interactsh.
type InteractshBackend struct {
	serverURL         string       // custom server URL, empty = use defaults
	redirectSupported bool         // whether the server supports redirect responses
	httpClient        *http.Client // shared HTTP client for all oobclient instances and probes
	mu                sync.RWMutex
	sessions          map[string]*oastSession // by domain (canonical key)
	byID              map[string]string       // short ID -> domain
	byLabel           map[string]string       // label -> domain (only non-empty labels)
	byNonce           map[string]string       // nonce -> domain (legacy server routing only)
	closed            bool

	// Clients keyed by redirect target ("" = default/no-redirect), lazily created.
	clients map[string]*oobclient.Client
	initMu  sync.Mutex // guards lazy client creation
}

// Compile-time check that InteractshBackend implements OastBackend
var _ OastBackend = (*InteractshBackend)(nil)

// oastSession holds the state for a single OAST session.
type oastSession struct {
	info  OastSessionInfo
	nonce string // nonce from Domain(), only set for legacy server sessions

	mu           sync.Mutex
	notify       chan struct{} // closed when new events arrive, then replaced
	events       []OastEventInfo
	droppedCount int
	lastPollIdx  int // Index after last poll (for "last" filter)

	stopped bool
}

// NewInteractshBackend creates a new Interactsh-backed OastBackend.
func NewInteractshBackend(serverURL string) *InteractshBackend {
	return &InteractshBackend{
		serverURL: serverURL,
		httpClient: &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: 10 * time.Second,
		},
		sessions: make(map[string]*oastSession),
		byID:     make(map[string]string),
		byLabel:  make(map[string]string),
		byNonce:  make(map[string]string),
		clients:  make(map[string]*oobclient.Client),
	}
}

// Start probes the server for capabilities and starts background maintenance.
// Must be called before creating sessions. Pair with Close() for cleanup.
func (b *InteractshBackend) Start(ctx context.Context) {
	b.ProbeRedirectSupport(ctx)
	go func() {
		ticker := time.NewTicker(clientCleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			b.mu.Lock()
			if b.closed {
				b.mu.Unlock()
				return
			}
			stale := b.cleanupIdleClients()
			b.mu.Unlock()
			for _, c := range stale {
				if err := c.Close(); err != nil {
					log.Printf("oast: error closing idle client: %v", err)
				}
			}
			if len(stale) > 0 {
				log.Printf("oast: cleaned up %d idle client(s)", len(stale))
			}
		}
	}()
}

// SupportsRedirect reports whether the OAST server supports redirect responses.
func (b *InteractshBackend) SupportsRedirect() bool {
	return b.redirectSupported
}

// ProbeRedirectSupport determines whether the OAST server supports redirect responses.
// Default and known interactsh-lite servers are assumed compatible.
// Custom servers are probed by registering with a 307 ResponseConfig and verifying the response.
func (b *InteractshBackend) ProbeRedirectSupport(ctx context.Context) {
	if b.serverURL == "" || isInteractLiteHost(b.serverURL) {
		b.redirectSupported = true
		return
	}

	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	c, err := oobclient.New(probeCtx, oobclient.Options{
		ServerURLs: []string{b.serverURL},
		HTTPClient: b.httpClient,
		Response: &oobclient.ResponseConfig{
			StatusCode: 307,
			Headers:    []string{"Location: " + b.serverURL},
		},
	})
	if err != nil {
		log.Printf("oast: redirect probe failed (registration): %v", err)
		return
	}
	defer func() { _ = c.Close() }()

	resp, err := b.httpClient.Get("http://" + c.Domain())
	if err != nil {
		log.Printf("oast: redirect probe failed (request): %v", err)
		return
	}
	_ = resp.Body.Close()

	b.redirectSupported = resp.StatusCode == http.StatusTemporaryRedirect
	log.Printf("oast: redirect probe for %s: supported=%v", b.serverURL, b.redirectSupported)
}

// ensureClientForRedirectTarget lazily creates an oobclient.Client for the given redirect target.
// An empty redirectTarget returns the default (no-redirect) client.
func (b *InteractshBackend) ensureClientForRedirectTarget(ctx context.Context, redirectTarget string) (*oobclient.Client, error) {
	b.mu.RLock()
	if c, ok := b.clients[redirectTarget]; ok {
		b.mu.RUnlock()
		return c, nil
	}
	b.mu.RUnlock()

	b.initMu.Lock()
	defer b.initMu.Unlock()

	b.mu.RLock()
	if c, ok := b.clients[redirectTarget]; ok {
		b.mu.RUnlock()
		return c, nil
	}
	closed := b.closed
	b.mu.RUnlock()
	if closed {
		return nil, errors.New("backend is closed")
	}

	opts := oobclient.Options{HTTPClient: b.httpClient}
	if b.serverURL != "" {
		opts.ServerURLs = []string{b.serverURL}
	} else {
		// Shorter nonce for structured domains;
		// oobclient bumps this automatically if it falls back to oast.* servers.
		opts.CorrelationIdNonceLength = correlationIdNonceLength
	}
	if redirectTarget != "" {
		opts.Response = &oobclient.ResponseConfig{
			StatusCode: 307,
			Headers:    []string{"Location: " + redirectTarget},
		}
	}

	c, err := oobclient.New(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create interactsh client: %w", err)
	}

	if err := c.StartPolling(interactshPollInterval, b.makeInteractionHandler(c.CorrelationID(), c.ServerHost())); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("oast failed to start polling: %w", err)
	}

	b.mu.Lock()
	b.clients[redirectTarget] = c
	b.mu.Unlock()

	log.Printf("oast: client created and polling (redirect=%q)", redirectTarget)
	return c, nil
}

// buildStructuredOASTDomain constructs a structured OAST domain from its parts.
// Format: correlationID.sessionID.serverHost or correlationID.label.sessionID.serverHost.
func buildStructuredOASTDomain(correlationID, label, sessionID, serverHost string) string {
	if label != "" && len(label) <= maxLabelPrefixLen {
		if lower := strings.ToLower(label); dnsLabelRe.MatchString(lower) {
			return correlationID + "." + lower + "." + sessionID + "." + serverHost
		}
	}
	return correlationID + "." + sessionID + "." + serverHost
}

// extractNonce extracts the per-domain nonce from an interactsh domain.
// Domain format: correlationID + nonce + "." + serverHost.
func extractNonce(domain, correlationID string) string {
	dotIdx := strings.IndexByte(domain, '.')
	if dotIdx < 0 || dotIdx <= len(correlationID) {
		panic(fmt.Sprintf("BUG: unexpected domain format from interactsh: %q (correlationID=%q)", domain, correlationID))
	}
	return domain[len(correlationID):dotIdx]
}

// makeInteractionHandler returns a polling callback bound to a specific client's identity.
// Each client has its own correlationID, so the closure captures it for routing.
//
// Structured servers (oastsrv.net, oastlab.net): FullId is dot-separated
// ("correlationID.sessionID"), last label is the sessionID routing key.
//
// Legacy servers: FullId leaf label is correlationID+nonce concatenated
// ("correlationIDnonce" or "label.correlationIDnonce").
func (b *InteractshBackend) makeInteractionHandler(correlationID, serverHost string) func(*oobclient.Interaction) {
	structured := isInteractLiteHost(serverHost)

	return func(interaction *oobclient.Interaction) {
		fullId := interaction.FullId

		var domain string
		var ok bool

		b.mu.RLock()

		if structured {
			// Structured server: last dot-label = sessionID
			lastDot := strings.LastIndexByte(fullId, '.')
			if lastDot < 0 {
				b.mu.RUnlock()
				return
			}
			nonce := fullId[lastDot+1:]
			domain, ok = b.byID[nonce]
		} else {
			// Legacy server: leaf label = correlationID + nonce
			leaf := fullId
			if dotIdx := strings.LastIndexByte(leaf, '.'); dotIdx >= 0 {
				leaf = leaf[dotIdx+1:]
			}
			if !strings.HasPrefix(leaf, correlationID) || len(leaf) <= len(correlationID) {
				b.mu.RUnlock()
				return
			}
			nonce := leaf[len(correlationID):]
			domain, ok = b.byNonce[nonce]
		}

		if !ok {
			b.mu.RUnlock()
			return
		}
		sess := b.sessions[domain]
		b.mu.RUnlock()

		sess.mu.Lock()
		defer sess.mu.Unlock()

		if sess.stopped {
			return
		}

		details := make(map[string]interface{}, 4)
		eventType := strings.ToLower(interaction.Protocol)
		switch eventType {
		case "dns":
			if interaction.QType != "" {
				details["query_type"] = interaction.QType
			}
		case schemeHTTP, schemeHTTPS, "smtp":
			if interaction.SMTPFrom != "" {
				details["smtp_from"] = interaction.SMTPFrom
			}
			if interaction.SMTPTo != "" {
				details["smtp_to"] = interaction.SMTPTo
			}
			if interaction.RawRequest != "" {
				h, b := splitHeadersBody([]byte(interaction.RawRequest))
				details["headers"] = string(bytes.TrimRight(h, "\r\n"))
				if len(b) > 0 {
					details["body"] = string(b)
				}
			}
		default:
			// Uncommon protocols (ftp, ldap, smb, responder): keep raw
			if interaction.RawRequest != "" {
				details["raw_request"] = interaction.RawRequest
			}
		}

		if len(sess.events) >= MaxOastEventsPerSession {
			sess.events = sess.events[1:]
			sess.droppedCount++
			if sess.lastPollIdx > 0 {
				sess.lastPollIdx--
			}
		}
		event := OastEventInfo{
			ID:        ids.Generate(ids.DefaultLength),
			Time:      interaction.Timestamp,
			Type:      eventType,
			SourceIP:  interaction.RemoteAddress,
			Subdomain: interaction.FullId,
			Details:   details,
		}
		sess.events = append(sess.events, event)

		close(sess.notify)
		sess.notify = make(chan struct{})

		log.Printf("oast: session %s received %s event from %s", sess.info.ID, event.Type, event.SourceIP)
	}
}

func (b *InteractshBackend) CreateSession(ctx context.Context, label, redirectTarget string) (*OastSessionInfo, error) {
	if redirectTarget != "" && !b.redirectSupported {
		return nil, errors.New("OAST server does not support redirect responses")
	}

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, errors.New("backend is closed")
	}
	// Check label uniqueness before potentially slow client init
	if label != "" {
		if existingDomain, exists := b.byLabel[label]; exists {
			existingSess := b.sessions[existingDomain]
			b.mu.Unlock()
			return nil, fmt.Errorf("%w: %q already in use by session %s; delete it first",
				ErrLabelExists, label, existingSess.info.ID)
		}
	}
	b.mu.Unlock()

	c, err := b.ensureClientForRedirectTarget(ctx, redirectTarget)
	if err != nil {
		return nil, err
	}

	structured := isInteractLiteHost(c.ServerHost())

	// For legacy servers, generate the base domain outside the lock (c.Domain() uses crypto/rand).
	var legacyBaseDomain, nonce string
	if !structured {
		legacyBaseDomain = c.Domain()
		nonce = extractNonce(legacyBaseDomain, c.CorrelationID())
	}

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, errors.New("backend is closed")
	}

	// Re-check label uniqueness in case of race
	if label != "" {
		if existingDomain, exists := b.byLabel[label]; exists {
			existingSess := b.sessions[existingDomain]
			b.mu.Unlock()
			return nil, fmt.Errorf("%w: %q already in use by session %s; delete it first",
				ErrLabelExists, label, existingSess.info.ID)
		}
	}

	// Generate unique session ID, then build domain once with the final value
	var sessionID, domain string
	if structured {
		sessionID = strings.ToLower(ids.Generate(ids.EntityLength))
		for b.byID[sessionID] != "" {
			sessionID = strings.ToLower(ids.Generate(ids.EntityLength))
		}
		domain = buildStructuredOASTDomain(c.CorrelationID(), label, sessionID, c.ServerHost())
	} else {
		sessionID = ids.Generate(ids.EntityLength)
		for b.byID[sessionID] != "" {
			sessionID = ids.Generate(ids.EntityLength)
		}
		domain = legacyBaseDomain
		if label != "" && len(label) <= maxLabelPrefixLen {
			if lower := strings.ToLower(label); dnsLabelRe.MatchString(lower) {
				domain = lower + "." + domain
			}
		}
	}

	sess := &oastSession{
		info: OastSessionInfo{
			ID:             sessionID,
			Domain:         domain,
			Label:          label,
			RedirectTarget: redirectTarget,
			CreatedAt:      time.Now(),
		},
		nonce:  nonce,
		notify: make(chan struct{}),
	}

	b.sessions[domain] = sess
	b.byID[sessionID] = domain
	if nonce != "" {
		b.byNonce[nonce] = domain
	}
	if label != "" {
		b.byLabel[label] = domain
	}
	b.mu.Unlock()

	return &sess.info, nil
}

func (b *InteractshBackend) PollSession(ctx context.Context, idOrDomain string, since string, eventType string, wait time.Duration, limit int) (*OastPollResultInfo, error) {
	sess, err := b.resolveSession(idOrDomain)
	if err != nil {
		return nil, err
	}

	deadline := time.Now().Add(wait)

	for {
		sess.mu.Lock()
		if sess.stopped {
			sess.mu.Unlock()
			return nil, errors.New("session has been deleted")
		}

		events := sess.filterEvents(since, eventType)
		if len(events) > 0 || wait == 0 || time.Now().After(deadline) || ctx.Err() != nil {
			if limit > 0 && len(events) > limit {
				events = events[:limit]
			}
			sess.updateLastPollIdx(events)
			result := &OastPollResultInfo{
				Events:       events,
				DroppedCount: sess.droppedCount,
			}
			sess.mu.Unlock()
			return result, nil
		}

		notify := sess.notify // capture before unlocking
		sess.mu.Unlock()

		select {
		case <-notify: // channel closed = new events or session stopped
		case <-ctx.Done():
		case <-time.After(time.Until(deadline)):
		}
	}
}

// filterEvents returns events based on the since and eventType filters.
// Caller must hold s.mu until result slice is discarded.
func (s *oastSession) filterEvents(since, eventType string) []OastEventInfo {
	var events []OastEventInfo
	switch since {
	case "":
		events = s.events
	case sinceLast:
		if s.lastPollIdx >= len(s.events) {
			events = nil
		} else {
			events = s.events[s.lastPollIdx:]
		}
	default:
		// Try parsing as timestamp first
		if sinceTime, ok := parseSinceTimestamp(since); ok {
			events = bulk.SliceFilter(func(e OastEventInfo) bool {
				return e.Time.After(sinceTime)
			}, s.events)
		} else {
			// Find event by ID and return everything after it
			var found bool
			for i, e := range s.events {
				if e.ID == since {
					if i+1 >= len(s.events) {
						events = nil
					} else {
						events = s.events[i+1:]
					}
					found = true
					break
				}
			}
			if !found {
				events = s.events
			}
		}
	}

	if eventType == "" || len(events) == 0 {
		return events
	}

	return bulk.SliceFilter(func(e OastEventInfo) bool {
		return matchesEventType(e.Type, eventType)
	}, events)
}

// matchesEventType reports whether an event type matches the filter.
// "http" and "https" are treated as equivalent since agents typically want both.
func matchesEventType(eventType, filter string) bool {
	if eventType == filter {
		return true
	}
	return (eventType == "http" || eventType == "https") && (filter == "http" || filter == "https")
}

// updateLastPollIdx updates lastPollIdx based on returned events (for --since last tracking).
// Caller must hold s.mu.
func (s *oastSession) updateLastPollIdx(returnedEvents []OastEventInfo) {
	if len(returnedEvents) == 0 {
		return
	}
	// Find the index of the last returned event in s.events
	lastEventID := returnedEvents[len(returnedEvents)-1].ID
	for i, e := range s.events {
		if e.ID == lastEventID {
			s.lastPollIdx = i + 1
			return
		}
	}
	// Fallback: if not found, use len(events)
	s.lastPollIdx = len(s.events)
}

func (b *InteractshBackend) GetEvent(_ context.Context, eventID string) (*OastEventInfo, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, sess := range b.sessions {
		sess.mu.Lock()
		if sess.stopped {
			sess.mu.Unlock()
			continue
		}
		for _, e := range sess.events {
			if e.ID == eventID {
				eventCopy := e
				sess.mu.Unlock()
				return &eventCopy, nil
			}
		}
		sess.mu.Unlock()
	}

	return nil, fmt.Errorf("%w: event %s", ErrNotFound, eventID)
}

func (b *InteractshBackend) ListSessions(ctx context.Context) ([]OastSessionInfo, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	sessions := make([]OastSessionInfo, 0, len(b.sessions))
	for _, sess := range b.sessions {
		sessions = append(sessions, sess.info)
	}
	return sessions, nil
}

func (b *InteractshBackend) DeleteSession(ctx context.Context, idOrDomain string) error {
	sess, err := b.resolveSession(idOrDomain)
	if err != nil {
		return err
	}

	return b.deleteSession(sess)
}

func (b *InteractshBackend) deleteSession(sess *oastSession) error {
	sess.mu.Lock()
	if sess.stopped {
		sess.mu.Unlock()
		return nil
	}
	sess.stopped = true
	close(sess.notify) // wake any waiters
	sess.mu.Unlock()

	b.mu.Lock()
	delete(b.sessions, sess.info.Domain)
	delete(b.byID, sess.info.ID)
	if sess.nonce != "" {
		delete(b.byNonce, sess.nonce)
	}
	if sess.info.Label != "" {
		delete(b.byLabel, sess.info.Label)
	}
	b.mu.Unlock()

	return nil
}

func (b *InteractshBackend) Close() error {
	b.initMu.Lock()
	defer b.initMu.Unlock()

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true

	// Stop all sessions under the lock.
	// Safe: sess.mu is a leaf lock, never held while acquiring b.mu.
	for _, sess := range b.sessions {
		sess.mu.Lock()
		if !sess.stopped {
			sess.stopped = true
			close(sess.notify)
		}
		sess.mu.Unlock()
	}

	// Close all clients in parallel (deregistration makes HTTP calls)
	var wg sync.WaitGroup
	for _, c := range b.clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Close(); err != nil {
				log.Printf("oast: error closing client: %v", err)
			}
		}()
	}

	b.sessions = nil
	b.byID = nil
	b.byLabel = nil
	b.byNonce = nil
	b.clients = nil
	b.mu.Unlock()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(clientCloseTimeout):
		log.Printf("oast: timeout closing clients")
	}

	return nil
}

// cleanupIdleClients removes clients with no active sessions from the map.
// Caller must hold b.mu. Returns removed clients for closing outside the lock.
func (b *InteractshBackend) cleanupIdleClients() []*oobclient.Client {
	activeTargets := make(map[string]bool, len(b.sessions))
	for _, sess := range b.sessions {
		activeTargets[sess.info.RedirectTarget] = true
	}

	var stale []*oobclient.Client
	for target, c := range b.clients {
		if target == "" {
			continue // never clean up the default (no-redirect) client
		}
		if !activeTargets[target] {
			stale = append(stale, c)
			delete(b.clients, target)
		}
	}
	return stale
}

// resolveSession finds a session by ID, label, or domain.
func (b *InteractshBackend) resolveSession(identifier string) (*oastSession, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Try as ID first
	if domain, ok := b.byID[identifier]; ok {
		if sess, ok := b.sessions[domain]; ok {
			return sess, nil
		}
	}

	// Try as label
	if domain, ok := b.byLabel[identifier]; ok {
		if sess, ok := b.sessions[domain]; ok {
			return sess, nil
		}
	}

	// Try as domain directly
	if sess, ok := b.sessions[identifier]; ok {
		return sess, nil
	}

	return nil, fmt.Errorf("%w: %s", ErrNotFound, identifier)
}
