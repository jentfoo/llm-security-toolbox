package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/ids"
	"github.com/go-appsec/toolbox/sectool/service/proxy"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sectool/service/store"
)

const responderKey = "responders"

// nativeStoredResponder is the persistent format for responders.
type nativeStoredResponder struct {
	ID         string            `msgpack:"id"`
	Label      string            `msgpack:"l,omitempty"`
	Host       string            `msgpack:"h"`
	Path       string            `msgpack:"pa"`
	Method     string            `msgpack:"m,omitempty"`
	StatusCode int               `msgpack:"sc"`
	Headers    map[string]string `msgpack:"hd,omitempty"`
	Body       string            `msgpack:"b,omitempty"`
}

func (r *nativeStoredResponder) toEntry() protocol.ResponderEntry {
	return protocol.ResponderEntry{
		ResponderID: r.ID,
		Host:        r.Host,
		Path:        r.Path,
		Method:      r.Method,
		StatusCode:  r.StatusCode,
		Headers:     r.Headers,
		Body:        r.Body,
		Label:       r.Label,
	}
}

// InterceptRequest checks if a request matches a registered responder.
func (b *NativeProxyBackend) InterceptRequest(host string, path string, method string) *proxy.InterceptedResponse {
	b.respondersMu.RLock()
	defer b.respondersMu.RUnlock()

	for _, r := range b.responders {
		if r.Host != host || r.Path != path {
			continue
		}
		if r.Method != "" && !strings.EqualFold(r.Method, method) {
			continue
		}
		headers := make(types.Headers, 0, len(r.Headers))
		for name, value := range r.Headers {
			headers = append(headers, types.Header{Name: name, Value: value})
		}
		return &proxy.InterceptedResponse{
			StatusCode: r.StatusCode,
			Headers:    headers,
			Body:       []byte(r.Body),
		}
	}
	return nil
}

// AddResponder registers a custom response for a specific host and path.
func (b *NativeProxyBackend) AddResponder(ctx context.Context, input protocol.ResponderEntry) (*protocol.ResponderEntry, error) {
	host, err := parseResponderHost(input.Host)
	if err != nil {
		return nil, err
	}

	statusCode := input.StatusCode
	if statusCode == 0 {
		statusCode = 200
	}

	b.respondersMu.Lock()
	defer b.respondersMu.Unlock()

	if input.Label != "" {
		if b.responderLabelExists(input.Label) {
			return nil, fmt.Errorf("%w: %s", ErrLabelExists, input.Label)
		}
	}

	r := nativeStoredResponder{
		ID:         ids.Generate(0),
		Label:      input.Label,
		Host:       host,
		Path:       input.Path,
		Method:     strings.ToUpper(input.Method),
		StatusCode: statusCode,
		Headers:    input.Headers,
		Body:       input.Body,
	}

	updated := append(slices.Clone(b.responders), r)
	if err := b.saveResponders(updated); err != nil {
		return nil, fmt.Errorf("persist responder: %w", err)
	}
	b.responders = updated

	entry := r.toEntry()
	return &entry, nil
}

// DeleteResponder removes a responder by ID or label.
func (b *NativeProxyBackend) DeleteResponder(ctx context.Context, idOrLabel string) error {
	b.respondersMu.Lock()
	defer b.respondersMu.Unlock()

	for i, r := range b.responders {
		if r.ID == idOrLabel || r.Label == idOrLabel {
			updated := slices.Delete(slices.Clone(b.responders), i, i+1)
			if err := b.saveResponders(updated); err != nil {
				return fmt.Errorf("persist responder: %w", err)
			}
			b.responders = updated
			return nil
		}
	}
	return ErrNotFound
}

// ListResponders returns all registered responders.
func (b *NativeProxyBackend) ListResponders(ctx context.Context) ([]protocol.ResponderEntry, error) {
	b.respondersMu.RLock()
	defer b.respondersMu.RUnlock()

	result := make([]protocol.ResponderEntry, len(b.responders))
	for i, r := range b.responders {
		result[i] = r.toEntry()
	}
	return result, nil
}

// responderLabelExists checks if a label is in use by any responder.
// Caller must hold respondersMu.
func (b *NativeProxyBackend) responderLabelExists(label string) bool {
	for _, r := range b.responders {
		if r.Label == label {
			return true
		}
	}
	return false
}

func (b *NativeProxyBackend) loadResponders() ([]nativeStoredResponder, error) {
	data, found, err := b.responderStorage.Get(responderKey)
	if err != nil {
		return nil, fmt.Errorf("load responders: %w", err)
	} else if !found {
		return nil, nil
	}
	var responders []nativeStoredResponder
	if err := store.Deserialize(data, &responders); err != nil {
		return nil, fmt.Errorf("deserialize responders: %w", err)
	}
	return responders, nil
}

func (b *NativeProxyBackend) saveResponders(responders []nativeStoredResponder) error {
	if len(responders) == 0 {
		return b.responderStorage.Delete(responderKey)
	}
	data, err := store.Serialize(responders)
	if err != nil {
		return fmt.Errorf("serialize responders: %w", err)
	}
	return b.responderStorage.Set(responderKey, data)
}

// parseResponderHost normalizes a responder host input to a lowercase hostname.
// Accepts a bare hostname, host:port, or full URL; any scheme and port are
// discarded, since responder matching is port- and scheme-agnostic.
func parseResponderHost(input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", errors.New("host is required")
	}

	// strip scheme (and any port) when given a full URL
	if strings.Contains(input, "://") {
		u, err := url.Parse(input)
		if err != nil {
			return "", fmt.Errorf("invalid host: %w", err)
		}
		input = u.Hostname()
	} else if host, _, err := net.SplitHostPort(input); err == nil {
		input = host
	}

	if input == "" {
		return "", errors.New("invalid host: missing hostname")
	} else if strings.ContainsAny(input, "/?#") {
		return "", errors.New("invalid host: pass only a hostname, no path")
	}
	return strings.ToLower(input), nil
}
