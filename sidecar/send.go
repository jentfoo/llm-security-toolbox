package sidecar

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-analyze/bulk"

	"github.com/go-appsec/toolbox/pkg/mutate"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// InvokeAdapter routes an outbound message through another registered adapter's
// injection_target and returns the flows it produced. Scope policy and the
// destination adapter's own validation apply.
func (c *Conn) InvokeAdapter(ctx context.Context, p wire.InvokeAdapterParams) (wire.InvokeAdapterResult, error) {
	var res wire.InvokeAdapterResult
	if rpcErr := c.peer.Call(ctx, wire.MethodInvokeAdapter, p, &res); rpcErr != nil {
		return wire.InvokeAdapterResult{}, rpcErr
	}
	return res, nil
}

// ApplyMutations applies the ordered mutation ops to msg in place, reusing the
// shared JSON/form body helpers. Ops run in slice order so later edits observe
// earlier ones. An unknown op or a body edit against an incompatible body errors.
func ApplyMutations(msg *wire.FlowMessage, muts []wire.Mutation) error {
	for _, m := range muts {
		switch m.Op {
		case "set_header":
			msg.Headers = setHeader(msg.Headers, m.Name, m.Value)
		case "remove_header":
			msg.Headers = removeHeader(msg.Headers, m.Name)
		case "set_json":
			b, err := mutate.JSON(msg.Body, map[string]interface{}{m.Name: m.Value}, nil)
			if err != nil {
				return fmt.Errorf("set_json %q: %w", m.Name, err)
			}
			msg.Body = b
		case "remove_json":
			b, err := mutate.JSON(msg.Body, nil, []string{m.Name})
			if err != nil {
				return fmt.Errorf("remove_json %q: %w", m.Name, err)
			}
			msg.Body = b
		case "set_form":
			b, err := mutate.Form(msg.Body, map[string]string{m.Name: m.Value}, nil)
			if err != nil {
				return fmt.Errorf("set_form %q: %w", m.Name, err)
			}
			msg.Body = b
		case "remove_form":
			b, err := mutate.Form(msg.Body, nil, []string{m.Name})
			if err != nil {
				return fmt.Errorf("remove_form %q: %w", m.Name, err)
			}
			msg.Body = b
		case "set_query":
			msg.Query = setQueryParam(msg.Query, m.Name, m.Value)
		case "remove_query":
			msg.Query = removeQueryParam(msg.Query, m.Name)
		case "query":
			msg.Query = m.Value
		case "method":
			msg.Method = m.Value
		case "path":
			msg.Path = m.Value
		case "body":
			msg.Body = []byte(m.Value)
		default:
			return fmt.Errorf("unknown mutation op %q", m.Op)
		}
	}
	return nil
}

// setHeader replaces the first case-insensitive match in place, else appends.
func setHeader(hs []wire.Header, name, value string) []wire.Header {
	for i := range hs {
		if strings.EqualFold(hs[i].Name, name) {
			hs[i].Value = value
			return hs
		}
	}
	return append(hs, wire.Header{Name: name, Value: value})
}

// removeHeader drops every case-insensitive match.
func removeHeader(hs []wire.Header, name string) []wire.Header {
	return bulk.SliceFilterInPlace(func(h wire.Header) bool { return !strings.EqualFold(h.Name, name) }, hs)
}

func setQueryParam(query, name, value string) string {
	vals, _ := url.ParseQuery(query)
	vals.Set(name, value)
	return vals.Encode()
}

func removeQueryParam(query, name string) string {
	vals, _ := url.ParseQuery(query)
	vals.Del(name)
	return vals.Encode()
}
