package js

import (
	"strings"

	"github.com/tdewolff/parse/v2/js"

	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/ids"
)

// endpointIDLength is the base62 length of a derived endpoint handle.
const endpointIDLength = 6

// EndpointID returns the deterministic detail handle for an endpoint, derived from its
// method and URL (the dedup key). The same (method, url) always yields the same id.
func EndpointID(method, url string) string {
	return ids.Derive(endpointIDLength, method, url)
}

// callDetail is the per-call-site request shape extracted from a single sink.
type callDetail struct {
	Method     string
	URL        string
	Library    string
	Call       string
	Body       *protocol.JSRequestBody
	Headers    []protocol.JSField
	Query      []protocol.JSField
	PathParams []string
}

// structured reports whether the call site carries detail beyond method+url.
// URL-embedded query is excluded (it is part of the list URL);
// param-sourced query is handled by the caller, which knows its origin.
func (d *callDetail) structured() bool {
	return d.Body != nil || len(d.Headers) > 0 || len(d.PathParams) > 0
}

// detailExtras holds the body/header/query detail a sink's options object contributes.
type detailExtras struct {
	body    *protocol.JSRequestBody
	headers []protocol.JSField
	query   []protocol.JSField
}

// configExtras pulls body, headers, and query params from a request options/config object.
// The body key is "body" for fetch and "data" for axios/jQuery.
func configExtras(library string, opts *js.ObjectExpr) detailExtras {
	if opts == nil {
		return detailExtras{}
	}
	bodyKey := "body"
	if library == libAxios || library == libJQuery {
		bodyKey = "data"
	}
	ex := detailExtras{body: bodyFromValue(propValue(opts, bodyKey))}
	if h, ok := propValue(opts, "headers").(*js.ObjectExpr); ok {
		ex.headers = fieldsFromObject(h)
	}
	if p, ok := propValue(opts, "params").(*js.ObjectExpr); ok {
		ex.query = fieldsFromObject(p)
	}
	return ex
}

// bodyFromValue builds a request body from a body-value expression: JSON.stringify(obj)
// and object literals yield JSON field shapes; anything else is rendered as Raw.
func bodyFromValue(val js.IExpr) *protocol.JSRequestBody {
	if val == nil {
		return nil
	} else if obj, ok := jsonStringifyArg(val); ok {
		return &protocol.JSRequestBody{ContentType: "json", Fields: fieldsFromObject(obj)}
	} else if obj, ok := val.(*js.ObjectExpr); ok {
		return &protocol.JSRequestBody{ContentType: "json", Fields: fieldsFromObject(obj)}
	}
	return &protocol.JSRequestBody{Raw: renderExpr(val)}
}

// jsonStringifyArg returns the object-literal argument of a JSON.stringify({...}) call.
func jsonStringifyArg(e js.IExpr) (*js.ObjectExpr, bool) {
	c, ok := e.(*js.CallExpr)
	if !ok || len(c.Args.List) == 0 {
		return nil, false
	}
	if d, ok := c.X.(*js.DotExpr); !ok {
		return nil, false
	} else if base, ok := dotObjectName(d.X); !ok || base != "JSON" {
		return nil, false
	} else if prop, ok := dotPropertyName(d.Y); !ok || prop != "stringify" {
		return nil, false
	}
	obj, ok := c.Args.List[0].Value.(*js.ObjectExpr)
	return obj, ok
}

// fieldsFromObject returns name/value pairs for an object literal's properties. Values are the static literal
// when resolvable, otherwise the rendered JS expression. A shorthand property ({name}) omits the redundant value.
func fieldsFromObject(o *js.ObjectExpr) []protocol.JSField {
	if o == nil {
		return nil
	}
	out := make([]protocol.JSField, 0, len(o.List))
	for _, p := range o.List {
		if p.Name == nil {
			continue // spread or method
		}
		name := propertyKeyName(p)
		if name == "" {
			continue
		}
		f := protocol.JSField{Name: name}
		if val := renderExpr(p.Value); val != name {
			f.Value = val
		}
		out = append(out, f)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// pathParamsFromArg returns the rendered interpolation expressions of a template-literal
// URL argument (the variable names behind ${...}). Non-template arguments yield nothing.
func pathParamsFromArg(urlArg js.IExpr) []string {
	t, ok := urlArg.(*js.TemplateExpr)
	if !ok || t.Tag != nil {
		return nil
	}
	var out []string
	for _, part := range t.List {
		if part.Expr == nil {
			continue
		}

		if name := strings.TrimSpace(part.Expr.String()); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// queryFromURL parses name/value pairs from the query portion of a URL string.
// Placeholder values (${...}) are preserved.
func queryFromURL(rawURL string) []protocol.JSField {
	i := strings.IndexByte(rawURL, '?')
	if i < 0 {
		return nil
	}
	q := rawURL[i+1:]
	if frag := strings.IndexByte(q, '#'); frag >= 0 {
		q = q[:frag]
	}
	var out []protocol.JSField
	for _, pair := range strings.Split(q, "&") {
		if pair == "" {
			continue
		}
		name, val, _ := strings.Cut(pair, "=")
		if name == "" {
			continue
		}
		out = append(out, protocol.JSField{Name: name, Value: val})
	}
	return out
}

// renderExpr returns the static string value of expr when resolvable, otherwise its JS source.
func renderExpr(e js.IExpr) string {
	if e == nil {
		return ""
	}
	if s, ok := staticString(e); ok {
		return s
	}
	return e.String()
}

// propValue returns the value expression for an object-literal property of the given key.
func propValue(obj *js.ObjectExpr, key string) js.IExpr {
	for _, p := range obj.List {
		if p.Name == nil {
			continue
		}

		if propertyKeyName(p) == key {
			return p.Value
		}
	}
	return nil
}

// objArg returns the i-th call argument as an object literal, or nil.
func objArg(c *js.CallExpr, i int) *js.ObjectExpr {
	if len(c.Args.List) <= i {
		return nil
	}
	obj, _ := c.Args.List[i].Value.(*js.ObjectExpr)
	return obj
}

// collectCallDetails walks ast and returns the per-call-site detail for every sink.
func collectCallDetails(ast *js.AST) []callDetail {
	if ast == nil {
		return nil
	}
	var out Extracted
	details := make([]callDetail, 0)
	v := &sinkVisitor{out: &out, scope: buildScope(ast), details: &details}
	js.Walk(v, ast)
	return details
}

// collectBlocks parses and collects call details across all source blocks.
func collectBlocks(blocks [][]byte) []callDetail {
	var all []callDetail
	for _, src := range blocks {
		if len(src) == 0 {
			continue
		}

		all = append(all, collectCallDetails(parseSource(src).ast)...)
	}
	return all
}

// AnalyzeJSEndpoint re-extracts a JavaScript body and returns the detail for the endpoint
// matching id, or (nil, false) when no call site matches.
func AnalyzeJSEndpoint(src []byte, id string) (*protocol.JSEndpointResponse, bool) {
	return buildEndpointResponse(collectBlocks([][]byte{src}), id)
}

// AnalyzeHTMLEndpoint re-extracts the inline scripts of an HTML body and returns the detail
// for the endpoint matching id, or (nil, false) when no call site matches.
func AnalyzeHTMLEndpoint(src []byte, id string) (*protocol.JSEndpointResponse, bool) {
	return buildEndpointResponse(collectBlocks(ParseHTMLScripts(src).Inline), id)
}

// buildEndpointResponse groups every call site whose EndpointID equals id into one response.
func buildEndpointResponse(details []callDetail, id string) (*protocol.JSEndpointResponse, bool) {
	resp := &protocol.JSEndpointResponse{EndpointID: id}
	seen := make(map[string]struct{})
	for _, d := range details {
		if EndpointID(d.Method, d.URL) != id {
			continue
		}
		if len(resp.CallSites) == 0 {
			resp.Method, resp.URL = d.Method, d.URL
		}
		if _, dup := seen[d.Call]; dup {
			continue
		}
		seen[d.Call] = struct{}{}
		resp.CallSites = append(resp.CallSites, protocol.JSCallSite{
			Library:    d.Library,
			Call:       d.Call,
			Body:       d.Body,
			Headers:    d.Headers,
			Query:      d.Query,
			PathParams: d.PathParams,
		})
	}
	if len(resp.CallSites) == 0 {
		return nil, false
	}
	return resp, true
}
