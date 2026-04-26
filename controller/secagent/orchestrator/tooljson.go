package orchestrator

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
)

// unmarshalToolArgs parses tool arguments into dest, with recovery for
// common LLM JSON misformulations seen in practice:
//
//   - An array field encoded as a JSON string: `"plans": "[{...},{...}]"`.
//     Recovered by string-decoding then re-injecting the inner array.
//   - An object field encoded as a JSON string: `"plan": "{...}"`.
//     Recovered the same way.
//   - A single object where the schema expects an array: `"plans": {...}`.
//     Recovered by wrapping into a one-element array.
//   - A single-element array where the schema expects an object:
//     `"plan": [{...}]`. Recovered by unwrapping.
//
// dest must be a pointer to a struct. Recovery is best-effort and
// per-field: a successful patch on field A still leaves field B alone if
// it's already valid. If no recovery applies or the patched parse still
// fails, the original error from the first attempt is returned so the
// tool's reject message stays accurate.
func unmarshalToolArgs(args json.RawMessage, dest any) error {
	origErr := json.Unmarshal(args, dest)
	if origErr == nil {
		return nil
	}
	rv := reflect.ValueOf(dest)
	if rv.Kind() != reflect.Pointer || rv.Elem().Kind() != reflect.Struct {
		return origErr
	}
	rt := rv.Elem().Type()

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(args, &raw); err != nil {
		return origErr
	}

	patched := false
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		key := jsonFieldKey(f)
		if key == "" {
			continue
		}
		rawVal, ok := raw[key]
		if !ok || len(rawVal) == 0 {
			continue
		}
		if newVal, ok := repairToolArgValue(rawVal, f.Type); ok {
			raw[key] = newVal
			patched = true
		}
	}
	if !patched {
		return origErr
	}
	rebuilt, err := json.Marshal(raw)
	if err != nil {
		return origErr
	}
	if err := json.Unmarshal(rebuilt, dest); err != nil {
		return origErr
	}
	return nil
}

// jsonFieldKey returns the JSON key the field is unmarshaled from, or ""
// when the field should be skipped (unexported or json:"-").
func jsonFieldKey(f reflect.StructField) string {
	if !f.IsExported() {
		return ""
	}
	tag := f.Tag.Get("json")
	if tag == "-" {
		return ""
	}
	name, _, _ := strings.Cut(tag, ",")
	if name == "" {
		return f.Name
	}
	return name
}

// repairToolArgValue inspects a raw JSON value against its target Go type
// and patches it into a decodable shape. Returns (patched, true) on
// success, (nil, false) when the raw value is already shaped correctly or
// the misformulation isn't one we recognize.
func repairToolArgValue(raw json.RawMessage, target reflect.Type) (json.RawMessage, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, false
	}
	elem := target
	for elem.Kind() == reflect.Pointer {
		elem = elem.Elem()
	}
	switch elem.Kind() {
	case reflect.Slice, reflect.Array:
		if trimmed[0] == '"' {
			var inner string
			if err := json.Unmarshal(trimmed, &inner); err != nil {
				return nil, false
			}
			innerTrim := strings.TrimSpace(inner)
			if strings.HasPrefix(innerTrim, "[") {
				return json.RawMessage(innerTrim), true
			}
			if strings.HasPrefix(innerTrim, "{") {
				return json.RawMessage("[" + innerTrim + "]"), true
			}
			return nil, false
		}
		if trimmed[0] == '{' {
			out := make([]byte, 0, len(trimmed)+2)
			out = append(out, '[')
			out = append(out, trimmed...)
			out = append(out, ']')
			return out, true
		}
	case reflect.Struct, reflect.Map:
		if trimmed[0] == '"' {
			var inner string
			if err := json.Unmarshal(trimmed, &inner); err != nil {
				return nil, false
			}
			innerTrim := strings.TrimSpace(inner)
			if strings.HasPrefix(innerTrim, "{") {
				return json.RawMessage(innerTrim), true
			}
			return nil, false
		}
		if trimmed[0] == '[' {
			var arr []json.RawMessage
			if err := json.Unmarshal(trimmed, &arr); err != nil {
				return nil, false
			}
			if len(arr) == 1 {
				return arr[0], true
			}
		}
	}
	return nil, false
}
