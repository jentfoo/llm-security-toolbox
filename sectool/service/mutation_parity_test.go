package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/pkg/mutate"
	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/proxy"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sectool/service/store"
	"github.com/go-appsec/toolbox/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

func TestMutationParity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		baseBody  string
		baseQuery string
		args      map[string]interface{}
	}{
		{
			name:     "body_then_json",
			baseBody: `{"keep":1}`,
			args: map[string]interface{}{
				"body":     `{"a":0}`,
				"set_json": map[string]interface{}{"a": "1"},
			},
		},
		{
			name:     "multi_key_json_determinism",
			baseBody: `{}`,
			args:     map[string]interface{}{"set_json": map[string]interface{}{"user": `{"name":"x"}`, "user.id": "5"}},
		},
		{
			name:     "form_remove_and_set",
			baseBody: `a=1&b=2&c=3`,
			args:     map[string]interface{}{"set_form": map[string]interface{}{"b": "9"}, "remove_form": []interface{}{"c"}},
		},
		{
			name:      "query_order_encoding_preserved",
			baseQuery: "z=1&sig=%2Fabc&a=2",
			args:      map[string]interface{}{"set_query": []interface{}{"a=changed"}, "remove_query": []interface{}{"z"}},
		},
		{
			name:      "query_value_verbatim_whitespace",
			baseQuery: "x=1",
			args:      map[string]interface{}{"set_query": []interface{}{"note= hello "}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			muts := buildMutations(argRequest(tt.args))

			msg := &wire.FlowMessage{Body: []byte(tt.baseBody), Query: tt.baseQuery}
			require.NoError(t, sidecar.ApplyMutations(msg, muts))

			opts, mods := mutationsToOpts(muts)
			body := []byte(tt.baseBody)
			if mods.Body != "" {
				body = []byte(mods.Body)
			}
			if len(mods.SetJSON) > 0 || len(mods.RemoveJSON) > 0 {
				var err error
				body, err = mutate.JSON(body, mods.SetJSON, mods.RemoveJSON)
				require.NoError(t, err)
			}
			if len(mods.SetForm) > 0 || len(mods.RemoveForm) > 0 {
				var err error
				body, err = mutate.Form(body, mods.SetForm, mods.RemoveForm)
				require.NoError(t, err)
			}
			query := tt.baseQuery
			if opts.Query != "" {
				query = opts.Query
			} else if len(opts.SetQuery) > 0 || len(opts.RemoveQuery) > 0 {
				query = mutate.Query(query, opts.RemoveQuery, opts.SetQuery)
			}

			assert.Equal(t, string(body), string(msg.Body))
			assert.Equal(t, query, msg.Query)
		})
	}
}

func TestRuleHeaderNonASCII(t *testing.T) {
	t.Parallel()

	backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.MemProvider, proxy.TimeoutConfig{}, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close(context.Background()) })

	_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
		Label:   "fold",
		Type:    wire.RuleTypeRequestHeader,
		Find:    "SECRET",
		Replace: "REDACTED",
	})
	require.NoError(t, err)

	req := &types.RawHTTP1Request{
		Method: "GET", Path: "/", Version: "HTTP/1.1",
		Headers: []types.Header{{Name: "X-Data", Value: "İ secret Ⱥ"}},
	}
	assert.Equal(t, "İ REDACTED Ⱥ", backend.ApplyRequestRules(req).GetHeader("X-Data"))
}
