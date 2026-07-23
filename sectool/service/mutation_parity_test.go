package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		wantBody  string
		wantQuery string
	}{
		{
			name:     "body_then_json",
			baseBody: `{"keep":1}`,
			args: map[string]interface{}{
				"body":     `{"a":0}`,
				"set_json": map[string]interface{}{"a": "1"},
			},
			wantBody: `{"a":1}`,
		},
		{
			name:     "form_remove_and_set",
			baseBody: `a=1&b=2&c=3`,
			args:     map[string]interface{}{"set_form": map[string]interface{}{"b": "9"}, "remove_form": []interface{}{"c"}},
			wantBody: `a=1&b=9`,
		},
		{
			name:      "query_order_encoding_preserved",
			baseQuery: "z=1&sig=%2Fabc&a=2",
			args:      map[string]interface{}{"set_query": []interface{}{"a=changed"}, "remove_query": []interface{}{"z"}},
			wantQuery: "sig=%2Fabc&a=changed",
		},
		{
			name:      "query_value_verbatim_whitespace",
			baseQuery: "x=1",
			args:      map[string]interface{}{"set_query": []interface{}{"note= hello "}},
			wantQuery: "x=1&note= hello ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			muts := buildMutations(argRequest(tt.args))

			msg := &wire.FlowMessage{Body: []byte(tt.baseBody), Query: tt.baseQuery}
			require.NoError(t, sidecar.ApplyMutations(msg, muts))

			assert.Equal(t, tt.wantBody, string(msg.Body))
			assert.Equal(t, tt.wantQuery, msg.Query)
		})
	}
}
