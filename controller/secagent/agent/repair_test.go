package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepairToolArgs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"empty", "", "{}", false},
		{"simple_object", `{"a":1}`, `{"a":1}`, false},
		{"fenced", "```json\n{\"a\":1}\n```", `{"a":1}`, false},
		{"fenced_no_lang", "```\n{\"a\":1}\n```", `{"a":1}`, false},
		{"double_encoded", `"{\"a\":1}"`, `{"a":1}`, false},
		{"trailing_brace_missing", `{"a":1`, `{"a":1}`, false},
		{"garbage", "not json", "", true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := RepairToolArgs(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, string(got))
		})
	}
}
