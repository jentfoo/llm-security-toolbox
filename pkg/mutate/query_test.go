package mutate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestQuery(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		query  string
		remove []string
		set    []string
		want   string
	}{
		{
			name:   "remove_single",
			query:  "a=1&b=2&c=3",
			remove: []string{"b"},
			want:   "a=1&c=3",
		},
		{
			name:  "set_existing",
			query: "a=1&b=2",
			set:   []string{"a=changed"},
			want:  "a=changed&b=2",
		},
		{
			name:  "set_new",
			query: "a=1",
			set:   []string{"b=2"},
			want:  "a=1&b=2",
		},
		{
			name:   "remove_then_set",
			query:  "a=1&b=2&c=3",
			remove: []string{"b"},
			set:    []string{"d=4"},
			want:   "a=1&c=3&d=4",
		},
		{
			name:  "encoding_preserved",
			query: "foo=%2F&bar=%20hello",
			set:   []string{"baz=new"},
			want:  "foo=%2F&bar=%20hello&baz=new",
		},
		{
			name:  "order_preserved",
			query: "z=1&a=2&m=3",
			set:   []string{"a=changed"},
			want:  "z=1&a=changed&m=3",
		},
		{
			name:  "empty_query_set",
			query: "",
			set:   []string{"key=value"},
			want:  "key=value",
		},
		{
			name:   "empty_query_remove",
			query:  "",
			remove: []string{"anything"},
			want:   "",
		},
		{
			name:   "remove_all",
			query:  "a=1",
			remove: []string{"a"},
			want:   "",
		},
		{
			name:   "remove_nonexistent",
			query:  "a=1",
			remove: []string{"b"},
			want:   "a=1",
		},
		{
			name:  "duplicate_params_preserved",
			query: "a=1&a=2&b=3",
			set:   []string{"c=4"},
			want:  "a=1&a=2&b=3&c=4",
		},
		{
			name:  "set_replaces_first_only",
			query: "a=1&a=2",
			set:   []string{"a=changed"},
			want:  "a=changed&a=2",
		},
		{
			name:   "remove_encoded_key",
			query:  "foo%20bar=1&b=2",
			remove: []string{"foo bar"},
			want:   "b=2",
		},
		{
			name:  "set_replaces_encoded_key",
			query: "foo%20bar=1&b=2",
			set:   []string{"foo bar=changed"},
			want:  "foo bar=changed&b=2",
		},
		{
			name:   "remove_plus_encoded_key",
			query:  "foo+bar=1&b=2",
			remove: []string{"foo bar"},
			want:   "b=2",
		},
		{
			name:  "set_encoded_replaces_raw",
			query: "foo bar=1&b=2",
			set:   []string{"foo%20bar=changed"},
			want:  "foo%20bar=changed&b=2",
		},
		{
			name:   "remove_encoded_matches_raw",
			query:  "foo bar=1&b=2",
			remove: []string{"foo%20bar"},
			want:   "b=2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Query(tt.query, tt.remove, tt.set))
		})
	}
}
