package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClearOptsModeCount(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		opts clearOpts
		want int
	}{
		{"none", clearOpts{}, 0},
		{"flow_only", clearOpts{flow: "f1"}, 1},
		{"before_only", clearOpts{before: "f1"}, 1},
		{"after_only", clearOpts{after: "f1"}, 1},
		{"from_only", clearOpts{from: "f1"}, 1},
		{"to_only", clearOpts{to: "f1"}, 1},
		{"from_and_to_count_as_one", clearOpts{from: "f1", to: "f2"}, 1},
		{"all_only", clearOpts{all: true}, 1},
		{"flow_plus_all", clearOpts{flow: "f1", all: true}, 2},
		{"before_plus_after", clearOpts{before: "a", after: "b"}, 2},
		{"flow_plus_range", clearOpts{flow: "f1", from: "a", to: "b"}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.opts.modeCount())
		})
	}
}

// runClassifier walks ids through a fresh classifier built from opts and returns the in-scope ids,
// whether the loop stopped, and any reverse-range error surfaced by the classifier. Anchor
// existence is the caller's responsibility (validateAnchors), not the classifier's.
func runClassifier(opts clearOpts, ids []string) (inScope []string, stopped bool, rangeErr error) {
	c := newClassifier(opts)
	for _, id := range ids {
		switch c.classify(id) {
		case decisionInclude:
			inScope = append(inScope, id)
		case decisionStop:
			stopped = true
		}
		if stopped {
			break
		}
	}
	return inScope, stopped, c.reverseRangeError()
}

func TestClassifier(t *testing.T) {
	t.Parallel()

	ids := []string{"a", "b", "c", "d", "e"}

	t.Run("all_includes_every_id", func(t *testing.T) {
		got, stopped, err := runClassifier(clearOpts{all: true}, ids)
		require.NoError(t, err)
		assert.False(t, stopped)
		assert.Equal(t, ids, got)
	})

	t.Run("before_anchor_kept", func(t *testing.T) {
		got, stopped, err := runClassifier(clearOpts{before: "c"}, ids)
		require.NoError(t, err)
		assert.True(t, stopped)
		assert.Equal(t, []string{"a", "b"}, got)
	})

	t.Run("after_anchor_kept", func(t *testing.T) {
		got, stopped, err := runClassifier(clearOpts{after: "c"}, ids)
		require.NoError(t, err)
		assert.False(t, stopped)
		assert.Equal(t, []string{"d", "e"}, got)
	})

	t.Run("range_inclusive_both_ends", func(t *testing.T) {
		got, stopped, err := runClassifier(clearOpts{from: "b", to: "d"}, ids)
		require.NoError(t, err)
		assert.True(t, stopped)
		assert.Equal(t, []string{"b", "c", "d"}, got)
	})

	t.Run("range_open_lower", func(t *testing.T) {
		got, _, err := runClassifier(clearOpts{to: "c"}, ids)
		require.NoError(t, err)
		assert.Equal(t, []string{"a", "b", "c"}, got)
	})

	t.Run("range_open_upper", func(t *testing.T) {
		got, stopped, err := runClassifier(clearOpts{from: "c"}, ids)
		require.NoError(t, err)
		assert.False(t, stopped)
		assert.Equal(t, []string{"c", "d", "e"}, got)
	})

	t.Run("range_to_before_from_errors", func(t *testing.T) {
		_, _, err := runClassifier(clearOpts{from: "d", to: "b"}, ids)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--from must come before --to")
	})

	t.Run("range_single_id_from_equals_to", func(t *testing.T) {
		got, stopped, err := runClassifier(clearOpts{from: "c", to: "c"}, ids)
		require.NoError(t, err)
		assert.True(t, stopped)
		assert.Equal(t, []string{"c"}, got)
	})
}
