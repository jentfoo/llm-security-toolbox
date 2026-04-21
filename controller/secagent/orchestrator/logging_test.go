package orchestrator

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestLogger(t *testing.T) (*Logger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "log.jsonl")
	l, err := NewLogger(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	return l, path
}

// newCapturedLogger writes JSON to a file and captures pretty output to a buffer.
func newCapturedLogger(t *testing.T) (*Logger, string, *bytes.Buffer) {
	t.Helper()
	l, path := newTestLogger(t)
	buf := &bytes.Buffer{}
	l.mirror = buf
	return l, path, buf
}

func TestLogger_WritesJSONRecord(t *testing.T) {
	t.Parallel()
	l, path := newTestLogger(t)
	l.Log("controller", "hello", map[string]any{"iter": 2})
	l.Logf("worker", "n=%d", 3)
	require.NoError(t, l.Close())

	content := mustReadFile(t, path)
	assert.Contains(t, content, `"tag":"controller"`)
	assert.Contains(t, content, `"msg":"hello"`)
	assert.Contains(t, content, `"iter":2`)
	assert.Contains(t, content, "n=3")
}

func TestLogger_PrettyOutput(t *testing.T) {
	t.Parallel()
	l, _, buf := newCapturedLogger(t)
	l.Log("worker", "seeded", map[string]any{"id": 1, "assignment": "hunt bugs"})
	l.Log("controller", "iteration start", nil)
	l.Log("worker", "error", map[string]any{"err": "context canceled"})

	out := buf.String()
	// timestamp format HH:MM:SS.mmm
	assert.Regexp(t, `^\d{2}:\d{2}:\d{2}\.\d{3} \[worker\] seeded`, out)
	// fields sorted alphabetically: assignment before id
	assert.Contains(t, out, `[worker] seeded assignment="hunt bugs" id=1`)
	// no trailing key-separator when fields empty
	assert.Contains(t, out, "[controller] iteration start\n")
	// value quoted when contains whitespace
	assert.Contains(t, out, `err="context canceled"`)
}

func TestLogger_StderrAllowlist(t *testing.T) {
	t.Parallel()
	l, path, buf := newCapturedLogger(t)
	// Mirrored: controller phase, finding, narrate, server, worker turn, slow tool.
	l.Log("controller", "phase", map[string]any{"from": "a", "to": "b"})
	l.Log("finding", "written", map[string]any{"path": "f.md"})
	l.Log("narrate", "worker scanning", nil)
	l.Log("server", "models", map[string]any{"worker": "m"})
	l.Log("worker", "turn", map[string]any{"worker_id": 1})
	l.Log("tool", "slow", map[string]any{"name": "crawl_poll", "elapsed": "7s"})
	l.Log("tool", "done", map[string]any{"name": "quick", "elapsed": "1s", "error": true})
	// Not mirrored: per-request telemetry, tool start/done-success, info-only agent.
	l.Log("agent", "request", map[string]any{"role": "worker-1"})
	l.Log("agent", "response", map[string]any{"role": "worker-1", "tokens_in": 7})
	l.Log("tool", "start", map[string]any{"name": "proxy_poll"})
	l.Log("tool", "done", map[string]any{"name": "proxy_poll", "elapsed": "1s", "error": false})
	require.NoError(t, l.Close())

	out := buf.String()
	// Mirrored:
	assert.Contains(t, out, "[controller] phase")
	assert.Contains(t, out, "[finding] written")
	assert.Contains(t, out, "[narrate] worker scanning")
	assert.Contains(t, out, "[server] models")
	assert.Contains(t, out, "[worker] turn")
	assert.Contains(t, out, "[tool] slow")
	assert.Contains(t, out, "[tool] done")
	// Not mirrored:
	assert.NotContains(t, out, "[agent] request")
	assert.NotContains(t, out, "[agent] response")
	assert.NotContains(t, out, "[tool] start")

	// File gets everything regardless.
	file := mustReadFile(t, path)
	assert.Contains(t, file, `"msg":"request"`)
	assert.Contains(t, file, `"msg":"start"`)
}

func TestLogger_PrettyDoesNotDuplicateJSON(t *testing.T) {
	t.Parallel()
	l, _, buf := newCapturedLogger(t)
	l.Log("controller", "phase", map[string]any{"from": "idle", "to": "autonomous"})
	out := buf.String()
	// Must be the pretty line, not JSON
	assert.NotContains(t, out, `"msg":"phase"`)
	assert.Contains(t, out, "[controller] phase from=idle to=autonomous")
}

func TestFormatPrettyValue(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"empty_string", "", `""`},
		{"plain_string", "hello", "hello"},
		{"string_with_space", "a b", `"a b"`},
		{"int", 42, "42"},
		{"bool_true", true, "true"},
		{"nil_value", nil, "null"},
		{"duration", 2 * time.Second, "2s"},
		{"error", errors.New("boom"), "boom"},
		{"map", map[string]int{"a": 1}, `{"a":1}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, formatPrettyValue(c.in))
		})
	}
}

func TestMalformedCounter_ObserveAndFlush(t *testing.T) {
	t.Parallel()
	l, path := newTestLogger(t)
	c := NewMalformedCounter(l)
	c.Observe("m1", "tool_a", errors.New("bad"))
	c.Observe("m1", "tool_b", errors.New("bad2"))
	c.Observe("m2", "tool_a", errors.New("bad3"))
	c.Flush()
	require.NoError(t, l.Close())

	content := mustReadFile(t, path)
	assert.Contains(t, content, `"msg":"malformed-args"`)
	assert.Contains(t, content, `"model":"m1"`)
	assert.Contains(t, content, `"msg":"malformed-summary"`)
	assert.Contains(t, content, `"m1":2`, "summary must show m1 count 2")
}

func TestMalformedCounter_FlushNoopWhenEmpty(t *testing.T) {
	t.Parallel()
	l, path := newTestLogger(t)
	c := NewMalformedCounter(l)
	c.Flush()
	require.NoError(t, l.Close())
	content := mustReadFile(t, path)
	assert.NotContains(t, content, "malformed-summary")
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(b)
}
