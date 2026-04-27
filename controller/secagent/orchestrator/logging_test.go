package orchestrator

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// TestLogger covers Logger.Log/Logf behavior. Parent does not call t.Parallel
// because colored_output mutates the global useColor.
func TestLogger(t *testing.T) {
	t.Run("writes_json_record", func(t *testing.T) {
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
	})

	t.Run("pretty_output", func(t *testing.T) {
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
	})

	t.Run("pretty_no_json_dup", func(t *testing.T) {
		t.Parallel()
		l, _, buf := newCapturedLogger(t)
		l.Log("controller", "transition phase idle to autonomous", nil)
		out := buf.String()
		assert.NotContains(t, out, `"msg":"transition phase idle to autonomous"`)
		assert.Contains(t, out, "[controller] transition phase idle to autonomous")
	})

	t.Run("stderr_allowlist", func(t *testing.T) {
		t.Parallel()
		// mirrorMarker is a substring unique to this case's pretty line, used to
		// distinguish cases that share the same [tag] msg prefix (e.g. tool done
		// with error=true vs error=false).
		cases := []struct {
			name         string
			tag          string
			msg          string
			fields       map[string]any
			mirrorMarker string
			wantMirrored bool
		}{
			{"controller_phase", "controller", "transition phase a to b", nil, "[controller] transition phase a to b", true},
			{"finding_written", "finding", "written", map[string]any{"path": "f.md"}, "[finding] written", true},
			{"recon_end", "recon", "end", map[string]any{"summary_chars": 100, "summary_tokens_est": 25}, "[recon] end", true},
			{"retire_enqueued", "retire", "enqueued", map[string]any{"worker_id": 1, "reason": "done"}, "[retire] enqueued", true},
			{"narrate", "narrate", "worker scanning", nil, "[narrate] worker scanning", true},
			{"server_models", "server", "models", map[string]any{"worker": "m"}, "[server] models", true},
			{"worker_turn", "worker", "turn", map[string]any{"worker_id": 1}, "[worker] turn", true},
			{"tool_slow", "tool", "slow", map[string]any{"name": "crawl_poll", "elapsed": "7s"}, "[tool] slow", true},
			{"tool_done_error", "tool", "done", map[string]any{"name": "quick", "elapsed": "1s", "error": true}, "name=quick", true},
			{"agent_request", "agent", "request", map[string]any{"role": "worker-1"}, "[agent] request", false},
			{"agent_response", "agent", "response", map[string]any{"role": "worker-1", "tokens_in": 7}, "[agent] response", false},
			{"tool_start", "tool", "start", map[string]any{"name": "proxy_poll"}, "[tool] start", false},
			{"tool_done_success", "tool", "done", map[string]any{"name": "proxy_poll", "elapsed": "1s", "error": false}, "name=proxy_poll", false},
		}

		l, path, buf := newCapturedLogger(t)
		for _, c := range cases {
			l.Log(c.tag, c.msg, c.fields)
		}
		require.NoError(t, l.Close())

		out := buf.String()
		file := mustReadFile(t, path)
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				if c.wantMirrored {
					assert.Contains(t, out, c.mirrorMarker)
				} else {
					assert.NotContains(t, out, c.mirrorMarker)
				}
				// File always gets every record regardless of mirror policy.
				assert.Contains(t, file, `"msg":"`+c.msg+`"`)
			})
		}
	})

	t.Run("colored_output", func(t *testing.T) {
		// mutates global useColor; no t.Parallel.
		withColors(t, true)
		l, _, buf := newCapturedLogger(t)
		l.Log("worker", "turn", map[string]any{"worker_id": 1})
		l.Log("narrate", "orchestrator: running scans", nil)
		l.Log("narrate", "agent (worker-2): probing login", nil)
		l.Log("narrate", "empty-ish line", nil)

		out := buf.String()
		assert.Contains(t, out, ansiGray)
		assert.Contains(t, out, "["+ansiBlue+"worker"+ansiReset+"]")
		assert.Contains(t, out, "["+ansiBlue+"narrate"+ansiReset+"]")
		assert.Contains(t, out, " "+ansiGray+"worker_id=1"+ansiReset)
		assert.Contains(t, out, ansiMedGreen+"orchestrator:"+ansiReset+" running scans")
		assert.Contains(t, out, ansiMedGreen+"agent (worker-2):"+ansiReset+" probing login")
		assert.Contains(t, out, "] empty-ish line")
	})
}

func TestWriteNarrateMsg(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		colored bool
		want    string
	}{
		{"orchestrator_plain", "orchestrator: did a thing", false, "orchestrator: did a thing"},
		{"orchestrator_colored", "orchestrator: did a thing", true, ansiMedGreen + "orchestrator:" + ansiReset + " did a thing"},
		{"agent_plain", "agent (worker-1): probing", false, "agent (worker-1): probing"},
		{"agent_colored", "agent (worker-1): probing", true, ansiMedGreen + "agent (worker-1):" + ansiReset + " probing"},
		{"unmatched_passthrough", "some other narrate", true, "some other narrate"},
		{"agent_open_no_close", "agent (oops no close", true, "agent (oops no close"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withColors(t, c.colored)
			var b strings.Builder
			writeNarrateMsg(&b, c.in)
			assert.Equal(t, c.want, b.String())
		})
	}
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

func TestMalformedCounterObserveAndFlush(t *testing.T) {
	t.Parallel()

	t.Run("observe_and_flush", func(t *testing.T) {
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
		assert.Contains(t, content, `"m1":2`)
	})

	t.Run("flush_noop_when_empty", func(t *testing.T) {
		t.Parallel()
		l, path := newTestLogger(t)
		c := NewMalformedCounter(l)
		c.Flush()
		require.NoError(t, l.Close())
		content := mustReadFile(t, path)
		assert.NotContains(t, content, "malformed-summary")
	})
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(b)
}
