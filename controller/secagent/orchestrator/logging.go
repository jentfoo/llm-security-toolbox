package orchestrator

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Logger emits structured JSON lines to a log file and human-readable
// lines to stderr. When a Narrator is attached, every Log call also feeds
// the narrator's event buffer so operator-facing summaries can be generated
// without re-plumbing every call site.
type Logger struct {
	mu       sync.Mutex
	file     io.WriteCloser
	mirror   io.Writer
	narrator *Narrator
}

// AttachNarrator wires a narrator so every Log call is recorded to its
// event buffer. Pass nil to detach.
func (l *Logger) AttachNarrator(n *Narrator) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.narrator = n
	l.mu.Unlock()
}

// NewLogger opens path for append-writing JSON records; stderr receives
// a human-readable mirror.
func NewLogger(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &Logger{file: f, mirror: os.Stderr}, nil
}

// Close closes the underlying log file.
func (l *Logger) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	return l.file.Close()
}

// Log writes a JSON record to the log file, and — when the tag/msg is
// operator-relevant — a pretty line to the stderr mirror. When a narrator
// is attached, the event is also recorded to its buffer.
func (l *Logger) Log(tag, msg string, fields map[string]any) {
	if l == nil {
		return
	}
	now := time.Now()
	l.mu.Lock()
	narrator := l.narrator
	if l.file != nil {
		if b := buildJSONLine(now, tag, msg, fields); b != nil {
			_, _ = l.file.Write(b)
		}
	}
	if l.mirror != nil && shouldMirror(tag, msg, fields) {
		_, _ = l.mirror.Write(buildPrettyLine(now, tag, msg, fields))
	}
	l.mu.Unlock()
	if narrator != nil && shouldNarrate(tag, msg) {
		narrator.Record(tag, msg, fields)
	}
}

// shouldNarrate is a stricter allowlist than shouldMirror: these are the
// events that should flow into the narrator's prompt buffer. We exclude
// purely diagnostic messages to keep the summary focused.
func shouldNarrate(tag, msg string) bool {
	switch tag {
	case "controller", "decision", "finding", "plan", "verify", "worker":
		return true
	case "tool":
		return msg == "start" || msg == "done" || msg == "timeout" || msg == "slow"
	case "agent":
		return msg == "response" || msg == "response timeout" || msg == "response error"
	}
	return false
}

// shouldMirror decides whether an event is noteworthy enough for stderr.
// The JSON file always gets every event; stderr gets only the signal.
func shouldMirror(tag, msg string, fields map[string]any) bool {
	switch tag {
	case "server", "controller", "decision", "finding", "summary", "narrate", "plan", "verify":
		return true
	case "worker":
		// per-turn escalation lines anchor human reading; drain-error is signal.
		return msg == "turn" || msg == "seeded" || strings.Contains(msg, "error")
	case "direct":
		return strings.Contains(msg, "error")
	case "tool":
		// tool lifecycle is chatty; only surface slow/timeout/error outcomes.
		switch msg {
		case "timeout", "slow":
			return true
		case "done":
			if b, ok := fields["error"].(bool); ok && b {
				return true
			}
		}
		return false
	case "agent":
		// request/response telemetry is file-only; malformed-args is signal.
		return msg == "malformed-args"
	}
	return false
}

// Logf is a convenience for simple messages.
func (l *Logger) Logf(tag, format string, args ...any) {
	l.Log(tag, fmt.Sprintf(format, args...), nil)
}

func buildJSONLine(now time.Time, tag, msg string, fields map[string]any) []byte {
	record := map[string]any{
		"ts":    now.UTC().Format(time.RFC3339Nano),
		"tag":   tag,
		"level": "info",
		"msg":   msg,
	}
	for k, v := range fields {
		record[k] = v
	}
	b, err := json.Marshal(record)
	if err != nil {
		return nil
	}
	return append(b, '\n')
}

func buildPrettyLine(now time.Time, tag, msg string, fields map[string]any) []byte {
	var b strings.Builder
	b.WriteString(now.Format("15:04:05.000"))
	b.WriteString(" [")
	b.WriteString(tag)
	b.WriteString("] ")
	b.WriteString(msg)
	if len(fields) > 0 {
		keys := make([]string, 0, len(fields))
		for k := range fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteByte(' ')
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(formatPrettyValue(fields[k]))
		}
	}
	b.WriteByte('\n')
	return []byte(b.String())
}

func formatPrettyValue(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case string:
		return quoteIfNeeded(t)
	case error:
		return quoteIfNeeded(t.Error())
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case time.Duration:
		return t.String()
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(b)
	}
}

func quoteIfNeeded(s string) string {
	if s == "" {
		return `""`
	}
	if strings.ContainsAny(s, " \t\"\\\n\r") {
		return strconv.Quote(s)
	}
	return s
}

// MalformedCounter tracks malformed tool-args occurrences per model so the
// operator can identify which backend needs schema tuning.
type MalformedCounter struct {
	mu    sync.Mutex
	byKey map[string]int
	log   *Logger
}

// NewMalformedCounter returns a counter that logs each increment and
// emits a by-model summary via Flush.
func NewMalformedCounter(log *Logger) *MalformedCounter {
	return &MalformedCounter{byKey: map[string]int{}, log: log}
}

// Observe records one malformed-args event for the given model and tool.
func (c *MalformedCounter) Observe(model, tool string, err error) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.byKey[model]++
	count := c.byKey[model]
	c.mu.Unlock()
	if c.log != nil {
		c.log.Log("agent", "malformed-args", map[string]any{
			"model": model, "tool": tool, "count": count, "err": err.Error(),
		})
	}
}

// Flush emits a single "malformed-summary" entry keyed by model. Call at
// shutdown; no-op if no events were recorded.
func (c *MalformedCounter) Flush() {
	if c == nil || c.log == nil {
		return
	}
	c.mu.Lock()
	if len(c.byKey) == 0 {
		c.mu.Unlock()
		return
	}
	snapshot := make(map[string]any, len(c.byKey))
	for k, v := range c.byKey {
		snapshot[k] = v
	}
	c.mu.Unlock()
	c.log.Log("controller", "malformed-summary", map[string]any{"by_model": snapshot})
}
