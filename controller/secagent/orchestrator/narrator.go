package orchestrator

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-appsec/secagent/agent"
)

// narratorSystemPrompt instructs the summary model to emit one sentence of
// operator-facing status. The body after "Events" is filled in by
// buildNarratorPrompt().
const narratorSystemPrompt = `You narrate autonomous security-testing agent activity to a human operator.
Given the event log that follows, respond with ONE short sentence describing what the agent is currently doing and what it just did.
No preamble, no bullets, no markdown. Under 40 words.`

// NarratorConfig tunes when and how the Narrator fires.
type NarratorConfig struct {
	Interval   time.Duration // 0 disables; else min time between fires.
	Model      string        // summary model ID.
	Client     agent.ChatClient
	CallBudget time.Duration // per-summary call timeout; 0 defaults to 15s.
}

// Narrator buffers orchestrator events and periodically asks a summary model
// to describe what the agent is doing. Firings run on a goroutine but are
// serialised — only one narration is in flight at a time, and later triggers
// coalesce behind the same lock so output order always matches wall-clock
// order. A background ticker fires every Interval regardless of caller
// triggers so long worker drains still get periodic narration.
type Narrator struct {
	cfg NarratorConfig
	log *Logger

	mu         sync.Mutex
	buf        []narratorEvent
	lastFireAt time.Time

	fireMu sync.Mutex     // held for the entire async call; serialises firings.
	wg     sync.WaitGroup // so Close can wait on the last in-flight firing.

	tickerStop chan struct{} // closed by Close to stop the background ticker.
	closed     bool
}

type narratorEvent struct {
	ts     time.Time
	tag    string
	msg    string
	fields map[string]any
}

// NewNarrator returns a Narrator or nil if cfg.Interval <= 0 (disabled).
// A background ticker goroutine is started that calls Tick() every Interval
// so periodic narration fires without requiring external trigger calls.
func NewNarrator(cfg NarratorConfig, log *Logger) *Narrator {
	if cfg.Interval <= 0 || cfg.Client == nil || cfg.Model == "" {
		return nil
	}
	if cfg.CallBudget <= 0 {
		cfg.CallBudget = 300 * time.Second
	}
	n := &Narrator{cfg: cfg, log: log, tickerStop: make(chan struct{})}
	n.wg.Add(1)
	go n.runTicker()
	return n
}

func (n *Narrator) runTicker() {
	defer n.wg.Done()
	t := time.NewTicker(n.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-n.tickerStop:
			return
		case <-t.C:
			n.Tick()
		}
	}
}

// Record buffers one event. Lightweight and safe to call from hot paths.
func (n *Narrator) Record(tag, msg string, fields map[string]any) {
	if n == nil {
		return
	}
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return
	}
	n.buf = append(n.buf, narratorEvent{
		ts: time.Now(), tag: tag, msg: msg, fields: fields,
	})
	n.mu.Unlock()
}

// Tick is called by the main loop to give the narrator a chance to fire
// based on cadence. Safe to call every iteration — it no-ops if nothing
// has changed since the last fire.
func (n *Narrator) Tick() {
	if n == nil {
		return
	}
	n.mu.Lock()
	now := time.Now()
	shouldFire := len(n.buf) > 0 && now.Sub(n.lastFireAt) >= n.cfg.Interval
	n.mu.Unlock()
	if shouldFire {
		n.fireAsync()
	}
}

// TriggerNow forces a firing regardless of cadence. Use at phase transitions,
// finding writes, and decision applications so narration stays in sync with
// human-meaningful events. No-op if the buffer is empty.
func (n *Narrator) TriggerNow() {
	if n == nil {
		return
	}
	n.mu.Lock()
	empty := len(n.buf) == 0
	n.mu.Unlock()
	if empty {
		return
	}
	n.fireAsync()
}

// fireAsync spawns a single serialised firing. Buffer is snapshotted INSIDE
// the firing goroutine (under fireMu + mu) so coalesced triggers always grab
// the latest events rather than stale ones. We intentionally do NOT short-
// circuit on n.closed here: a firing that was scheduled before shutdown must
// still emit its events, otherwise Close() loses in-flight narrations.
func (n *Narrator) fireAsync() {
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		n.fireMu.Lock()
		defer n.fireMu.Unlock()

		n.mu.Lock()
		if len(n.buf) == 0 {
			n.mu.Unlock()
			return
		}
		snapshot := n.buf
		n.buf = nil
		n.lastFireAt = time.Now()
		n.mu.Unlock()

		n.runSummary(snapshot)
	}()
}

func (n *Narrator) runSummary(events []narratorEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), n.cfg.CallBudget)
	defer cancel()

	body := buildNarratorPrompt(events)
	resp, err := n.cfg.Client.CreateChatCompletion(ctx, agent.ChatRequest{
		Model: n.cfg.Model,
		Messages: []agent.ChatMessage{
			{Role: "system", Content: narratorSystemPrompt},
			{Role: "user", Content: body},
		},
		MaxTokens: 120,
	})
	if err != nil {
		if n.log != nil {
			n.log.Log("narrate", "error", map[string]any{"err": err.Error()})
		}
		return
	}
	line := firstLine(agent.StripThinkBlocks(resp.Content))
	if line == "" {
		return
	}
	if n.log != nil {
		n.log.Log("narrate", line, map[string]any{"events": len(events)})
	}
}

// Close stops the background ticker, flushes any in-flight narration,
// prevents further records, and returns once the last firing has emitted.
func (n *Narrator) Close() {
	if n == nil {
		return
	}
	n.mu.Lock()
	alreadyClosed := n.closed
	n.closed = true
	pending := len(n.buf)
	n.mu.Unlock()
	if !alreadyClosed {
		close(n.tickerStop)
	}
	if pending > 0 {
		// fire the final batch so shutdown doesn't drop it
		n.fireAsync()
	}
	n.wg.Wait()
}

// buildNarratorPrompt renders events as a compact plaintext log the summary
// model can read. Fields are emitted in a stable order (role, worker_id
// first, then alphabetic) to keep the prompt deterministic.
func buildNarratorPrompt(events []narratorEvent) string {
	var b strings.Builder
	b.WriteString("Events since last narration:\n")
	for _, e := range events {
		b.WriteString(e.ts.Format("15:04:05"))
		b.WriteString(" [")
		b.WriteString(e.tag)
		b.WriteString("] ")
		b.WriteString(e.msg)
		// Put role / worker_id first for readability, then the rest alphabetic.
		if v, ok := e.fields["role"]; ok {
			fmt.Fprintf(&b, " role=%s", formatPrettyValue(v))
		}
		if v, ok := e.fields["worker_id"]; ok {
			fmt.Fprintf(&b, " worker_id=%s", formatPrettyValue(v))
		}
		for _, k := range sortedKeys(e.fields, "role", "worker_id") {
			fmt.Fprintf(&b, " %s=%s", k, formatPrettyValue(e.fields[k]))
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func sortedKeys(m map[string]any, skip ...string) []string {
	if len(m) == 0 {
		return nil
	}
	skipSet := make(map[string]bool, len(skip))
	for _, s := range skip {
		skipSet[s] = true
	}
	out := make([]string, 0, len(m))
	for k := range m {
		if skipSet[k] {
			continue
		}
		out = append(out, k)
	}
	// simple insertion sort — N is tiny.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}
