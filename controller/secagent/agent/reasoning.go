package agent

import (
	"context"
	"sync"
	"time"
)

// ReasoningFormat describes how a model surfaces its thinking on the
// OpenAI-compatible endpoint.
type ReasoningFormat int

const (
	// ReasoningFormatUnknown is the pre-detection / probe-failed state.
	// NewReasoningHandler maps it to the inline handler.
	ReasoningFormatUnknown ReasoningFormat = iota
	// ReasoningFormatNone: model does not emit any thinking (small / non-reasoning).
	ReasoningFormatNone
	// ReasoningFormatInline: model embeds `<think>...</think>` inside content.
	ReasoningFormatInline
	// ReasoningFormatStructured: model populates the `reasoning_content` field.
	ReasoningFormatStructured
)

// String returns the canonical lowercase name, suitable for log fields.
func (f ReasoningFormat) String() string {
	switch f {
	case ReasoningFormatNone:
		return "none"
	case ReasoningFormatInline:
		return "inline"
	case ReasoningFormatStructured:
		return "structured"
	default:
		return "unknown"
	}
}

// ReasoningHandler encapsulates per-model reasoning behaviour. Each
// OpenAIAgent gets exactly one after startup detection; the rest of the
// code stays format-agnostic and routes through the handler.
type ReasoningHandler interface {
	// Format returns the detected format.
	Format() ReasoningFormat

	// Ingest normalizes a response for storage. Returns Content and
	// ReasoningContent as they should be appended to history.
	Ingest(resp ChatResponse) (content, reasoning string)

	// Replay prepares history for the agent's own next send, applying a
	// format-appropriate KeepThinkTurns window. Returns a new slice.
	Replay(msgs []Message, keepLastN int) []Message

	// ForSummary unifies history to inline shape for a one-shot summary /
	// narrator prompt so the summary model sees one input shape regardless
	// of the agent's native format.
	ForSummary(msgs []Message) []Message

	// Extract returns a confident single-line prose summary from resp,
	// sourced from whichever field(s) carry the real answer for this
	// format. Returns "" when no confident summary can be produced —
	// callers should fall back to Tail for a best-effort fragment.
	Extract(resp ChatResponse) string

	// Tail returns a best-effort reasoning fragment for narrator fallback
	// when Extract produced nothing. Displayed with a "…thinking:" prefix
	// so the operator knows it's a partial thought rather than a summary.
	Tail(resp ChatResponse) string
}

// NewReasoningHandler returns the handler matching the given format.
// ReasoningFormatUnknown maps to the inline handler.
func NewReasoningHandler(f ReasoningFormat) ReasoningHandler {
	switch f {
	case ReasoningFormatNone:
		return noReasoningHandler{}
	case ReasoningFormatStructured:
		return structuredHandler{}
	default:
		return inlineHandler{}
	}
}

// inlineHandler handles models that emit `<think>...</think>` in content.
type inlineHandler struct{}

func (inlineHandler) Format() ReasoningFormat { return ReasoningFormatInline }

func (inlineHandler) Ingest(resp ChatResponse) (string, string) {
	return resp.Content, ""
}

func (inlineHandler) Replay(msgs []Message, keepLastN int) []Message {
	return FilterThinkBlocks(msgs, keepLastN)
}

func (inlineHandler) ForSummary(msgs []Message) []Message {
	// Inline reasoning lives in Content already — summary model sees it
	// exactly as the agent does.
	return msgs
}

func (inlineHandler) Extract(resp ChatResponse) string {
	return ExtractProse(resp.Content)
}

func (inlineHandler) Tail(resp ChatResponse) string {
	return TruncatedThinkTail(resp.Content)
}

// structuredHandler handles models that populate `reasoning_content`.
type structuredHandler struct{}

func (structuredHandler) Format() ReasoningFormat { return ReasoningFormatStructured }

func (structuredHandler) Ingest(resp ChatResponse) (string, string) {
	return resp.Content, resp.ReasoningContent
}

func (structuredHandler) Replay(msgs []Message, _ int) []Message {
	// Structured reasoning is ephemeral per the deepseek / LM Studio
	// convention: servers don't accept it on input. Blank it on every
	// replayed message so it never reaches the wire (omitempty handles it).
	// KeepThinkTurns has no meaning here; replay is strictly zero-turn.
	out := make([]Message, len(msgs))
	copy(out, msgs)
	for i := range out {
		if out[i].Role == roleAssistant {
			out[i].ReasoningContent = ""
		}
	}
	return out
}

func (structuredHandler) ForSummary(msgs []Message) []Message {
	// Unify to inline: wrap structured reasoning as <think>...</think> and
	// prepend to Content so the summary prompt looks the same regardless of
	// source. Safe for one-shot summary calls; the summary model's output
	// is processed via StripThinkBlocks after.
	out := make([]Message, len(msgs))
	copy(out, msgs)
	for i := range out {
		m := out[i]
		if m.Role != roleAssistant || m.ReasoningContent == "" {
			continue
		}
		wrapped := "<think>" + m.ReasoningContent + "</think>"
		if m.Content != "" {
			wrapped = wrapped + "\n" + m.Content
		}
		out[i].Content = wrapped
		out[i].ReasoningContent = ""
	}
	return out
}

func (structuredHandler) Extract(resp ChatResponse) string {
	// Content first: reasoning models occasionally populate both fields,
	// and when they do, Content is the "clean" output.
	if line := ExtractProse(resp.Content); line != "" {
		return line
	}
	// Common case on qwen3/LM Studio: Content is empty, all output is in
	// ReasoningContent. Many reasoning models emit a Final:/Output:/Answer:
	// marker inside their reasoning before the token cap — salvage that
	// as the confident summary instead of showing meta-chatter.
	if resp.ReasoningContent != "" {
		if line := ExtractMarkedOutput(resp.ReasoningContent); line != "" {
			return line
		}
	}
	return ""
}

func (structuredHandler) Tail(resp ChatResponse) string {
	// Content may still be a reasonable source (rare: truncated mid-inline),
	// so try that first, then fall back to the structured field.
	if tail := TruncatedThinkTail(resp.Content); tail != "" {
		return tail
	}
	if resp.ReasoningContent != "" {
		return compactThinkTail(resp.ReasoningContent, 240)
	}
	return ""
}

// noReasoningHandler is a pass-through for models that don't emit thinking.
type noReasoningHandler struct{}

func (noReasoningHandler) Format() ReasoningFormat                   { return ReasoningFormatNone }
func (noReasoningHandler) Ingest(resp ChatResponse) (string, string) { return resp.Content, "" }
func (noReasoningHandler) Replay(msgs []Message, _ int) []Message    { return msgs }
func (noReasoningHandler) ForSummary(msgs []Message) []Message       { return msgs }
func (noReasoningHandler) Extract(resp ChatResponse) string          { return ExtractProse(resp.Content) }
func (noReasoningHandler) Tail(_ ChatResponse) string                { return "" }

// reasoningProbePrompt is the question sent during format detection.
// Picked because it reliably induces multi-step thinking in reasoning-
// trained models (requires explanation of three interacting physical
// phenomena) while being cheap and obvious to classify afterward.
const reasoningProbePrompt = "If the sky is blue, why is the sun orange and the moon white?"

// reasoningProbeMaxTokens is the per-probe output cap. Kept high so a
// long-thinking reasoning model isn't truncated before emitting content
// and then misclassified as ReasoningFormatNone.
const reasoningProbeMaxTokens = 20000

// SummaryReasoningEffort is forwarded as `reasoning_effort` on summary
// calls (narrator + per-agent status). "none" disables reasoning on
// supporting backends; unsupported backends ignore it.
const SummaryReasoningEffort = "none"

// reasoningProbeTimeout bounds probe latency.
const reasoningProbeTimeout = 60 * time.Second

// DetectReasoningFormat sends a single probe query and classifies the
// response. Errors (network, timeout) return ReasoningFormatUnknown so the
// caller can fall back to the inline handler without crashing startup.
func DetectReasoningFormat(ctx context.Context, client ChatClient, model string) (ReasoningFormat, error) {
	ctx, cancel := context.WithTimeout(ctx, reasoningProbeTimeout)
	defer cancel()
	resp, err := client.CreateChatCompletion(ctx, ChatRequest{
		Model: model,
		Messages: []ChatMessage{
			{Role: roleUser, Content: reasoningProbePrompt},
		},
		MaxTokens: reasoningProbeMaxTokens,
	})
	if err != nil {
		return ReasoningFormatUnknown, err
	}
	if resp.ReasoningContent != "" {
		return ReasoningFormatStructured, nil
	}
	if HasInlineThink(resp.Content) {
		return ReasoningFormatInline, nil
	}
	return ReasoningFormatNone, nil
}

// ReasoningFormatCache memoizes detection results keyed by (baseURL, model)
// so identical backend targets are probed only once per run. Callers that
// share a cache across roles (worker/orchestrator/summary) automatically
// benefit from dedup when URLs and models coincide.
type ReasoningFormatCache struct {
	mu    sync.Mutex
	byKey map[string]ReasoningFormat
}

// NewReasoningFormatCache constructs an empty cache.
func NewReasoningFormatCache() *ReasoningFormatCache {
	return &ReasoningFormatCache{byKey: map[string]ReasoningFormat{}}
}

// Resolve returns a cached format for (baseURL, model) or runs detection
// once and caches the result. Detection errors cache ReasoningFormatUnknown
// so a bad endpoint doesn't retry on every role. onDetect fires after each
// real probe with elapsed time; useful for operator logging. Pass nil to skip.
func (c *ReasoningFormatCache) Resolve(
	ctx context.Context, client ChatClient,
	baseURL, model string,
	onDetect func(format ReasoningFormat, elapsed time.Duration, err error),
) ReasoningFormat {
	key := baseURL + "|" + model
	c.mu.Lock()
	if f, ok := c.byKey[key]; ok {
		c.mu.Unlock()
		return f
	}
	c.mu.Unlock()
	start := time.Now()
	f, err := DetectReasoningFormat(ctx, client, model)
	if onDetect != nil {
		onDetect(f, time.Since(start), err)
	}
	c.mu.Lock()
	c.byKey[key] = f
	c.mu.Unlock()
	return f
}
