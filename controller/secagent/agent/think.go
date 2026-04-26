package agent

import (
	"regexp"
	"slices"
	"strings"
)

// Think-block variants seen in practice. Matches are case-insensitive,
// multiline, non-greedy. Add more as new models surface.
var thinkBlockPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?is)<think>.*?</think>`),
	regexp.MustCompile(`(?is)<thinking>.*?</thinking>`),
	regexp.MustCompile(`(?is)<\|thinking\|>.*?<\|/thinking\|>`),
	regexp.MustCompile(`(?is)<reasoning>.*?</reasoning>`),
}

// thinkTagPairs mirrors thinkBlockPatterns as literal open/close strings for
// unclosed-tag detection. Kept in sync by hand.
var thinkTagPairs = []struct {
	open, close string
}{
	{"<think>", "</think>"},
	{"<thinking>", "</thinking>"},
	{"<|thinking|>", "<|/thinking|>"},
	{"<reasoning>", "</reasoning>"},
}

// StripThinkBlocks removes any recognized thinking-block variants from s.
// Only balanced pairs are stripped; an unclosed `<think>` (e.g. a reasoning
// model truncated mid-thought) is left intact. Callers that need to treat
// such output as "no summary" should also check HasLeadingThinkOpen.
func StripThinkBlocks(s string) string {
	out := s
	for _, re := range thinkBlockPatterns {
		out = re.ReplaceAllString(out, "")
	}
	return out
}

// FilterThinkBlocks returns a copy of msgs with `<think>` blocks preserved
// on the last keepLastN assistant messages (by reverse walk) and stripped
// from all older assistants. Reasoning models benefit from recent
// chain-of-thought continuity across turns; keeping the full history
// retained would blow context budget (think blocks run 1-4K tokens each).
// keepLastN <= 0 strips think from every assistant message.
// Non-assistant roles (system, user, tool) pass through untouched —
// StripThinkBlocks on user-provided prompts is handled by compaction pass 1
// when context pressure warrants it.
func FilterThinkBlocks(msgs []Message, keepLastN int) []Message {
	if len(msgs) == 0 {
		return msgs
	}
	out := slices.Clone(msgs)
	remaining := keepLastN
	for i := len(out) - 1; i >= 0; i-- {
		if out[i].Role != roleAssistant {
			continue
		}
		if remaining > 0 {
			remaining--
			continue
		}
		out[i].Content = StripThinkBlocks(out[i].Content)
	}
	return out
}

// HasLeadingThinkOpen reports whether s (post-StripThinkBlocks) still begins
// with an opening think tag — the signature of an unclosed block the
// stripper could not remove. Such a "line" is noise to log; callers should
// fall back to TruncatedThinkTail.
func HasLeadingThinkOpen(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	for _, p := range thinkTagPairs {
		if strings.HasPrefix(lower, strings.ToLower(p.open)) {
			return true
		}
	}
	return false
}

// HasInlineThink reports whether s contains a balanced `<think>...</think>`
// pair. Used by reasoning-format detection to distinguish inline-think
// responses from responses that just happen to have stray angle brackets.
func HasInlineThink(s string) bool {
	for _, re := range thinkBlockPatterns {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// StripCodeFences removes a leading and/or trailing markdown fenced-code
// line so callers extracting a prose summary don't surface the fence marker
// as the "first line". Handles both bare ``` and language-tagged variants
// (```json, ```markdown, etc.) on the opener; the trailing fence must be
// an exact ``` on its own line to avoid accidental stripping inside
// legitimate prose. Only strips one fence at each end — nested blocks are
// out of scope.
func StripCodeFences(s string) string {
	lines := strings.Split(s, "\n")
	start := 0
	for start < len(lines) && strings.TrimSpace(lines[start]) == "" {
		start++
	}
	if start < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[start]), "```") {
		start++
	}
	end := len(lines)
	for end > start && strings.TrimSpace(lines[end-1]) == "" {
		end--
	}
	if end > start && strings.TrimSpace(lines[end-1]) == "```" {
		end--
	}
	return strings.Join(lines[start:end], "\n")
}

// TruncatedThinkTail returns a best-effort tail of the content inside an
// unclosed think block. When a reasoning model hits the token cap mid-thought
// StripThinkBlocks cannot strip the block (there is no close tag), so the
// stripped output still leads with the opening tag and firstLine yields
// nothing useful. Surfacing the model's most recent reasoning is more
// informative for the operator than a silent "empty". Returns "" when no
// unclosed think tag is found.
func TruncatedThinkTail(s string) string {
	lower := strings.ToLower(s)
	for _, p := range thinkTagPairs {
		openLow := strings.ToLower(p.open)
		closeLow := strings.ToLower(p.close)
		openIdx := strings.LastIndex(lower, openLow)
		if openIdx < 0 {
			continue
		}
		afterStart := openIdx + len(p.open)
		if strings.Contains(lower[afterStart:], closeLow) {
			continue
		}
		return compactThinkTail(s[afterStart:], 240)
	}
	return ""
}

// compactThinkTail collapses whitespace and returns the final portion of s
// up to maxChars, starting at the first word boundary after the cut and
// skipping forward to the first sentence boundary when one is present —
// so operators get a clean tail rather than a mid-word fragment.
func compactThinkTail(s string, maxChars int) string {
	collapsed := strings.Join(strings.Fields(s), " ")
	if collapsed == "" {
		return ""
	}
	if len(collapsed) <= maxChars {
		return collapsed
	}
	tail := collapsed[len(collapsed)-maxChars:]
	if sp := strings.IndexByte(tail, ' '); sp > 0 {
		tail = tail[sp+1:]
	}
	for i := 0; i < len(tail); i++ {
		c := tail[i]
		if c == '.' || c == '!' || c == '?' {
			rest := strings.TrimSpace(tail[i+1:])
			if rest != "" {
				return "…" + rest
			}
			break
		}
	}
	return "…" + tail
}
