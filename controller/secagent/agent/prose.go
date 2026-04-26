package agent

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/go-analyze/bulk"
)

// outputMarkers are common patterns reasoning models use to demarcate their
// intended response from internal thinking. Ordered most-specific-first so
// longer markers match before shorter substrings of the same pattern.
var outputMarkers = []string{
	"final output:",
	"final answer:",
	"my response:",
	"my answer:",
	"final:",
	"output:",
	"answer:",
	"response:",
}

// jsonSummaryFields are field names we'll probe on a JSON-wrapped response
// to extract the actual prose line.
var jsonSummaryFields = []string{
	"summary", "status", "description", "message",
	"text", "content", "response", "output", "answer",
}

// ExtractProse returns a best-effort single-line prose summary from s. Strips
// think blocks, peels code fences, probes JSON fields, looks for output
// markers, and skips structural lines. Returns "" when nothing usable remains.
func ExtractProse(s string) string {
	s = StripCodeFences(StripThinkBlocks(s))
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// Unclosed think tag residue — not usable prose; caller should fall
	// back to Tail/TruncatedThinkTail.
	if HasLeadingThinkOpen(s) {
		return ""
	}
	if len(s) > 0 && (s[0] == '{' || s[0] == '[') {
		line, validJSON := extractFromJSON(s)
		if validJSON {
			// Commit to JSON path: line may be "" (object had no usable
			// strings), but falling through would surface structural noise.
			return line
		}
	}
	if line := ExtractMarkedOutput(s); line != "" {
		return line
	}
	return firstMeaningfulLine(s)
}

// ExtractMarkedOutput scans s for the last occurrence of any output marker
// (case-insensitive) and returns the prose immediately following it, capped
// at the first newline or sentence-ending punctuation. Returns "" when no
// marker is found.
//
// Intended to salvage the real response from reasoning models that wrap
// their output in meta-narration ("…Output matches.✅ Final: The agent
// just dispatched a test request.")
func ExtractMarkedOutput(s string) string {
	lower := strings.ToLower(s)
	bestIdx := -1
	var bestLen int
	for _, m := range outputMarkers {
		idx := strings.LastIndex(lower, m)
		if idx > bestIdx {
			bestIdx = idx
			bestLen = len(m)
		}
	}
	if bestIdx < 0 {
		return ""
	}
	after := strings.TrimSpace(s[bestIdx+bestLen:])
	return firstSentenceOrLine(after)
}

// extractFromJSON tries to parse s as a JSON object and returns the first
// non-empty string value from a known summary-field name, falling back to
// any string value if no known field matches. The second return value
// signals "parsed as valid JSON"; callers use it to commit to the JSON
// path versus falling through to other extraction (so `{}` returns (""
// ,true) and doesn't get recovered as structural-noise prose).
func extractFromJSON(s string) (string, bool) {
	var obj map[string]any
	if err := json.Unmarshal([]byte(s), &obj); err != nil {
		return "", false
	}
	for _, k := range jsonSummaryFields {
		if v, ok := obj[k].(string); ok {
			if trimmed := strings.TrimSpace(v); trimmed != "" {
				return firstSentenceOrLine(trimmed), true
			}
		}
	}
	keys := bulk.MapKeysSlice(obj)
	sort.Strings(keys)
	for _, k := range keys {
		if v, ok := obj[k].(string); ok {
			if trimmed := strings.TrimSpace(v); trimmed != "" {
				return firstSentenceOrLine(trimmed), true
			}
		}
	}
	return "", true
}

// firstSentenceOrLine returns s up to the first newline or sentence-ending
// punctuation (.!?), whichever comes first. Trims whitespace. When neither
// boundary exists, returns the whole trimmed string.
func firstSentenceOrLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\n' {
			return strings.TrimSpace(s[:i])
		}
		if c == '.' || c == '!' || c == '?' {
			return strings.TrimSpace(s[:i+1])
		}
	}
	return s
}

// structuralOnlyLines is the set of trimmed line contents we treat as
// "structural noise" — a model emitting `{` on its own line is almost
// certainly wrapping JSON, not producing a summary.
var structuralOnlyLines = map[string]bool{
	"{": true, "}": true, "[": true, "]": true,
	"\"": true, "'": true, "`": true,
	",": true, ":": true,
	"```": true,
}

// firstMeaningfulLine walks s line by line and returns the first line whose
// trimmed content is not empty and not a single structural character.
// Returns "" when every line is empty or structural.
func firstMeaningfulLine(s string) string {
	for s != "" {
		var line string
		if nl := strings.IndexByte(s, '\n'); nl >= 0 {
			line = s[:nl]
			s = s[nl+1:]
		} else {
			line = s
			s = ""
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || structuralOnlyLines[trimmed] {
			continue
		}
		return trimmed
	}
	return ""
}
