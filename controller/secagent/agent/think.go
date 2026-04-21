package agent

import "regexp"

// Think-block variants seen in practice. Matches are case-insensitive,
// multiline, non-greedy. Add more as new models surface.
var thinkBlockPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?is)<think>.*?</think>`),
	regexp.MustCompile(`(?is)<thinking>.*?</thinking>`),
	regexp.MustCompile(`(?is)<\|thinking\|>.*?<\|/thinking\|>`),
	regexp.MustCompile(`(?is)<reasoning>.*?</reasoning>`),
}

// StripThinkBlocks removes any recognized thinking-block variants from s.
func StripThinkBlocks(s string) string {
	out := s
	for _, re := range thinkBlockPatterns {
		out = re.ReplaceAllString(out, "")
	}
	return out
}
