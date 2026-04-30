package agent

import "strings"

// FilterErrorMessages returns a copy of msgs with tool-error noise stripped:
// tool-result messages whose Content begins with "ERROR:" (the marker
// applied at openai_agent.go when ToolResult.IsError is set) and synthetic
// repair-error messages (IsRepairError=true) are dropped, along with their
// matching ToolCall entries on the preceding assistant message. An assistant
// message left with no remaining ToolCalls and no Content is dropped too.
//
// Used by summarizer call sites — orphaned tool errors burn context without
// informing the recap and cumulatively dominate the prompt on noisy runs.
func FilterErrorMessages(msgs []Message) []Message {
	if len(msgs) == 0 {
		return msgs
	}
	dropIDs := make(map[string]bool)
	for _, m := range msgs {
		if isErrorToolResult(m) && m.ToolCallID != "" {
			dropIDs[m.ToolCallID] = true
		}
	}
	out := make([]Message, 0, len(msgs))
	for _, m := range msgs {
		switch m.Role {
		case roleTool:
			if isErrorToolResult(m) {
				continue
			}
			out = append(out, m)
		case roleAssistant:
			if len(m.ToolCalls) == 0 {
				out = append(out, m)
				continue
			}
			kept := m
			kept.ToolCalls = filterToolCalls(m.ToolCalls, dropIDs)
			if len(kept.ToolCalls) == 0 && strings.TrimSpace(kept.Content) == "" {
				continue
			}
			out = append(out, kept)
		default:
			out = append(out, m)
		}
	}
	return out
}

// HasSubstantiveMessages reports whether msgs contains anything worth
// summarizing: an assistant message with text or tool_calls, or any
// tool-result message. A slice of only system+user (or empty) is not
// substantive — there is nothing for a summarizer to recap.
//
// Pair with FilterErrorMessages: filter the noise first, then check
// whether anything remains, and skip the LLM call if not.
func HasSubstantiveMessages(msgs []Message) bool {
	for _, m := range msgs {
		switch m.Role {
		case roleAssistant:
			if strings.TrimSpace(m.Content) != "" || len(m.ToolCalls) > 0 {
				return true
			}
		case roleTool:
			return true
		}
	}
	return false
}

func isErrorToolResult(m Message) bool {
	if m.Role != roleTool {
		return false
	}
	if m.IsRepairError {
		return true
	}
	return strings.HasPrefix(m.Content, "ERROR:")
}

func filterToolCalls(tcs []ToolCall, drop map[string]bool) []ToolCall {
	out := make([]ToolCall, 0, len(tcs))
	for _, tc := range tcs {
		if drop[tc.ID] {
			continue
		}
		out = append(out, tc)
	}
	return out
}

// collapseSameToolErrorStreaks drops earlier tool-error messages whose
// IMMEDIATE NEXT tool-result message is also an error from the same tool
// name. Strips matching ToolCall entries from the preceding assistant
// messages and drops assistants left with no tool_calls and no content.
// Returns the modified slice and the count of error messages dropped.
//
// "Same tool consecutive" means the next tool-RESULT message in the stream
// (assistant messages between are ignored, since they only carry tool_calls
// not results). A successful tool-result or an error from a DIFFERENT tool
// breaks the streak — both signal that the model's context shifted, so the
// earlier error may still be informative. This matches the failure pattern
// seen in practice: a worker retrying tool X with bad args 3-5 times in a
// row, where only the final error carries the freshest feedback.
func collapseSameToolErrorStreaks(msgs []Message) ([]Message, int) {
	drop := make(map[string]bool)
	for i, m := range msgs {
		if !isErrorToolResult(m) || m.ToolCallID == "" {
			continue
		}
		for j := i + 1; j < len(msgs); j++ {
			if msgs[j].Role != roleTool {
				continue
			}
			if isErrorToolResult(msgs[j]) && msgs[j].ToolName == m.ToolName {
				drop[m.ToolCallID] = true
			}
			break
		}
	}
	if len(drop) == 0 {
		return msgs, 0
	}
	out := make([]Message, 0, len(msgs))
	dropped := 0
	for _, m := range msgs {
		switch m.Role {
		case roleTool:
			if drop[m.ToolCallID] {
				dropped++
				continue
			}
			out = append(out, m)
		case roleAssistant:
			if len(m.ToolCalls) == 0 {
				out = append(out, m)
				continue
			}
			kept := m
			kept.ToolCalls = filterToolCalls(m.ToolCalls, drop)
			if len(kept.ToolCalls) == 0 && strings.TrimSpace(kept.Content) == "" {
				continue
			}
			out = append(out, kept)
		default:
			out = append(out, m)
		}
	}
	return out, dropped
}
