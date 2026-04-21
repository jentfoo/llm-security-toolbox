package agent

// ClassifyEscalation applies the spec's escalation rules to a TurnSummary
// and returns the escalation reason. "" means productive (keep running).
// candidateFound is a controller-supplied signal (true when the turn
// produced at least one new candidate_id attributed to this worker).
func ClassifyEscalation(s TurnSummary, candidateFound bool) string {
	if s.TimedOut {
		return escalationSilent
	}
	if candidateFound {
		return escalationCandidate
	}
	if len(s.ToolCalls) == 0 && len(s.FlowIDs) == 0 {
		return escalationSilent
	}
	return ""
}
