package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-appsec/secagent/agent"
)

// Severities for validation.
var severities = map[string]bool{
	"critical":      true,
	"high":          true,
	"medium":        true,
	"low":           true,
	"informational": true,
}

var progressTags = map[string]bool{
	"none":        true,
	"incremental": true,
	"new":         true,
}

// WorkerToolDefs builds the per-worker tool set: report_finding_candidate.
func WorkerToolDefs(candidates *CandidatePool, workerID int) []agent.ToolDef {
	return []agent.ToolDef{
		{
			Name: "report_finding_candidate",
			Description: `Report a potential security finding for orchestrator verification.
Include proof flow IDs from your testing (replay_send, request_send, or proxy_poll).
Do NOT write a full finding document — the orchestrator will reproduce the issue and file the formal finding.
Returns a candidate_id confirmation.`,
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"title":    map[string]any{"type": "string", "description": "Concise vulnerability name"},
					"severity": map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low", "informational"}},
					"endpoint": map[string]any{"type": "string", "description": "Affected endpoint path + method"},
					"flow_ids": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Proof flow IDs. At least one required.",
					},
					"summary":           map[string]any{"type": "string"},
					"evidence_notes":    map[string]any{"type": "string"},
					"reproduction_hint": map[string]any{"type": "string"},
				},
				"required": []string{
					"title", "severity", "endpoint", "flow_ids", "summary",
					"evidence_notes", "reproduction_hint",
				},
			},
			Handler: func(ctx context.Context, args json.RawMessage) agent.ToolResult {
				var in struct {
					Title            string   `json:"title"`
					Severity         string   `json:"severity"`
					Endpoint         string   `json:"endpoint"`
					FlowIDs          []string `json:"flow_ids"`
					Summary          string   `json:"summary"`
					EvidenceNotes    string   `json:"evidence_notes"`
					ReproductionHint string   `json:"reproduction_hint"`
				}
				if err := json.Unmarshal(args, &in); err != nil {
					return agent.ToolResult{Text: "Rejected: invalid arguments: " + err.Error(), IsError: true}
				}
				sev := strings.ToLower(in.Severity)
				if !severities[sev] {
					return agent.ToolResult{
						Text:    "Rejected: severity must be one of critical/high/medium/low/informational.",
						IsError: true,
					}
				}
				if len(in.FlowIDs) == 0 {
					return agent.ToolResult{
						Text:    "Rejected: flow_ids must be a non-empty array.",
						IsError: true,
					}
				}
				cid := candidates.Add(AddInput{
					WorkerID:         workerID,
					Title:            orDefault(strings.TrimSpace(in.Title), "untitled"),
					Severity:         sev,
					Endpoint:         strings.TrimSpace(in.Endpoint),
					FlowIDs:          in.FlowIDs,
					Summary:          strings.TrimSpace(in.Summary),
					EvidenceNotes:    strings.TrimSpace(in.EvidenceNotes),
					ReproductionHint: strings.TrimSpace(in.ReproductionHint),
				})
				return agent.ToolResult{
					Text: fmt.Sprintf(
						"Candidate %s recorded. The orchestrator will verify and, if confirmed, file the formal finding. Continue your testing.",
						cid,
					),
				}
			},
		},
	}
}

// VerifierToolDefs builds the in-process tool set for the verifier.
// sectool tools are added separately from the MCP server.
func VerifierToolDefs(decisions *DecisionQueue) []agent.ToolDef {
	reject := func(name string) agent.ToolResult {
		cur := decisions.Phase()
		return agent.ToolResult{
			Text: fmt.Sprintf(
				"Rejected: `%s` is not allowed in phase '%s'. Expected phase 'verification'.",
				name, cur,
			),
			IsError: true,
		}
	}

	return []agent.ToolDef{
		{
			Name: "file_finding",
			Description: `File a verified security finding. Call ONLY after independently reproducing
the issue with sectool tools. The verification_notes field should cite the flow IDs you used.`,
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"title":              map[string]any{"type": "string"},
					"severity":           map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low", "informational"}},
					"endpoint":           map[string]any{"type": "string"},
					"description":        map[string]any{"type": "string"},
					"reproduction_steps": map[string]any{"type": "string"},
					"evidence":           map[string]any{"type": "string"},
					"impact":             map[string]any{"type": "string"},
					"verification_notes": map[string]any{"type": "string"},
					"supersedes_candidate_ids": map[string]any{
						"type":  "array",
						"items": map[string]any{"type": "string"},
					},
				},
				"required": []string{
					"title", "severity", "endpoint", "description",
					"reproduction_steps", "evidence", "impact", "verification_notes",
				},
			},
			Handler: func(ctx context.Context, args json.RawMessage) agent.ToolResult {
				if decisions.Phase() != agent.PhaseVerification {
					return reject("file_finding")
				}
				var in struct {
					Title                  string   `json:"title"`
					Severity               string   `json:"severity"`
					Endpoint               string   `json:"endpoint"`
					Description            string   `json:"description"`
					ReproductionSteps      string   `json:"reproduction_steps"`
					Evidence               string   `json:"evidence"`
					Impact                 string   `json:"impact"`
					VerificationNotes      string   `json:"verification_notes"`
					SupersedesCandidateIDs []string `json:"supersedes_candidate_ids"`
				}
				if err := json.Unmarshal(args, &in); err != nil {
					return agent.ToolResult{Text: "Rejected: invalid arguments: " + err.Error(), IsError: true}
				}
				sev := strings.ToLower(in.Severity)
				if !severities[sev] {
					return agent.ToolResult{
						Text:    "Rejected: severity must be one of critical/high/medium/low/informational.",
						IsError: true,
					}
				}
				notes := strings.TrimSpace(in.VerificationNotes)
				if notes == "" {
					return agent.ToolResult{
						Text:    "Rejected: verification_notes must describe how you reproduced the issue with sectool tools.",
						IsError: true,
					}
				}
				f := FindingFiled{
					Title:                  orDefault(strings.TrimSpace(in.Title), "untitled"),
					Severity:               sev,
					Endpoint:               strings.TrimSpace(in.Endpoint),
					Description:            strings.TrimSpace(in.Description),
					ReproductionSteps:      strings.TrimSpace(in.ReproductionSteps),
					Evidence:               strings.TrimSpace(in.Evidence),
					Impact:                 strings.TrimSpace(in.Impact),
					VerificationNotes:      notes,
					SupersedesCandidateIDs: in.SupersedesCandidateIDs,
				}
				decisions.AddFinding(f)
				return agent.ToolResult{Text: fmt.Sprintf("Finding '%s' recorded for persistence.", f.Title)}
			},
		},
		{
			Name:        "dismiss_candidate",
			Description: `Mark a worker-reported finding candidate as not a real issue. Provide a short reason.`,
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"candidate_id": map[string]any{"type": "string"},
					"reason":       map[string]any{"type": "string"},
				},
				"required": []string{"candidate_id", "reason"},
			},
			Handler: func(ctx context.Context, args json.RawMessage) agent.ToolResult {
				if decisions.Phase() != agent.PhaseVerification {
					return reject("dismiss_candidate")
				}
				var in struct {
					CandidateID string `json:"candidate_id"`
					Reason      string `json:"reason"`
				}
				if err := json.Unmarshal(args, &in); err != nil {
					return agent.ToolResult{Text: "Rejected: invalid arguments.", IsError: true}
				}
				cid := strings.TrimSpace(in.CandidateID)
				reason := strings.TrimSpace(in.Reason)
				if cid == "" || reason == "" {
					return agent.ToolResult{
						Text:    "Rejected: candidate_id and reason required.",
						IsError: true,
					}
				}
				decisions.AddDismissal(cid, reason)
				return agent.ToolResult{Text: fmt.Sprintf("Candidate %s dismissal recorded.", cid)}
			},
		},
		{
			Name:        "verification_done",
			Description: `Signal that the verification phase is complete.`,
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"summary": map[string]any{"type": "string"},
				},
				"required": []string{"summary"},
			},
			Handler: func(ctx context.Context, args json.RawMessage) agent.ToolResult {
				if decisions.Phase() != agent.PhaseVerification {
					return reject("verification_done")
				}
				var in struct {
					Summary string `json:"summary"`
				}
				if err := json.Unmarshal(args, &in); err != nil {
					return agent.ToolResult{Text: "Rejected: invalid arguments.", IsError: true}
				}
				s := strings.TrimSpace(in.Summary)
				if s == "" {
					return agent.ToolResult{Text: "Rejected: summary is required.", IsError: true}
				}
				decisions.SetVerificationDone(s)
				return agent.ToolResult{Text: "Verification phase complete."}
			},
		},
	}
}

// DirectorToolDefs builds the in-process tool set for the director.
func DirectorToolDefs(decisions *DecisionQueue) []agent.ToolDef {
	reject := func(name string) agent.ToolResult {
		cur := decisions.Phase()
		return agent.ToolResult{
			Text: fmt.Sprintf(
				"Rejected: `%s` is not allowed in phase '%s'. Expected phase 'direction'.",
				name, cur,
			),
			IsError: true,
		}
	}

	workerDirectiveSchema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"worker_id":         map[string]any{"type": "integer", "minimum": 1},
			"instruction":       map[string]any{"type": "string"},
			"progress":          map[string]any{"type": "string", "enum": []string{"none", "incremental", "new"}},
			"autonomous_budget": map[string]any{"type": "integer", "minimum": 1, "maximum": 20},
		},
		"required": []string{"worker_id", "instruction", "progress"},
	}

	recordDecision := func(kind string, args json.RawMessage) agent.ToolResult {
		if decisions.Phase() != agent.PhaseDirection {
			return reject(kind + "_worker")
		}
		var in struct {
			WorkerID         int    `json:"worker_id"`
			Instruction      string `json:"instruction"`
			Progress         string `json:"progress"`
			AutonomousBudget int    `json:"autonomous_budget"`
		}
		if err := json.Unmarshal(args, &in); err != nil {
			return agent.ToolResult{Text: "Rejected: invalid arguments.", IsError: true}
		}
		if in.WorkerID < 1 {
			return agent.ToolResult{Text: "Rejected: worker_id required.", IsError: true}
		}
		if !progressTags[in.Progress] {
			return agent.ToolResult{
				Text:    "Rejected: progress must be one of none/incremental/new.",
				IsError: true,
			}
		}
		if strings.TrimSpace(in.Instruction) == "" {
			return agent.ToolResult{Text: "Rejected: instruction is required.", IsError: true}
		}
		budget := in.AutonomousBudget
		if budget <= 0 {
			budget = defaultAutonomousBudget
		}
		budget = min(budget, 20)
		decisions.AddDecision(WorkerDecision{
			Kind:             kind,
			WorkerID:         in.WorkerID,
			Instruction:      in.Instruction,
			Progress:         in.Progress,
			AutonomousBudget: budget,
		})
		return agent.ToolResult{
			Text: fmt.Sprintf(
				"%s recorded for worker %d (progress=%s, autonomous_budget=%d).",
				kind, in.WorkerID, in.Progress, budget,
			),
		}
	}

	return []agent.ToolDef{
		{
			Name:        "plan_workers",
			Description: `Spawn or retarget workers for parallel testing.`,
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"plans": map[string]any{
						"type": "array",
						"items": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"worker_id":  map[string]any{"type": "integer", "minimum": 1},
								"assignment": map[string]any{"type": "string"},
							},
							"required": []string{"worker_id", "assignment"},
						},
					},
				},
				"required": []string{"plans"},
			},
			Handler: func(ctx context.Context, args json.RawMessage) agent.ToolResult {
				if decisions.Phase() != agent.PhaseDirection {
					return reject("plan_workers")
				}
				var in struct {
					Plans []struct {
						WorkerID   int    `json:"worker_id"`
						Assignment string `json:"assignment"`
					} `json:"plans"`
				}
				if err := json.Unmarshal(args, &in); err != nil {
					return agent.ToolResult{Text: "Rejected: invalid arguments.", IsError: true}
				}
				var entries []PlanEntry
				for _, p := range in.Plans {
					asg := strings.TrimSpace(p.Assignment)
					if p.WorkerID < 1 || asg == "" {
						continue
					}
					entries = append(entries, PlanEntry{WorkerID: p.WorkerID, Assignment: asg})
				}
				if len(entries) == 0 {
					return agent.ToolResult{Text: "Rejected: no valid plan entries.", IsError: true}
				}
				decisions.SetPlan(entries)
				return agent.ToolResult{
					Text: fmt.Sprintf("Plan recorded: %d worker assignment(s).", len(entries)),
				}
			},
		},
		{
			Name:        "continue_worker",
			Description: `Tell worker N to keep going with its current plan.`,
			Schema:      workerDirectiveSchema,
			Handler: func(ctx context.Context, args json.RawMessage) agent.ToolResult {
				return recordDecision("continue", args)
			},
		},
		{
			Name:        "expand_worker",
			Description: `Pivot worker N with an adjusted plan.`,
			Schema:      workerDirectiveSchema,
			Handler: func(ctx context.Context, args json.RawMessage) agent.ToolResult {
				return recordDecision("expand", args)
			},
		},
		{
			Name:        "stop_worker",
			Description: `Stop worker N.`,
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"worker_id": map[string]any{"type": "integer", "minimum": 1},
					"reason":    map[string]any{"type": "string"},
				},
				"required": []string{"worker_id", "reason"},
			},
			Handler: func(ctx context.Context, args json.RawMessage) agent.ToolResult {
				if decisions.Phase() != agent.PhaseDirection {
					return reject("stop_worker")
				}
				var in struct {
					WorkerID int    `json:"worker_id"`
					Reason   string `json:"reason"`
				}
				if err := json.Unmarshal(args, &in); err != nil {
					return agent.ToolResult{Text: "Rejected: invalid arguments.", IsError: true}
				}
				if in.WorkerID < 1 {
					return agent.ToolResult{Text: "Rejected: worker_id required.", IsError: true}
				}
				if strings.TrimSpace(in.Reason) == "" {
					return agent.ToolResult{Text: "Rejected: reason is required.", IsError: true}
				}
				decisions.AddDecision(WorkerDecision{
					Kind: "stop", WorkerID: in.WorkerID, Reason: in.Reason,
				})
				return agent.ToolResult{Text: fmt.Sprintf("stop recorded for worker %d.", in.WorkerID)}
			},
		},
		{
			Name:        "direction_done",
			Description: `Signal direction phase complete.`,
			Schema: map[string]any{
				"type":       "object",
				"properties": map[string]any{"summary": map[string]any{"type": "string"}},
				"required":   []string{"summary"},
			},
			Handler: func(ctx context.Context, args json.RawMessage) agent.ToolResult {
				if decisions.Phase() != agent.PhaseDirection {
					return reject("direction_done")
				}
				var in struct {
					Summary string `json:"summary"`
				}
				if err := json.Unmarshal(args, &in); err != nil {
					return agent.ToolResult{Text: "Rejected: invalid arguments.", IsError: true}
				}
				s := strings.TrimSpace(in.Summary)
				if s == "" {
					return agent.ToolResult{Text: "Rejected: summary is required.", IsError: true}
				}
				decisions.SetDirectionDone(s)
				return agent.ToolResult{Text: "Direction phase complete."}
			},
		},
		{
			Name:        "done",
			Description: `Signal that the exploration run should end.`,
			Schema: map[string]any{
				"type":       "object",
				"properties": map[string]any{"summary": map[string]any{"type": "string"}},
				"required":   []string{"summary"},
			},
			Handler: func(ctx context.Context, args json.RawMessage) agent.ToolResult {
				if decisions.Phase() != agent.PhaseDirection {
					return reject("done")
				}
				var in struct {
					Summary string `json:"summary"`
				}
				if err := json.Unmarshal(args, &in); err != nil {
					return agent.ToolResult{Text: "Rejected: invalid arguments.", IsError: true}
				}
				s := strings.TrimSpace(in.Summary)
				if s == "" {
					return agent.ToolResult{Text: "Rejected: summary is required.", IsError: true}
				}
				decisions.SetDone(s)
				return agent.ToolResult{Text: "Run end signaled."}
			},
		},
	}
}
