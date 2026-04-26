package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
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

// MergeSubmitter schedules an asynchronous merge of a worker-reported
// candidate into an already-filed finding. The implementation owns goroutine
// lifetime and bounded concurrency; the worker tool just calls Submit and
// continues. Pass nil to disable async merge (the dedup verdict "merge"
// degrades to "duplicate" in that case).
type MergeSubmitter interface {
	Submit(matchedFilename string, incoming AddInput)
}

// WorkerToolDefs builds the per-worker tool set: report_finding_candidate.
//
// dedupReviewer (optional) classifies each incoming candidate against
// already-filed findings via the summary model. When nil, the deterministic
// writer.MatchesFiled fallback runs instead.
//
// merger (optional) is invoked when the dedup verdict is "merge" — the
// candidate is acknowledged synchronously and the merge proceeds in a
// background goroutine owned by the submitter. When nil, "merge" verdicts
// degrade to "duplicate" rejections.
func WorkerToolDefs(
	candidates *CandidatePool,
	writer *FindingWriter,
	workerID int,
	dedupReviewer CandidateDedupReviewer,
	merger MergeSubmitter,
) []agent.ToolDef {
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
				if err := unmarshalToolArgs(args, &in); err != nil {
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
				addIn := AddInput{
					WorkerID:         workerID,
					Title:            orDefault(strings.TrimSpace(in.Title), "untitled"),
					Severity:         sev,
					Endpoint:         strings.TrimSpace(in.Endpoint),
					FlowIDs:          in.FlowIDs,
					Summary:          strings.TrimSpace(in.Summary),
					EvidenceNotes:    strings.TrimSpace(in.EvidenceNotes),
					ReproductionHint: strings.TrimSpace(in.ReproductionHint),
				}
				if writer != nil {
					if rej, ok := dedupRejectOrMerge(ctx, dedupReviewer, merger, writer, addIn); ok {
						return rej
					}
				}
				cid := candidates.Add(addIn)
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

// dedupRejectOrMerge consults the dedup pipeline and returns (result, true)
// when the candidate should NOT be added to the pool — either because it
// duplicates an existing finding or because it was queued for async merge.
// Returns (_, false) when the candidate is unique and should proceed to
// CandidatePool.Add.
//
// When dedupReviewer is nil, falls back to writer.MatchesFiled (deterministic
// slug + endpoint match), preserving the prior behaviour.
func dedupRejectOrMerge(
	ctx context.Context,
	dedupReviewer CandidateDedupReviewer,
	merger MergeSubmitter,
	writer *FindingWriter,
	in AddInput,
) (agent.ToolResult, bool) {
	if dedupReviewer == nil {
		if matched, path, ok := writer.MatchesFiled(in.Title, in.Endpoint); ok {
			return agent.ToolResult{
				Text: fmt.Sprintf(
					"Rejected: matches already-filed finding %q (%s). Pick a different angle — do not re-report this issue.",
					matched, filepath.Base(path),
				),
				IsError: true,
			}, true
		}
		return agent.ToolResult{}, false
	}
	digests := writer.Digests()
	if len(digests) == 0 {
		return agent.ToolResult{}, false
	}
	verdict, err := dedupReviewer.ClassifyCandidate(ctx, in, digests)
	if err != nil {
		// Fail-open on classifier errors: let the candidate enter the pool
		// and rely on the verifier-side dedup pipeline as the safety net.
		return agent.ToolResult{}, false
	}
	switch verdict.Action {
	case dedupActionDuplicate:
		return agent.ToolResult{
			Text: fmt.Sprintf(
				"Rejected: matches already-filed finding %s. Pick a different angle — your candidate is fully covered there.",
				verdict.MatchedFilename,
			),
			IsError: true,
		}, true
	case dedupActionMerge:
		if merger == nil {
			// No async merge available — degrade to a duplicate-style reject.
			return agent.ToolResult{
				Text: fmt.Sprintf(
					"Rejected: matches already-filed finding %s. Pick a different angle — your candidate is fully covered there.",
					verdict.MatchedFilename,
				),
				IsError: true,
			}, true
		}
		merger.Submit(verdict.MatchedFilename, in)
		return agent.ToolResult{
			Text: fmt.Sprintf(
				"Match detected with finding %s. Your evidence will be merged into that finding in the background — pick a different angle next.",
				verdict.MatchedFilename,
			),
		}, true
	}
	return agent.ToolResult{}, false
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
the issue with sectool tools. All fields must be session-agnostic: describe endpoints, payloads,
headers, and observed behavior — never cite flow IDs, OAST session IDs, or other ephemeral test state.`,
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"title":       map[string]any{"type": "string"},
					"severity":    map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low", "informational"}},
					"endpoint":    map[string]any{"type": "string"},
					"description": map[string]any{"type": "string"},
					"reproduction_steps": map[string]any{
						"type":        "string",
						"description": "Step-by-step reproduction using endpoint, method, headers, and payload — no flow IDs or session references.",
					},
					"evidence": map[string]any{
						"type":        "string",
						"description": "Observable proof: response content, status codes, headers, behavior — no flow IDs or session references.",
					},
					"impact": map[string]any{"type": "string"},
					"verification_notes": map[string]any{
						"type":        "string",
						"description": "How you reproduced the issue: tools used, mutations applied, what you observed — no flow IDs or session IDs.",
					},
					"supersedes_candidate_ids": map[string]any{
						"type":  "array",
						"items": map[string]any{"type": "string"},
					},
					"follow_up_hint": map[string]any{
						"type":        "string",
						"description": "Optional one-line hint for the director: a related angle, variant, or adjacent endpoint worth probing next. Advisory only; omit if nothing stands out.",
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
					FollowUpHint           string   `json:"follow_up_hint"`
				}
				if err := unmarshalToolArgs(args, &in); err != nil {
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
					FollowUpHint:           strings.TrimSpace(in.FollowUpHint),
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
					"follow_up_hint": map[string]any{
						"type":        "string",
						"description": "Optional one-line hint for the director: a related angle or real lead this dead-end points toward. Advisory only; omit if nothing stands out.",
					},
				},
				"required": []string{"candidate_id", "reason"},
			},
			Handler: func(ctx context.Context, args json.RawMessage) agent.ToolResult {
				if decisions.Phase() != agent.PhaseVerification {
					return reject("dismiss_candidate")
				}
				var in struct {
					CandidateID  string `json:"candidate_id"`
					Reason       string `json:"reason"`
					FollowUpHint string `json:"follow_up_hint"`
				}
				if err := unmarshalToolArgs(args, &in); err != nil {
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
				decisions.AddDismissal(CandidateDismissal{
					CandidateID:  cid,
					Reason:       reason,
					FollowUpHint: strings.TrimSpace(in.FollowUpHint),
				})
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
				if err := unmarshalToolArgs(args, &in); err != nil {
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
//
// guardState returns (iteration, findingsThisRun). It must be non-nil — the
// end_run handler consults it to reject premature calls that local models
// emit when they confuse end_run with direction_done. Pass a closure that
// captures the controller's loop iteration and writer.RunCount.
func DirectorToolDefs(
	decisions *DecisionQueue,
	guardState func() (iter, runFindings int),
) []agent.ToolDef {
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
		if err := unmarshalToolArgs(args, &in); err != nil {
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
				if err := unmarshalToolArgs(args, &in); err != nil {
					return agent.ToolResult{
						Text: fmt.Sprintf(
							"Rejected: cannot parse arguments (%s). Expected JSON shape {\"plans\":[{\"worker_id\":N,\"assignment\":\"...\"}]}.",
							err.Error(),
						),
						IsError: true,
					}
				}
				if len(in.Plans) == 0 {
					return agent.ToolResult{
						Text:    "Rejected: 'plans' array is empty. Provide at least one {worker_id, assignment} object.",
						IsError: true,
					}
				}
				var entries []PlanEntry
				var reasons []string
				for i, p := range in.Plans {
					asg := strings.TrimSpace(p.Assignment)
					if p.WorkerID < 1 {
						reasons = append(reasons, fmt.Sprintf("plans[%d]: worker_id must be >= 1 (got %d)", i, p.WorkerID))
						continue
					}
					if asg == "" {
						reasons = append(reasons, fmt.Sprintf("plans[%d] (worker_id=%d): assignment is empty", i, p.WorkerID))
						continue
					}
					entries = append(entries, PlanEntry{WorkerID: p.WorkerID, Assignment: asg})
				}
				if len(entries) == 0 {
					msg := "Rejected: no valid plan entries."
					if len(reasons) > 0 {
						msg += " " + strings.Join(reasons, "; ")
					}
					return agent.ToolResult{Text: msg, IsError: true}
				}
				decisions.SetPlan(entries)
				text := fmt.Sprintf("Plan recorded: %d worker assignment(s).", len(entries))
				if len(reasons) > 0 {
					text += " Skipped: " + strings.Join(reasons, "; ")
				}
				return agent.ToolResult{Text: text}
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
			Name: "fork_worker",
			Description: `Spawn a new worker that inherits the parent's investigative summary plus a steering instruction. ` +
				`Use when an in-progress worker has uncovered a permutation worth a parallel deep-dive while the parent continues its current line. ` +
				`Distinct from plan_workers (fresh, no inherited memory) and expand_worker (retargets the same worker in place). ` +
				`Example: {"parent_worker_id":3,"new_worker_id":9,"instruction":"Pursue the JWT alg=none variant on /oauth2/userinfo that worker 3 just discovered."}`,
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"parent_worker_id": map[string]any{"type": "integer", "minimum": 1},
					"new_worker_id":    map[string]any{"type": "integer", "minimum": 1},
					"instruction":      map[string]any{"type": "string"},
				},
				"required": []string{"parent_worker_id", "new_worker_id", "instruction"},
			},
			Handler: func(ctx context.Context, args json.RawMessage) agent.ToolResult {
				if decisions.Phase() != agent.PhaseDirection {
					return reject("fork_worker")
				}
				var in struct {
					ParentWorkerID int    `json:"parent_worker_id"`
					NewWorkerID    int    `json:"new_worker_id"`
					Instruction    string `json:"instruction"`
				}
				if err := unmarshalToolArgs(args, &in); err != nil {
					return agent.ToolResult{Text: "Rejected: invalid arguments.", IsError: true}
				}
				if in.ParentWorkerID < 1 || in.NewWorkerID < 1 {
					return agent.ToolResult{Text: "Rejected: parent_worker_id and new_worker_id must both be >= 1.", IsError: true}
				}
				if in.ParentWorkerID == in.NewWorkerID {
					return agent.ToolResult{Text: "Rejected: parent_worker_id and new_worker_id must differ.", IsError: true}
				}
				if strings.TrimSpace(in.Instruction) == "" {
					return agent.ToolResult{Text: "Rejected: instruction is required.", IsError: true}
				}
				decisions.AddFork(ForkEntry{
					ParentWorkerID: in.ParentWorkerID,
					NewWorkerID:    in.NewWorkerID,
					Instruction:    in.Instruction,
				})
				return agent.ToolResult{Text: fmt.Sprintf(
					"fork recorded: worker %d will inherit worker %d's investigation.",
					in.NewWorkerID, in.ParentWorkerID,
				)}
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
				if err := unmarshalToolArgs(args, &in); err != nil {
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
				if err := unmarshalToolArgs(args, &in); err != nil {
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
			Name: "end_run",
			Description: `End the ENTIRE exploration run. Use only after many iterations when ` +
				`the assignment is exhausted and findings have been filed (or the target is confidently clean). ` +
				`Never use this to close a phase — that is direction_done's job.`,
			Schema: map[string]any{
				"type":       "object",
				"properties": map[string]any{"summary": map[string]any{"type": "string"}},
				"required":   []string{"summary"},
			},
			Handler: func(ctx context.Context, args json.RawMessage) agent.ToolResult {
				if decisions.Phase() != agent.PhaseDirection {
					return reject("end_run")
				}
				var in struct {
					Summary string `json:"summary"`
				}
				if err := unmarshalToolArgs(args, &in); err != nil {
					return agent.ToolResult{Text: "Rejected: invalid arguments.", IsError: true}
				}
				s := strings.TrimSpace(in.Summary)
				if s == "" {
					return agent.ToolResult{Text: "Rejected: summary is required.", IsError: true}
				}
				iter, runFindings := guardState()
				if iter < MinIterationsForDone && runFindings == 0 {
					return agent.ToolResult{
						Text: fmt.Sprintf(
							"Rejected: `end_run` is premature (iteration %d/%d, %d findings filed this run). "+
								"Use `direction_done(summary)` to close this phase. `end_run` ends the ENTIRE run "+
								"and is only for exhausted assignments after findings have been filed.",
							iter, MinIterationsForDone, runFindings,
						),
						IsError: true,
					}
				}
				decisions.SetEndRun(s)
				return agent.ToolResult{Text: "Run end signaled."}
			},
		},
	}
}
