"""SDK MCP tool definitions for worker and orchestrator agents.

Tools append records into in-process queues; the controller drains them each
turn. Handlers return short acknowledgements — real dispatch happens in the
controller loop.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from typing import Any

from claude_agent_sdk import create_sdk_mcp_server, tool


SEVERITIES = ("critical", "high", "medium", "low", "informational")
PROGRESS_TAGS = ("none", "incremental", "new")


# ---------------------------------------------------------------------------
# Worker turn summary
# ---------------------------------------------------------------------------


@dataclass
class ToolCallRecord:
    """One tool call observed in a worker turn."""

    name: str
    input_summary: str
    result_summary: str = ""
    is_error: bool = False


@dataclass
class WorkerTurnSummary:
    """Structured summary of a single worker's turn."""

    worker_id: int
    iteration: int
    assistant_text: str = ""
    tool_calls: list[ToolCallRecord] = field(default_factory=list)
    flow_ids_touched: list[str] = field(default_factory=list)
    candidate_ids: list[str] = field(default_factory=list)
    cost_usd: float | None = None


# ---------------------------------------------------------------------------
# Finding candidates (worker-reported, unverified)
# ---------------------------------------------------------------------------


@dataclass
class FindingCandidate:
    candidate_id: str
    worker_id: int | None
    title: str
    severity: str
    endpoint: str
    flow_ids: list[str]
    summary: str
    evidence_notes: str
    reproduction_hint: str
    status: str = "pending"  # pending | verified | dismissed


class CandidatePool:
    """Thread-safe pool of worker-reported finding candidates."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_id: dict[str, FindingCandidate] = {}
        self._order: list[str] = []
        self._counter = 0
        # Controller sets this before awaiting a worker response so any
        # candidates raised during that turn are attributed to the worker.
        self.active_worker_id: int | None = None

    def add(
        self,
        *,
        title: str,
        severity: str,
        endpoint: str,
        flow_ids: list[str],
        summary: str,
        evidence_notes: str,
        reproduction_hint: str,
    ) -> str:
        with self._lock:
            self._counter += 1
            cid = f"c{self._counter:03d}"
            cand = FindingCandidate(
                candidate_id=cid,
                worker_id=self.active_worker_id,
                title=title,
                severity=severity,
                endpoint=endpoint,
                flow_ids=list(flow_ids),
                summary=summary,
                evidence_notes=evidence_notes,
                reproduction_hint=reproduction_hint,
            )
            self._by_id[cid] = cand
            self._order.append(cid)
            return cid

    def get(self, candidate_id: str) -> FindingCandidate | None:
        with self._lock:
            return self._by_id.get(candidate_id)

    def pending(self) -> list[FindingCandidate]:
        with self._lock:
            return [self._by_id[i] for i in self._order if self._by_id[i].status == "pending"]

    def mark(self, candidate_id: str, status: str) -> None:
        with self._lock:
            c = self._by_id.get(candidate_id)
            if c is not None:
                c.status = status

    def ids_since(self, counter_before: int) -> list[str]:
        """IDs minted after `counter_before`."""
        with self._lock:
            return [f"c{i:03d}" for i in range(counter_before + 1, self._counter + 1)]

    @property
    def counter(self) -> int:
        with self._lock:
            return self._counter


# ---------------------------------------------------------------------------
# Orchestrator decisions
# ---------------------------------------------------------------------------


@dataclass
class WorkerDecision:
    """Per-worker orchestrator decision."""

    kind: str  # continue | expand | stop
    worker_id: int
    instruction: str = ""
    progress: str = "none"
    reason: str = ""


@dataclass
class PlanEntry:
    worker_id: int
    assignment: str


@dataclass
class FindingFiled:
    title: str
    severity: str
    endpoint: str
    description: str
    reproduction_steps: str
    evidence: str
    impact: str
    verification_notes: str
    supersedes_candidate_ids: list[str] = field(default_factory=list)


@dataclass
class CandidateDismissal:
    candidate_id: str
    reason: str


class DecisionQueue:
    """Collects orchestrator tool calls within a single orchestrator turn."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.plan: list[PlanEntry] | None = None
        self.worker_decisions: list[WorkerDecision] = []
        self.findings: list[FindingFiled] = []
        self.dismissals: list[CandidateDismissal] = []
        self.done_summary: str | None = None

    def reset(self) -> None:
        with self._lock:
            self.plan = None
            self.worker_decisions = []
            self.findings = []
            self.dismissals = []
            self.done_summary = None

    def set_plan(self, plan: list[PlanEntry]) -> None:
        with self._lock:
            self.plan = list(plan)

    def add_decision(self, d: WorkerDecision) -> None:
        with self._lock:
            self.worker_decisions.append(d)

    def add_finding(self, f: FindingFiled) -> None:
        with self._lock:
            self.findings.append(f)

    def add_dismissal(self, candidate_id: str, reason: str) -> None:
        with self._lock:
            self.dismissals.append(CandidateDismissal(candidate_id=candidate_id, reason=reason))

    def set_done(self, summary: str) -> None:
        with self._lock:
            self.done_summary = summary


# ---------------------------------------------------------------------------
# Flow ID extraction
# ---------------------------------------------------------------------------


# Flow IDs (sectool/service/ids/ids.go): base62, default length 6, entity IDs 4.
# Only match prefixed forms — a bare `flow` keyword mis-matches prose like
# "flow chart" → "chart". Structured sources are handled by the dict walker.
_FLOW_ID_RE = re.compile(
    r"""(?:flow[_ ]?id|flow_a|flow_b|source_flow_id)\b   # keyword
        \s*[:=]?\s*                                      # optional sep
        ["']?                                            # optional quote
        ([0-9A-Za-z]{4,16})                              # base62 token
    """,
    re.VERBOSE | re.IGNORECASE,
)


def extract_flow_ids(*sources: Any) -> list[str]:
    """Extract sectool flow IDs from a mix of strings, dicts, and lists.

    Order-preserving and deduplicated.
    """
    seen: dict[str, None] = {}

    def walk(val: Any) -> None:
        if val is None:
            return
        if isinstance(val, str):
            for m in _FLOW_ID_RE.finditer(val):
                fid = m.group(1)
                if fid not in seen:
                    seen[fid] = None
            return
        if isinstance(val, dict):
            for k, v in val.items():
                if isinstance(k, str) and k.lower() in (
                    "flow_id",
                    "flow_a",
                    "flow_b",
                    "source_flow_id",
                ) and isinstance(v, str) and v:
                    if v not in seen:
                        seen[v] = None
                walk(v)
            return
        if isinstance(val, (list, tuple)):
            for item in val:
                walk(item)

    for src in sources:
        walk(src)
    return list(seen.keys())


# ---------------------------------------------------------------------------
# Worker MCP server — report_finding_candidate
# ---------------------------------------------------------------------------


def build_worker_mcp_server(candidates: CandidatePool) -> Any:
    """SDK MCP server that exposes `report_finding_candidate` to workers."""

    @tool(
        "report_finding_candidate",
        (
            "Report a potential security finding for orchestrator verification. "
            "Include proof flow IDs from your testing (replay_send, request_send, "
            "or proxy_poll). Do NOT write a full finding document — the "
            "orchestrator will reproduce the issue and file the formal finding. "
            "Returns a candidate_id confirmation."
        ),
        {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Concise vulnerability name"},
                "severity": {"type": "string", "enum": list(SEVERITIES)},
                "endpoint": {"type": "string", "description": "Affected endpoint path + method"},
                "flow_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Proof flow IDs. At least one required.",
                },
                "summary": {"type": "string", "description": "1-3 sentence description"},
                "evidence_notes": {
                    "type": "string",
                    "description": "What makes this exploitable — response content, status codes, behavior.",
                },
                "reproduction_hint": {
                    "type": "string",
                    "description": "How the orchestrator should re-run to verify.",
                },
            },
            "required": [
                "title",
                "severity",
                "endpoint",
                "flow_ids",
                "summary",
                "evidence_notes",
                "reproduction_hint",
            ],
        },
    )
    async def report_finding_candidate(args: dict[str, Any]) -> dict[str, Any]:
        severity = str(args.get("severity", "")).lower()
        if severity not in SEVERITIES:
            return {
                "content": [{
                    "type": "text",
                    "text": f"Rejected: severity must be one of {SEVERITIES}.",
                }],
                "is_error": True,
            }
        flow_ids = args.get("flow_ids") or []
        if not isinstance(flow_ids, list) or not flow_ids:
            return {
                "content": [{
                    "type": "text",
                    "text": "Rejected: flow_ids must be a non-empty array.",
                }],
                "is_error": True,
            }
        cid = candidates.add(
            title=str(args.get("title", "")).strip() or "untitled",
            severity=severity,
            endpoint=str(args.get("endpoint", "")).strip(),
            flow_ids=[str(f) for f in flow_ids],
            summary=str(args.get("summary", "")).strip(),
            evidence_notes=str(args.get("evidence_notes", "")).strip(),
            reproduction_hint=str(args.get("reproduction_hint", "")).strip(),
        )
        return {
            "content": [{
                "type": "text",
                "text": (
                    f"Candidate {cid} recorded. The orchestrator will verify and, "
                    "if confirmed, file the formal finding. Continue your testing."
                ),
            }],
        }

    return create_sdk_mcp_server(
        name="worker_tools",
        version="1.0.0",
        tools=[report_finding_candidate],
    )


# ---------------------------------------------------------------------------
# Orchestrator MCP server — decision + finding tools
# ---------------------------------------------------------------------------


def build_orch_mcp_server(decisions: DecisionQueue) -> Any:
    """SDK MCP server with the orchestrator's decision + finding tools."""

    @tool(
        "plan_workers",
        (
            "Spawn or retarget workers for parallel testing. Provide a list of "
            "{worker_id, assignment} entries; worker IDs start at 1. Callable any "
            "turn. The controller diffs against the current worker set: new IDs "
            "are spawned, existing IDs are retargeted, and omitted alive workers "
            "are left running (use stop_worker to retire)."
        ),
        {
            "type": "object",
            "properties": {
                "plans": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "worker_id": {"type": "integer", "minimum": 1},
                            "assignment": {"type": "string"},
                        },
                        "required": ["worker_id", "assignment"],
                    },
                },
            },
            "required": ["plans"],
        },
    )
    async def plan_workers(args: dict[str, Any]) -> dict[str, Any]:
        raw = args.get("plans") or []
        if not isinstance(raw, list) or not raw:
            return {
                "content": [{"type": "text", "text": "Rejected: plans must be a non-empty array."}],
                "is_error": True,
            }
        entries: list[PlanEntry] = []
        for p in raw:
            if not isinstance(p, dict):
                continue
            try:
                wid = int(p["worker_id"])
                asg = str(p["assignment"]).strip()
            except (KeyError, TypeError, ValueError):
                continue
            if wid < 1 or not asg:
                continue
            entries.append(PlanEntry(worker_id=wid, assignment=asg))
        if not entries:
            return {
                "content": [{"type": "text", "text": "Rejected: no valid plan entries."}],
                "is_error": True,
            }
        decisions.set_plan(entries)
        return {
            "content": [{"type": "text", "text": f"Plan recorded: {len(entries)} worker assignment(s)."}],
        }

    def _record_worker_decision(kind: str, args: dict[str, Any]) -> dict[str, Any]:
        try:
            wid = int(args["worker_id"])
        except (KeyError, TypeError, ValueError):
            return {
                "content": [{"type": "text", "text": "Rejected: worker_id required."}],
                "is_error": True,
            }
        instruction = str(args.get("instruction", "")).strip()
        progress = str(args.get("progress", "")).lower()
        if progress not in PROGRESS_TAGS:
            return {
                "content": [{"type": "text", "text": f"Rejected: progress must be one of {PROGRESS_TAGS}."}],
                "is_error": True,
            }
        if not instruction:
            return {
                "content": [{"type": "text", "text": "Rejected: instruction is required."}],
                "is_error": True,
            }
        decisions.add_decision(WorkerDecision(
            kind=kind, worker_id=wid, instruction=instruction, progress=progress,
        ))
        return {
            "content": [{"type": "text", "text": f"{kind} recorded for worker {wid} (progress={progress})."}],
        }

    _worker_directive_schema = {
        "type": "object",
        "properties": {
            "worker_id": {"type": "integer", "minimum": 1},
            "instruction": {"type": "string"},
            "progress": {"type": "string", "enum": list(PROGRESS_TAGS)},
        },
        "required": ["worker_id", "instruction", "progress"],
    }

    @tool(
        "continue_worker",
        (
            "Tell worker N to keep going with its current plan. Use when its "
            "work is productive and no pivot is needed. progress: 'none' if no "
            "new information gained, 'incremental' for steady progress, 'new' "
            "if a new attack surface opened."
        ),
        _worker_directive_schema,
    )
    async def continue_worker(args: dict[str, Any]) -> dict[str, Any]:
        return _record_worker_decision("continue", args)

    @tool(
        "expand_worker",
        (
            "Pivot worker N with an adjusted plan. Use when results warrant a "
            "new angle of attack or the current plan is exhausted. progress: "
            "same semantics as continue_worker."
        ),
        _worker_directive_schema,
    )
    async def expand_worker(args: dict[str, Any]) -> dict[str, Any]:
        return _record_worker_decision("expand", args)

    @tool(
        "stop_worker",
        (
            "Stop worker N. Use when its assignment is complete or the area is "
            "already covered by other workers."
        ),
        {
            "type": "object",
            "properties": {
                "worker_id": {"type": "integer", "minimum": 1},
                "reason": {"type": "string"},
            },
            "required": ["worker_id", "reason"],
        },
    )
    async def stop_worker(args: dict[str, Any]) -> dict[str, Any]:
        try:
            wid = int(args["worker_id"])
        except (KeyError, TypeError, ValueError):
            return {
                "content": [{"type": "text", "text": "Rejected: worker_id required."}],
                "is_error": True,
            }
        reason = str(args.get("reason", "")).strip()
        if not reason:
            return {
                "content": [{"type": "text", "text": "Rejected: reason is required."}],
                "is_error": True,
            }
        decisions.add_decision(WorkerDecision(
            kind="stop", worker_id=wid, reason=reason,
        ))
        return {"content": [{"type": "text", "text": f"stop recorded for worker {wid}."}]}

    @tool(
        "file_finding",
        (
            "File a verified security finding. Call ONLY after independently "
            "reproducing the issue with sectool tools (flow_get, replay_send, "
            "request_send, diff_flow, etc). The verification_notes field "
            "should cite the flow IDs you used to confirm the behavior."
        ),
        {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "severity": {"type": "string", "enum": list(SEVERITIES)},
                "endpoint": {"type": "string"},
                "description": {"type": "string"},
                "reproduction_steps": {"type": "string"},
                "evidence": {"type": "string"},
                "impact": {"type": "string"},
                "verification_notes": {"type": "string"},
                "supersedes_candidate_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": [],
                },
            },
            "required": [
                "title",
                "severity",
                "endpoint",
                "description",
                "reproduction_steps",
                "evidence",
                "impact",
                "verification_notes",
            ],
        },
    )
    async def file_finding(args: dict[str, Any]) -> dict[str, Any]:
        severity = str(args.get("severity", "")).lower()
        if severity not in SEVERITIES:
            return {
                "content": [{"type": "text", "text": f"Rejected: severity must be one of {SEVERITIES}."}],
                "is_error": True,
            }
        verification = str(args.get("verification_notes", "")).strip()
        if not verification:
            return {
                "content": [{
                    "type": "text",
                    "text": (
                        "Rejected: verification_notes must describe how you "
                        "reproduced the issue with sectool tools."
                    ),
                }],
                "is_error": True,
            }
        filed = FindingFiled(
            title=str(args.get("title", "")).strip() or "untitled",
            severity=severity,
            endpoint=str(args.get("endpoint", "")).strip(),
            description=str(args.get("description", "")).strip(),
            reproduction_steps=str(args.get("reproduction_steps", "")).strip(),
            evidence=str(args.get("evidence", "")).strip(),
            impact=str(args.get("impact", "")).strip(),
            verification_notes=verification,
            supersedes_candidate_ids=[
                str(c) for c in (args.get("supersedes_candidate_ids") or [])
            ],
        )
        decisions.add_finding(filed)
        return {
            "content": [{"type": "text", "text": f"Finding '{filed.title}' recorded for persistence."}],
        }

    @tool(
        "dismiss_candidate",
        (
            "Mark a worker-reported finding candidate as not a real issue — "
            "false positive, already covered by another finding, or out of "
            "scope. Provide a short reason. Dismissed candidates are no longer "
            "shown in subsequent turns."
        ),
        {
            "type": "object",
            "properties": {
                "candidate_id": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["candidate_id", "reason"],
        },
    )
    async def dismiss_candidate(args: dict[str, Any]) -> dict[str, Any]:
        cid = str(args.get("candidate_id", "")).strip()
        reason = str(args.get("reason", "")).strip()
        if not cid or not reason:
            return {
                "content": [{"type": "text", "text": "Rejected: candidate_id and reason required."}],
                "is_error": True,
            }
        decisions.add_dismissal(cid, reason)
        return {"content": [{"type": "text", "text": f"Candidate {cid} dismissal recorded."}]}

    @tool(
        "done",
        (
            "Signal that the exploration run should end. Provide a brief "
            "summary of what was covered. All unreported findings must already "
            "have been filed before calling this."
        ),
        {
            "type": "object",
            "properties": {"summary": {"type": "string"}},
            "required": ["summary"],
        },
    )
    async def done(args: dict[str, Any]) -> dict[str, Any]:
        summary = str(args.get("summary", "")).strip()
        if not summary:
            return {
                "content": [{"type": "text", "text": "Rejected: summary is required."}],
                "is_error": True,
            }
        decisions.set_done(summary)
        return {"content": [{"type": "text", "text": "Run end signaled."}]}

    return create_sdk_mcp_server(
        name="orch_tools",
        version="1.0.0",
        tools=[
            plan_workers,
            continue_worker,
            expand_worker,
            stop_worker,
            file_finding,
            dismiss_candidate,
            done,
        ],
    )


# Public allowed-tool names (use with ClaudeAgentOptions.allowed_tools).
WORKER_TOOL_ALLOWED = "mcp__worker_tools__report_finding_candidate"
ORCH_TOOL_NAMES = (
    "plan_workers",
    "continue_worker",
    "expand_worker",
    "stop_worker",
    "file_finding",
    "dismiss_candidate",
    "done",
)
ORCH_TOOL_ALLOWED = [f"mcp__orch_tools__{n}" for n in ORCH_TOOL_NAMES]
