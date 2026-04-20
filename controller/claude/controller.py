"""Main orchestrator loop for autonomous security exploration.

Iteration anatomy (see README):
  1) Autonomous worker phase — each alive worker runs up to its autonomous
     budget of turns concurrently, escalating on candidate / silent / budget.
  2) Verification phase — verifier client, multi-substep; reproduces and files
     or dismisses each pending candidate.
  3) Direction phase — director client, multi-substep; decides next move per
     alive worker (continue/expand/stop) and the autonomous budget.
"""

import asyncio
import io
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    ResultMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
)

from config import Config, parse_args
from findings import FindingWriter, match_pending_candidates
from prompts import orchestrator_director as director_prompts
from prompts import orchestrator_verifier as verifier_prompts
from prompts import worker as worker_prompts
from tools import (
    DEFAULT_AUTONOMOUS_BUDGET,
    DIRECTOR_TOOL_ALLOWED,
    MAX_AUTONOMOUS_BUDGET,
    PHASE_DIRECTION,
    PHASE_VERIFICATION,
    VERIFIER_TOOL_ALLOWED,
    WORKER_TOOL_ALLOWED,
    CandidatePool,
    DecisionQueue,
    FindingCandidate,
    PlanEntry,
    ToolCallRecord,
    WorkerDecision,
    WorkerTurnSummary,
    build_orch_mcp_server,
    build_worker_mcp_server,
    extract_flow_ids,
    reset_active_worker,
    set_active_worker,
)


# Glob granting the verifier access to every sectool tool so it can reproduce
# candidates with the same surface workers use (including mutating tools like
# proxy_rule_*, crawl_*, oast_*, proxy_respond_*).
ORCH_SECTOOL_TOOLS_GLOB = "mcp__sectool__*"

# Stall thresholds — counted against escalation_reason == "silent".
STALL_WARN_AFTER = 3
STALL_STOP_AFTER = 4

# Phase substep caps.
VERIFICATION_MAX_SUBSTEPS = 6
DIRECTION_MAX_SUBSTEPS = 4

# Per-turn worker timeout in seconds.
WORKER_TURN_TIMEOUT = 300


def log(tag: str, msg: str) -> None:
    print(f"[{tag:<8s}] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Build and server lifecycle
# ---------------------------------------------------------------------------


def build_sectool(repo_root: str) -> None:
    log("build", "Building sectool...")
    result = subprocess.run(
        ["make", "build"], cwd=repo_root, capture_output=True, text=True,
    )
    if result.returncode != 0:
        log("build", f"Build failed:\n{result.stdout}\n{result.stderr}")
        sys.exit(1)
    log("build", "Build complete.")


def start_mcp_server(
    repo_root: str, proxy_port: int, mcp_port: int, workflow: str,
) -> tuple[subprocess.Popen, "io.TextIOWrapper"]:
    binary = os.path.join(repo_root, "bin", "sectool")
    cmd = [
        binary, "mcp",
        f"--proxy-port={proxy_port}",
        f"--port={mcp_port}",
        f"--workflow={workflow}",
    ]
    log_path = os.path.join(repo_root, "sectool-mcp.log")
    log_file = open(log_path, "w")  # noqa: SIM115
    log("server", f"Starting sectool MCP server on :{mcp_port} (proxy :{proxy_port}, workflow: {workflow})")
    log("server", f"Server stderr → {log_path}")
    proc = subprocess.Popen(cmd, stderr=log_file, stdout=subprocess.DEVNULL)
    return proc, log_file


def wait_for_server(mcp_port: int, proc: subprocess.Popen, timeout: float = 10.0) -> None:
    url = f"http://127.0.0.1:{mcp_port}/mcp"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        exit_code = proc.poll()
        if exit_code is not None:
            log("server", f"MCP server exited early (code {exit_code}). See sectool-mcp.log.")
            sys.exit(1)
        try:
            urllib.request.urlopen(
                urllib.request.Request(url, method="GET"), timeout=2,
            )
            log("server", "MCP server ready.")
            return
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(0.5)
    log("server", f"MCP server failed to become ready within {timeout}s.")
    sys.exit(1)


def terminate_process(proc: subprocess.Popen, log_file: io.TextIOWrapper | None = None) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    if log_file is not None:
        log_file.close()


# ---------------------------------------------------------------------------
# Worker state
# ---------------------------------------------------------------------------


@dataclass
class WorkerState:
    worker_id: int
    options: ClaudeAgentOptions
    client: ClaudeSDKClient | None = None
    last_instruction: str | None = None
    alive: bool = True
    assignment: str = ""
    progress_none_streak: int = 0
    stall_warned: bool = False
    autonomous_budget: int = DEFAULT_AUTONOMOUS_BUDGET
    escalation_reason: str | None = None
    autonomous_turns: list[WorkerTurnSummary] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Text shortening helpers
# ---------------------------------------------------------------------------


def _short(s: str, n: int) -> str:
    s = s.strip()
    if len(s) <= n:
        return s
    return s[: n - 1] + "…"


def _summarize_input(tool_input: dict) -> str:
    try:
        serialized = json.dumps(tool_input, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError):
        serialized = repr(tool_input)
    return _short(serialized, 240)


def _summarize_result(content) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return _short(content, 300)
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text", "")))
            else:
                parts.append(repr(item))
        return _short("\n".join(parts), 300)
    return _short(repr(content), 300)


# ---------------------------------------------------------------------------
# Worker turn collection
# ---------------------------------------------------------------------------


async def collect_worker_turn(
    client: ClaudeSDKClient,
    worker_id: int,
    iteration: int,
    candidates: CandidatePool,
    verbose_tag: str | None = None,
) -> WorkerTurnSummary:
    """Drain one turn from a worker into a WorkerTurnSummary.

    Sets the `_ACTIVE_WORKER_ID` ContextVar so any `report_finding_candidate`
    calls attribute to this worker even under concurrent drains.
    """
    candidates_before = candidates.counter
    token = set_active_worker(worker_id)

    summary = WorkerTurnSummary(worker_id=worker_id, iteration=iteration)
    pending_calls: dict[str, ToolCallRecord] = {}

    try:
        async for message in client.receive_response():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        summary.assistant_text += (block.text or "")
                        if verbose_tag:
                            first = (block.text or "").strip().split("\n", 1)[0]
                            if first:
                                log(verbose_tag, f"text: {_short(first, 120)}")
                    elif isinstance(block, ToolUseBlock):
                        rec = ToolCallRecord(
                            name=block.name,
                            input_summary=_summarize_input(block.input or {}),
                        )
                        pending_calls[block.id] = rec
                        summary.tool_calls.append(rec)
                        for fid in extract_flow_ids(block.input or {}):
                            if fid not in summary.flow_ids_touched:
                                summary.flow_ids_touched.append(fid)
                        if verbose_tag:
                            log(verbose_tag, f"tool: {block.name}")
            elif isinstance(message, UserMessage):
                blocks = message.content if isinstance(message.content, list) else []
                for block in blocks:
                    if isinstance(block, ToolResultBlock):
                        rec = pending_calls.pop(block.tool_use_id, None)
                        if rec is not None:
                            rec.result_summary = _summarize_result(block.content)
                            rec.is_error = bool(block.is_error)
                        for fid in extract_flow_ids(block.content):
                            if fid not in summary.flow_ids_touched:
                                summary.flow_ids_touched.append(fid)
            elif isinstance(message, ResultMessage):
                summary.cost_usd = message.total_cost_usd
                break
    finally:
        reset_active_worker(token)

    # Scope candidates to this worker so concurrent drains don't cross-attribute.
    summary.candidate_ids = candidates.ids_since_for_worker(candidates_before, worker_id)

    for fid in extract_flow_ids(summary.assistant_text):
        if fid not in summary.flow_ids_touched:
            summary.flow_ids_touched.append(fid)

    if verbose_tag:
        cost_str = f"${summary.cost_usd:.4f}" if summary.cost_usd else "n/a"
        log(
            verbose_tag,
            f"done ({len(summary.tool_calls)} tools, "
            f"{len(summary.flow_ids_touched)} flow IDs, "
            f"{len(summary.candidate_ids)} candidates, cost: {cost_str})",
        )

    return summary


# ---------------------------------------------------------------------------
# Worker lifecycle
# ---------------------------------------------------------------------------


def _build_worker_options(
    base: ClaudeAgentOptions,
    worker_tools_server,
    mcp_url: str,
    worker_id: int,
    num_workers: int,
    stderr_cb,
) -> ClaudeAgentOptions:
    return ClaudeAgentOptions(
        mcp_servers={
            "sectool": {"type": "http", "url": mcp_url},
            "worker_tools": worker_tools_server,
        },
        allowed_tools=[
            "mcp__sectool__*",
            WORKER_TOOL_ALLOWED,
            "Read", "Glob", "Grep", "Bash",
        ],
        disallowed_tools=["Write", "Edit"],
        permission_mode="acceptEdits",
        cwd=base.cwd,
        max_turns=base.max_turns,
        model=base.model,
        stderr=stderr_cb,
        system_prompt=worker_prompts.build_system_prompt(worker_id, num_workers),
    )


async def create_worker(
    worker_id: int,
    num_workers: int,
    worker_tools_server,
    mcp_url: str,
    base: ClaudeAgentOptions,
    stderr_cb,
) -> WorkerState:
    opts = _build_worker_options(base, worker_tools_server, mcp_url, worker_id, num_workers, stderr_cb)
    client = ClaudeSDKClient(options=opts)
    await client.__aenter__()
    return WorkerState(worker_id=worker_id, options=opts, client=client)


async def teardown_worker(state: WorkerState) -> None:
    state.alive = False
    if state.client is not None:
        try:
            await state.client.__aexit__(None, None, None)
        except BaseException:
            pass
    state.client = None


async def attempt_worker_recovery(state: WorkerState) -> bool:
    await teardown_worker(state)
    for attempt in range(1, 3):
        try:
            await asyncio.sleep(2)
            client = ClaudeSDKClient(options=state.options)
            await client.__aenter__()
            state.client = client
            state.alive = True
            log(f"worker {state.worker_id}", f"Recovery succeeded (attempt {attempt})")
            if state.last_instruction:
                await client.query(state.last_instruction)
            return True
        except Exception as exc:
            log(f"worker {state.worker_id}", f"Recovery attempt {attempt} failed: {exc}")
    state.alive = False
    return False


async def attempt_client_recovery(
    old_client: ClaudeSDKClient | None,
    options: ClaudeAgentOptions,
    tag: str,
) -> ClaudeSDKClient | None:
    """Recover a long-lived orchestrator client (verifier or director)."""
    if old_client is not None:
        try:
            await old_client.__aexit__(None, None, None)
        except BaseException:
            pass
    for attempt in range(1, 3):
        try:
            await asyncio.sleep(2)
            client = ClaudeSDKClient(options=options)
            await client.__aenter__()
            log(tag, f"Recovery succeeded (attempt {attempt})")
            return client
        except Exception as exc:
            log(tag, f"Recovery attempt {attempt} failed: {exc}")
    return None


# ---------------------------------------------------------------------------
# Autonomous worker runs
# ---------------------------------------------------------------------------


def _classify_escalation(summary: WorkerTurnSummary) -> str | None:
    """Return an escalation reason, or None if the turn was productive."""
    if summary.candidate_ids:
        return "candidate"
    if not summary.tool_calls and not summary.flow_ids_touched:
        return "silent"
    return None


async def run_worker_autonomous_turn(
    worker: WorkerState,
    iteration: int,
    candidates: CandidatePool,
    verbose: bool,
) -> tuple[WorkerTurnSummary | None, str | None]:
    """Drain one turn from the worker; classify as candidate/silent/None/error.

    Returns (summary, escalation_reason). On connection error returns
    (None, "error"); on timeout returns a stub summary and reason="silent"
    (treat the worker as unproductive this turn).
    """
    tag = f"w{worker.worker_id}" if verbose else None
    try:
        summary = await asyncio.wait_for(
            collect_worker_turn(worker.client, worker.worker_id, iteration, candidates, tag),
            timeout=WORKER_TURN_TIMEOUT,
        )
    except asyncio.TimeoutError:
        log(f"worker {worker.worker_id}", "Turn timed out; interrupting.")
        try:
            await worker.client.interrupt()
        except Exception:
            pass
        stub = WorkerTurnSummary(worker_id=worker.worker_id, iteration=iteration)
        stub.assistant_text = "(Worker turn timed out and was interrupted.)"
        return stub, "silent"
    except (ConnectionError, OSError) as exc:
        log(f"worker {worker.worker_id}", f"Connection lost: {exc}")
        return None, "error"

    return summary, _classify_escalation(summary)


async def run_worker_until_escalation(
    worker: WorkerState,
    iteration: int,
    candidates: CandidatePool,
    verbose: bool,
) -> list[WorkerTurnSummary]:
    """Run a worker for up to autonomous_budget turns or until it escalates.

    Mutates `worker.escalation_reason` with the terminating reason.
    Appends each turn's summary to `worker.autonomous_turns`.
    """
    run_turns: list[WorkerTurnSummary] = []
    budget = max(1, min(MAX_AUTONOMOUS_BUDGET, worker.autonomous_budget))

    for attempt in range(budget):
        if attempt > 0:
            try:
                await worker.client.query("Continue your current testing plan.")
            except (ConnectionError, OSError) as exc:
                log(f"worker {worker.worker_id}", f"Continue query failed: {exc}")
                worker.escalation_reason = "error"
                return run_turns

        summary, reason = await run_worker_autonomous_turn(
            worker, iteration, candidates, verbose,
        )
        if summary is not None:
            run_turns.append(summary)
            worker.autonomous_turns.append(summary)
        if reason is not None:
            worker.escalation_reason = reason
            return run_turns

    worker.escalation_reason = "budget"
    return run_turns


async def run_all_workers_until_escalation(
    workers: list[WorkerState],
    iteration: int,
    candidates: CandidatePool,
    verbose: bool = False,
) -> dict[int, list[WorkerTurnSummary]]:
    """Run every alive worker concurrently until all have escalated."""
    async def per_worker(w: WorkerState) -> tuple[int, list[WorkerTurnSummary]]:
        w.escalation_reason = None
        w.autonomous_turns = []
        runs = await run_worker_until_escalation(w, iteration, candidates, verbose)
        return w.worker_id, runs

    alive = [w for w in workers if w.alive and w.client is not None]
    if not alive:
        return {}
    tasks = [asyncio.create_task(per_worker(w)) for w in alive]
    results: dict[int, list[WorkerTurnSummary]] = {}
    for t in tasks:
        wid, runs = await t
        results[wid] = runs
    return results


# ---------------------------------------------------------------------------
# Prompt formatting
# ---------------------------------------------------------------------------


def _format_tool_calls(calls: list[ToolCallRecord], limit: int = 20) -> str:
    if not calls:
        return "  (no tool calls)"
    lines: list[str] = []
    shown = calls[:limit]
    for i, c in enumerate(shown, 1):
        status = " [ERROR]" if c.is_error else ""
        line = f"  {i}. {c.name}({c.input_summary}){status}"
        if c.result_summary:
            line += f"\n     → {c.result_summary}"
        lines.append(line)
    if len(calls) > limit:
        lines.append(f"  … and {len(calls) - limit} more tool call(s) omitted.")
    return "\n".join(lines)


def _format_autonomous_run(
    worker_id: int,
    turns: list[WorkerTurnSummary],
    escalation_reason: str | None,
) -> str:
    if not turns:
        return (
            f"### Worker {worker_id}\n"
            f"(No autonomous turns this iteration. escalation_reason={escalation_reason or 'unknown'})"
        )
    parts = [
        f"### Worker {worker_id} — {len(turns)} autonomous turn(s), "
        f"escalated: {escalation_reason or 'unknown'}",
    ]
    for i, s in enumerate(turns, 1):
        calls = ", ".join(c.name for c in s.tool_calls) or "(no tool calls)"
        flows = ", ".join(s.flow_ids_touched) if s.flow_ids_touched else "(no flows)"
        cands = ", ".join(s.candidate_ids) if s.candidate_ids else "(no candidates)"
        first_line = (s.assistant_text.strip().split("\n", 1)[0]) or "(no text)"
        parts.append(
            f"  Turn {i}: tools=[{_short(calls, 200)}] flows=[{flows}] cands=[{cands}]\n"
            f"    text: {_short(first_line, 240)}"
        )
    last = turns[-1]
    parts.append("")
    parts.append(f"Last turn tool calls ({len(last.tool_calls)}):")
    parts.append(_format_tool_calls(last.tool_calls, limit=10))
    return "\n".join(parts)


def _format_pending_candidates_list(pending: list[FindingCandidate]) -> str:
    if not pending:
        return "No pending finding candidates."
    lines = ["**Pending finding candidates (awaiting verification):**"]
    for c in pending:
        lines.append(
            f"- `{c.candidate_id}` [{c.severity}] {c.title} — {c.endpoint}\n"
            f"  worker: {c.worker_id}\n"
            f"  flows: {', '.join(c.flow_ids) or '(none)'}\n"
            f"  summary: {_short(c.summary, 200)}\n"
            f"  reproduction hint: {_short(c.reproduction_hint, 200)}"
        )
    return "\n".join(lines)


def _format_pending_candidates(candidates: CandidatePool) -> str:
    return _format_pending_candidates_list(candidates.pending())


def _format_status_line(
    iteration: int, max_iter: int,
    total_cost: float, max_cost: float | None,
    findings_count: int,
) -> str:
    cost_part = f"${total_cost:.2f}"
    if max_cost is not None:
        cost_part += f"/${max_cost:.2f}"
    return f"**Status:** iteration {iteration}/{max_iter}, cost {cost_part}, findings filed: {findings_count}"


def _format_stall_warnings(workers: list[WorkerState]) -> str:
    warnings: list[str] = []
    for w in workers:
        if not w.alive:
            continue
        if w.progress_none_streak >= STALL_WARN_AFTER and not w.stall_warned:
            warnings.append(
                f"- Worker {w.worker_id} has had {w.progress_none_streak} consecutive "
                "silent autonomous runs. Either expand its plan or stop it."
            )
    if not warnings:
        return ""
    return "**Stall warnings:**\n" + "\n".join(warnings)


def _build_verifier_prompt(
    *,
    workers: list[WorkerState],
    worker_runs: dict[int, list[WorkerTurnSummary]],
    pending: list[FindingCandidate],
    findings_summary: str,
    iteration: int, max_iter: int,
    total_cost: float, max_cost: float | None,
    findings_count: int,
) -> str:
    parts = [
        _format_status_line(iteration, max_iter, total_cost, max_cost, findings_count),
        "",
        findings_summary,
        "",
        _format_pending_candidates_list(pending),
        "",
        "**Worker autonomous runs this iteration:**",
        "",
    ]
    for w in workers:
        if not w.alive:
            continue
        parts.append(_format_autonomous_run(
            w.worker_id, worker_runs.get(w.worker_id, []), w.escalation_reason,
        ))
        parts.append("")
    parts.append(
        "Verify every pending candidate. Use sectool tools (flow_get, "
        "replay_send, request_send, diff_flow, find_reflected, etc.) to "
        "reproduce before filing. Call `file_finding` for each confirmed "
        "issue (cite flow IDs in verification_notes) and `dismiss_candidate` "
        "for the rest. When every pending candidate has a disposition, call "
        "`verification_done(summary)`. You may take multiple substeps — "
        "reflect between them."
    )
    return "\n".join(parts)


def _build_verifier_continue_prompt(
    *,
    pending: list[FindingCandidate],
    filed_this_iter: int,
    dismissed_this_iter: int,
    substep: int,
    max_substeps: int,
) -> str:
    return "\n".join([
        f"**Verification substep {substep} of {max_substeps} max.**",
        "",
        (
            f"So far this iteration you have filed {filed_this_iter} finding(s) "
            f"and dismissed {dismissed_this_iter} candidate(s)."
        ),
        "",
        _format_pending_candidates_list(pending),
        "",
        "Continue verifying. When every pending candidate has a disposition, "
        "call `verification_done(summary)`.",
    ])


def _build_director_prompt(
    *,
    workers: list[WorkerState],
    worker_runs: dict[int, list[WorkerTurnSummary]],
    verification_summary: str,
    findings_summary: str,
    iteration: int, max_iter: int,
    total_cost: float, max_cost: float | None,
    findings_count: int,
    stall_warnings: str,
) -> str:
    parts = [
        _format_status_line(iteration, max_iter, total_cost, max_cost, findings_count),
        "",
        findings_summary,
        "",
        f"**Verification phase summary:** {verification_summary}",
    ]
    if stall_warnings:
        parts.append("")
        parts.append(stall_warnings)
    parts.append("")
    parts.append("**Worker autonomous runs this iteration:**")
    parts.append("")
    for w in workers:
        if not w.alive:
            continue
        parts.append(_format_autonomous_run(
            w.worker_id, worker_runs.get(w.worker_id, []), w.escalation_reason,
        ))
        parts.append("")
    alive_ids = [str(w.worker_id) for w in workers if w.alive]
    parts.append(
        f"**Alive workers awaiting direction:** "
        f"{', '.join(alive_ids) if alive_ids else '(none)'}"
    )
    parts.append("")
    parts.append(
        "For EACH alive worker call exactly one of `continue_worker`, "
        "`expand_worker`, or `stop_worker` (or include it in a `plan_workers` "
        "entry). Set `autonomous_budget` thoughtfully based on the worker's "
        "escalation_reason and the path you want it to drill. When every "
        "alive worker has a decision, call `direction_done(summary)`. Call "
        "`done(summary)` instead if the run is complete."
    )
    if iteration == 1:
        parts.append("")
        parts.append(
            "This is iteration 1 — the worker's initial discovery phase. "
            "Decide whether to fan out via `plan_workers` or to keep a single "
            "focused worker and set a higher autonomous_budget."
        )
    return "\n".join(parts)


def _build_director_continue_prompt(
    *,
    pending_wids: set[int],
    substep: int,
    max_substeps: int,
) -> str:
    pending_str = (
        ", ".join(str(w) for w in sorted(pending_wids)) if pending_wids else "(none)"
    )
    return "\n".join([
        f"**Direction substep {substep} of {max_substeps} max.**",
        "",
        f"Workers still awaiting direction: {pending_str}.",
        "",
        "Issue a continue/expand/stop decision for each (or include them in a "
        "`plan_workers` entry). Call `direction_done(summary)` when every "
        "alive worker is covered.",
    ])


# ---------------------------------------------------------------------------
# Phase substep runner and printing
# ---------------------------------------------------------------------------


def _phase_tag(phase: str) -> str:
    return "verify" if phase == PHASE_VERIFICATION else "direct"


def _print_phase_turn(
    phase: str,
    text: str,
    tool_calls: list[str],
    iteration: int,
    substep: int,
    verbose: bool,
) -> None:
    print(flush=True)
    label = "Verifier" if phase == PHASE_VERIFICATION else "Director"
    print(f"=== {label} (iter {iteration}, substep {substep}) ===", flush=True)
    if verbose and text:
        print(text, flush=True)
    elif text:
        print(_short(text, 500), flush=True)
    if tool_calls:
        counts: dict[str, int] = {}
        for n in tool_calls:
            counts[n] = counts.get(n, 0) + 1
        ordered = sorted(counts.items())
        summary = ", ".join(f"{n}×{c}" for n, c in ordered)
        print(f"Tool calls: {summary}", flush=True)
    else:
        print("Tool calls: (none)", flush=True)
    print("=" * 50, flush=True)
    print(flush=True)


async def run_phase_substep(
    client: ClaudeSDKClient,
    user_content: str,
    phase: str,
    iteration: int,
    substep: int,
    verbose: bool,
) -> tuple[bool, float | None]:
    """Send a substep message and drain. Returns (ok, cost). On error ok=False."""
    text_parts: list[str] = []
    tool_calls: list[str] = []
    cost: float | None = None
    try:
        await client.query(user_content)
        async for msg in client.receive_response():
            if isinstance(msg, AssistantMessage):
                for block in msg.content:
                    if isinstance(block, TextBlock):
                        text_parts.append(block.text or "")
                    elif isinstance(block, ToolUseBlock):
                        tool_calls.append(block.name)
                        if verbose:
                            log(_phase_tag(phase), f"tool: {block.name}")
            elif isinstance(msg, ResultMessage):
                cost = msg.total_cost_usd
                break
    except (ConnectionError, OSError, asyncio.TimeoutError) as exc:
        log(_phase_tag(phase), f"Substep error iter {iteration} sub {substep}: {exc}")
        return False, None

    _print_phase_turn(phase, "\n".join(text_parts).strip(), tool_calls, iteration, substep, verbose)
    return True, cost


# ---------------------------------------------------------------------------
# Verification phase
# ---------------------------------------------------------------------------


async def run_verification_phase(
    client: ClaudeSDKClient,
    options: ClaudeAgentOptions,
    decisions: DecisionQueue,
    candidates: CandidatePool,
    finding_writer: FindingWriter,
    worker_runs: dict[int, list[WorkerTurnSummary]],
    workers: list[WorkerState],
    iteration: int,
    max_iter: int,
    total_cost: float,
    max_cost: float | None,
    verbose: bool,
) -> tuple[ClaudeSDKClient, float, str]:
    """Drive the verifier over up to VERIFICATION_MAX_SUBSTEPS substeps.

    Applies findings/dismissals incrementally so each substep's prompt
    reflects the current state. Exits when the verifier calls
    `verification_done`, when no pending candidates remain, or at the cap.
    """
    decisions.begin_phase(PHASE_VERIFICATION)
    phase_cost = 0.0

    if not candidates.pending():
        log("verify", "No pending candidates; skipping verification phase.")
        return client, phase_cost, "No pending candidates this iteration."

    applied_findings = 0
    applied_dismissals = 0

    for substep in range(1, VERIFICATION_MAX_SUBSTEPS + 1):
        pending = candidates.pending()
        if not pending:
            break

        if substep == 1:
            user_content = _build_verifier_prompt(
                workers=workers,
                worker_runs=worker_runs,
                pending=pending,
                findings_summary=finding_writer.summary_for_orchestrator(),
                iteration=iteration, max_iter=max_iter,
                total_cost=total_cost + phase_cost,
                max_cost=max_cost,
                findings_count=finding_writer.count,
            )
        else:
            user_content = _build_verifier_continue_prompt(
                pending=pending,
                filed_this_iter=applied_findings,
                dismissed_this_iter=applied_dismissals,
                substep=substep,
                max_substeps=VERIFICATION_MAX_SUBSTEPS,
            )

        ok, cost = await run_phase_substep(
            client, user_content, PHASE_VERIFICATION, iteration, substep, verbose,
        )
        if not ok:
            new_client = await attempt_client_recovery(client, options, "verify")
            if new_client is not None:
                client = new_client
            log("verify", f"Aborting verification phase at substep {substep}.")
            break
        if cost is not None:
            phase_cost += cost

        # Apply new findings this substep produced
        for filed in decisions.findings[applied_findings:]:
            if finding_writer.is_duplicate(filed):
                log("finding", f"Duplicate skipped: {filed.title}")
            else:
                path = finding_writer.write(filed)
                log("finding", f"Written: {path}")
            resolved = list(filed.supersedes_candidate_ids)
            if not resolved:
                auto = match_pending_candidates(filed, candidates.pending())
                for cid in auto:
                    log("finding", f"Auto-resolved candidate {cid} (matched endpoint+title)")
                resolved = auto
            for cid in resolved:
                candidates.mark(cid, "verified")
        applied_findings = len(decisions.findings)

        for dm in decisions.dismissals[applied_dismissals:]:
            candidates.mark(dm.candidate_id, "dismissed")
            log("finding", f"Candidate {dm.candidate_id} dismissed: {_short(dm.reason, 80)}")
        applied_dismissals = len(decisions.dismissals)

        if decisions.verification_done_summary is not None:
            break

    summary = (
        decisions.verification_done_summary
        or f"Verification phase ended with {applied_findings} filed, "
           f"{applied_dismissals} dismissed, {len(candidates.pending())} still pending."
    )
    return client, phase_cost, summary


# ---------------------------------------------------------------------------
# Direction phase
# ---------------------------------------------------------------------------


async def run_direction_phase(
    client: ClaudeSDKClient,
    options: ClaudeAgentOptions,
    decisions: DecisionQueue,
    workers: list[WorkerState],
    worker_runs: dict[int, list[WorkerTurnSummary]],
    verification_summary: str,
    findings_summary: str,
    iteration: int,
    max_iter: int,
    total_cost: float,
    max_cost: float | None,
    findings_count: int,
    stall_warnings: str,
    verbose: bool,
) -> tuple[ClaudeSDKClient, float]:
    """Drive the director over up to DIRECTION_MAX_SUBSTEPS substeps."""
    decisions.begin_phase(PHASE_DIRECTION)
    phase_cost = 0.0
    alive_ids = {w.worker_id for w in workers if w.alive}

    for substep in range(1, DIRECTION_MAX_SUBSTEPS + 1):
        covered = {d.worker_id for d in decisions.worker_decisions}
        if decisions.plan is not None:
            covered |= {p.worker_id for p in decisions.plan}
        pending_wids = alive_ids - covered

        if substep == 1:
            user_content = _build_director_prompt(
                workers=workers,
                worker_runs=worker_runs,
                verification_summary=verification_summary,
                findings_summary=findings_summary,
                iteration=iteration, max_iter=max_iter,
                total_cost=total_cost + phase_cost,
                max_cost=max_cost,
                findings_count=findings_count,
                stall_warnings=stall_warnings,
            )
        else:
            user_content = _build_director_continue_prompt(
                pending_wids=pending_wids,
                substep=substep,
                max_substeps=DIRECTION_MAX_SUBSTEPS,
            )

        ok, cost = await run_phase_substep(
            client, user_content, PHASE_DIRECTION, iteration, substep, verbose,
        )
        if not ok:
            new_client = await attempt_client_recovery(client, options, "direct")
            if new_client is not None:
                client = new_client
            log("direct", f"Aborting direction phase at substep {substep}.")
            break
        if cost is not None:
            phase_cost += cost

        if (
            decisions.direction_done_summary is not None
            or decisions.done_summary is not None
        ):
            break

        covered = {d.worker_id for d in decisions.worker_decisions}
        if decisions.plan is not None:
            covered |= {p.worker_id for p in decisions.plan}
        if not (alive_ids - covered):
            break

    return client, phase_cost


# ---------------------------------------------------------------------------
# Apply decisions
# ---------------------------------------------------------------------------


async def apply_plan_diff(
    plan: list[PlanEntry],
    workers: list[WorkerState],
    worker_tools_server,
    mcp_url: str,
    base_options: ClaudeAgentOptions,
    stderr_cb,
    max_workers: int,
) -> None:
    by_id = {w.worker_id: w for w in workers}
    existing_ids = {w.worker_id for w in workers if w.alive}
    plan_ids = {p.worker_id for p in plan}
    total_after = len(existing_ids | plan_ids)
    if total_after > max_workers:
        log("plan", f"Plan requested {total_after} workers; capped at {max_workers}.")

    for p in plan:
        snippet = _short(p.assignment, 120)
        if p.worker_id in by_id and by_id[p.worker_id].alive:
            w = by_id[p.worker_id]
            log(f"worker {p.worker_id}", f"Retargeting: {snippet}")
            w.assignment = p.assignment
            w.last_instruction = p.assignment
            w.progress_none_streak = 0
            w.stall_warned = False
            try:
                await w.client.query(p.assignment)
            except (ConnectionError, OSError):
                await attempt_worker_recovery(w)
        else:
            if len(existing_ids) >= max_workers:
                log(f"worker {p.worker_id}", f"Spawn skipped: max_workers={max_workers} reached.")
                continue
            num_workers_total = max(1, total_after)
            log(f"worker {p.worker_id}", f"Spawning: {snippet}")
            try:
                new_w = await create_worker(
                    p.worker_id, num_workers_total, worker_tools_server, mcp_url, base_options, stderr_cb,
                )
                new_w.assignment = p.assignment
                new_w.last_instruction = p.assignment
                await new_w.client.query(p.assignment)
                workers.append(new_w)
                existing_ids.add(p.worker_id)
                log(f"worker {p.worker_id}", "Connected and assigned.")
            except Exception as exc:
                log(f"worker {p.worker_id}", f"Spawn failed: {exc}")


async def apply_decision(
    decision: WorkerDecision,
    worker: WorkerState,
    iteration: int,
) -> None:
    """Dispatch a single director decision to the target worker.

    No longer touches stall tracking (that is done from escalation_reason in
    the main loop). Copies the director's `autonomous_budget` onto the worker.
    """
    if decision.kind == "stop":
        log(f"iter {iteration}", f"Worker {worker.worker_id}: stop — {decision.reason}")
        await teardown_worker(worker)
        return

    worker.autonomous_budget = max(1, min(MAX_AUTONOMOUS_BUDGET, decision.autonomous_budget))

    snippet = _short(decision.instruction, 120)
    log(f"iter {iteration}",
        f"Worker {worker.worker_id}: {decision.kind} "
        f"(budget={worker.autonomous_budget}) — \"{snippet}\"")

    worker.last_instruction = decision.instruction
    try:
        await worker.client.query(decision.instruction)
    except (ConnectionError, OSError):
        await attempt_worker_recovery(worker)


def update_worker_streaks(workers: list[WorkerState]) -> None:
    """Update progress_none_streak from escalation_reason after autonomous runs."""
    for w in workers:
        if not w.alive:
            continue
        produced_flows = any(t.flow_ids_touched for t in w.autonomous_turns)
        if w.escalation_reason == "silent":
            w.progress_none_streak += 1
        elif w.escalation_reason == "candidate" or produced_flows:
            w.progress_none_streak = 0
            w.stall_warned = False


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------


async def run(config: Config) -> None:
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    server_proc = None
    server_log = None

    if config.external:
        log("server", f"External mode: connecting to existing MCP server on :{config.mcp_port}")
    else:
        if not config.skip_build:
            build_sectool(repo_root)
        server_proc, server_log = start_mcp_server(
            repo_root, config.proxy_port, config.mcp_port, config.workflow,
        )

    iteration = 0
    finding_writer = FindingWriter(config.findings_dir)
    candidates = CandidatePool()
    decisions = DecisionQueue()
    total_cost = 0.0

    try:
        if not config.external:
            wait_for_server(config.mcp_port, server_proc)

        for key in [k for k in os.environ if k.startswith("CLAUDE")]:
            os.environ.pop(key, None)

        mcp_url = f"http://127.0.0.1:{config.mcp_port}/mcp"
        stderr_cb = (lambda line: log("claude", line.rstrip())) if config.verbose else None

        worker_tools_server = build_worker_mcp_server(candidates)
        orch_tools_server = build_orch_mcp_server(decisions)

        base_options = ClaudeAgentOptions(cwd=repo_root, max_turns=100)
        if config.worker_model_id:
            base_options.model = config.worker_model_id

        verifier_options = ClaudeAgentOptions(
            mcp_servers={
                "sectool": {"type": "http", "url": mcp_url},
                "orch_tools": orch_tools_server,
            },
            allowed_tools=[ORCH_SECTOOL_TOOLS_GLOB] + list(VERIFIER_TOOL_ALLOWED),
            permission_mode="acceptEdits",
            cwd=repo_root,
            max_turns=100,
            model=config.orchestrator_model_id,
            stderr=stderr_cb,
            system_prompt=verifier_prompts.build_system_prompt(config.max_workers),
        )

        director_options = ClaudeAgentOptions(
            mcp_servers={
                "orch_tools": orch_tools_server,
            },
            allowed_tools=list(DIRECTOR_TOOL_ALLOWED),
            permission_mode="acceptEdits",
            cwd=repo_root,
            max_turns=100,
            model=config.orchestrator_model_id,
            stderr=stderr_cb,
            system_prompt=director_prompts.build_system_prompt(config.max_workers),
        )

        workers: list[WorkerState] = []
        verifier_client: ClaudeSDKClient | None = None
        director_client: ClaudeSDKClient | None = None

        try:
            # Initial worker
            log("worker", "Connecting Claude Code worker 1...")
            try:
                w1 = await create_worker(
                    1, 1, worker_tools_server, mcp_url, base_options, stderr_cb,
                )
                workers.append(w1)
            except Exception as exc:
                log("worker", f"Failed to connect worker 1: {exc}")
                raise SystemExit(1) from exc
            log("worker", "Worker 1 connected.")

            # Verifier and director clients
            try:
                verifier_client = ClaudeSDKClient(options=verifier_options)
                await verifier_client.__aenter__()
                log("verify", "Verifier connected.")
            except Exception as exc:
                await teardown_worker(workers[0])
                log("verify", f"Failed to connect verifier: {exc}")
                raise SystemExit(1) from exc

            try:
                director_client = ClaudeSDKClient(options=director_options)
                await director_client.__aenter__()
                log("direct", "Director connected.")
            except Exception as exc:
                await teardown_worker(workers[0])
                log("direct", f"Failed to connect director: {exc}")
                raise SystemExit(1) from exc

            # Initial prompt to worker 1
            workers[0].last_instruction = config.prompt
            workers[0].assignment = config.prompt
            try:
                await workers[0].client.query(config.prompt)
            except (ConnectionError, OSError) as exc:
                log("worker", f"Initial prompt failed: {exc}. Recovery...")
                if not await attempt_worker_recovery(workers[0]):
                    raise SystemExit(1)

            # Main loop
            for iteration in range(1, config.max_iterations + 1):
                alive = [w for w in workers if w.alive]
                if not alive:
                    log(f"iter {iteration}", "No alive workers. Stopping.")
                    break

                # 1) Autonomous worker phase
                budgets = ", ".join(f"w{w.worker_id}={w.autonomous_budget}" for w in alive)
                log(f"iter {iteration}",
                    f"Running {len(alive)} worker(s) autonomously ({budgets})...")
                worker_runs = await run_all_workers_until_escalation(
                    alive, iteration, candidates, verbose=config.verbose,
                )

                # Recover any connection-errored workers
                for w in alive:
                    if w.escalation_reason == "error" and w.client is None:
                        if await attempt_worker_recovery(w):
                            log(f"worker {w.worker_id}", "Recovered after autonomous run error.")

                # 2) Update stall tracking
                update_worker_streaks(alive)

                # 3) Cost + per-worker log
                for w in alive:
                    cost_this = sum((t.cost_usd or 0.0) for t in w.autonomous_turns)
                    total_cost += cost_this
                    log(f"iter {iteration}",
                        f"Worker {w.worker_id}: turns={len(w.autonomous_turns)} "
                        f"escalation={w.escalation_reason} cost=${cost_this:.4f}")

                if config.verbose:
                    for w in alive:
                        if not w.autonomous_turns:
                            continue
                        print(f"\n--- Worker {w.worker_id} autonomous run (iter {iteration}) ---")
                        for i, s in enumerate(w.autonomous_turns, 1):
                            print(f"[turn {i}] {s.assistant_text}")
                        print(f"--- End Worker {w.worker_id} autonomous run ---\n")

                if config.max_cost is not None and total_cost >= config.max_cost:
                    log(f"iter {iteration}", f"Cost ceiling reached (${total_cost:.2f}). Stopping.")
                    break

                # 4) Reset decisions for this iteration
                decisions.reset()

                # 5) Verification phase
                verifier_client, v_cost, v_summary = await run_verification_phase(
                    verifier_client, verifier_options, decisions, candidates,
                    finding_writer, worker_runs, workers, iteration,
                    config.max_iterations, total_cost, config.max_cost, config.verbose,
                )
                total_cost += v_cost

                if config.max_cost is not None and total_cost >= config.max_cost:
                    log(f"iter {iteration}", f"Cost ceiling reached (${total_cost:.2f}). Stopping.")
                    break

                # 6) Direction phase
                stall_warnings = _format_stall_warnings(workers)
                director_client, d_cost = await run_direction_phase(
                    director_client, director_options, decisions, workers, worker_runs,
                    v_summary, finding_writer.summary_for_orchestrator(),
                    iteration, config.max_iterations, total_cost, config.max_cost,
                    finding_writer.count, stall_warnings, config.verbose,
                )
                total_cost += d_cost

                for w in workers:
                    if w.alive and w.progress_none_streak >= STALL_WARN_AFTER:
                        w.stall_warned = True

                # 7) Done?
                if decisions.done_summary is not None:
                    log(f"iter {iteration}",
                        f"Director: done — {_short(decisions.done_summary, 120)}")
                    break

                # 8) Plan diff
                if decisions.plan is not None:
                    await apply_plan_diff(
                        decisions.plan, workers, worker_tools_server, mcp_url,
                        base_options, stderr_cb, config.max_workers,
                    )

                # 9) Per-worker decisions
                decided_wids: set[int] = set()
                for d in decisions.worker_decisions:
                    worker = next((w for w in workers if w.worker_id == d.worker_id), None)
                    if worker is None or not worker.alive:
                        log(f"iter {iteration}",
                            f"Decision for unknown/dead worker {d.worker_id} — skipped.")
                        continue
                    await apply_decision(d, worker, iteration)
                    decided_wids.add(d.worker_id)

                # 10) Implicit continue for undirected alive workers
                for w in workers:
                    if not w.alive or w.worker_id in decided_wids:
                        continue
                    if decisions.plan is not None and any(p.worker_id == w.worker_id for p in decisions.plan):
                        continue
                    log(f"iter {iteration}",
                        f"Worker {w.worker_id}: no explicit decision — implicit continue "
                        f"(budget={w.autonomous_budget}).")
                    try:
                        await w.client.query("Continue your current testing plan.")
                    except (ConnectionError, OSError):
                        await attempt_worker_recovery(w)

                # 11) Forced stop for stalled workers
                for w in list(workers):
                    if w.alive and w.progress_none_streak >= STALL_STOP_AFTER:
                        log(f"iter {iteration}",
                            f"Worker {w.worker_id}: stalled past threshold "
                            f"({w.progress_none_streak} silent escalations). Stopping.")
                        await teardown_worker(w)

            else:
                log("summary", f"Max iterations ({config.max_iterations}) reached.")

        finally:
            alive_count = sum(1 for w in workers if w.alive)
            for w in workers:
                if w.alive:
                    await teardown_worker(w)
            for name, client in (("verifier", verifier_client), ("director", director_client)):
                if client is not None:
                    try:
                        await client.__aexit__(None, None, None)
                    except BaseException:
                        pass

        print()
        log("summary",
            f"Workers: {alive_count}/{len(workers)} | Iterations: {iteration} | "
            f"Findings: {finding_writer.count} | Cost: ${total_cost:.2f}")
        if finding_writer.paths:
            log("summary", "Finding files:")
            for path in finding_writer.paths:
                print(f"              {path}")

    finally:
        if server_proc is not None:
            terminate_process(server_proc, server_log)
            log("server", "MCP server terminated.")


def main() -> None:
    config = parse_args()
    try:
        asyncio.run(run(config))
    except KeyboardInterrupt:
        print()
        log("ctrl-c", "Interrupted by user.")
        sys.exit(130)


if __name__ == "__main__":
    main()
