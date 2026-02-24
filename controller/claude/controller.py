"""Main orchestrator loop for autonomous security exploration."""

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
from findings import FindingWriter
from prompts import orchestrator as orch_prompts
from prompts import worker as worker_prompts
from tools import (
    CandidatePool,
    DecisionQueue,
    ORCH_TOOL_ALLOWED,
    PlanEntry,
    ToolCallRecord,
    WORKER_TOOL_ALLOWED,
    WorkerDecision,
    WorkerTurnSummary,
    build_orch_mcp_server,
    build_worker_mcp_server,
    extract_flow_ids,
)


# Tools the orchestrator is allowed to use from sectool for verification.
# Intentionally omits destructive / mutating tools that could disrupt workers
# (crawl_stop, oast_delete, proxy_rule_*).
ORCH_SECTOOL_READ_TOOLS = (
    "mcp__sectool__proxy_poll",
    "mcp__sectool__flow_get",
    "mcp__sectool__cookie_jar",
    "mcp__sectool__proxy_rule_list",
    "mcp__sectool__replay_send",
    "mcp__sectool__request_send",
    "mcp__sectool__crawl_status",
    "mcp__sectool__crawl_poll",
    "mcp__sectool__crawl_sessions",
    "mcp__sectool__oast_poll",
    "mcp__sectool__oast_get",
    "mcp__sectool__oast_list",
    "mcp__sectool__encode",
    "mcp__sectool__decode",
    "mcp__sectool__hash",
    "mcp__sectool__jwt_decode",
    "mcp__sectool__diff_flow",
    "mcp__sectool__find_reflected",
    "mcp__sectool__notes_save",
    "mcp__sectool__notes_list",
)

# Stall thresholds (in consecutive `progress=none` turns).
STALL_WARN_AFTER = 3
STALL_STOP_AFTER = 4


def log(tag: str, msg: str) -> None:
    print(f"[{tag:<8s}] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Build and server lifecycle (unchanged)
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


# ---------------------------------------------------------------------------
# Helpers — summarizing tool call inputs/results for the orchestrator prompt
# ---------------------------------------------------------------------------


def _short(s: str, n: int) -> str:
    s = s.strip()
    if len(s) <= n:
        return s
    return s[: n - 1] + "…"


def _summarize_input(tool_input: dict) -> str:
    """Condense tool arguments to a single short string."""
    try:
        serialized = json.dumps(tool_input, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError):
        serialized = repr(tool_input)
    return _short(serialized, 240)


def _summarize_result(content) -> str:
    """Condense a tool result to a short string."""
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
# Worker turn collection → WorkerTurnSummary  (task 4)
# ---------------------------------------------------------------------------


async def collect_worker_turn(
    client: ClaudeSDKClient,
    worker_id: int,
    iteration: int,
    candidates: CandidatePool,
    verbose_tag: str | None = None,
) -> WorkerTurnSummary:
    """Consume messages until ResultMessage, returning a structured summary.

    Pairs ToolUseBlocks with their ToolResultBlocks by tool_use_id. Scans for
    flow IDs in tool arguments, results, and assistant text. Attributes any
    new candidates minted during the turn to this worker.
    """
    candidates_before = candidates.counter
    candidates.active_worker_id = worker_id

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
                # Tool results return as UserMessage content blocks.
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
        candidates.active_worker_id = None

    # Candidates created during this turn
    summary.candidate_ids = candidates.ids_since(candidates_before)

    # Flow IDs from assistant text (last pass)
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
# Worker lifecycle helpers
# ---------------------------------------------------------------------------


def _build_worker_options(
    base: ClaudeAgentOptions,
    worker_tools_server,
    mcp_url: str,
    worker_id: int,
    num_workers: int,
    stderr_cb,
) -> ClaudeAgentOptions:
    """Build options for a worker agent — sectool HTTP + worker_tools SDK MCP."""
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


async def attempt_orchestrator_recovery(
    old_client: ClaudeSDKClient | None,
    orch_options: ClaudeAgentOptions,
) -> ClaudeSDKClient | None:
    if old_client is not None:
        try:
            await old_client.__aexit__(None, None, None)
        except BaseException:
            pass
    for attempt in range(1, 3):
        try:
            await asyncio.sleep(2)
            client = ClaudeSDKClient(options=orch_options)
            await client.__aenter__()
            log("orch", f"Recovery succeeded (attempt {attempt})")
            return client
        except Exception as exc:
            log("orch", f"Recovery attempt {attempt} failed: {exc}")
    return None


# ---------------------------------------------------------------------------
# Parallel worker collection
# ---------------------------------------------------------------------------


async def _collect_one_worker(
    worker: WorkerState,
    iteration: int,
    candidates: CandidatePool,
    timeout: float,
    verbose: bool,
) -> WorkerTurnSummary | None:
    tag = f"w{worker.worker_id}" if verbose else None
    try:
        return await asyncio.wait_for(
            collect_worker_turn(worker.client, worker.worker_id, iteration, candidates, tag),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        log(f"worker {worker.worker_id}", "Timed out (5 min). Interrupting...")
        try:
            await worker.client.interrupt()
        except Exception:
            pass
        s = WorkerTurnSummary(worker_id=worker.worker_id, iteration=iteration)
        s.assistant_text = "(Worker timed out and was interrupted.)"
        return s
    except (ConnectionError, OSError) as exc:
        log(f"worker {worker.worker_id}", f"Connection lost: {exc}")
        return None


async def collect_all_workers(
    workers: list[WorkerState],
    iteration: int,
    candidates: CandidatePool,
    timeout: float = 300,
    verbose: bool = False,
) -> dict[int, WorkerTurnSummary | None]:
    tasks = {
        w.worker_id: asyncio.create_task(
            _collect_one_worker(w, iteration, candidates, timeout, verbose),
        )
        for w in workers if w.alive and w.client is not None
    }
    results: dict[int, WorkerTurnSummary | None] = {}
    for wid, task in tasks.items():
        results[wid] = await task
    return results


# ---------------------------------------------------------------------------
# Orchestrator turn  (task 5)
# ---------------------------------------------------------------------------


async def run_orchestrator_turn(
    client: ClaudeSDKClient,
    user_content: str,
    decisions: DecisionQueue,
    iteration: int,
    verbose: bool,
) -> tuple[bool, float | None]:
    """Send a message to the orchestrator and drain messages until ResultMessage.

    Side-effect: orchestrator tool handlers populate `decisions`. Returns
    (success, cost). On retryable error, returns (False, None).
    """
    decisions.reset()
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
                            log("orch", f"tool: {block.name}")
            elif isinstance(msg, ResultMessage):
                cost = msg.total_cost_usd
                break
    except (ConnectionError, OSError, asyncio.TimeoutError) as exc:
        log(f"iter {iteration}", f"Orchestrator error: {exc}")
        return False, None

    orch_text = "\n".join(text_parts).strip()
    _print_orchestrator_turn(orch_text, tool_calls, iteration, decisions, verbose)
    return True, cost


def _print_orchestrator_turn(
    text: str,
    tool_calls: list[str],
    iteration: int,
    decisions: DecisionQueue,
    verbose: bool,
) -> None:
    print(flush=True)
    print(f"=== Orchestrator (iter {iteration}) ===", flush=True)
    if verbose and text:
        print(text, flush=True)
    elif text:
        print(_short(text, 500), flush=True)

    actions: list[str] = []
    if decisions.plan is not None:
        actions.append(f"plan_workers({len(decisions.plan)} assignments)")
    for d in decisions.worker_decisions:
        if d.kind == "stop":
            actions.append(f"stop_worker({d.worker_id})")
        else:
            actions.append(f"{d.kind}_worker({d.worker_id}, progress={d.progress})")
    for f in decisions.findings:
        actions.append(f"file_finding({f.severity}: {_short(f.title, 40)})")
    for dm in decisions.dismissals:
        actions.append(f"dismiss_candidate({dm.candidate_id})")
    if decisions.done_summary is not None:
        actions.append("done")
    if actions:
        print("Decisions: " + " | ".join(actions), flush=True)
    else:
        print("Decisions: (none — worker(s) will continue with implicit progress=none)", flush=True)
    print("=" * 38, flush=True)
    print(flush=True)


# ---------------------------------------------------------------------------
# Message builders
# ---------------------------------------------------------------------------


def _format_tool_calls(calls: list[ToolCallRecord], limit: int = 20) -> str:
    if not calls:
        return "  (no tool calls)"
    lines = []
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


def _format_worker_summary(s: WorkerTurnSummary) -> str:
    parts = [
        f"### Worker {s.worker_id}",
        f"Assistant summary: {s.assistant_text.strip() or '(no text)'}",
        "",
        f"Tool calls ({len(s.tool_calls)}):",
        _format_tool_calls(s.tool_calls),
    ]
    if s.flow_ids_touched:
        parts.append("")
        parts.append(f"Flow IDs referenced: {', '.join(s.flow_ids_touched)}")
    if s.candidate_ids:
        parts.append(f"Finding candidates raised this turn: {', '.join(s.candidate_ids)}")
    return "\n".join(parts)


def _format_pending_candidates(candidates: CandidatePool) -> str:
    pending = candidates.pending()
    if not pending:
        return "No pending finding candidates."
    lines = ["**Pending finding candidates (awaiting verification):**"]
    for c in pending:
        lines.append(
            f"- `{c.candidate_id}` [{c.severity}] {c.title} — {c.endpoint}\n"
            f"  flows: {', '.join(c.flow_ids) or '(none)'}\n"
            f"  summary: {_short(c.summary, 200)}\n"
            f"  reproduction hint: {_short(c.reproduction_hint, 200)}"
        )
    return "\n".join(lines)


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
                "'progress=none' turns. Either expand its plan or stop it."
            )
    if not warnings:
        return ""
    return "**Stall warnings:**\n" + "\n".join(warnings)


def _build_orch_message(
    iteration: int,
    max_iter: int,
    total_cost: float,
    max_cost: float | None,
    findings_summary: str,
    findings_count: int,
    pending_candidates_text: str,
    stall_warnings: str,
    worker_summaries: list[WorkerTurnSummary],
    worker_status_note: str = "",
) -> str:
    parts = [
        _format_status_line(iteration, max_iter, total_cost, max_cost, findings_count),
        "",
        findings_summary,
        "",
        pending_candidates_text,
    ]
    if stall_warnings:
        parts.append("")
        parts.append(stall_warnings)
    parts.append("")
    parts.append(f"**Iteration {iteration} — worker turn results:**")
    parts.append("")
    for s in worker_summaries:
        parts.append(_format_worker_summary(s))
        parts.append("")
    if worker_status_note:
        parts.append(worker_status_note)
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Apply orchestrator decisions  (tasks 6 + 8)
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
    """Spawn new workers, retarget existing. Omitted alive workers are left running."""
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
    """Dispatch a single orchestrator decision to the target worker."""
    if decision.kind == "stop":
        log(f"iter {iteration}", f"Worker {worker.worker_id}: stop — {decision.reason}")
        await teardown_worker(worker)
        return

    # Update stall tracking
    if decision.progress == "none":
        worker.progress_none_streak += 1
    else:
        worker.progress_none_streak = 0
        worker.stall_warned = False

    snippet = _short(decision.instruction, 120)
    log(f"iter {iteration}",
        f"Worker {worker.worker_id}: {decision.kind} (progress={decision.progress}) — \"{snippet}\"")

    worker.last_instruction = decision.instruction
    try:
        await worker.client.query(decision.instruction)
    except (ConnectionError, OSError):
        await attempt_worker_recovery(worker)


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

        # Strip inherited Claude session env
        for key in [k for k in os.environ if k.startswith("CLAUDE")]:
            os.environ.pop(key, None)

        mcp_url = f"http://127.0.0.1:{config.mcp_port}/mcp"
        stderr_cb = (lambda line: log("claude", line.rstrip())) if config.verbose else None

        worker_tools_server = build_worker_mcp_server(candidates)
        orch_tools_server = build_orch_mcp_server(decisions)

        # Base options (cwd, model, max_turns) — worker/orchestrator options are
        # built on top of these with their own mcp_servers.
        base_options = ClaudeAgentOptions(
            cwd=repo_root,
            max_turns=100,
        )
        if config.worker_model_id:
            base_options.model = config.worker_model_id

        orch_options = ClaudeAgentOptions(
            mcp_servers={
                "sectool": {"type": "http", "url": mcp_url},
                "orch_tools": orch_tools_server,
            },
            allowed_tools=list(ORCH_SECTOOL_READ_TOOLS) + list(ORCH_TOOL_ALLOWED),
            permission_mode="acceptEdits",
            cwd=repo_root,
            max_turns=100,
            model=config.orchestrator_model_id,
            stderr=stderr_cb,
            system_prompt=orch_prompts.build_system_prompt(config.max_workers),
        )

        workers: list[WorkerState] = []
        orch_client: ClaudeSDKClient | None = None

        try:
            # Create initial worker
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

            try:
                orch_client = ClaudeSDKClient(options=orch_options)
                await orch_client.__aenter__()
            except Exception as exc:
                await teardown_worker(workers[0])
                log("orch", f"Failed to connect orchestrator: {exc}")
                raise SystemExit(1) from exc
            log("orch", "Orchestrator connected.")

            # Initial prompt to worker 1
            workers[0].last_instruction = config.prompt
            try:
                await workers[0].client.query(config.prompt)
            except (ConnectionError, OSError) as exc:
                log("worker", f"Initial prompt failed: {exc}. Recovery...")
                if not await attempt_worker_recovery(workers[0]):
                    raise SystemExit(1)

            # Main iteration loop
            for iteration in range(1, config.max_iterations + 1):
                alive = [w for w in workers if w.alive]
                if not alive:
                    log(f"iter {iteration}", "No alive workers. Stopping.")
                    break

                log(f"iter {iteration}", f"Waiting for {len(alive)} worker(s)...")
                results = await collect_all_workers(
                    alive, iteration, candidates, verbose=config.verbose,
                )

                # Recover any dead workers
                for w in alive:
                    if results.get(w.worker_id) is None:
                        if await attempt_worker_recovery(w):
                            # Re-collect just this one
                            r = await _collect_one_worker(
                                w, iteration, candidates, 300, config.verbose,
                            )
                            results[w.worker_id] = r

                # Cost accumulation + per-worker log
                for wid, s in results.items():
                    if s is not None and s.cost_usd is not None:
                        total_cost += s.cost_usd
                    if s is not None:
                        names = ", ".join(c.name for c in s.tool_calls) or "none"
                        log(f"iter {iteration}", f"Worker {wid}: tools=[{names}] flows={len(s.flow_ids_touched)} candidates={len(s.candidate_ids)}")

                if config.verbose:
                    for wid in sorted(results.keys()):
                        s = results[wid]
                        if s is None:
                            continue
                        print(f"\n--- Worker {wid} Output (iter {iteration}) ---")
                        print(s.assistant_text)
                        print(f"--- End Worker {wid} Output ---\n")

                # Cost ceiling check
                if config.max_cost is not None and total_cost >= config.max_cost:
                    log(f"iter {iteration}", f"Cost ceiling reached (${total_cost:.2f}). Stopping.")
                    break

                # Build orchestrator prompt
                findings_summary = finding_writer.summary_for_orchestrator()
                pending_text = _format_pending_candidates(candidates)
                stall_warnings = _format_stall_warnings(workers)

                alive_ids = {w.worker_id for w in workers if w.alive}
                dead_ids = {w.worker_id for w in workers} - alive_ids
                worker_status = ""
                if dead_ids:
                    worker_status = (
                        f"**Worker status**: Active: "
                        f"{', '.join(str(i) for i in sorted(alive_ids))}. "
                        f"No longer active: "
                        f"{', '.join(str(i) for i in sorted(dead_ids))}."
                    )

                summary_list = [
                    results[wid] for wid in sorted(results.keys()) if results[wid] is not None
                ]

                first_turn_note = (
                    "\n\nThis is iteration 1 — the worker's initial discovery turn. "
                    "Based on what was found, you may call `plan_workers` to fan out "
                    "into parallel assignments, or call `continue_worker` / "
                    "`expand_worker` for worker 1 if a single worker suffices."
                    if iteration == 1 else ""
                )

                orch_user = _build_orch_message(
                    iteration=iteration,
                    max_iter=config.max_iterations,
                    total_cost=total_cost,
                    max_cost=config.max_cost,
                    findings_summary=findings_summary,
                    findings_count=finding_writer.count,
                    pending_candidates_text=pending_text,
                    stall_warnings=stall_warnings,
                    worker_summaries=summary_list,
                    worker_status_note=worker_status,
                )
                orch_user += first_turn_note

                # Run orchestrator turn
                ok, orch_cost = await run_orchestrator_turn(
                    orch_client, orch_user, decisions, iteration, config.verbose,
                )
                if not ok:
                    log(f"iter {iteration}", "Orchestrator turn failed. Attempting recovery...")
                    orch_client = await attempt_orchestrator_recovery(orch_client, orch_options)
                    if orch_client is None:
                        log(f"iter {iteration}", "Orchestrator recovery failed. Stopping.")
                        break
                    ok, orch_cost = await run_orchestrator_turn(
                        orch_client, orch_user, decisions, iteration, config.verbose,
                    )
                    if not ok:
                        log(f"iter {iteration}", "Orchestrator still unavailable. Stopping.")
                        break
                if orch_cost is not None:
                    total_cost += orch_cost

                # Mark warning issuance now (after the orchestrator had a chance to act)
                for w in workers:
                    if w.alive and w.progress_none_streak >= STALL_WARN_AFTER:
                        w.stall_warned = True

                # Apply findings
                for filed in decisions.findings:
                    if finding_writer.is_duplicate(filed):
                        log("finding", f"Duplicate skipped: {filed.title}")
                    else:
                        path = finding_writer.write(filed)
                        log("finding", f"Written: {path}")
                    # Resolve candidates regardless of dup status — the
                    # orchestrator verified them; only the doc is redundant.
                    for cid in filed.supersedes_candidate_ids:
                        candidates.mark(cid, "verified")

                # Apply dismissals
                for dm in decisions.dismissals:
                    candidates.mark(dm.candidate_id, "dismissed")
                    log("finding", f"Candidate {dm.candidate_id} dismissed: {_short(dm.reason, 80)}")

                # Check done
                if decisions.done_summary is not None:
                    log(f"iter {iteration}", f"Orchestrator: done — {_short(decisions.done_summary, 120)}")
                    break

                # Apply plan diff (if any)
                if decisions.plan is not None:
                    await apply_plan_diff(
                        decisions.plan, workers, worker_tools_server, mcp_url,
                        base_options, stderr_cb, config.max_workers,
                    )

                # Dispatch per-worker decisions
                decided_wids: set[int] = set()
                for d in decisions.worker_decisions:
                    worker = next((w for w in workers if w.worker_id == d.worker_id), None)
                    if worker is None or not worker.alive:
                        log(f"iter {iteration}", f"Decision for unknown/dead worker {d.worker_id} — skipped.")
                        continue
                    await apply_decision(d, worker, iteration)
                    decided_wids.add(d.worker_id)

                # Implicit continue for alive workers with no decision
                for w in workers:
                    if not w.alive or w.worker_id in decided_wids:
                        continue
                    if decisions.plan is not None and any(p.worker_id == w.worker_id for p in decisions.plan):
                        continue  # already handled by plan diff
                    log(f"iter {iteration}",
                        f"Worker {w.worker_id}: no explicit decision — implicit continue (progress=none).")
                    w.progress_none_streak += 1
                    if w.last_instruction:
                        try:
                            await w.client.query("Continue your current testing plan.")
                        except (ConnectionError, OSError):
                            await attempt_worker_recovery(w)

                # Forced stop after warned + still-stuck
                for w in list(workers):
                    if w.alive and w.progress_none_streak >= STALL_STOP_AFTER:
                        log(f"iter {iteration}",
                            f"Worker {w.worker_id}: stalled past threshold ({w.progress_none_streak} × progress=none). Stopping.")
                        await teardown_worker(w)

            else:
                log("summary", f"Max iterations ({config.max_iterations}) reached.")

        finally:
            alive_count = sum(1 for w in workers if w.alive)
            for w in workers:
                if w.alive:
                    await teardown_worker(w)
            if orch_client is not None:
                try:
                    await orch_client.__aexit__(None, None, None)
                except BaseException:
                    pass

        # Final summary
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
