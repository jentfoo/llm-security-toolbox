"""Main orchestrator loop for autonomous security exploration."""

import asyncio
import io
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    ResultMessage,
    TextBlock,
    ToolUseBlock,
)

from config import Config, parse_args
from findings import FindingWriter
from prompts import orchestrator as orch_prompts
from prompts import worker as worker_prompts


def log(tag: str, msg: str) -> None:
    print(f"[{tag:<8s}] {msg}", flush=True)


def print_orchestrator_response(response: str, iteration: int, verbose: bool) -> None:
    """Always print the orchestrator's decision. Show full text in verbose mode."""
    print(flush=True)
    print(f"=== Orchestrator (iter {iteration}) ===", flush=True)
    if verbose:
        print(response, flush=True)
    else:
        # Print a meaningful summary: first 500 chars
        trimmed = response.strip()
        if len(trimmed) > 500:
            print(trimmed[:500], flush=True)
            print(f"... [{len(trimmed) - 500} chars truncated, use --verbose for full output]", flush=True)
        else:
            print(trimmed, flush=True)
    print("=" * 38, flush=True)
    print(flush=True)


# ---------------------------------------------------------------------------
# Build and server lifecycle
# ---------------------------------------------------------------------------


def build_sectool(repo_root: str) -> None:
    log("build", "Building sectool...")
    result = subprocess.run(
        ["make", "build"],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        log("build", f"Build failed:\n{result.stdout}\n{result.stderr}")
        sys.exit(1)
    log("build", "Build complete.")


def start_mcp_server(
    repo_root: str,
    proxy_port: int,
    mcp_port: int,
    workflow: str,
) -> tuple[subprocess.Popen, "io.TextIOWrapper"]:
    binary = os.path.join(repo_root, "bin", "sectool")
    cmd = [
        binary,
        "mcp",
        f"--proxy-port={proxy_port}",
        f"--port={mcp_port}",
        f"--workflow={workflow}",
    ]
    log_path = os.path.join(repo_root, "sectool-mcp.log")
    log_file = open(log_path, "w")  # noqa: SIM115
    log("server", f"Starting sectool MCP server on :{mcp_port} (proxy :{proxy_port}, workflow: {workflow})")
    log("server", f"Server stderr → {log_path}")
    proc = subprocess.Popen(
        cmd,
        stderr=log_file,
        stdout=subprocess.DEVNULL,
    )
    return proc, log_file


def wait_for_server(mcp_port: int, proc: subprocess.Popen, timeout: float = 10.0) -> None:
    url = f"http://127.0.0.1:{mcp_port}/mcp"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        exit_code = proc.poll()
        if exit_code is not None:
            log("server", f"MCP server exited early (code {exit_code}). Check sectool-mcp.log for details.")
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
    consecutive_failures: int = 0
    assignment: str = ""
    consecutive_continues: int = 0
    stall_warned: bool = False


# ---------------------------------------------------------------------------
# Worker response collection
# ---------------------------------------------------------------------------


async def collect_worker_response(
    client: ClaudeSDKClient,
    verbose_tag: str | None = None,
) -> tuple[str, list[str], float | None]:
    """Consume messages until ResultMessage.

    Returns (text_output, tools_used, cost_usd).
    When verbose_tag is set, logs tool calls and text snippets in real-time.
    """
    text_parts: list[str] = []
    tools_used: list[str] = []
    cost: float | None = None

    async for message in client.receive_response():
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    text_parts.append(block.text)
                    if verbose_tag:
                        # Show first line of text as progress
                        first_line = block.text.strip().split("\n", 1)[0]
                        if first_line:
                            preview = first_line[:120] + ("..." if len(first_line) > 120 else "")
                            log(verbose_tag, f"text: {preview}")
                elif isinstance(block, ToolUseBlock):
                    tools_used.append(block.name)
                    if verbose_tag:
                        log(verbose_tag, f"tool: {block.name}")
        elif isinstance(message, ResultMessage):
            cost = message.total_cost_usd
            if verbose_tag:
                cost_str = f"${cost:.4f}" if cost else "n/a"
                log(verbose_tag, f"done ({len(tools_used)} tools, cost: {cost_str})")
            break

    return "\n".join(text_parts), tools_used, cost


# ---------------------------------------------------------------------------
# Worker lifecycle helpers
# ---------------------------------------------------------------------------


def _new_worker_options(
    base: ClaudeAgentOptions, worker_id: int, num_workers: int,
) -> ClaudeAgentOptions:
    """Build a fresh ClaudeAgentOptions for a worker, avoiding deepcopy."""
    return ClaudeAgentOptions(
        mcp_servers=base.mcp_servers,
        allowed_tools=list(base.allowed_tools),
        disallowed_tools=list(base.disallowed_tools),
        permission_mode=base.permission_mode,
        cwd=base.cwd,
        max_turns=base.max_turns,
        model=base.model,
        stderr=base.stderr,
        system_prompt=worker_prompts.build_system_prompt(worker_id, num_workers),
    )


async def create_worker(
    worker_id: int,
    base_options: ClaudeAgentOptions,
    num_workers: int,
) -> WorkerState:
    """Create and connect a new worker."""
    opts = _new_worker_options(base_options, worker_id, num_workers)
    client = ClaudeSDKClient(options=opts)
    await client.__aenter__()
    return WorkerState(
        worker_id=worker_id,
        options=opts,
        client=client,
    )


async def teardown_worker(state: WorkerState) -> None:
    """Gracefully disconnect a worker."""
    state.alive = False
    if state.client is not None:
        try:
            await state.client.__aexit__(None, None, None)
        except BaseException:
            pass
    state.client = None


async def attempt_worker_recovery(state: WorkerState) -> bool:
    """Attempt to reconnect a failed worker. Up to 2 retries with 2s backoff."""
    await teardown_worker(state)
    for attempt in range(1, 3):
        try:
            await asyncio.sleep(2)
            client = ClaudeSDKClient(options=state.options)
            await client.__aenter__()
            state.client = client
            state.alive = True
            state.consecutive_failures = 0
            log(f"worker {state.worker_id}", f"Recovery succeeded (attempt {attempt})")
            # Replay last instruction if available
            if state.last_instruction:
                await client.query(state.last_instruction)
            return True
        except Exception as exc:
            log(f"worker {state.worker_id}", f"Recovery attempt {attempt} failed: {exc}")
    state.consecutive_failures += 1
    state.alive = False
    return False


async def attempt_orchestrator_recovery(
    old_client: ClaudeSDKClient | None,
    orch_options: ClaudeAgentOptions,
) -> ClaudeSDKClient | None:
    """Attempt to reconnect the orchestrator. Returns client or None."""
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
# Parallel collection
# ---------------------------------------------------------------------------


async def _collect_one_worker(
    worker: WorkerState, timeout: float = 300, verbose: bool = False,
) -> tuple[str, list[str], float | None] | None:
    """Collect from a single worker with timeout. Returns None on connection failure."""
    tag = f"w{worker.worker_id}" if verbose else None
    try:
        return await asyncio.wait_for(
            collect_worker_response(worker.client, verbose_tag=tag),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        log(f"worker {worker.worker_id}", "Timed out (5 min). Interrupting...")
        try:
            await worker.client.interrupt()
        except Exception:
            pass
        return ("(Worker timed out and was interrupted.)", [], None)
    except (ConnectionError, OSError) as exc:
        log(f"worker {worker.worker_id}", f"Connection lost: {exc}")
        return None


async def collect_all_workers(
    workers: list[WorkerState], timeout: float = 300, verbose: bool = False,
) -> dict[int, tuple[str, list[str], float | None] | None]:
    """Collect responses from all alive workers in parallel."""
    tasks = {
        w.worker_id: asyncio.create_task(
            _collect_one_worker(w, timeout, verbose=verbose),
        )
        for w in workers if w.alive and w.client is not None
    }
    results = {}
    for wid, task in tasks.items():
        results[wid] = await task
    return results


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


MAX_ORCH_RETRIES = 2


async def query_orchestrator(
    client: ClaudeSDKClient,
    message: str,
    iteration: int,
) -> tuple[str, float | None] | None:
    """Send message to orchestrator, collect text response. Returns None on failure."""
    last_exc: Exception | None = None
    for attempt in range(1, MAX_ORCH_RETRIES + 1):
        try:
            await client.query(message)
            text_parts: list[str] = []
            cost: float | None = None
            async for msg in client.receive_response():
                if isinstance(msg, AssistantMessage):
                    for block in msg.content:
                        if isinstance(block, TextBlock):
                            text_parts.append(block.text)
                elif isinstance(msg, ResultMessage):
                    cost = msg.total_cost_usd
                    break
            return "\n".join(text_parts), cost
        except (ConnectionError, OSError, asyncio.TimeoutError) as exc:
            last_exc = exc
            log(f"iter {iteration}", f"Orchestrator attempt {attempt}/{MAX_ORCH_RETRIES} failed: {exc}")
            if attempt < MAX_ORCH_RETRIES:
                await asyncio.sleep(2)
        except Exception as exc:
            log(f"iter {iteration}", f"Orchestrator error (non-retryable): {exc}")
            return None
    log(f"iter {iteration}", f"Orchestrator failed after {MAX_ORCH_RETRIES} attempts: {last_exc}")
    return None


# ---------------------------------------------------------------------------
# Decision parsing
# ---------------------------------------------------------------------------


def parse_decision(response: str) -> tuple[str, str]:
    """Parse the orchestrator decision prefix.

    Returns (decision_type, content) where decision_type is one of
    CONTINUE, EXPAND, FINDING, DONE.
    """
    stripped = response.strip()
    for prefix in ("CONTINUE:", "EXPAND:", "FINDING:", "DONE:"):
        if stripped.startswith(prefix):
            return prefix[:-1], stripped[len(prefix):].strip()
    # Case-insensitive fallback
    upper = stripped.upper()
    for prefix in ("CONTINUE:", "EXPAND:", "FINDING:", "DONE:"):
        if upper.startswith(prefix):
            return prefix[:-1], stripped[len(prefix):].strip()
    # No recognised prefix — treat as CONTINUE
    return "CONTINUE", stripped


_PLAN_WORKER_RE = re.compile(r"^WORKER\s+(\d+)\s*:\s*(.+)", re.IGNORECASE)


def parse_plan(response: str) -> list[tuple[int, str]]:
    """Parse a PLAN: response into worker assignments.

    Returns list of (worker_id, assignment) tuples.
    """
    assignments = []
    in_plan = False
    for line in response.splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("PLAN:"):
            in_plan = True
            continue
        if not in_plan:
            continue
        m = _PLAN_WORKER_RE.match(stripped)
        if m:
            wid = int(m.group(1))
            assignment = m.group(2).strip()
            assignments.append((wid, assignment))
    return assignments


_WORKER_DECISION_RE = re.compile(
    r"^WORKER\s+(\d+)\s+(CONTINUE|EXPAND|DONE)\s*:\s*(.*)",
    re.IGNORECASE,
)


def parse_multi_decision(
    response: str, num_workers: int,
) -> tuple[list[tuple[int, str, str]], list[str]]:
    """Parse multi-worker orchestrator decisions.

    Returns (worker_decisions, findings) where:
    - worker_decisions: list of (worker_id, decision_type, content)
        worker_id 0 = global
    - findings: list of finding texts from FINDING: blocks
    """
    if num_workers == 1:
        decision, content = parse_decision(response)
        if decision == "FINDING":
            return ([], [content])
        return ([(1, decision, content)], [])

    worker_decisions: list[tuple[int, str, str]] = []
    findings: list[str] = []
    mentioned_workers: set[int] = set()

    lines = response.splitlines()
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()

        # FINDING: block — collect until next recognized prefix
        if stripped.upper().startswith("FINDING:"):
            finding_lines = [stripped[len("FINDING:"):].strip()]
            i += 1
            while i < len(lines):
                next_stripped = lines[i].strip()
                upper_next = next_stripped.upper()
                if (upper_next.startswith("FINDING:")
                        or upper_next.startswith("DONE:")
                        or upper_next.startswith("CONTINUE:")
                        or upper_next.startswith("EXPAND:")
                        or _WORKER_DECISION_RE.match(next_stripped)):
                    break
                finding_lines.append(lines[i])
                i += 1
            findings.append("\n".join(finding_lines).strip())
            continue

        # WORKER N DECISION: ...
        m = _WORKER_DECISION_RE.match(stripped)
        if m:
            wid = int(m.group(1))
            decision = m.group(2).upper()
            content = m.group(3).strip()
            # Collect continuation lines
            i += 1
            while i < len(lines):
                next_stripped = lines[i].strip()
                upper_next = next_stripped.upper()
                if (upper_next.startswith("FINDING:")
                        or upper_next.startswith("DONE:")
                        or upper_next.startswith("CONTINUE:")
                        or upper_next.startswith("EXPAND:")
                        or _WORKER_DECISION_RE.match(next_stripped)):
                    break
                content += "\n" + lines[i]
                i += 1
            worker_decisions.append((wid, decision, content.strip()))
            mentioned_workers.add(wid)
            continue

        # Global DONE:
        if stripped.upper().startswith("DONE:"):
            worker_decisions.append((0, "DONE", stripped[len("DONE:"):].strip()))
            i += 1
            continue

        # Bare CONTINUE:/EXPAND: applies to all alive workers
        for prefix in ("CONTINUE:", "EXPAND:"):
            if stripped.upper().startswith(prefix):
                decision = prefix[:-1]
                content = stripped[len(prefix):].strip()
                for wid in range(1, num_workers + 1):
                    worker_decisions.append((wid, decision, content))
                    mentioned_workers.add(wid)
                break
        i += 1

    # Unmentioned workers default to CONTINUE with empty content
    for wid in range(1, num_workers + 1):
        if wid not in mentioned_workers:
            worker_decisions.append((wid, "CONTINUE", ""))

    return worker_decisions, findings


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
        # 1. Build
        if not config.skip_build:
            build_sectool(repo_root)

        # 2. Start MCP server
        server_proc, server_log = start_mcp_server(
            repo_root, config.proxy_port, config.mcp_port, config.workflow,
        )

    iteration = 0
    finding_writer = FindingWriter(config.findings_dir)
    total_cost = 0.0

    try:
        if not config.external:
            wait_for_server(config.mcp_port, server_proc)

        # 3. Connect Claude Code
        # Strip env vars from any parent Claude Code session
        for key in [k for k in os.environ if k.startswith("CLAUDE")]:
            os.environ.pop(key, None)

        mcp_url = f"http://127.0.0.1:{config.mcp_port}/mcp"
        stderr_cb = (lambda line: log("claude", line.rstrip())) if config.verbose else None

        # Base worker options (without system prompt — set per-worker)
        worker_options_base = ClaudeAgentOptions(
            mcp_servers={
                "sectool": {
                    "type": "http",
                    "url": mcp_url,
                },
            },
            allowed_tools=[
                "mcp__sectool__*",
                "Read",
                "Glob",
                "Grep",
                "Bash",
            ],
            disallowed_tools=["Write", "Edit"],
            permission_mode="acceptEdits",
            cwd=repo_root,
            max_turns=100,
            stderr=stderr_cb,
        )
        if config.worker_model_id:
            worker_options_base.model = config.worker_model_id

        orch_options = ClaudeAgentOptions(
            system_prompt=orch_prompts.build_system_prompt(config.max_workers),
        )
        orch_options.model = config.orchestrator_model_id

        workers: list[WorkerState] = []
        orch_client: ClaudeSDKClient | None = None

        try:
            # Create initial worker (single, for discovery)
            log("worker", "Connecting Claude Code worker 1...")
            try:
                w1 = await create_worker(1, worker_options_base, 1)
                workers.append(w1)
            except Exception as exc:
                log("worker", f"Failed to connect Claude Code worker: {exc}")
                raise SystemExit(1) from exc
            log("worker", "Claude Code worker 1 connected.")

            try:
                orch_client = ClaudeSDKClient(options=orch_options)
                await orch_client.__aenter__()
            except Exception as exc:
                await teardown_worker(workers[0])
                log("orch", f"Failed to connect Claude Code orchestrator: {exc}")
                raise SystemExit(1) from exc
            log("orch", "Orchestrator connected.")

            # 4. Initial prompt with retry
            log("worker", "Sending initial prompt...")
            workers[0].last_instruction = config.prompt
            try:
                await workers[0].client.query(config.prompt)
            except (ConnectionError, OSError) as exc:
                log("worker", f"Initial prompt failed: {exc}. Attempting recovery...")
                if not await attempt_worker_recovery(workers[0]):
                    log("worker", "Recovery failed. Exiting.")
                    raise SystemExit(1)

            # ================================================================
            # Phase 1: Discovery (iteration 1)
            # ================================================================
            iteration = 1
            log(f"iter {iteration}", "Waiting for worker (discovery)...")

            results = await collect_all_workers(workers, verbose=config.verbose)
            result_1 = results.get(1)
            if result_1 is None:
                log(f"iter {iteration}", "Worker connection lost during discovery.")
                if not await attempt_worker_recovery(workers[0]):
                    raise SystemExit(1)
                results = await collect_all_workers(workers, verbose=config.verbose)
                result_1 = results.get(1)
                if result_1 is None:
                    log(f"iter {iteration}", "Worker failed again. Exiting.")
                    raise SystemExit(1)

            worker_output, tools_used, cost = result_1
            if cost is not None:
                total_cost += cost

            tools_str = ", ".join(tools_used) if tools_used else "none"
            log(f"iter {iteration}", f"Worker 1: used tools [{tools_str}]")
            if config.verbose:
                print(f"\n--- Worker 1 Output (iter {iteration}) ---")
                print(worker_output)
                print("--- End Worker 1 Output ---\n")

            # Cost ceiling check
            if config.max_cost is not None and total_cost >= config.max_cost:
                log(f"iter {iteration}", f"Cost ceiling reached (${total_cost:.2f}). Stopping.")
                return

            # Send discovery results to orchestrator
            initial_context = orch_prompts.format_initial_message(config.prompt, config.max_workers)
            worker_msg = orch_prompts.format_worker_result(worker_output, tools_used, iteration)
            user_content = initial_context + "\n\n" + worker_msg

            result = await query_orchestrator(orch_client, user_content, iteration)
            if result is None:
                log(f"iter {iteration}", "Orchestrator unavailable. Attempting recovery...")
                orch_client = await attempt_orchestrator_recovery(orch_client, orch_options)
                if orch_client is None:
                    log(f"iter {iteration}", "Orchestrator recovery failed. Stopping.")
                    return
                result = await query_orchestrator(orch_client, user_content, iteration)
                if result is None:
                    log(f"iter {iteration}", "Orchestrator still unavailable. Stopping.")
                    return

            orch_response, orch_cost = result
            if orch_cost is not None:
                total_cost += orch_cost

            print_orchestrator_response(orch_response, iteration, config.verbose)

            # ================================================================
            # Phase 2: Planning — parse orchestrator's response to discovery
            # ================================================================
            num_workers = 1
            plan = parse_plan(orch_response)

            # Process any findings in the planning response
            decision, content = parse_decision(orch_response)
            if decision == "FINDING":
                if not finding_writer.is_duplicate(content):
                    filepath = finding_writer.write(content)
                    log("finding", f"Written to {filepath}")

            if decision == "DONE":
                log(f"iter {iteration}", f'Orchestrator: DONE — "{content[:100]}"')
                return
            elif plan:
                # PLAN: response — spawn workers
                num_workers = min(len(plan), config.max_workers)
                log(f"iter {iteration}", f"Orchestrator planned {num_workers} workers.")
                for wid, assignment in plan[:num_workers]:
                    snippet = assignment[:150] + ("..." if len(assignment) > 150 else "")
                    log("plan", f"Worker {wid}: {snippet}")

                for wid, assignment in plan[:num_workers]:
                    if wid == 1:
                        workers[0].assignment = assignment
                        workers[0].last_instruction = assignment
                        # Update worker 1's system prompt for multi-worker if needed
                        if num_workers > 1:
                            workers[0].options.system_prompt = worker_prompts.build_system_prompt(1, num_workers)
                        try:
                            await workers[0].client.query(assignment)
                        except (ConnectionError, OSError):
                            await attempt_worker_recovery(workers[0])
                    else:
                        log(f"worker", f"Connecting Claude Code worker {wid}...")
                        try:
                            new_worker = await create_worker(wid, worker_options_base, num_workers)
                            new_worker.assignment = assignment
                            new_worker.last_instruction = assignment
                            await new_worker.client.query(assignment)
                            workers.append(new_worker)
                            log(f"worker", f"Worker {wid} connected and assigned.")
                        except Exception as exc:
                            log(f"worker", f"Failed to create worker {wid}: {exc}")
            else:
                # Single-worker continuation (CONTINUE/EXPAND)
                snippet = content[:100] + ("..." if len(content) > 100 else "")
                log(f"iter {iteration}", f'Orchestrator: {decision} — "{snippet}"')
                workers[0].last_instruction = content
                try:
                    await workers[0].client.query(content)
                except (ConnectionError, OSError):
                    await attempt_worker_recovery(workers[0])

            # ================================================================
            # Phase 3: Execution loop (iterations 2+)
            # ================================================================
            for iteration in range(2, config.max_iterations + 1):
                alive = [w for w in workers if w.alive]
                if not alive:
                    log(f"iter {iteration}", "No alive workers. Stopping.")
                    break

                # Collect from all alive workers
                log(f"iter {iteration}", f"Waiting for {len(alive)} worker(s)...")
                results = await collect_all_workers(alive, verbose=config.verbose)

                # Recovery for failed workers
                for w in alive:
                    if results.get(w.worker_id) is None:
                        await attempt_worker_recovery(w)

                # Accumulate costs
                for wid, res in results.items():
                    if res is not None and res[2] is not None:
                        total_cost += res[2]

                if config.verbose:
                    for wid in sorted(results.keys()):
                        res = results[wid]
                        if res is not None:
                            print(f"\n--- Worker {wid} Output (iter {iteration}) ---")
                            print(res[0])
                            print(f"--- End Worker {wid} Output ---\n")

                # Log tools per worker
                for wid in sorted(results.keys()):
                    res = results[wid]
                    if res is not None:
                        ts = ", ".join(res[1]) if res[1] else "none"
                        log(f"iter {iteration}", f"Worker {wid}: used tools [{ts}]")

                # Cost ceiling check
                if config.max_cost is not None and total_cost >= config.max_cost:
                    log(f"iter {iteration}", f"Cost ceiling reached (${total_cost:.2f}). Stopping.")
                    break

                # Build orchestrator message
                findings_summary = finding_writer.summary_for_orchestrator()
                alive_after_recovery = [w for w in workers if w.alive]
                num_alive = len(alive_after_recovery)

                if num_alive <= 1 and num_workers <= 1:
                    # Single-worker path
                    res = results.get(1)
                    if res is not None:
                        wo, tu, _ = res
                    else:
                        wo, tu = "(Worker unavailable.)", []
                    user_content = orch_prompts.format_worker_result(wo, tu, iteration)
                    user_content += "\n\n" + findings_summary

                    # Stall detection (single worker)
                    w1 = workers[0]
                    if w1.consecutive_continues >= 3 and not w1.stall_warned:
                        user_content += orch_prompts.STALL_WARNING
                        w1.stall_warned = True
                        log(f"iter {iteration}", "Appending stall warning.")
                else:
                    # Multi-worker path
                    user_content = orch_prompts.format_multi_worker_result(
                        results, iteration, findings_summary,
                    )
                    all_ids = {w.worker_id for w in workers}
                    alive_ids = {w.worker_id for w in workers if w.alive}
                    dead_ids = all_ids - alive_ids
                    if dead_ids:
                        user_content += (
                            f"\n**Worker status**: Active: {', '.join(str(i) for i in sorted(alive_ids))}. "
                            f"No longer active: {', '.join(str(i) for i in sorted(dead_ids))}.\n"
                        )

                # Query orchestrator
                result = await query_orchestrator(orch_client, user_content, iteration)
                if result is None:
                    log(f"iter {iteration}", "Orchestrator unavailable. Attempting recovery...")
                    orch_client = await attempt_orchestrator_recovery(orch_client, orch_options)
                    if orch_client is None:
                        log(f"iter {iteration}", "Orchestrator recovery failed. Stopping.")
                        break
                    result = await query_orchestrator(orch_client, user_content, iteration)
                    if result is None:
                        log(f"iter {iteration}", "Orchestrator still unavailable. Stopping.")
                        break

                orch_response, orch_cost = result
                if orch_cost is not None:
                    total_cost += orch_cost

                print_orchestrator_response(orch_response, iteration, config.verbose)

                # Parse decisions
                if num_alive <= 1 and num_workers <= 1:
                    # Single-worker decision path
                    decision, content = parse_decision(orch_response)
                    snippet = content[:100] + ("..." if len(content) > 100 else "")
                    log(f"iter {iteration}", f'Orchestrator: {decision} — "{snippet}"')

                    if decision == "DONE":
                        break

                    if decision == "FINDING":
                        followup = None
                        while decision == "FINDING":
                            if not finding_writer.is_duplicate(content):
                                filepath = finding_writer.write(content)
                                log("finding", f"Written to {filepath}")
                            else:
                                log("finding", "Duplicate finding skipped.")
                            followup = await query_orchestrator(
                                orch_client,
                                "Finding recorded. Should we continue testing or is coverage sufficient?",
                                iteration,
                            )
                            if followup is None:
                                log(f"iter {iteration}", "Orchestrator unavailable after finding. Stopping.")
                                break
                            followup_response, followup_cost = followup
                            if followup_cost is not None:
                                total_cost += followup_cost
                            print_orchestrator_response(followup_response, iteration, config.verbose)
                            decision, content = parse_decision(followup_response)
                            snippet = content[:100] + ("..." if len(content) > 100 else "")
                            log(f"iter {iteration}", f'Orchestrator (post-finding): {decision} — "{snippet}"')
                        if followup is None or decision == "DONE":
                            break
                        workers[0].consecutive_continues = 0
                        workers[0].stall_warned = False
                        workers[0].last_instruction = content
                        try:
                            await workers[0].client.query(content)
                        except (ConnectionError, OSError):
                            await attempt_worker_recovery(workers[0])
                    elif decision == "EXPAND":
                        workers[0].consecutive_continues = 0
                        workers[0].stall_warned = False
                        workers[0].last_instruction = content
                        try:
                            await workers[0].client.query(content)
                        except (ConnectionError, OSError):
                            await attempt_worker_recovery(workers[0])
                    else:  # CONTINUE
                        workers[0].consecutive_continues += 1
                        if workers[0].stall_warned:
                            log(f"iter {iteration}", "STALLED: orchestrator did not redirect. Halting.")
                            break
                        workers[0].last_instruction = content
                        try:
                            await workers[0].client.query(content)
                        except (ConnectionError, OSError):
                            await attempt_worker_recovery(workers[0])
                else:
                    # Multi-worker decision path
                    worker_decisions, findings = parse_multi_decision(orch_response, num_workers)

                    # Process findings with dedup
                    for finding_text in findings:
                        if finding_writer.is_duplicate(finding_text):
                            log("finding", "Duplicate finding skipped.")
                            continue
                        filepath = finding_writer.write(finding_text)
                        log("finding", f"Written to {filepath}")

                    # Check global DONE
                    if any(d == "DONE" for wid, d, _ in worker_decisions if wid == 0):
                        log(f"iter {iteration}", "Orchestrator: global DONE.")
                        break

                    # Dispatch per-worker instructions
                    for wid, decision, content in worker_decisions:
                        if wid == 0:
                            continue
                        # Find worker by id
                        worker = None
                        for w in workers:
                            if w.worker_id == wid:
                                worker = w
                                break
                        if worker is None or not worker.alive:
                            continue

                        if decision == "DONE":
                            log(f"iter {iteration}", f"Worker {wid}: DONE.")
                            await teardown_worker(worker)
                            continue

                        message = content if content else "Continue your current testing plan."
                        snippet = message[:100] + ("..." if len(message) > 100 else "")
                        log(f"iter {iteration}", f'Worker {wid}: {decision} — "{snippet}"')
                        worker.last_instruction = message
                        worker.assignment = message[:100]
                        try:
                            await worker.client.query(message)
                        except (ConnectionError, OSError):
                            await attempt_worker_recovery(worker)
            else:
                log("summary", f"Max iterations ({config.max_iterations}) reached.")

        finally:
            # Capture before teardown
            alive_count = sum(1 for w in workers if w.alive)

            # Teardown all workers and orchestrator
            for w in workers:
                if w.alive:
                    await teardown_worker(w)
            if orch_client is not None:
                try:
                    await orch_client.__aexit__(None, None, None)
                except BaseException:
                    pass

        # -- Final summary --
        total_workers = len(workers)
        print()
        log("summary", f"Workers: {alive_count}/{total_workers} | Iterations: {iteration} | Findings: {finding_writer.count} | Cost: ${total_cost:.2f}")
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
