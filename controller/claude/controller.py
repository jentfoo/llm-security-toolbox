"""Main orchestrator loop for autonomous security exploration."""

import asyncio
import io
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

import anthropic
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
# Worker response collection
# ---------------------------------------------------------------------------


async def collect_worker_response(
    client: ClaudeSDKClient,
) -> tuple[str, list[str], float | None]:
    """Consume messages until ResultMessage.

    Returns (text_output, tools_used, cost_usd).
    """
    text_parts: list[str] = []
    tools_used: list[str] = []
    cost: float | None = None

    async for message in client.receive_response():
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    text_parts.append(block.text)
                elif isinstance(block, ToolUseBlock):
                    tools_used.append(block.name)
        elif isinstance(message, ResultMessage):
            cost = message.total_cost_usd
            break

    return "\n".join(text_parts), tools_used, cost


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

CONTEXT_WINDOW = 200_000
SUMMARIZE_AT = int(CONTEXT_WINDOW * 0.4)  # 80,000 tokens


def call_orchestrator(
    client: anthropic.Anthropic,
    model: str,
    messages: list[dict],
) -> tuple[str, anthropic.types.Usage]:
    """Single orchestrator API call. Returns (response_text, usage)."""
    response = client.messages.create(
        model=model,
        max_tokens=4096,
        system=orch_prompts.SYSTEM_PROMPT,
        messages=messages,
    )
    return response.content[0].text, response.usage


def call_orchestrator_with_retry(
    client: anthropic.Anthropic,
    model: str,
    messages: list[dict],
    iteration: int,
) -> tuple[str, anthropic.types.Usage] | None:
    """Call orchestrator with one retry on API errors. Returns None on failure."""
    try:
        return call_orchestrator(client, model, messages)
    except anthropic.APIError as exc:
        log(f"iter {iteration}", f"Orchestrator API error, retrying: {exc}")
    try:
        time.sleep(2)
        return call_orchestrator(client, model, messages)
    except anthropic.APIError as exc:
        log(f"iter {iteration}", f"Orchestrator API error (retry failed): {exc}")
        return None


def summarize_context(
    client: anthropic.Anthropic,
    messages: list[dict],
    model: str,
) -> list[dict]:
    """Summarize older orchestrator messages to reduce context size.

    Keeps the first message (goal context) and the last 40% of messages intact,
    replacing the middle portion with a single summary message.
    """
    if len(messages) < 4:
        return messages

    keep_recent = max(2, int(len(messages) * 0.4))
    # Ensure even count so the slice starts on a user message (preserving alternation)
    if keep_recent % 2 != 0:
        keep_recent += 1
    keep_recent = min(keep_recent, len(messages) - 1)
    first_msg = messages[0]
    middle = messages[1:-keep_recent]
    recent = messages[-keep_recent:]

    if not middle:
        return messages

    middle_text = "\n\n---\n\n".join(
        f"[{m['role']}]: {m['content']}" for m in middle
    )

    try:
        response = client.messages.create(
            model=model,
            max_tokens=2048,
            messages=[{
                "role": "user",
                "content": (
                    "Summarize this security testing conversation history concisely. "
                    "Preserve: endpoints tested, vulnerability findings, tools used, "
                    "and key decisions. Omit redundant details.\n\n"
                    f"{middle_text}"
                ),
            }],
        )
        summary_text = response.content[0].text
    except anthropic.APIError as exc:
        log("context", f"Summarization failed, keeping original messages: {exc}")
        return messages

    summary_msg = {
        "role": "assistant",
        "content": f"[Context summary of iterations 2–{len(messages) - keep_recent}]:\n{summary_text}",
    }
    log("context", f"Summarized {len(middle)} messages into 1 (keeping first + {keep_recent} recent)")
    return [first_msg, summary_msg, *recent]


def parse_decision(response: str) -> tuple[str, str]:
    """Parse the orchestrator decision prefix.

    Returns (decision_type, content) where decision_type is one of
    CONTINUE, EXPAND, FINDING, DONE.
    """
    stripped = response.strip()
    for prefix in ("CONTINUE:", "EXPAND:", "FINDING:", "DONE:"):
        if stripped.startswith(prefix):
            return prefix[:-1], stripped[len(prefix) :].strip()
    # Case-insensitive fallback
    upper = stripped.upper()
    for prefix in ("CONTINUE:", "EXPAND:", "FINDING:", "DONE:"):
        if upper.startswith(prefix):
            return prefix[:-1], stripped[len(prefix) :].strip()
    # No recognised prefix — treat as CONTINUE
    return "CONTINUE", stripped


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
        mcp_url = f"http://127.0.0.1:{config.mcp_port}/mcp"
        options = ClaudeAgentOptions(
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
            system_prompt=worker_prompts.SYSTEM_PROMPT,
        )
        if config.worker_model_id:
            options.model = config.worker_model_id

        orch_client = anthropic.Anthropic()
        orch_messages: list[dict] = []
        consecutive_continues = 0
        stall_warned = False
        initial_context = orch_prompts.format_initial_message(config.prompt)

        async with ClaudeSDKClient(options=options) as client:
            # 4. Initial prompt
            log("worker", "Sending initial prompt...")
            await client.query(config.prompt)

            for iteration in range(1, config.max_iterations + 1):
                # -- Collect worker output --
                try:
                    worker_output, tools_used, cost = await asyncio.wait_for(
                        collect_worker_response(client),
                        timeout=300,
                    )
                except asyncio.TimeoutError:
                    log(f"iter {iteration}", "Worker timed out (5 min). Interrupting...")
                    await client.interrupt()
                    worker_output = "(Worker timed out and was interrupted.)"
                    tools_used = []
                    cost = None

                if cost is not None:
                    total_cost += cost

                tools_str = ", ".join(tools_used) if tools_used else "none"
                log(f"iter {iteration}", f"Worker: used tools [{tools_str}]")

                if config.verbose:
                    print(f"\n--- Worker Output (iter {iteration}) ---")
                    print(worker_output)
                    print("--- End Worker Output ---\n")

                # -- Cost ceiling check --
                if config.max_cost is not None and total_cost >= config.max_cost:
                    log(
                        f"iter {iteration}",
                        f"Cost ceiling reached (${total_cost:.2f} >= ${config.max_cost:.2f}). Stopping.",
                    )
                    break

                # -- Build orchestrator message --
                worker_msg = orch_prompts.format_worker_result(
                    worker_output, tools_used, iteration,
                )

                # First iteration: prepend the goal context
                if iteration == 1:
                    user_content = initial_context + "\n\n" + worker_msg
                else:
                    user_content = worker_msg

                # Append stall warning when threshold is reached
                if consecutive_continues >= 3 and not stall_warned:
                    user_content += orch_prompts.STALL_WARNING
                    stall_warned = True
                    log(f"iter {iteration}", "Appending stall warning to orchestrator message.")

                orch_messages.append({"role": "user", "content": user_content})

                # -- Summarize context if approaching window limit --
                try:
                    token_count = orch_client.messages.count_tokens(
                        model=config.orchestrator_model_id,
                        system=orch_prompts.SYSTEM_PROMPT,
                        messages=orch_messages,
                    )
                    if token_count.input_tokens >= SUMMARIZE_AT:
                        log("context", f"Token count {token_count.input_tokens} >= {SUMMARIZE_AT}, summarizing...")
                        orch_messages = summarize_context(orch_client, orch_messages, config.orchestrator_model_id)
                except Exception as exc:
                    log("context", f"Token counting failed (non-fatal): {exc}")

                # -- Call orchestrator --
                result = call_orchestrator_with_retry(
                    orch_client, config.orchestrator_model_id, orch_messages, iteration,
                )
                if result is None:
                    log(f"iter {iteration}", "Orchestrator unavailable. Stopping.")
                    break

                orch_response, _usage = result
                orch_messages.append({"role": "assistant", "content": orch_response})

                decision, content = parse_decision(orch_response)

                if config.verbose:
                    print(f"\n--- Orchestrator Response (iter {iteration}) ---")
                    print(orch_response)
                    print("--- End Orchestrator Response ---\n")

                # Truncate content for the log line
                snippet = content[:100] + ("..." if len(content) > 100 else "")
                log(f"iter {iteration}", f'Orchestrator: {decision} — "{snippet}"')

                # -- Dispatch --
                if decision == "DONE":
                    break

                if decision == "FINDING":
                    filepath = finding_writer.write(content)
                    log("finding", f"Written to {filepath}")
                    consecutive_continues = 0
                    stall_warned = False
                    await client.query("Finding recorded. Continue exploration.")
                elif decision == "EXPAND":
                    consecutive_continues = 0
                    stall_warned = False
                    await client.query(content)
                else:  # CONTINUE or unrecognised
                    consecutive_continues += 1
                    if stall_warned:
                        log(f"iter {iteration}", "STALLED: orchestrator did not redirect after stall warning. Halting.")
                        break
                    await client.query(content)
            else:
                log("summary", f"Max iterations ({config.max_iterations}) reached.")

        # -- Final summary --
        print()
        log("summary", f"Iterations: {iteration} | Findings: {finding_writer.count} | Cost: ${total_cost:.2f}")
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
