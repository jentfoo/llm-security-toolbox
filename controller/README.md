# sectool Autonomous Controllers

Two implementations of the same idea: drive a sectool MCP server with a
multi-agent loop (workers + verifier + director) so an LLM can autonomously
explore a target for vulnerabilities, reproduce candidates, and file
findings.

| Implementation | Language | Backend | Auth | Use when |
|----------------|----------|---------|------|----------|
| [`secagent/`](secagent/) | Go | Any OpenAI-compatible chat-completions endpoint | API key (or none, for local) | **Default choice.** You want provider flexibility, local models, or you don't have a Claude subscription. |
| [`claude/`](claude/) | Python | Claude Agent SDK | Claude Code OAuth (uses your `claude` CLI session) | You already pay for a Claude subscription via Claude Code and want to use that quota directly without an API key. |

## Recommendation

**Start with [`secagent/`](secagent/)** unless you specifically want to ride
your Claude Code subscription. secagent is the more flexible option: it
talks to any OpenAI-compatible endpoint (OpenAI, Azure, vLLM, llama.cpp,
LM Studio, OpenRouter, Together, Groq, Anthropic via a compatibility shim,
…), supports independent worker / orchestrator endpoints and models, and
ships as a single `bin/secagent` binary built by `make build`.

Reach for [`claude/`](claude/) only when you specifically want to bill the
work to your Claude Code subscription rather than to an API key - it
authenticates through the `claude` CLI's OAuth session, so calls don't hit
a separate API budget.

## Both controllers share the same architecture

- **Workers** call sectool MCP tools (proxy, replay, crawl, OAST,
  diff/reflection, encoders) plus a `report_finding_candidate` tool.
- **Verifier** is a separate agent with the full sectool tool surface
  whose only job is to independently reproduce candidates, then call
  `file_finding` or `dismiss_candidate`.
- **Director** is a separate agent whose only job is to decide what each
  worker does next: `continue_worker`, `expand_worker`, `stop_worker`,
  `plan_workers`, or `done`. It also sets each worker's per-iteration
  `autonomous_budget`.
- The outer loop runs **autonomous worker turns → verification → direction**
  per iteration, with phase-gated tools so each role stays in lane.
- Findings are deduplicated and written as markdown files with a
  Verification section in the configured findings directory.

The differences are mostly operational: how you authenticate, where the
model runs, which models you can pick, and what language the controller
itself is written in. The agent contract (worker reports candidates,
verifier reproduces and files, director plans the next iteration) is the
same in both.

## Quick start - secagent (recommended)

```bash
make build           # builds bin/sectool and bin/secagent

bin/secagent \
  --base-url https://api.openai.com/v1 \
  --api-key "$OPENAI_API_KEY" \
  --worker-model gpt-4.1-mini \
  --orchestrator-model gpt-4.1 \
  --prompt "The proxy is on port 8181. Explore https://target.example.com for security issues."
```

See [`secagent/README.md`](secagent/README.md) for the full flag reference,
local-model setups, split worker/orchestrator endpoints, phase mechanics,
and tuning knobs.

## Quick start - claude

```bash
cd controller/claude
pip install -r requirements.txt   # requires `claude` CLI on PATH and authenticated

python controller.py \
  --prompt "The proxy is on port 8181. Explore https://target.example.com for security issues." \
  --proxy-port 8181 \
  --model sonnet
```

See [`claude/README.md`](claude/README.md) for the full flag reference,
verifier/director gating, and stall behavior.

## Where findings land

Both controllers write to `--findings-dir` (default `./findings/`) as
`finding-NN-<slug>.md` files containing Title, Severity, Affected Endpoint,
Description, Reproduction Steps, Evidence, Impact, and a Verification
section sourced from the verifier's reproduction notes.
