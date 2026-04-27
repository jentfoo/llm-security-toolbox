package orchestrator

// defaultAutonomousBudget is the per-iteration autonomous-run budget used
// when a director decision or director tool call doesn't specify one.
// Mirrors config.DefaultAutoBudget and spec §8 default.
const defaultAutonomousBudget = 8

// MinIterationsForDone is the earliest iteration at which the director's
// `done(summary)` decision is accepted when zero findings have been filed.
// Earlier calls are rejected as premature so local models that conflate
// `done` with `direction_done` can't end the run prematurely.
const MinIterationsForDone = 5

// ReconDirective is the hard-coded scope-mapping prompt used as worker 1's
// iter-1 directive. Pure observation — the worker maps the surface for
// downstream testing workers and does not file findings. The
// finding-reporting tool is structurally absent for this worker, so
// the "no findings" contract is enforced both in prose and by the
// registered tool list. Active sectool tools remain available because
// recon often needs to send shaped probes to learn how the target
// behaves under auth, error conditions, or with specific headers.
//
// The recon worker's chronicle is summarized at retirement (via
// SummarizeCompletedWorker) and the result is held as
// factory.ReconSummary — anchored into every subsequent worker spawn's
// system prompt and the verifier's per-iter compose.
const ReconDirective = `Map the target's surface area and scope so future testing workers have concrete targets. Your job is observation: do not file findings — that is the testing workers' job that follows yours.

Capture: every endpoint you see, the authentication boundary on each, the technology stack and frameworks in use, the data flows between services, and any service-level configuration that's externally visible. Note dynamic elements (CSRF tokens, session cookies, JWT structures, OAST callbacks if any).

Explore and query — do not update state on the target service. Read endpoints (GET / HEAD / OPTIONS) and authentication flows (login, token exchange) are fine, because mapping authenticated surface requires them. Do NOT send requests that create, modify, or delete resources (POST / PUT / PATCH / DELETE on resource endpoints), do NOT trigger state-changing workflows (cancel / send / enable / disable / publish), and do NOT escalate privileges.

When the surface is mapped, end your turn with a concise observation summary. Your work will be distilled into a recon summary that anchors the testing workers spawned after you.`
