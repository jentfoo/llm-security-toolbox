package orchestrator

// defaultAutonomousBudget is the per-iteration autonomous-run budget when
// no decision specifies one.
const defaultAutonomousBudget = 8

// decisionDrainMaxRounds caps the per-worker decide_worker drain.
const decisionDrainMaxRounds = 4

// MinIterationsForDone is the earliest iteration at which `end_run` is
// accepted with zero findings filed.
const MinIterationsForDone = 5

// ReconDirective is the iter-1 recon worker's directive (pure observation,
// no finding filing).
const ReconDirective = `Map the target's surface area and scope so future testing workers have concrete targets. Your job is observation: do not file findings — that is the testing workers' job that follows yours.

Capture: every endpoint you see, the authentication boundary on each, the technology stack and frameworks in use, the data flows between services, and any service-level configuration that's externally visible. Note dynamic elements (CSRF tokens, session cookies, JWT structures, OAST callbacks if any).

Explore and query — do not update state on the target service. Read endpoints (GET / HEAD / OPTIONS) and authentication flows (login, token exchange) are fine, because mapping authenticated surface requires them. Do NOT send requests that create, modify, or delete resources (POST / PUT / PATCH / DELETE on resource endpoints), do NOT trigger state-changing workflows (cancel / send / enable / disable / publish), and do NOT escalate privileges.

When the surface is mapped, end your turn with a concise observation summary. Your work will be distilled into a recon summary that anchors the testing workers spawned after you.`
