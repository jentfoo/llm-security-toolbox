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
