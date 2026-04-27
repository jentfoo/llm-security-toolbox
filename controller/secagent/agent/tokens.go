package agent

import "sync"

// Tunables for the learned token calibration. The estimator multiplies a
// raw char/charsPerToken count by a calibration factor that is updated by
// EMA whenever an upstream call returns a real prompt-token count via
// ObservePromptTokens. Bounds prevent a single outlier from wrecking the
// estimator. Calibration is process-wide because every History feeds the
// same EMA — agents pointed at the same model converge faster, and the
// non-History sites (status budgeting, stub annotations, recon-summary
// logging) read the same learned ratio instead of three uncalibrated
// duplicates.
const (
	charsPerToken      = 4
	perMessageOverhead = 4
	calibrationMin     = 0.5
	calibrationMax     = 3.0
	calibrationAlpha   = 0.3
)

var (
	calibrationMu sync.RWMutex
	calibration   = 1.0
)

// Calibration returns the current learned multiplier applied to char/N
// estimates. Seeded at 1.0 until ObservePromptTokens supplies a real
// measurement.
func Calibration() float64 {
	calibrationMu.RLock()
	defer calibrationMu.RUnlock()
	return calibration
}

// ObservePromptTokens feeds one observation into the EMA: real is the
// server-reported prompt token count, raw is the matching uncalibrated
// estimate (sum of rawMessageTokens over the messages that produced it).
// No-op when either is non-positive.
func ObservePromptTokens(real, raw int) {
	if real <= 0 || raw <= 0 {
		return
	}
	observed := float64(real) / float64(raw)
	calibrationMu.Lock()
	next := (1-calibrationAlpha)*calibration + calibrationAlpha*observed
	if next < calibrationMin {
		next = calibrationMin
	} else if next > calibrationMax {
		next = calibrationMax
	}
	calibration = next
	calibrationMu.Unlock()
}

// resetCalibrationForTest restores the seed value of 1.0. Tests that read
// or assert estimator output must call this and run non-parallel since the
// calibration is process-wide.
func resetCalibrationForTest() {
	calibrationMu.Lock()
	calibration = 1.0
	calibrationMu.Unlock()
}

// EstimateStringTokens estimates the calibrated token cost of a raw string,
// no per-message overhead. Use for text that will be embedded into another
// prompt (system-prompt fragments, log annotations) rather than sent as a
// standalone message.
func EstimateStringTokens(s string) int {
	return int(float64(len(s)) / charsPerToken * Calibration())
}

// rawMessageTokens returns the uncalibrated char/charsPerToken estimate
// for one Message, including per-message overhead. Used by the calibration
// update path so the EMA does not self-cancel against its own output.
// ReasoningContent is counted alongside Content so structured-reasoning
// payloads (deepseek/qwen3) pressure compaction the same way inline
// `<think>` blocks do.
func rawMessageTokens(m Message) int {
	total := (len(m.Content) + len(m.ReasoningContent)) / charsPerToken
	for _, tc := range m.ToolCalls {
		total += (len(tc.Function.Name) + len(tc.Function.Arguments)) / charsPerToken
	}
	return total + perMessageOverhead
}

// EstimateMessageTokens returns the calibrated token estimate for one
// Message, including per-message overhead.
func EstimateMessageTokens(m Message) int {
	return int(float64(rawMessageTokens(m)) * Calibration())
}
