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
// estimates.
func Calibration() float64 {
	calibrationMu.RLock()
	defer calibrationMu.RUnlock()
	return calibration
}

// ObservePromptTokens feeds one observation into the calibration EMA: real
// is the server-reported prompt token count, raw is the matching
// uncalibrated estimate. No-op when either is non-positive.
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

// resetCalibrationForTest restores the seed calibration value of 1.0.
func resetCalibrationForTest() {
	calibrationMu.Lock()
	calibration = 1.0
	calibrationMu.Unlock()
}

// EstimateStringTokens returns the calibrated token estimate for s, with
// no per-message overhead.
func EstimateStringTokens(s string) int {
	return int(float64(len(s)) / charsPerToken * Calibration())
}

// rawMessageTokens returns the uncalibrated token estimate for m,
// including per-message overhead. ReasoningContent is excluded since it
// never reaches the wire.
func rawMessageTokens(m Message) int {
	total := len(m.Content) / charsPerToken
	for _, tc := range m.ToolCalls {
		total += (len(tc.Function.Name) + len(tc.Function.Arguments)) / charsPerToken
	}
	return total + perMessageOverhead
}

// EstimateMessageTokens returns the calibrated token estimate for m,
// including per-message overhead.
func EstimateMessageTokens(m Message) int {
	return int(float64(rawMessageTokens(m)) * Calibration())
}
