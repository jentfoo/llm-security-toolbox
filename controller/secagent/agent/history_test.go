package agent

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHistory(t *testing.T) {
	// Not parallel: token_tracking calls SetPromptTokens which mutates the
	// process-wide calibration EMA. Running serially (and resetting on
	// cleanup) keeps parallel tests from observing the perturbation.

	t.Run("token_tracking", func(t *testing.T) {
		t.Cleanup(resetCalibrationForTest)
		h := NewHistory(4096)
		assert.Equal(t, 4096, h.MaxContext())
		h.Append(Message{Role: "system", Content: "sys"})
		h.Append(Message{Role: "user", Content: "hello world hello world"})
		assert.Positive(t, h.EstimateTokens())

		// server-reported prompt tokens replace the local estimate as baseline
		h.SetPromptTokens(2048)
		assert.Equal(t, 2048, h.EstimateTokens())

		h.Append(Message{Role: "assistant", Content: "ok"})
		assert.Greater(t, h.EstimateTokens(), 2048)
	})

	t.Run("effective_max_unset_equals_max", func(t *testing.T) {
		h := NewHistory(250_000)
		assert.Equal(t, 250_000, h.EffectiveMaxContext())
	})

	t.Run("shrink_clamps_to_80_percent", func(t *testing.T) {
		h := NewHistory(250_000)
		// 200k estimate at rejection → effective max shrinks to 160k.
		h.ShrinkEffectiveMaxOnRejection(200_000)
		assert.Equal(t, 160_000, h.EffectiveMaxContext())
	})

	t.Run("sticky_downward_only", func(t *testing.T) {
		h := NewHistory(250_000)
		h.ShrinkEffectiveMaxOnRejection(200_000) // → 160k
		h.ShrinkEffectiveMaxOnRejection(180_000) // → 144k (lower)
		assert.Equal(t, 144_000, h.EffectiveMaxContext())
		h.ShrinkEffectiveMaxOnRejection(250_000) // would → 200k; ignored (higher)
		assert.Equal(t, 144_000, h.EffectiveMaxContext())
	})

	t.Run("floored_to_prevent_cripple", func(t *testing.T) {
		h := NewHistory(250_000)
		// 1000-token rejection → 800, but floor raises it to 4096.
		h.ShrinkEffectiveMaxOnRejection(1000)
		assert.Equal(t, 4096, h.EffectiveMaxContext())
	})

	t.Run("zero_or_negative_estimate_noop", func(t *testing.T) {
		h := NewHistory(250_000)
		h.ShrinkEffectiveMaxOnRejection(0)
		h.ShrinkEffectiveMaxOnRejection(-5)
		assert.Equal(t, 250_000, h.EffectiveMaxContext())
	})

	t.Run("rejection_above_max_noop", func(t *testing.T) {
		h := NewHistory(100_000)
		// 150k × 0.80 = 120k > maxContext (100k); ignored.
		h.ShrinkEffectiveMaxOnRejection(150_000)
		assert.Equal(t, 100_000, h.EffectiveMaxContext())
	})
}

func TestHistory_CalibrationLearnsFromRealPromptTokens(t *testing.T) {
	// Not parallel: every subtest mutates the process-wide calibration EMA.
	// Each subtest resets at start (so sibling order doesn't matter) and on
	// cleanup (so unrelated parallel tests see the seed value).

	t.Run("starts_at_one", func(t *testing.T) {
		resetCalibrationForTest()
		t.Cleanup(resetCalibrationForTest)
		h := NewHistory(8192)
		assert.InDelta(t, 1.0, h.Calibration(), 0.001)
	})

	t.Run("under_count_raises_calibration", func(t *testing.T) {
		resetCalibrationForTest()
		t.Cleanup(resetCalibrationForTest)
		h := NewHistory(8192)
		// Message pool whose raw char/4 estimate will be lower than the
		// "real" PromptTokens we report → calibration goes above 1.0.
		h.Append(Message{Role: "system", Content: "sys"})
		for i := 0; i < 10; i++ {
			h.Append(Message{Role: "user", Content: "abcdefghij"})
		}
		// 10 messages × (10/4 + 4 overhead) + sys ≈ ~69 raw tokens.
		// Report 200 real tokens → observed ratio ≈ 2.9; after EMA (α=0.3)
		// calibration moves from 1.0 toward 2.9, landing around 1.57.
		h.SetPromptTokens(200)
		cal := h.Calibration()
		assert.Greater(t, cal, 1.3)
		assert.Less(t, cal, 2.1)
	})

	t.Run("clamped_to_bounds", func(t *testing.T) {
		resetCalibrationForTest()
		t.Cleanup(resetCalibrationForTest)
		h := NewHistory(8192)
		h.Append(Message{Role: "user", Content: "hi"})
		// Absurd real count overshoots the EMA → clamps to calibrationMax.
		h.SetPromptTokens(1_000_000)
		assert.InDelta(t, calibrationMax, h.Calibration(), 0.001)
	})

	t.Run("ema_smoothing_converges", func(t *testing.T) {
		resetCalibrationForTest()
		t.Cleanup(resetCalibrationForTest)
		h := NewHistory(8192)
		h.Append(Message{Role: "user", Content: strings.Repeat("x", 400)})
		// Raw estimate: 400/4 + 4 = 104. Real: 208 → ratio 2.0. EMA from 1.0
		// converges toward 2.0 over many updates.
		for i := 0; i < 50; i++ {
			h.SetPromptTokens(208)
		}
		assert.InDelta(t, 2.0, h.Calibration(), 0.05)
	})
}
