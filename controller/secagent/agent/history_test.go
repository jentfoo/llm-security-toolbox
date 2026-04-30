package agent

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHistory_ShrinkEffectiveMaxOnRejection(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		maxCtx    int
		rejects   []int
		wantEffMx int
	}{
		{name: "clamps_to_80_percent", maxCtx: 250_000, rejects: []int{200_000}, wantEffMx: 160_000},
		{name: "sticky_downward_only", maxCtx: 250_000, rejects: []int{200_000, 180_000, 250_000}, wantEffMx: 144_000},
		{name: "floored_to_prevent_cripple", maxCtx: 250_000, rejects: []int{1000}, wantEffMx: 4096},
		{name: "zero_or_negative_noop", maxCtx: 250_000, rejects: []int{0, -5}, wantEffMx: 250_000},
		{name: "rejection_above_max_noop", maxCtx: 100_000, rejects: []int{150_000}, wantEffMx: 100_000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := NewHistory(tc.maxCtx)
			for _, r := range tc.rejects {
				h.ShrinkEffectiveMaxOnRejection(r)
			}
			assert.Equal(t, tc.wantEffMx, h.EffectiveMaxContext())
		})
	}
}

func TestHistory_TokenTracking(t *testing.T) {
	// Serial: SetPromptTokens mutates the process-wide calibration EMA.
	t.Cleanup(resetCalibrationForTest)
	h := NewHistory(4096)
	assert.Equal(t, 4096, h.MaxContext())
	h.Append(Message{Role: roleSystem, Content: "sys"})
	h.Append(Message{Role: roleUser, Content: "hello world hello world"})
	assert.Positive(t, h.EstimateTokens())

	h.SetPromptTokens(2048)
	assert.Equal(t, 2048, h.EstimateTokens())

	h.Append(Message{Role: roleAssistant, Content: "ok"})
	assert.Greater(t, h.EstimateTokens(), 2048)
}

func TestHistory_Calibration(t *testing.T) {
	// Serial: each subtest mutates the process-wide calibration EMA.
	t.Run("starts_at_one", func(t *testing.T) {
		resetCalibrationForTest()
		t.Cleanup(resetCalibrationForTest)
		h := NewHistory(8192)
		assert.InDelta(t, 1.0, h.Calibration(), 0.001)
	})

	t.Run("under_count_raises", func(t *testing.T) {
		resetCalibrationForTest()
		t.Cleanup(resetCalibrationForTest)
		h := NewHistory(8192)
		h.Append(Message{Role: roleSystem, Content: "sys"})
		for range 10 {
			h.Append(Message{Role: roleUser, Content: "abcdefghij"})
		}
		// raw ≈ 69 tokens, reported 200 → observed ratio ≈ 2.9; EMA α=0.3 lands ~1.57
		h.SetPromptTokens(200)
		assert.InDelta(t, 1.57, h.Calibration(), 0.2)
	})

	t.Run("clamped_to_bounds", func(t *testing.T) {
		resetCalibrationForTest()
		t.Cleanup(resetCalibrationForTest)
		h := NewHistory(8192)
		h.Append(Message{Role: roleUser, Content: "hi"})
		h.SetPromptTokens(1_000_000)
		assert.InDelta(t, calibrationMax, h.Calibration(), 0.001)
	})

	t.Run("ema_converges", func(t *testing.T) {
		resetCalibrationForTest()
		t.Cleanup(resetCalibrationForTest)
		h := NewHistory(8192)
		h.Append(Message{Role: roleUser, Content: strings.Repeat("x", 400)})
		// raw 104, real 208 → ratio 2.0; EMA converges over many updates
		for range 50 {
			h.SetPromptTokens(208)
		}
		assert.InDelta(t, 2.0, h.Calibration(), 0.05)
	})
}
