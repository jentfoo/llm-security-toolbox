package agent

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"testing"
	"time"

	openai "github.com/sashabaranov/go-openai"
	"github.com/stretchr/testify/assert"
)

func TestClassify(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		err     error
		wantCat ErrCategory
		wantRA  time.Duration
	}{
		{"nil", nil, ErrOther, 0},
		{"canceled", context.Canceled, ErrDeadline, 0},
		{"deadline_exceeded", context.DeadlineExceeded, ErrDeadline, 0},
		{"context_overflow_local", errors.New("Context size has been exceeded"), ErrContextOverflow, 0},
		{"context_overflow_openai_code", errors.New("context_length_exceeded"), ErrContextOverflow, 0},
		{"rate_limit_from_api_error", &openai.APIError{HTTPStatusCode: 429, Message: "rate limited"}, ErrRateLimit, 0},
		{"rate_limit_with_retry_after_seconds",
			&openai.APIError{HTTPStatusCode: 429, Message: "slow down; retry after 7 seconds"},
			ErrRateLimit, 7 * time.Second},
		{"rate_limit_with_retry_after_ms",
			&openai.APIError{HTTPStatusCode: 429, Message: "retry-after: 250ms"},
			ErrRateLimit, 250 * time.Millisecond},
		{"server_5xx", &openai.APIError{HTTPStatusCode: 503, Message: "upstream"}, ErrTransientNet, 0},
		{"model_error_4xx", &openai.APIError{HTTPStatusCode: 400, Message: "bad request"}, ErrModelError, 0},
		{"auth_error_4xx", &openai.APIError{HTTPStatusCode: 401, Message: "unauthorized"}, ErrModelError, 0},
		{"connection_reset", errors.New("read tcp: connection reset by peer"), ErrTransientNet, 0},
		{"connection_refused", errors.New("dial tcp: connection refused"), ErrTransientNet, 0},
		{"eof", errors.New("unexpected EOF"), ErrTransientNet, 0},
		{"broken_pipe", errors.New("write: broken pipe"), ErrTransientNet, 0},
		{"net_timeout", &fakeNetErr{timeout: true}, ErrTransientNet, 0},
		{"unknown_error", errors.New("something surprising"), ErrOther, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotCat, gotRA := Classify(c.err)
			assert.Equal(t, c.wantCat, gotCat)
			assert.Equal(t, c.wantRA, gotRA)
		})
	}
}

func TestBackoffFor_RateLimit_HonorsRetryAfter(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(1))
	got := BackoffFor(ErrRateLimit, 0, 500*time.Millisecond, time.Second, rng)
	assert.Equal(t, 500*time.Millisecond, got, "Retry-After takes precedence over base backoff")
}

func TestBackoffFor_RateLimit_FallsBackToExponential(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(1))
	base := 100 * time.Millisecond
	// Attempt 2: base * 2^2 = 400ms before jitter; jitter ±20% → [320ms, 480ms).
	got := BackoffFor(ErrRateLimit, 2, 0, base, rng)
	assert.GreaterOrEqual(t, got, 320*time.Millisecond)
	assert.Less(t, got, 480*time.Millisecond)
}

func TestBackoffFor_TransientNet_JitteredExponential(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(42))
	base := 200 * time.Millisecond
	// Attempt 0: base * 2^0 = 200ms before jitter → [160ms, 240ms).
	got := BackoffFor(ErrTransientNet, 0, 0, base, rng)
	assert.GreaterOrEqual(t, got, 160*time.Millisecond)
	assert.Less(t, got, 240*time.Millisecond)
}

func TestBackoffFor_TransientNet_CappedAt30s(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(1))
	// Attempt 20: base * 2^20 would be enormous; cap at 30s then jitter.
	got := BackoffFor(ErrTransientNet, 20, 0, time.Second, rng)
	// Max possible: 30s * 1.2 = 36s.
	assert.Less(t, got, 37*time.Second)
	assert.GreaterOrEqual(t, got, 24*time.Second)
}

func TestBackoffFor_NonRetryableCategoriesReturnZero(t *testing.T) {
	t.Parallel()
	for _, cat := range []ErrCategory{ErrOther, ErrDeadline, ErrContextOverflow, ErrModelError} {
		assert.Zero(t, BackoffFor(cat, 0, 0, time.Second, nil), "cat=%v should not back off", cat)
	}
}

// fakeNetErr implements net.Error so Classify exercises the timeout branch.
type fakeNetErr struct {
	timeout bool
}

func (e *fakeNetErr) Error() string   { return "fake net error" }
func (e *fakeNetErr) Timeout() bool   { return e.timeout }
func (e *fakeNetErr) Temporary() bool { return false }

var _ net.Error = (*fakeNetErr)(nil)
