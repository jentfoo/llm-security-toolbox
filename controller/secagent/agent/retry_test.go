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

func TestBackoffFor(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		cat        ErrCategory
		attempt    int
		retryAfter time.Duration
		base       time.Duration
		wantMin    time.Duration // inclusive
		wantMax    time.Duration // exclusive
	}{
		{
			name:       "rate_limit_honors_retry_after",
			cat:        ErrRateLimit,
			retryAfter: 500 * time.Millisecond,
			base:       time.Second,
			wantMin:    500 * time.Millisecond,
			wantMax:    500*time.Millisecond + 1,
		},
		{
			// attempt 2: base * 2^2 = 400ms before jitter; jitter ±20% → [320ms, 480ms).
			name:    "rate_limit_falls_back_to_exponential",
			cat:     ErrRateLimit,
			attempt: 2,
			base:    100 * time.Millisecond,
			wantMin: 320 * time.Millisecond,
			wantMax: 480 * time.Millisecond,
		},
		{
			// attempt 0: base * 2^0 = 200ms before jitter → [160ms, 240ms).
			name:    "transient_net_jittered_exponential",
			cat:     ErrTransientNet,
			base:    200 * time.Millisecond,
			wantMin: 160 * time.Millisecond,
			wantMax: 240 * time.Millisecond,
		},
		{
			// attempt 20: exponential would be enormous; capped at 30s then jittered.
			name:    "transient_net_capped_at_30s",
			cat:     ErrTransientNet,
			attempt: 20,
			base:    time.Second,
			wantMin: 24 * time.Second,
			wantMax: 37 * time.Second,
		},
		{name: "non_retryable_other", cat: ErrOther, base: time.Second, wantMax: 1},
		{name: "non_retryable_deadline", cat: ErrDeadline, base: time.Second, wantMax: 1},
		{name: "non_retryable_context_overflow", cat: ErrContextOverflow, base: time.Second, wantMax: 1},
		{name: "non_retryable_model_error", cat: ErrModelError, base: time.Second, wantMax: 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rng := rand.New(rand.NewSource(1))
			got := BackoffFor(tc.cat, tc.attempt, tc.retryAfter, tc.base, rng)
			assert.GreaterOrEqual(t, got, tc.wantMin)
			assert.Less(t, got, tc.wantMax)
		})
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
