package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComposeVerifier(t *testing.T) {
	t.Parallel()
	msgs := ComposeVerifier("verify candidates: c001, c002")
	require.Len(t, msgs, 1)
	assert.Equal(t, "user", msgs[0].Role)
	assert.Equal(t, "verify candidates: c001, c002", msgs[0].Content)
}
