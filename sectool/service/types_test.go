package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsTimeoutError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil_error", nil, false},
		{"generic_error", errors.New("some error"), false},
		{"context_deadline", context.DeadlineExceeded, true},
		{"wrapped_deadline", fmt.Errorf("wrapped: %w", context.DeadlineExceeded), true},
		{"os_deadline", os.ErrDeadlineExceeded, true},
		{"wrapped_os_deadline", fmt.Errorf("wrapped: %w", os.ErrDeadlineExceeded), true},
		{"context_canceled", context.Canceled, false},
		{"net_timeout", &timeoutError{timeout: true}, true},
		{"net_non_timeout", &timeoutError{timeout: false}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, IsTimeoutError(tc.err))
		})
	}
}

// timeoutError implements net.Error for testing
type timeoutError struct {
	timeout bool
}

func (e *timeoutError) Error() string   { return "timeout error" }
func (e *timeoutError) Timeout() bool   { return e.timeout }
func (e *timeoutError) Temporary() bool { return false }

var _ net.Error = (*timeoutError)(nil)

func TestSafePath(t *testing.T) {
	t.Parallel()

	workDir := "/home/user/project"
	paths := NewServicePaths(workDir)

	tests := []struct {
		name     string
		input    string
		wantPath string
		wantErr  error
	}{
		{"relative_in_workdir", "subdir/file.txt", "/home/user/project/subdir/file.txt", nil},
		{"relative_nested", "a/b/c/file.txt", "/home/user/project/a/b/c/file.txt", nil},
		{"absolute_in_workdir", "/home/user/project/subdir/file.txt", "/home/user/project/subdir/file.txt", nil},
		{"workdir_root", ".", "/home/user/project", nil},
		{"relative_traversal", "../sibling/file.txt", "", ErrPathTraversal},
		{"relative_deep_traversal", "subdir/../../etc/passwd", "", ErrPathTraversal},
		{"absolute_outside", "/etc/passwd", "", ErrPathTraversal},
		{"absolute_parent", "/home/user", "", ErrPathTraversal},
		{"traversal_to_root", "../../../../etc/passwd", "", ErrPathTraversal},
		{"hidden_traversal", "subdir/../../../etc/passwd", "", ErrPathTraversal},
		{"prefix_attack", "/home/user/project_evil/file", "", ErrPathTraversal},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := paths.SafePath(tc.input)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				assert.Empty(t, got)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.wantPath, got)
			}
		})
	}
}
