package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetectSystemToolsWith(t *testing.T) {
	t.Parallel()

	t.Run("all_found", func(t *testing.T) {
		lookup := func(name string) (string, error) {
			return "/usr/bin/" + name, nil
		}
		found := detectSystemToolsWith(lookup)
		assert.Equal(t, securityTools, found)
	})

	t.Run("none_found", func(t *testing.T) {
		lookup := func(name string) (string, error) {
			return "", errors.New("not found")
		}
		found := detectSystemToolsWith(lookup)
		assert.Empty(t, found)
	})

	t.Run("partial_match", func(t *testing.T) {
		available := map[string]bool{"nmap": true, "openssl": true, "python3": true}
		lookup := func(name string) (string, error) {
			if available[name] {
				return "/usr/bin/" + name, nil
			}
			return "", errors.New("not found")
		}
		found := detectSystemToolsWith(lookup)
		// Order follows securityTools iteration order
		assert.Equal(t, []string{"nmap", "openssl", "python3"}, found)
	})
}

func TestEnrichWorkflowContent(t *testing.T) {
	t.Parallel()

	t.Run("nil_tools", func(t *testing.T) {
		base := "# Workflow\nSome content"
		result := enrichWorkflowContent(base, nil)
		assert.Equal(t, base, result)
	})

	t.Run("empty_tools", func(t *testing.T) {
		base := "# Workflow\nSome content"
		result := enrichWorkflowContent(base, []string{})
		assert.Equal(t, base, result)
	})

	t.Run("multiple_tools", func(t *testing.T) {
		base := "# Workflow\nSome content\n"
		result := enrichWorkflowContent(base, []string{"nmap", "sqlmap"})
		assert.True(t, strings.HasPrefix(result, base))
		assert.Contains(t, result, "nmap, sqlmap")
		assert.Contains(t, result, "system commands are available")
	})

	t.Run("single_tool", func(t *testing.T) {
		base := "# Workflow"
		result := enrichWorkflowContent(base, []string{"nmap"})
		assert.Contains(t, result, "nmap")
		assert.NotContains(t, result, ",")
	})
}
