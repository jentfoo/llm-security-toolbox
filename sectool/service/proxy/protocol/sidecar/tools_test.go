package sidecar

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// fakeCoreTools is a CoreService stub reporting core tool names for collision checks.
type fakeCoreTools struct{ names []string }

func (fakeCoreTools) CoreQuery(context.Context, string, json.RawMessage) (string, bool, error) {
	return "", false, nil
}

func (f fakeCoreTools) CoreToolNames() []string { return f.names }

func toolManager(coreNames []string) *Manager {
	cfg := Config{
		HeartbeatInterval: time.Hour,
		HeartbeatTimeout:  time.Hour,
		ReservedNames:     []string{"http/1.1", "http/2", "websocket"},
	}
	return NewManager(cfg, &protocol.Registry{}, newFakeFlows(), fakeCoreTools{names: coreNames}, fakeRules{})
}

func toolParams(name string, toolNames ...string) wire.RegisterParams {
	p := baseParams(name)
	for _, tn := range toolNames {
		p.MCPTools = append(p.MCPTools, wire.MCPTool{Name: tn})
	}
	return p
}

func TestManagerRegisterToolCollision(t *testing.T) {
	t.Parallel()

	t.Run("collides_with_core", func(t *testing.T) {
		m := toolManager([]string{"proxy_poll", "flow_get"})
		p := dialManager(t, m, true)
		_, err := register(t, p, toolParams("demo", "proxy_poll"))
		require.NotNil(t, err)
		assert.Equal(t, wire.CodeToolNameConflict, err.Code)
		require.NotNil(t, err.Data)
		assert.Equal(t, "demo", err.Data.Adapter)
		assert.Equal(t, "sectool", err.Data.ConflictAdapter)
		assert.Equal(t, 0, m.Count())
	})

	t.Run("collides_with_other_sidecar", func(t *testing.T) {
		m := toolManager(nil)
		p1 := dialManager(t, m, true)
		_, err1 := register(t, p1, toolParams("first", "ts_inject"))
		require.Nil(t, err1)

		p2 := dialManager(t, m, true)
		_, err2 := register(t, p2, toolParams("second", "ts_inject"))
		require.NotNil(t, err2)
		assert.Equal(t, wire.CodeToolNameConflict, err2.Code)
		assert.Equal(t, "second", err2.Data.Adapter)
		assert.Equal(t, "first", err2.Data.ConflictAdapter)
	})

	t.Run("duplicate_in_registration", func(t *testing.T) {
		m := toolManager(nil)
		p := dialManager(t, m, true)
		_, err := register(t, p, toolParams("demo", "dup", "dup"))
		require.NotNil(t, err)
		assert.Equal(t, wire.CodeToolNameConflict, err.Code)
	})

	t.Run("distinct_tools_ok", func(t *testing.T) {
		m := toolManager([]string{"proxy_poll"})
		p1 := dialManager(t, m, true)
		_, err1 := register(t, p1, toolParams("first", "a_tool"))
		require.Nil(t, err1)

		p2 := dialManager(t, m, true)
		_, err2 := register(t, p2, toolParams("second", "b_tool"))
		require.Nil(t, err2)
		assert.Equal(t, 2, m.Count())
	})
}
