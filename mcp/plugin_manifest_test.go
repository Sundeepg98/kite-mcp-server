package mcp

import (
	"context"
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// TestRegisterPluginInfo_Basic — register a plugin manifest and
// confirm it's retrievable via ListPlugins.
func TestRegisterPluginInfo_Basic(t *testing.T) {
	ClearPluginInfo()
	defer ClearPluginInfo()

	err := RegisterPluginInfo(PluginInfo{
		Name:        "example_plugin",
		Version:     "1.0.0",
		Description: "A sample plugin",
		Author:      "example@example.com",
	})
	require.NoError(t, err)

	plugins := ListPlugins()
	require.Len(t, plugins, 1)
	assert.Equal(t, "example_plugin", plugins[0].Name)
	assert.Equal(t, "1.0.0", plugins[0].Version)
}

// TestRegisterPluginInfo_RejectsEmpty — name and version are required.
func TestRegisterPluginInfo_RejectsEmpty(t *testing.T) {
	ClearPluginInfo()
	defer ClearPluginInfo()

	assert.Error(t, RegisterPluginInfo(PluginInfo{Name: "", Version: "1.0.0"}))
	assert.Error(t, RegisterPluginInfo(PluginInfo{Name: "x", Version: ""}))
}

// TestRegisterPluginInfo_DuplicateReplaces — last-wins matches other
// plugin registries.
func TestRegisterPluginInfo_DuplicateReplaces(t *testing.T) {
	ClearPluginInfo()
	defer ClearPluginInfo()

	require.NoError(t, RegisterPluginInfo(PluginInfo{Name: "p", Version: "1.0.0"}))
	require.NoError(t, RegisterPluginInfo(PluginInfo{Name: "p", Version: "2.0.0"}))

	plugins := ListPlugins()
	require.Len(t, plugins, 1)
	assert.Equal(t, "2.0.0", plugins[0].Version)
}

// TestListPlugins_SortedByName — returns plugins in sorted name order
// for deterministic admin display.
func TestListPlugins_SortedByName(t *testing.T) {
	ClearPluginInfo()
	defer ClearPluginInfo()

	require.NoError(t, RegisterPluginInfo(PluginInfo{Name: "zulu", Version: "1.0.0"}))
	require.NoError(t, RegisterPluginInfo(PluginInfo{Name: "alpha", Version: "1.0.0"}))
	require.NoError(t, RegisterPluginInfo(PluginInfo{Name: "mike", Version: "1.0.0"}))

	plugins := ListPlugins()
	require.Len(t, plugins, 3)
	assert.Equal(t, "alpha", plugins[0].Name)
	assert.Equal(t, "mike", plugins[1].Name)
	assert.Equal(t, "zulu", plugins[2].Name)
}

// TestGetPluginManifest — global manifest aggregates all plugin
// extension registrations (tools, hooks, middleware, widgets,
// Telegram commands, routes, event subs). This is the single-call
// "what does this deployment have?" surface.
func TestGetPluginManifest(t *testing.T) {
	// Clear everything to a known state.
	ClearPluginInfo()
	ClearPlugins()
	ClearHooks()
	ClearPluginWidgets()
	ClearPluginMiddleware()
	ClearPluginEventSubscriptions()
	defer func() {
		ClearPluginInfo()
		ClearPlugins()
		ClearHooks()
		ClearPluginWidgets()
		ClearPluginMiddleware()
		ClearPluginEventSubscriptions()
	}()

	// Seed one of each.
	require.NoError(t, RegisterPluginInfo(PluginInfo{
		Name:    "manifest_plugin",
		Version: "0.1.0",
	}))
	OnBeforeToolExecution(func(ctx context.Context, toolName string, args map[string]interface{}) error {
		return nil
	})
	require.NoError(t, RegisterWidget("ui://manifest-test/widget", "Manifest Widget",
		func(ctx context.Context, req gomcp.ReadResourceRequest) ([]gomcp.ResourceContents, error) {
			return nil, nil
		}))
	require.NoError(t, RegisterMiddleware("manifest_mw",
		func(next server.ToolHandlerFunc) server.ToolHandlerFunc { return next }, 100))
	require.NoError(t, SubscribePluginEvent("order.placed", func(e domain.Event) {}))

	m := GetPluginManifest()
	assert.Len(t, m.Plugins, 1)
	assert.Equal(t, 1, m.BeforeHookCount)
	assert.Equal(t, 1, m.WidgetCount)
	assert.Equal(t, 1, m.MiddlewareCount)
	assert.Equal(t, 1, m.EventSubscriptionCount)
}

// TestPluginCountInfo — coverage/count test for the admin endpoint.
func TestPluginCountInfo(t *testing.T) {
	ClearPluginInfo()
	defer ClearPluginInfo()

	assert.Equal(t, 0, PluginInfoCount())
	_ = RegisterPluginInfo(PluginInfo{Name: "a", Version: "1.0.0"})
	_ = RegisterPluginInfo(PluginInfo{Name: "b", Version: "1.0.0"})
	assert.Equal(t, 2, PluginInfoCount())
}
