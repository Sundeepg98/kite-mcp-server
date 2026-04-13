package mcp

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPluginRegistry(t *testing.T) {
	// Clean state
	ClearPlugins()
	assert.Equal(t, 0, PluginCount())

	// Register a plugin
	RegisterPlugin(&ServerMetricsTool{})
	assert.Equal(t, 1, PluginCount())

	// GetAllTools includes plugin — server_metrics appears twice (built-in + plugin)
	allTools := GetAllTools()
	count := 0
	for _, tool := range allTools {
		if tool.Tool().Name == "server_metrics" {
			count++
		}
	}
	assert.Equal(t, 2, count, "server_metrics should appear twice (built-in + plugin)")

	// Cleanup
	ClearPlugins()
	assert.Equal(t, 0, PluginCount())
}

func TestRegisterMultiplePlugins(t *testing.T) {
	ClearPlugins()
	defer ClearPlugins()

	RegisterPlugins(&ServerMetricsTool{}, &AdminListUsersTool{})
	assert.Equal(t, 2, PluginCount())
}

func TestPluginCountAfterClear(t *testing.T) {
	ClearPlugins()

	RegisterPlugin(&ServerMetricsTool{})
	RegisterPlugin(&AdminListUsersTool{})
	assert.Equal(t, 2, PluginCount())

	ClearPlugins()
	assert.Equal(t, 0, PluginCount())

	// GetAllTools should have only built-in tools
	baseCount := len(GetAllTools())
	RegisterPlugin(&ServerMetricsTool{})
	assert.Equal(t, baseCount+1, len(GetAllTools()))

	ClearPlugins()
}

func TestPluginToolsAppearInGetAllTools(t *testing.T) {
	ClearPlugins()
	defer ClearPlugins()

	baseTools := GetAllTools()
	baseCount := len(baseTools)

	RegisterPlugin(&ServerMetricsTool{})
	RegisterPlugin(&AdminListUsersTool{})

	allTools := GetAllTools()
	assert.Equal(t, baseCount+2, len(allTools),
		"GetAllTools should return built-in + 2 plugins")
}

func TestBeforeHook(t *testing.T) {
	ClearHooks()
	defer ClearHooks()

	called := false
	OnBeforeToolExecution(func(ctx context.Context, toolName string, args map[string]interface{}) error {
		called = true
		assert.Equal(t, "place_order", toolName)
		return nil
	})

	err := RunBeforeHooks(context.Background(), "place_order", map[string]interface{}{"qty": 10})
	require.NoError(t, err)
	assert.True(t, called)
}

func TestBeforeHookBlocksOnError(t *testing.T) {
	ClearHooks()
	defer ClearHooks()

	errBlocked := errors.New("blocked by hook")
	OnBeforeToolExecution(func(ctx context.Context, toolName string, args map[string]interface{}) error {
		return errBlocked
	})

	// Second hook should NOT run
	secondCalled := false
	OnBeforeToolExecution(func(ctx context.Context, toolName string, args map[string]interface{}) error {
		secondCalled = true
		return nil
	})

	err := RunBeforeHooks(context.Background(), "place_order", nil)
	assert.ErrorIs(t, err, errBlocked)
	assert.False(t, secondCalled, "second hook should not run after first returns error")
}

func TestAfterHook(t *testing.T) {
	ClearHooks()
	defer ClearHooks()

	var capturedTool string
	OnAfterToolExecution(func(ctx context.Context, toolName string, args map[string]interface{}) error {
		capturedTool = toolName
		return nil
	})

	RunAfterHooks(context.Background(), "get_holdings", map[string]interface{}{"segment": "equity"})
	assert.Equal(t, "get_holdings", capturedTool)
}

func TestAfterHookContinuesOnError(t *testing.T) {
	ClearHooks()
	defer ClearHooks()

	secondCalled := false
	OnAfterToolExecution(func(ctx context.Context, toolName string, args map[string]interface{}) error {
		return errors.New("first hook fails")
	})
	OnAfterToolExecution(func(ctx context.Context, toolName string, args map[string]interface{}) error {
		secondCalled = true
		return nil
	})

	RunAfterHooks(context.Background(), "get_orders", nil)
	assert.True(t, secondCalled, "after hooks should continue even if one fails")
}

func TestClearHooks(t *testing.T) {
	ClearHooks()

	OnBeforeToolExecution(func(ctx context.Context, toolName string, args map[string]interface{}) error {
		return errors.New("should not run")
	})
	OnAfterToolExecution(func(ctx context.Context, toolName string, args map[string]interface{}) error {
		return errors.New("should not run")
	})

	ClearHooks()

	// No hooks should run
	err := RunBeforeHooks(context.Background(), "test", nil)
	assert.NoError(t, err)
	RunAfterHooks(context.Background(), "test", nil) // should not panic
}
