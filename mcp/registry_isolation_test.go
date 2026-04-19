package mcp

import (
	"context"
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegistryIsolation_FreshInstanceStartsEmpty confirms NewRegistry
// returns a registry with no widgets, middleware, hooks, etc.
// registered. Isolation between tests depends on this.
func TestRegistryIsolation_FreshInstanceStartsEmpty(t *testing.T) {
	t.Parallel()

	r := NewRegistry()
	assert.Equal(t, 0, r.WidgetCount())
	assert.Equal(t, 0, r.MiddlewareCount())
	assert.Equal(t, 0, r.BeforeHookCount())
	assert.Equal(t, 0, r.AfterHookCount())
	assert.Equal(t, 0, r.AroundHookCount())
	assert.Equal(t, 0, r.MutableAroundHookCount())
	assert.Equal(t, 0, r.EventSubscriptionCount())
	assert.Equal(t, 0, r.LifecycleCount())
	assert.Equal(t, 0, r.InfoCount())
	assert.Equal(t, 0, r.SBOMCount())
}

// TestRegistryIsolation_SeparateInstancesDontShare is the core
// parallel-safety contract: two Registry instances are fully
// independent — mutations to one do NOT leak into the other.
// This is what lets parallel tests each own a Registry.
func TestRegistryIsolation_SeparateInstancesDontShare(t *testing.T) {
	t.Parallel()

	a := NewRegistry()
	b := NewRegistry()

	handler := func(ctx context.Context, req gomcp.ReadResourceRequest) ([]gomcp.ResourceContents, error) {
		return nil, nil
	}
	require.NoError(t, a.RegisterWidget("ui://test-iso/a", "A", handler))

	assert.Equal(t, 1, a.WidgetCount(), "A has its widget")
	assert.Equal(t, 0, b.WidgetCount(), "B must NOT see A's widget")
}

// TestRegistryIsolation_DefaultRegistryBackedByFreeFunctions confirms
// that every free-standing package-level function operates on
// DefaultRegistry. This is the backward-compat contract: production
// callers like app/wire.go's `mcp.RegisterWidget(...)` must hit
// DefaultRegistry without any additional wiring.
func TestRegistryIsolation_DefaultRegistryBackedByFreeFunctions(t *testing.T) {
	// Not parallel — this test mutates DefaultRegistry to prove the
	// wiring. Parallel plugin tests use NewRegistry() instead.
	DefaultRegistry.Reset()
	t.Cleanup(DefaultRegistry.Reset)

	handler := func(ctx context.Context, req gomcp.ReadResourceRequest) ([]gomcp.ResourceContents, error) {
		return nil, nil
	}
	require.NoError(t, RegisterWidget("ui://default-test/x", "X", handler))

	// Free function sees the registration.
	assert.Equal(t, 1, PluginWidgetCount())
	// Method on DefaultRegistry sees it too.
	assert.Equal(t, 1, DefaultRegistry.WidgetCount())
}

// TestRegistryIsolation_ResetClearsAll confirms Reset() wipes every
// registry within the Registry struct so a test using
// DefaultRegistry with t.Cleanup(DefaultRegistry.Reset) gets a
// clean slate for the next test.
func TestRegistryIsolation_ResetClearsAll(t *testing.T) {
	// Sequential — this modifies DefaultRegistry state.
	DefaultRegistry.Reset()
	t.Cleanup(DefaultRegistry.Reset)

	handler := func(ctx context.Context, req gomcp.ReadResourceRequest) ([]gomcp.ResourceContents, error) {
		return nil, nil
	}
	require.NoError(t, DefaultRegistry.RegisterWidget("ui://reset/x", "X", handler))
	require.NoError(t, DefaultRegistry.RegisterPluginInfo(PluginInfo{Name: "p", Version: "1.0"}))
	OnBeforeToolExecution(func(ctx context.Context, toolName string, args map[string]interface{}) error { return nil })

	// Reset wipes everything.
	DefaultRegistry.Reset()
	assert.Equal(t, 0, DefaultRegistry.WidgetCount())
	assert.Equal(t, 0, DefaultRegistry.InfoCount())
	assert.Equal(t, 0, DefaultRegistry.BeforeHookCount())
}
