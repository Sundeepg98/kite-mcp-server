package app

// registry_isolation_test.go — B77 cycle-buster verification.
//
// Before B77, every App instance shared the package-level mcp.DefaultRegistry
// for plugin/hook/widget registration. Two parallel App constructions in one
// process polluted each other's hook chains, blocking in-process multi-server
// tests and capping the agent-concurrency ceiling at the wire-layer.
//
// After B77, each App owns a *mcp.Registry instance (app.registry) wired in
// via wire.go and consulted by the production middleware/registration path.
// The free mcp.X() functions stay as deprecated shims pointing at
// DefaultRegistry — backward compat for the ~140 in-package call sites and
// the plugin/example init() registrations that run at package import time.
//
// These tests pin the contract:
//  1. NewAppWithConfig allocates app.registry as a fresh *mcp.Registry.
//  2. Two Apps in one process get DISTINCT registries.
//  3. Hooks installed on app.registry don't leak into DefaultRegistry,
//     and vice versa — this is the t.Parallel-readiness keystone.

import (
	"context"
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/mcp"
)

// TestApp_HasIsolatedRegistry verifies NewAppWithConfig allocates a fresh
// *mcp.Registry on every App, and two Apps in the same process do NOT
// share the registry pointer.
func TestApp_HasIsolatedRegistry(t *testing.T) {
	t.Parallel()
	a := newTestAppWithConfig(t, &Config{InstrumentsSkipFetch: true})
	b := newTestAppWithConfig(t, &Config{InstrumentsSkipFetch: true})

	require.NotNil(t, a.Registry(), "App.Registry() must be non-nil after NewAppWithConfig")
	require.NotNil(t, b.Registry(), "App.Registry() must be non-nil after NewAppWithConfig")
	assert.NotSame(t, a.Registry(), b.Registry(),
		"two distinct Apps must hold distinct *mcp.Registry instances")
}

// TestApp_RegistryHookIsolation_DoesNotLeakToDefaultRegistry verifies that a
// hook installed on app.registry does NOT also appear on the package-level
// mcp.DefaultRegistry. This is the property that unblocks t.Parallel for
// hook-using tests at the App layer (the per-App registry is independent of
// DefaultRegistry).
func TestApp_RegistryHookIsolation_DoesNotLeakToDefaultRegistry(t *testing.T) {
	// NOT t.Parallel — this test reads DefaultRegistry's before-hook count
	// and would race with any other test that mutates DefaultRegistry. The
	// LockDefaultRegistryForTest pattern in the mcp package handles
	// in-package tests; this app-level test serializes by omitting Parallel.
	a := newTestAppWithConfig(t, &Config{InstrumentsSkipFetch: true})

	defaultBefore := mcp.DefaultRegistry.BeforeHookCount()
	registryBefore := a.Registry().BeforeHookCount()

	// Install a no-op hook on the app's registry. Should NOT appear on
	// DefaultRegistry — that's the isolation contract.
	a.Registry().OnBeforeToolExecution(func(ctx context.Context, toolName string, args map[string]any) error {
		return nil
	})

	defaultAfter := mcp.DefaultRegistry.BeforeHookCount()
	registryAfter := a.Registry().BeforeHookCount()

	assert.Equal(t, defaultBefore, defaultAfter,
		"hook installed on app.registry must NOT increment DefaultRegistry's count")
	assert.Equal(t, registryBefore+1, registryAfter,
		"hook installed on app.registry must increment app.registry's own count")
}

// TestApp_RegistryHookIsolation_SilencesAcrossApps verifies the keystone
// property: a hook installed on App-1's registry does not fire when App-2
// runs HookMiddlewareFor against App-2's registry. This is the property
// the agent-concurrency ceiling was hitting — two parallel tests now both
// run their hook chains independently.
func TestApp_RegistryHookIsolation_SilencesAcrossApps(t *testing.T) {
	t.Parallel()
	a := newTestAppWithConfig(t, &Config{InstrumentsSkipFetch: true})
	b := newTestAppWithConfig(t, &Config{InstrumentsSkipFetch: true})

	aHookFired := false
	a.Registry().OnBeforeToolExecution(func(ctx context.Context, toolName string, args map[string]any) error {
		aHookFired = true
		return nil
	})

	// Run HookMiddlewareFor against B's registry — A's hook must not fire.
	mw := mcp.HookMiddlewareFor(b.Registry())
	dummy := func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("ok"), nil
	}
	wrapped := mw(dummy)
	req := gomcp.CallToolRequest{}
	req.Params.Name = "test_tool"
	_, err := wrapped(context.Background(), req)
	require.NoError(t, err)

	assert.False(t, aHookFired,
		"a's hook must not fire when HookMiddlewareFor runs against b's registry — registries are isolated")
}
