package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/mcp/paper"
	"github.com/zerodha/kite-mcp-server/mcp/plugin"
)

// Test-only scaffolding for snapshotting/restoring the registry.
// Anchor 1 PR 1.4: the canonical implementation moved to mcp/plugin
// alongside the registry state. These thin local wrappers preserve the
// pre-PR test-helper names (snapshotInternalTools etc.) so the test
// bodies below need no rewrite.
type internalToolSnapshot = plugin.InternalToolSnapshot

func snapshotInternalTools() internalToolSnapshot {
	return plugin.SnapshotInternalTools()
}

func restoreInternalTools(s internalToolSnapshot) {
	plugin.RestoreInternalTools(s)
}

func resetInternalTools() {
	plugin.ResetInternalTools()
}

// TestRegisterInternalTool_AppearsInGetAllTools proves the registry pattern:
// any tool registered via init() (or explicit RegisterInternalTool) appears
// in GetAllTools() output. This is the contract that lets per-file init()
// blocks replace the central GetAllTools() slice — eliminating mcp.go as a
// shared edit point per Investment J in
// .research/agent-concurrency-decoupling-plan.md.
func TestRegisterInternalTool_AppearsInGetAllTools(t *testing.T) {
	// Not parallel — touches package-level registry.
	saved := snapshotInternalTools()
	t.Cleanup(func() { restoreInternalTools(saved) })

	// ServerVersionTool is already migrated to the registry (no longer in
	// the GetAllTools() literal slice). Reset, then register it and prove
	// the registry hookup is the path through which it reaches GetAllTools.
	resetInternalTools()

	got := GetAllTools()
	for _, tl := range got {
		if tl.Tool().Name == "server_version" {
			t.Fatalf("after reset, server_version should NOT be in GetAllTools — registry contract broken")
		}
	}

	RegisterInternalTool(&ServerVersionTool{})
	got = GetAllTools()
	var found bool
	for _, tl := range got {
		if tl.Tool().Name == "server_version" {
			found = true
			break
		}
	}
	assert.True(t, found, "registered tool must appear in GetAllTools()")
}

// TestRegisterInternalTool_DuplicateNamePanics proves the registration-time
// guard: a second registration of the same Name() panics rather than silently
// overwriting. Closes Plugin#13 from final-138-gap-catalogue.md (tool name
// collision unguarded in GetAllTools — corruption risk).
func TestRegisterInternalTool_DuplicateNamePanics(t *testing.T) {
	saved := snapshotInternalTools()
	t.Cleanup(func() { restoreInternalTools(saved) })
	resetInternalTools()

	RegisterInternalTool(&paper.LoginTool{})
	require.Panics(t, func() {
		RegisterInternalTool(&paper.LoginTool{}) // same Name() = "login"
	})
}
