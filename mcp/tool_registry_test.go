package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// internalToolSnapshot + helpers are test-only scaffolding for
// snapshotting and restoring the package-level registry across tests.
// Lives in _test.go (compiled only under `go test`) so prod binaries
// don't carry this code.
type internalToolSnapshot struct {
	tools []Tool
	names map[string]struct{}
}

func snapshotInternalTools() internalToolSnapshot {
	internalToolRegistryMu.Lock()
	defer internalToolRegistryMu.Unlock()
	s := internalToolSnapshot{
		tools: append([]Tool(nil), internalToolRegistry...),
		names: make(map[string]struct{}, len(internalToolNames)),
	}
	for n := range internalToolNames {
		s.names[n] = struct{}{}
	}
	return s
}

func restoreInternalTools(s internalToolSnapshot) {
	internalToolRegistryMu.Lock()
	defer internalToolRegistryMu.Unlock()
	internalToolRegistry = append(internalToolRegistry[:0], s.tools...)
	internalToolNames = make(map[string]struct{}, len(s.names))
	for n := range s.names {
		internalToolNames[n] = struct{}{}
	}
}

func resetInternalTools() {
	internalToolRegistryMu.Lock()
	defer internalToolRegistryMu.Unlock()
	internalToolRegistry = internalToolRegistry[:0]
	internalToolNames = make(map[string]struct{})
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

	RegisterInternalTool(&LoginTool{})
	require.Panics(t, func() {
		RegisterInternalTool(&LoginTool{}) // same Name() = "login"
	})
}
