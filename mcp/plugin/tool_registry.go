package plugin

import (
	"fmt"
	"sync"

	"github.com/zerodha/kite-mcp-server/mcp/common"
)

// internalToolRegistry holds Tool instances registered by built-in
// `<feature>_tools.go` files via init(). It is the package-internal
// counterpart to DefaultRegistry (which holds external/3rd-party plugins
// registered via RegisterPlugin). Splitting them lets agents adding new
// built-in tools edit ONLY their feature file (with `init() {
// plugin.RegisterInternalTool(...) }`) without touching a central
// GetAllTools() slice — eliminating mcp.go as a shared edit point per
// Investment J in .research/agent-concurrency-decoupling-plan.md.
//
// Anchor 1 PR 1.4: relocated from mcp/tool_registry.go alongside the
// rest of the plugin-registry infrastructure (DefaultRegistry,
// RegisterPlugin, etc.). The mcp/ root keeps a thin passthrough
// (RegisterInternalTool) for backward-compat with the 60+ in-tree
// `func init() { mcp.RegisterInternalTool(...) }` callers. Per-domain
// sub-packages (mcp/admin, mcp/trade, etc.) call
// plugin.RegisterInternalTool directly to avoid a cycle through
// mcp/ root.
//
// Wire-protocol stability: GetInternalTools() returns these in
// registration order followed by external plugins, so the SHA256-
// locked tool surface (mcp/tool_surface_lock_test.go) does not change
// as long as the migration preserves which Tool types are registered.
var (
	internalToolRegistryMu sync.Mutex
	internalToolRegistry   []common.Tool
	internalToolNames      = make(map[string]struct{})
)

// RegisterInternalTool installs a built-in Tool. Intended to be called
// from a package-level init() in the tool's own feature file. Panics on
// duplicate Tool().Name() — a programmer error caught at process start
// rather than silently shadowing in GetAllTools (closes Plugin#13).
func RegisterInternalTool(t common.Tool) {
	if t == nil {
		panic("RegisterInternalTool: nil Tool")
	}
	name := t.Tool().Name
	internalToolRegistryMu.Lock()
	defer internalToolRegistryMu.Unlock()
	if _, exists := internalToolNames[name]; exists {
		panic(fmt.Sprintf("RegisterInternalTool: duplicate tool name %q", name))
	}
	internalToolNames[name] = struct{}{}
	internalToolRegistry = append(internalToolRegistry, t)
}

// GetInternalTools returns a snapshot of the internally-registered
// tools. The mcp/ root's GetAllToolsForRegistry calls this to compose
// the merged tool slice with App-scoped plugin tools.
func GetInternalTools() []common.Tool {
	internalToolRegistryMu.Lock()
	defer internalToolRegistryMu.Unlock()
	out := make([]common.Tool, len(internalToolRegistry))
	copy(out, internalToolRegistry)
	return out
}

// ClearInternalTools removes all internally-registered tools. Used
// only by test fixtures that need to reset state between runs.
func ClearInternalTools() {
	internalToolRegistryMu.Lock()
	defer internalToolRegistryMu.Unlock()
	internalToolRegistry = internalToolRegistry[:0]
	internalToolNames = make(map[string]struct{})
}

// InternalToolSnapshot is the test-only snapshot of the internal
// tool registry. Captured before mutations and restored after.
//
// Anchor 1 PR 1.4: exposed for cross-package test fixtures
// (mcp/tool_registry_test.go, package mcp) that need to snapshot/
// restore the registry across t.Run() blocks. The fields are
// exported because the consumer test package cannot reach into
// plugin package privates.
type InternalToolSnapshot struct {
	Tools []common.Tool
	Names map[string]struct{}
}

// SnapshotInternalTools captures the current registry state for
// later restoration. Test-only.
func SnapshotInternalTools() InternalToolSnapshot {
	internalToolRegistryMu.Lock()
	defer internalToolRegistryMu.Unlock()
	s := InternalToolSnapshot{
		Tools: append([]common.Tool(nil), internalToolRegistry...),
		Names: make(map[string]struct{}, len(internalToolNames)),
	}
	for n := range internalToolNames {
		s.Names[n] = struct{}{}
	}
	return s
}

// RestoreInternalTools rolls back to a snapshot. Test-only.
func RestoreInternalTools(s InternalToolSnapshot) {
	internalToolRegistryMu.Lock()
	defer internalToolRegistryMu.Unlock()
	internalToolRegistry = append(internalToolRegistry[:0], s.Tools...)
	internalToolNames = make(map[string]struct{}, len(s.Names))
	for n := range s.Names {
		internalToolNames[n] = struct{}{}
	}
}

// ResetInternalTools clears the registry. Test-only.
func ResetInternalTools() {
	internalToolRegistryMu.Lock()
	defer internalToolRegistryMu.Unlock()
	internalToolRegistry = internalToolRegistry[:0]
	internalToolNames = make(map[string]struct{})
}
