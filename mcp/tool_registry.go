package mcp

import (
	"fmt"
	"sync"
)

// internalToolRegistry holds Tool instances registered by built-in
// `<feature>_tools.go` files via init(). It is the package-internal
// counterpart to DefaultRegistry (which holds external/3rd-party plugins
// registered via RegisterPlugin). Splitting them lets agents adding new
// built-in tools edit ONLY their feature file (with `init() { mcp.
// RegisterInternalTool(...) }`) without touching the central
// GetAllTools() slice — eliminating mcp.go as a shared edit point per
// Investment J in .research/agent-concurrency-decoupling-plan.md.
//
// Wire-protocol stability: GetAllTools() returns these in registration
// order followed by external plugins, so the SHA256-locked tool surface
// (mcp/tool_surface_lock_test.go) does not change as long as the migration
// preserves which Tool types are registered.
var (
	internalToolRegistryMu sync.Mutex
	internalToolRegistry   []Tool
	internalToolNames      = make(map[string]struct{})
)

// RegisterInternalTool installs a built-in Tool. Intended to be called
// from a package-level init() in the tool's own feature file. Panics on
// duplicate Tool().Name() — a programmer error caught at process start
// rather than silently shadowing in GetAllTools (closes Plugin#13).
func RegisterInternalTool(t Tool) {
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

