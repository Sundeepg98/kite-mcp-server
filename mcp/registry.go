package mcp

import "sync"

// ToolRegistry allows external packages to register custom MCP tools.
// Tools are merged with built-in tools at server startup.
var registry = &toolRegistry{
	plugins: make([]Tool, 0),
}

type toolRegistry struct {
	mu      sync.Mutex
	plugins []Tool
}

// RegisterPlugin adds a custom tool to the registry.
// Call this before server startup (e.g., in init() or main()).
func RegisterPlugin(tool Tool) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.plugins = append(registry.plugins, tool)
}

// RegisterPlugins adds multiple custom tools.
func RegisterPlugins(tools ...Tool) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.plugins = append(registry.plugins, tools...)
}

// PluginCount returns the number of registered plugins.
func PluginCount() int {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return len(registry.plugins)
}

// ClearPlugins removes all registered plugins (useful for testing).
func ClearPlugins() {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.plugins = registry.plugins[:0]
}

// ToolHook is called before or after tool execution.
type ToolHook func(toolName string, args map[string]interface{}) error

var (
	beforeHooks []ToolHook
	afterHooks  []ToolHook
	hooksMu     sync.RWMutex
)

// OnBeforeToolExecution registers a hook called before any tool runs.
func OnBeforeToolExecution(hook ToolHook) {
	hooksMu.Lock()
	defer hooksMu.Unlock()
	beforeHooks = append(beforeHooks, hook)
}

// OnAfterToolExecution registers a hook called after any tool runs.
func OnAfterToolExecution(hook ToolHook) {
	hooksMu.Lock()
	defer hooksMu.Unlock()
	afterHooks = append(afterHooks, hook)
}

// RunBeforeHooks executes all before hooks. Returns first error.
func RunBeforeHooks(toolName string, args map[string]interface{}) error {
	hooksMu.RLock()
	defer hooksMu.RUnlock()
	for _, hook := range beforeHooks {
		if err := hook(toolName, args); err != nil {
			return err
		}
	}
	return nil
}

// RunAfterHooks executes all after hooks.
func RunAfterHooks(toolName string, args map[string]interface{}) {
	hooksMu.RLock()
	defer hooksMu.RUnlock()
	for _, hook := range afterHooks {
		_ = hook(toolName, args)
	}
}

// ClearHooks removes all registered hooks (useful for testing).
func ClearHooks() {
	hooksMu.Lock()
	defer hooksMu.Unlock()
	beforeHooks = beforeHooks[:0]
	afterHooks = afterHooks[:0]
}
