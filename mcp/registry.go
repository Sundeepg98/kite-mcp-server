package mcp

import (
	"context"
	"fmt"
	"sync"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

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

// ToolHook is called before or after tool execution. ctx carries the
// request's session context (including caller email via
// oauth.EmailFromContext) so hooks can enforce per-user policy — e.g.,
// role-gated tool access for family viewers. Before-hooks may return an
// error to block execution.
type ToolHook func(ctx context.Context, toolName string, args map[string]any) error

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
func RunBeforeHooks(ctx context.Context, toolName string, args map[string]any) error {
	hooksMu.RLock()
	defer hooksMu.RUnlock()
	for _, hook := range beforeHooks {
		if err := hook(ctx, toolName, args); err != nil {
			return err
		}
	}
	return nil
}

// RunAfterHooks executes all after hooks.
func RunAfterHooks(ctx context.Context, toolName string, args map[string]any) {
	hooksMu.RLock()
	defer hooksMu.RUnlock()
	for _, hook := range afterHooks {
		_ = hook(ctx, toolName, args)
	}
}

// ClearHooks removes all registered hooks (useful for testing).
func ClearHooks() {
	hooksMu.Lock()
	defer hooksMu.Unlock()
	beforeHooks = beforeHooks[:0]
	afterHooks = afterHooks[:0]
}

// HookMiddleware returns a ToolHandlerMiddleware that runs registered
// before/after hooks around every tool invocation.
func HookMiddleware() server.ToolHandlerMiddleware {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if err := RunBeforeHooks(ctx, request.Params.Name, request.GetArguments()); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Hook blocked execution: %s", err.Error())), nil
			}
			result, err := next(ctx, request)
			RunAfterHooks(ctx, request.Params.Name, request.GetArguments())
			return result, err
		}
	}
}
