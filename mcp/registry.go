package mcp

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// RegisterPlugin adds a custom tool to DefaultRegistry.
// Call this before server startup (e.g., in init() or main()).
func RegisterPlugin(tool Tool) {
	DefaultRegistry.RegisterPlugin(tool)
}

// RegisterPlugins adds multiple custom tools.
func RegisterPlugins(tools ...Tool) {
	DefaultRegistry.RegisterPlugins(tools...)
}

// PluginCount returns the number of registered plugins on DefaultRegistry.
func PluginCount() int {
	return DefaultRegistry.PluginCount()
}

// ClearPlugins removes all registered plugins on DefaultRegistry
// (useful for testing).
func ClearPlugins() {
	DefaultRegistry.toolMu.Lock()
	defer DefaultRegistry.toolMu.Unlock()
	DefaultRegistry.toolPlugins = nil
}

// ToolHook is called before or after tool execution. ctx carries the
// request's session context (including caller email via
// oauth.EmailFromContext) so hooks can enforce per-user policy — e.g.,
// role-gated tool access for family viewers. Before-hooks may return an
// error to block execution.
type ToolHook func(ctx context.Context, toolName string, args map[string]any) error

// ToolHandlerNext is the continuation passed to an around-style
// ToolAroundHook. It is a type alias for server.ToolHandlerFunc so
// callers can forward through the middleware chain transparently —
// `next(ctx, req)` invokes the real handler (or the next around-hook
// if multiple are registered).
type ToolHandlerNext = server.ToolHandlerFunc

// ToolAroundHook is a full around-wrapping hook. Unlike ToolHook (which
// can only observe args and optionally block via an error return), an
// around-hook receives the entire CallToolRequest plus a `next`
// continuation. It MAY:
//
//   - invoke next(ctx, req) to proceed to the real handler (optionally
//     transforming the returned *mcp.CallToolResult or error);
//   - return a synthetic *mcp.CallToolResult without calling next, which
//     short-circuits the handler entirely (result substitution);
//   - return an error to abort the call.
//
// Use cases:
//   - cache layer returning a synthetic result on hit, falling through on miss;
//   - compliance shield returning a canned "feature disabled" result for
//     gated tools instead of letting the handler run;
//   - a/b testing wrapper that returns an alternative handler's result.
//
// Safety: panics inside an around-hook are recovered by HookMiddleware
// and surfaced as an IsError=true CallToolResult — they do NOT crash
// the MCP server. See around_hook_test.go for the full contract.
type ToolAroundHook func(ctx context.Context, req mcp.CallToolRequest, next ToolHandlerNext) (*mcp.CallToolResult, error)

// aroundHookEntry tags an immutable ToolAroundHook with its global
// registration sequence so HookMiddleware can interleave it with
// ToolMutableAroundHook entries in true registration order.
type aroundHookEntry struct {
	hook ToolAroundHook
	seq  uint64
}

// mergedAroundEntry is the unified view used by HookMiddleware to
// compose a single around-hook chain regardless of whether each
// entry mutates the request. Exactly one of immutable/mutable is
// non-nil per entry.
type mergedAroundEntry struct {
	seq       uint64
	immutable ToolAroundHook
	mutable   ToolMutableAroundHook
}

// OnBeforeToolExecution registers a before-hook on DefaultRegistry.
func OnBeforeToolExecution(hook ToolHook) {
	DefaultRegistry.OnBeforeToolExecution(hook)
}

// OnAfterToolExecution registers an after-hook on DefaultRegistry.
func OnAfterToolExecution(hook ToolHook) {
	DefaultRegistry.OnAfterToolExecution(hook)
}

// OnToolExecution registers an immutable around-hook on
// DefaultRegistry. See ToolAroundHook for the full contract.
func OnToolExecution(hook ToolAroundHook) {
	DefaultRegistry.OnToolExecution(hook)
}

// RunBeforeHooks executes all before hooks on DefaultRegistry.
func RunBeforeHooks(ctx context.Context, toolName string, args map[string]any) error {
	return DefaultRegistry.RunBeforeHooks(ctx, toolName, args)
}

// safeRunBeforeHook invokes a single before-hook with panic recovery.
// A panic is converted into a non-nil error so the caller can short-
// circuit identically to a returned error — preserves the existing
// "first non-nil error blocks execution" semantics.
func safeRunBeforeHook(hook ToolHook, ctx context.Context, toolName string, args map[string]any) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("before-hook panic: %v", r)
		}
	}()
	return hook(ctx, toolName, args)
}

// RunAfterHooks executes all after hooks on DefaultRegistry.
func RunAfterHooks(ctx context.Context, toolName string, args map[string]any) {
	DefaultRegistry.RunAfterHooks(ctx, toolName, args)
}

// safeRunAfterHook invokes a single after-hook with panic recovery.
// Errors and panics are both swallowed — see RunAfterHooks for the
// rationale.
func safeRunAfterHook(hook ToolHook, ctx context.Context, toolName string, args map[string]any) {
	defer func() {
		_ = recover()
	}()
	_ = hook(ctx, toolName, args)
}

// ClearHooks removes all registered hooks (useful for testing) on
// DefaultRegistry. Clears the before, after, around, AND mutable-
// around registries — every hook surface the package exposes — so a
// single call in a test's defer rewinds the whole state.
func ClearHooks() {
	DefaultRegistry.hooksMu.Lock()
	DefaultRegistry.beforeHooks = nil
	DefaultRegistry.afterHooks = nil
	DefaultRegistry.aroundHooks = nil
	DefaultRegistry.aroundSeqCounter = 0
	DefaultRegistry.hooksMu.Unlock()
	DefaultRegistry.mutableAroundHookMu.Lock()
	DefaultRegistry.mutableAroundHooks = nil
	DefaultRegistry.mutableAroundHookMu.Unlock()
}

// HookMiddleware returns a ToolHandlerMiddleware that runs hooks
// registered on DefaultRegistry. Backward-compat shim — production
// callers wired through an App should use HookMiddlewareFor(app.Registry())
// for per-App isolation (B77).
//
// Execution order, outermost first:
//
//  1. before-hooks — run sequentially; first error short-circuits and
//     surfaces as an error-shaped CallToolResult to the client;
//  2. around-hook chain — composed in registration order with the real
//     handler innermost. An around-hook that short-circuits prevents
//     the real handler (and any inner around-hooks) from running;
//  3. after-hooks — fire unconditionally (even after a short-circuit
//     or panic), observe-only.
//
// Panic safety: around-hooks are individually recover()-wrapped. A
// panic is surfaced as an IsError=true CallToolResult and logged (via
// the fmt.Errorf path — adequate for a runtime plugin bug). The
// handler is NOT called after a panicking around-hook, matching the
// semantics of a short-circuit reject.
func HookMiddleware() server.ToolHandlerMiddleware {
	return HookMiddlewareFor(DefaultRegistry)
}

// HookMiddlewareFor returns a ToolHandlerMiddleware that runs hooks
// registered on the given Registry. This is the App-isolated entry
// point — hooks installed on app.Registry() fire only when the
// middleware was built with that same registry. Two parallel Apps
// in one process can each carry their own hook chain without
// pollution (B77).
//
// reg may be nil — a nil registry is treated as an empty hook chain
// (the middleware passes the request straight through to the next
// handler). This keeps the code path defensive against a wiring
// regression: if an agent forgets to construct app.registry, tools
// still respond instead of panicking.
func HookMiddlewareFor(reg *Registry) server.ToolHandlerMiddleware {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if reg == nil {
				return next(ctx, request)
			}
			if err := reg.RunBeforeHooks(ctx, request.Params.Name, request.GetArguments()); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Hook blocked execution: %s", err.Error())), nil
			}
			// Build the around chain around the real handler.
			// Immutable and mutable around-hooks are interleaved by
			// their GLOBAL registration sequence (see aroundSeq in
			// registry.go / mutable_request.go). First-registered
			// ends up as the outermost wrapper — matches HTTP
			// middleware convention and gives plugin authors a
			// single intuitive rule regardless of hook kind.
			//
			// The around chain composition is delegated to
			// composeAroundChain (decorator_chain.go), which expresses
			// the layered wrap as a kc/decorators.Compose call over
			// typed Decorator[Req, Resp] values. Behaviour is
			// identical to the prior hand-written reverse-iteration
			// loop; the typed surface lets the chain be reasoned
			// about with the same vocabulary used for other
			// cross-cutting concerns in the codebase.
			merged := reg.mergedAroundChain()
			handler := composeAroundChain(merged, next)

			result, err := handler(ctx, request)
			reg.RunAfterHooks(ctx, request.Params.Name, request.GetArguments())
			return result, err
		}
	}
}

// safeInvokeAroundHook runs a single around-hook with panic recovery.
// Panics are converted into IsError=true CallToolResults so the client
// receives a well-formed response and the server does not crash. This
// is a server safety feature, not a general error-handling pattern —
// hooks SHOULD return errors via the normal path; recovery is a
// defensive net against plugin bugs.
func safeInvokeAroundHook(hook ToolAroundHook, ctx context.Context, req mcp.CallToolRequest, next ToolHandlerNext) (result *mcp.CallToolResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			// Return an IsError=true result so the MCP client sees a
			// clean failure message rather than a dropped connection.
			// err is deliberately nil — the failure IS the result.
			result = mcp.NewToolResultError(fmt.Sprintf("around-hook panic: %v", r))
			err = nil
		}
	}()
	return hook(ctx, req, next)
}
