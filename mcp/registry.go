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

var (
	beforeHooks []ToolHook
	afterHooks  []ToolHook
	// aroundHooks holds ToolAroundHook values paired with a global
	// registration sequence number (aroundSeqCounter). The sequence
	// lets HookMiddleware interleave immutable and mutable around-hooks
	// by true registration order — first-registered becomes the
	// outermost wrapper regardless of which kind.
	aroundHooks []aroundHookEntry
	hooksMu     sync.RWMutex
	// aroundSeqCounter is incremented on every OnToolExecution or
	// OnToolExecutionMutable call. Guarded by aroundSeqMu to keep
	// the counter monotonic across the two registrar sites.
	aroundSeqCounter uint64
	aroundSeqMu      sync.Mutex
)

// aroundHookEntry tags an immutable ToolAroundHook with its global
// registration sequence so HookMiddleware can interleave it with
// ToolMutableAroundHook entries in true registration order.
type aroundHookEntry struct {
	hook ToolAroundHook
	seq  uint64
}

// nextAroundSeq returns the next global registration sequence
// number. Shared between OnToolExecution and OnToolExecutionMutable
// so both registrars read from the same monotonic source.
func nextAroundSeq() uint64 {
	aroundSeqMu.Lock()
	defer aroundSeqMu.Unlock()
	aroundSeqCounter++
	return aroundSeqCounter
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

// mergedAroundChain returns the combined around-hook chain sorted
// by global registration sequence (ascending — first-registered
// first). Called once per tool invocation; the snapshot is
// concurrency-safe against concurrent Register calls.
func mergedAroundChain() []mergedAroundEntry {
	// Snapshot immutable side.
	hooksMu.RLock()
	immutable := make([]aroundHookEntry, len(aroundHooks))
	copy(immutable, aroundHooks)
	hooksMu.RUnlock()
	// Snapshot mutable side.
	mutable := mutableAroundHookEntries()

	out := make([]mergedAroundEntry, 0, len(immutable)+len(mutable))
	for _, e := range immutable {
		out = append(out, mergedAroundEntry{seq: e.seq, immutable: e.hook})
	}
	for _, e := range mutable {
		out = append(out, mergedAroundEntry{seq: e.seq, mutable: e.hook})
	}
	// Stable ascending sort by seq (small N in practice — ~tens of hooks).
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1].seq > out[j].seq; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

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

// OnToolExecution registers an around-style hook that wraps the tool
// handler. See ToolAroundHook for the full contract. Multiple
// registrations compose in registration order: the first registered
// becomes the outermost wrapper, the last is closest to the real
// handler.
//
// Relative to OnBefore/OnAfter: all three kinds of hook coexist. When
// HookMiddleware runs, it fires before-hooks first, then the around
// chain (with the handler innermost), then after-hooks. An around-hook
// that short-circuits prevents the handler from running but still
// triggers the after-hooks (they fire unconditionally, consistent with
// their observe-only semantics).
func OnToolExecution(hook ToolAroundHook) {
	if hook == nil {
		return
	}
	// Acquire the global sequence FIRST to preserve registration
	// order across both immutable and mutable registrars.
	seq := nextAroundSeq()
	hooksMu.Lock()
	defer hooksMu.Unlock()
	aroundHooks = append(aroundHooks, aroundHookEntry{hook: hook, seq: seq})
}

// RunBeforeHooks executes all before hooks. Returns first error.
// Panics inside a hook are recovered and returned as an error so a
// misbehaving plugin cannot take down the server.
func RunBeforeHooks(ctx context.Context, toolName string, args map[string]any) error {
	hooksMu.RLock()
	hooks := append([]ToolHook(nil), beforeHooks...)
	hooksMu.RUnlock()
	for _, hook := range hooks {
		if err := safeRunBeforeHook(hook, ctx, toolName, args); err != nil {
			return err
		}
	}
	return nil
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

// RunAfterHooks executes all after hooks. Panics are recovered per-hook
// so one misbehaving hook cannot prevent subsequent ones from running.
// Errors (returned or recovered from panic) are intentionally swallowed —
// after-hooks are fire-and-forget observers; by the time they run the
// tool has already produced a result.
func RunAfterHooks(ctx context.Context, toolName string, args map[string]any) {
	hooksMu.RLock()
	hooks := append([]ToolHook(nil), afterHooks...)
	hooksMu.RUnlock()
	for _, hook := range hooks {
		safeRunAfterHook(hook, ctx, toolName, args)
	}
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

// ClearHooks removes all registered hooks (useful for testing).
// Clears the before, after, around, AND mutable-around registries —
// every hook surface the package exposes — so a single call in a
// test's defer rewinds the whole state. Also resets the global
// aroundSeqCounter so tests that assert specific sequence values
// (rare, but supported) get a predictable counter.
func ClearHooks() {
	hooksMu.Lock()
	beforeHooks = beforeHooks[:0]
	afterHooks = afterHooks[:0]
	aroundHooks = nil
	hooksMu.Unlock()
	// mutable hooks live in their own file's mutex; keep the lock
	// ordering consistent (this one first, then mutable).
	clearMutableAroundHooks()
	aroundSeqMu.Lock()
	aroundSeqCounter = 0
	aroundSeqMu.Unlock()
}

// HookMiddleware returns a ToolHandlerMiddleware that runs registered
// before/around/after hooks around every tool invocation.
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
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if err := RunBeforeHooks(ctx, request.Params.Name, request.GetArguments()); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Hook blocked execution: %s", err.Error())), nil
			}
			// Build the around chain around the real handler.
			// Immutable and mutable around-hooks are interleaved by
			// their GLOBAL registration sequence (see aroundSeq in
			// registry.go / mutable_request.go). First-registered
			// ends up as the outermost wrapper — matches HTTP
			// middleware convention and gives plugin authors a
			// single intuitive rule regardless of hook kind.
			merged := mergedAroundChain()

			// Compose right-to-left.
			handler := ToolHandlerNext(next)
			for i := len(merged) - 1; i >= 0; i-- {
				entry := merged[i]
				inner := handler
				if entry.mutable != nil {
					hook := entry.mutable
					handler = func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
						m := NewMutableCallToolRequest(req)
						return safeInvokeMutableAroundHook(hook, ctx, m, inner)
					}
				} else {
					hook := entry.immutable
					handler = func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
						return safeInvokeAroundHook(hook, ctx, req, inner)
					}
				}
			}

			result, err := handler(ctx, request)
			RunAfterHooks(ctx, request.Params.Name, request.GetArguments())
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
