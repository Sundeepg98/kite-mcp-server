package mcp

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/zerodha/kite-mcp-server/kc/decorators"
)

// Phase 3a Decorator Option 2 consumer migration: the around-hook chain
// in HookMiddlewareFor (mcp/registry.go) is exactly the cross-cutting
// "wrap a handler with N layers" pattern that kc/decorators models. This
// file bridges the existing mergedAroundEntry shape onto the typed
// Decorator[Req, Resp] surface so the chain composition is expressed
// declaratively rather than via a hand-written reverse-iteration loop.
//
// Behaviour preserved exactly:
//   - first-registered ends up as the OUTERMOST wrapper (matches
//     gRPC / Echo / mcp.HookMiddleware historic convention)
//   - panic recovery via safeInvokeAroundHook /
//     safeInvokeMutableAroundHook is unchanged
//   - mutable hooks see a freshly-wrapped MutableCallToolRequest each
//     invocation (no shared state between invocations)
//   - empty chain returns the original handler (Compose with zero
//     decorators is the identity, mirroring the pre-migration loop's
//     "skip the loop, return next unchanged" branch)
//
// What changes:
//   - the right-to-left for-loop in HookMiddlewareFor becomes a
//     decorators.Compose(...) call;
//   - per-entry adapter aroundEntryToDecorator captures the immutable /
//     mutable branch decision once at composition time;
//   - the typed surface (mcpToolHandler / mcpToolDecorator) makes it
//     obvious to readers that the around chain is a Decorator[Req, Resp]
//     instance — no need to re-derive the contract from the loop body.

// mcpToolHandler is the around-chain's typed handler shape: the same
// function signature as server.ToolHandlerFunc, expressed through the
// generic Handler[Req, Resp] type so kc/decorators.Compose can operate
// on it directly. Defined-type identity prevents accidental mixing with
// other Handler instantiations.
type mcpToolHandler = decorators.Handler[mcp.CallToolRequest, *mcp.CallToolResult]

// mcpToolDecorator is the corresponding around-chain Decorator: a
// function that wraps an mcpToolHandler with cross-cutting logic
// (panic recovery, request mutation, short-circuit, …). Around-hooks
// registered via OnToolExecution / OnToolExecutionMutable are adapted
// to this shape by aroundEntryToDecorator below.
type mcpToolDecorator = decorators.Decorator[mcp.CallToolRequest, *mcp.CallToolResult]

// aroundEntryToDecorator converts a mergedAroundEntry into a typed
// Decorator. The immutable / mutable branch decision is captured in the
// returned closure so HookMiddlewareFor's compose loop is a
// straight-line iteration with no per-entry conditional in the hot
// path.
//
// Panic recovery delegates to the existing safeInvokeAroundHook /
// safeInvokeMutableAroundHook helpers — the same crash protection
// shipped with the hand-written loop, applied identically in the
// migrated code path.
func aroundEntryToDecorator(entry mergedAroundEntry) mcpToolDecorator {
	if entry.mutable != nil {
		hook := entry.mutable
		return func(next mcpToolHandler) mcpToolHandler {
			return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				m := NewMutableCallToolRequest(req)
				return safeInvokeMutableAroundHook(hook, ctx, m, server.ToolHandlerFunc(next))
			}
		}
	}
	hook := entry.immutable
	return func(next mcpToolHandler) mcpToolHandler {
		return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return safeInvokeAroundHook(hook, ctx, req, server.ToolHandlerFunc(next))
		}
	}
}

// composeAroundChain composes the merged around-hook chain around the
// real tool handler, returning a single mcp-go-compatible handler
// function. Returns the base handler unchanged when no around-hooks are
// registered — same fast-path the pre-migration loop produced when len
// (merged) == 0.
//
// The order argument matters: Compose treats the FIRST element as the
// OUTERMOST wrapper, matching the documented HookMiddleware contract.
// mergedAroundChain (plugin_registry.go) already returns entries sorted
// by global registration sequence ascending, so passing the slice
// straight through preserves first-registered-outermost semantics.
func composeAroundChain(merged []mergedAroundEntry, base server.ToolHandlerFunc) server.ToolHandlerFunc {
	if len(merged) == 0 {
		return base
	}
	chain := make([]mcpToolDecorator, 0, len(merged))
	for _, entry := range merged {
		chain = append(chain, aroundEntryToDecorator(entry))
	}
	composed := decorators.Compose(chain...)(mcpToolHandler(base))
	return server.ToolHandlerFunc(composed)
}
