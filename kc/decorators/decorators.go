// Package decorators provides a generic, type-safe decorator factory for
// composable cross-cutting concerns at arbitrary request/response types.
//
// Phase 3a Decorator Option 2 (per `.research/decorator-code-gen-evaluation.md`):
// closes the rubric path-F gap — generic typed-decorator composition — at
// 80 LOC of pure Go. Idiomatic post-1.21 generics; no codegen, no
// reflection, no runtime overhead beyond the function-pointer indirection
// already present in HTTP middleware patterns (gRPC interceptor /
// Echo middleware / Buffalo / Temporal).
//
// # Why a separate package
//
// The MCP-specific around-hook surface in mcp/registry.go (ToolAroundHook +
// ToolMutableAroundHook) is parameterized on mcp.CallToolRequest /
// *mcp.CallToolResult — the exact MCP wire shape. That parameterization is
// load-bearing for tool-level integration with the mcp-go server.
//
// This package solves a different problem: callers (use cases, hooks,
// plugins) that want to compose middleware around their OWN typed
// request/response shapes — say a Money calculator, a riskguard check, a
// portfolio query — should not have to wrap-then-unwrap mcp.CallToolRequest
// just to get composition. Decorator[Req, Resp] gives them a typed surface
// that reads and writes the actual domain type.
//
// # Composition contract
//
// Compose(d1, d2, d3) returns a Decorator that wraps a handler "outermost
// first": d1 wraps d2 wraps d3 wraps handler. Execution order matches
// gRPC's UnaryServerInterceptor + the existing mcp.HookMiddleware
// convention — the FIRST decorator listed is the OUTERMOST wrapper, the
// LAST is closest to the handler.
//
// # Short-circuit semantics
//
// A decorator MAY return without calling next — this implements the same
// "synthetic response" pattern as mcp.ToolAroundHook short-circuit (used by
// riskguard for blocked orders, billing for tier-gated tools, paper-trading
// for order interception). Inner decorators after the short-circuit do
// NOT run, mirroring the HTTP middleware contract.
//
// # Error propagation
//
// Errors from the handler flow back through the decorators in reverse
// order — each decorator's "inner-side" branch sees the error and may
// either surface or swallow. This matches Go's idiomatic
// `result, err := next()` pattern.
//
// # Nil safety
//
// Compose panics at composition time if any decorator in the chain is nil.
// This is fail-fast — wrong wiring should crash at startup, not on the
// first user request. (Tested in TestCompose_NilSafety.)
package decorators

import (
	"context"
	"fmt"
)

// Handler is a typed request-handler function: takes a request, returns a
// response or an error. The Req and Resp type parameters let callers
// declare exactly what they handle without the type-erasure ceremony of
// `any` / `interface{}` boxing.
//
// This is a regular Go function type, NOT a wrapper struct — Handler
// values are directly callable as `h(ctx, req)`. Tests assert this in
// TestHandler_TypeIsCallable.
type Handler[Req, Resp any] func(ctx context.Context, req Req) (Resp, error)

// Decorator wraps a Handler — it receives the inner handler and returns a
// new Handler that may run logic before/after, mutate the request, observe
// the response, or short-circuit by returning without calling next.
//
// This is the Go-idiomatic decorator: a function-typed wrapper, identical
// in shape to `grpc.UnaryServerInterceptor` and `echo.MiddlewareFunc`. It
// is a regular function type — Decorator values are directly callable as
// `d(next)`. Tests assert this in TestDecorator_TypeIsCallable.
type Decorator[Req, Resp any] func(next Handler[Req, Resp]) Handler[Req, Resp]

// Compose returns a Decorator that applies the given decorators in
// outermost-first order: the first decorator listed wraps the second wraps
// the third (etc.) wraps the handler. This matches the gRPC / Echo /
// mcp.HookMiddleware convention so plugin authors carry one mental model
// across the codebase.
//
// Compose with zero decorators returns the identity decorator (the
// handler is returned unchanged). Compose with a nil decorator panics —
// see the Nil safety note in the package doc.
//
// Example:
//
//	composed := decorators.Compose(
//	    AuditDecorator,    // outermost — runs first, runs last
//	    RiskguardDecorator,
//	    BillingDecorator,  // innermost — wraps the real handler
//	)(rawPlaceOrder)
func Compose[Req, Resp any](decorators ...Decorator[Req, Resp]) Decorator[Req, Resp] {
	// Validate all decorators are non-nil at composition time so wiring
	// regressions surface at startup rather than on the first user request.
	for i, d := range decorators {
		if d == nil {
			panic(fmt.Sprintf("decorators.Compose: nil Decorator at index %d", i))
		}
	}

	return func(handler Handler[Req, Resp]) Handler[Req, Resp] {
		// Wrap right-to-left so the FIRST decorator listed ends up as
		// the OUTERMOST wrapper. Mirrors mcp.HookMiddlewareFor's
		// composition order (mcp/registry.go lines 207-225).
		for i := len(decorators) - 1; i >= 0; i-- {
			handler = decorators[i](handler)
		}
		return handler
	}
}

// Apply is the convenience inverse of Compose — composes decorators around
// a handler in a single call. Some callers find the reading order
// `Apply(handler, d1, d2, d3)` more natural than
// `Compose(d1, d2, d3)(handler)`. Semantics are identical.
//
// Example:
//
//	composed := decorators.Apply(rawPlaceOrder, AuditDecorator, RiskguardDecorator, BillingDecorator)
func Apply[Req, Resp any](handler Handler[Req, Resp], decorators ...Decorator[Req, Resp]) Handler[Req, Resp] {
	return Compose(decorators...)(handler)
}
