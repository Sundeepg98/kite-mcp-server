package mcp

import (
	"context"
	"fmt"
	"sync"

	"github.com/mark3labs/mcp-go/mcp"
)

// MutableCallToolRequest is a thin wrapper around mcp.CallToolRequest
// that lets plugin around-hooks MUTATE the request before forwarding
// it to downstream middleware / the real handler.
//
// Why this exists:
//
//   The upstream mcp-go library passes CallToolRequest BY VALUE
//   through the handler chain. The Params.Arguments field is
//   typed `any` (concrete `map[string]any` at runtime). So a hook
//   could technically type-assert and mutate the map in place —
//   but that relies on implementation details of mcp-go's
//   Arguments representation AND produces surprising aliasing
//   (mutations leak back into the caller's request). A proper
//   mutable API gives plugin authors:
//
//     1. Explicit, typed mutation primitives (SetArg/GetArg/
//        DeleteArg) — no reflection, no type assertions.
//     2. Copy-on-construct semantics — the ORIGINAL CallToolRequest
//        the host passed into the middleware is NEVER mutated.
//     3. A clean ToRequest() boundary that produces a fresh
//        CallToolRequest with the mutated args, ready to hand
//        off to next(ctx, request).
//
// Use cases unlocked (the "plugin depth" axis):
//
//   - PII scrubbing before audit log: hook deletes a sensitive
//     field after the request has been logged.
//   - Default injection: hook sets request.Arguments["market"]="NSE"
//     when caller omitted it.
//   - Broker abstraction: hook rewrites Tradingsymbol from a
//     user-friendly alias ("APPLE") to the broker-recognised
//     form ("AAPL").
//
// Not a wire-format wrapper — MutableCallToolRequest is
// host-internal. The JSON that travels over the MCP protocol is the
// UNMUTATED inbound request. Plugin authors who want audit-log
// visibility of their mutations should emit an explicit log line
// from their hook.
type MutableCallToolRequest struct {
	// Original preserves the inbound CallToolRequest exactly as the
	// middleware chain received it. Used by ToRequest() to clone
	// non-Arguments fields (Header, Request, Meta, Task) without
	// hooks having to reason about them.
	original mcp.CallToolRequest
	// args is a COPY of the inbound Arguments map (made at wrap
	// time). Mutations to this map do not leak back to the
	// original. Lazily allocated — a nil args map on a fresh
	// wrapper means "caller supplied no arguments."
	args map[string]any
	// mu guards concurrent Set/Get/Delete against each other. In
	// the common case a hook is single-threaded, but the contract
	// MUST hold if a plugin author spins up a goroutine inside
	// their hook.
	mu sync.RWMutex
}

// NewMutableCallToolRequest wraps a CallToolRequest for mutation.
// The inbound Arguments are shallow-copied so plugin mutations do
// not leak back to the caller. Arguments that are not the standard
// map[string]any (rare — malformed client payloads) produce an
// empty mutation surface; ToRequest() preserves the original
// Arguments field verbatim in that case.
func NewMutableCallToolRequest(req mcp.CallToolRequest) *MutableCallToolRequest {
	m := &MutableCallToolRequest{original: req}
	if src, ok := req.Params.Arguments.(map[string]any); ok && src != nil {
		m.args = make(map[string]any, len(src))
		for k, v := range src {
			m.args[k] = v
		}
	}
	return m
}

// ToolName returns the tool being invoked. Host-authoritative —
// plugin hooks should NOT rename tools mid-flight (doing so would
// reroute the call to a handler the caller didn't ask for).
func (m *MutableCallToolRequest) ToolName() string {
	return m.original.Params.Name
}

// GetArg returns the value stored for the given argument key and a
// bool indicating whether the key was present. The returned value
// is the raw type produced by the JSON decoder (float64 for
// numbers, string for strings, map[string]any for nested objects).
func (m *MutableCallToolRequest) GetArg(key string) (any, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.args == nil {
		return nil, false
	}
	v, ok := m.args[key]
	return v, ok
}

// SetArg sets an argument value, creating the internal map on
// demand if this wrapper was constructed from a nil-Arguments
// request. Idempotent on equal values — safe to call repeatedly.
func (m *MutableCallToolRequest) SetArg(key string, value any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.args == nil {
		m.args = make(map[string]any)
	}
	m.args[key] = value
}

// DeleteArg removes an argument key. No-op if the key does not
// exist. Safe to call on a wrapper constructed from a nil-Arguments
// request.
func (m *MutableCallToolRequest) DeleteArg(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.args == nil {
		return
	}
	delete(m.args, key)
}

// Arguments returns a SNAPSHOT of the current argument map.
// Mutating the returned map does NOT affect the wrapper — the
// snapshot is a fresh allocation on every call. Plugin authors
// who want to loop over arguments and decide what to change use
// this, then feed individual changes through SetArg / DeleteArg.
func (m *MutableCallToolRequest) Arguments() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]any, len(m.args))
	for k, v := range m.args {
		out[k] = v
	}
	return out
}

// ToRequest produces a fresh CallToolRequest with the wrapper's
// CURRENT mutation state. Called by the middleware to hand the
// mutated request to the next hook / handler in the chain. All
// non-Arguments fields (Request, Header, Meta, Task, Name) are
// copied verbatim from the original inbound request.
//
// Thread safety: the returned Arguments map is a fresh copy of the
// wrapper's internal state; mutations to the returned request do
// not propagate back to the wrapper.
func (m *MutableCallToolRequest) ToRequest() mcp.CallToolRequest {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := m.original
	// Preserve non-standard Arguments shapes (e.g., the caller sent
	// a raw string or a JSON blob we couldn't parse as a map).
	if m.args == nil && !isMapShape(m.original.Params.Arguments) {
		return out
	}
	// Normal path: replace Arguments with a fresh snapshot.
	copyArgs := make(map[string]any, len(m.args))
	for k, v := range m.args {
		copyArgs[k] = v
	}
	out.Params.Arguments = copyArgs
	return out
}

// isMapShape reports whether the given any-typed Arguments value
// is the standard map[string]any shape. Non-map shapes are rare
// (malformed or non-JSON clients) and we preserve them verbatim
// through ToRequest() to avoid accidentally dropping the payload.
func isMapShape(a any) bool {
	_, ok := a.(map[string]any)
	return ok
}

// --- Mutable around-hook surface ---

// ToolMutableAroundHook is the mutable variant of ToolAroundHook
// (see registry.go). Instead of receiving an immutable
// mcp.CallToolRequest, the hook receives a *MutableCallToolRequest
// it can SetArg / DeleteArg on before calling next.
//
// The hook MUST call next(ctx, req.ToRequest()) to proceed — there
// is no implicit forward. A hook that returns a synthetic
// CallToolResult without calling next short-circuits the chain, same
// as the immutable ToolAroundHook contract.
type ToolMutableAroundHook func(
	ctx context.Context,
	req *MutableCallToolRequest,
	next ToolHandlerNext,
) (*mcp.CallToolResult, error)

// mutableAroundHookEntry pairs a ToolMutableAroundHook with its
// global registration sequence number. Mirrors the immutable
// aroundHookEntry in registry.go so the two slices can be merged
// into a single chain ordered by true registration sequence (see
// mergedAroundChain in registry.go).
type mutableAroundHookEntry struct {
	hook ToolMutableAroundHook
	seq  uint64
}

// OnToolExecutionMutable registers a mutable around-hook on
// DefaultRegistry. Hooks compose with the immutable ones from
// OnToolExecution in true registration order (shared sequence
// counter): the first OnToolExecution or OnToolExecutionMutable
// call becomes the outermost wrapper, the last is closest to the
// handler.
func OnToolExecutionMutable(hook ToolMutableAroundHook) {
	DefaultRegistry.OnToolExecutionMutable(hook)
}

// MutableAroundHookCount exposes the registered mutable-hook count
// on DefaultRegistry for the admin / manifest surface.
func MutableAroundHookCount() int {
	return DefaultRegistry.MutableAroundHookCount()
}

// safeInvokeMutableAroundHook runs a single mutable hook with
// panic recovery. Mirrors the existing safeInvokeAroundHook; a
// panic surfaces as an IsError=true CallToolResult so the MCP
// client sees a clean error, not a dropped connection.
func safeInvokeMutableAroundHook(
	hook ToolMutableAroundHook,
	ctx context.Context,
	req *MutableCallToolRequest,
	next ToolHandlerNext,
) (result *mcp.CallToolResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			result = mcp.NewToolResultError(fmt.Sprintf("mutable around-hook panic: %v", r))
			err = nil
		}
	}()
	return hook(ctx, req, next)
}
