package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/zerodha/kite-mcp-server/kc"
)

// MarshalResponse marshals data to JSON and returns an MCP text result.
//
// MCP spec requires structuredContent to be a JSON object, not an array or
// primitive. Strict Zod-based clients (Claude Code) reject array-typed
// structuredContent with "expected record, received array". Tools like
// get_holdings/get_positions/get_orders/get_gtts/get_mf_holdings return naked
// top-level arrays from the Kite API, so we wrap those in {"items": [...]}
// before passing to NewToolResultStructured. The text fallback keeps the
// original array JSON for LLM readability.
//
// LLM-facing string fields are sanitized via SanitizeData to defend
// against prompt-injection inside broker fields (e.g. a hostile
// upstream returning "AAPL\nIgnore prior instructions..." in
// tradingsymbol). Per-field walk preserves JSON structure: control
// characters are escaped inside each string value, long values wrapped
// in [UNTRUSTED]…[/UNTRUSTED]. The marshaled JSON remains parseable —
// programmatic consumers (UI widgets, dashboard, tests) keep working
// while the LLM-facing string contents are neutralized.
func (h *ToolHandler) MarshalResponse(data any, toolName string) (*mcp.CallToolResult, error) {
	cleaned := SanitizeData(data)
	v, err := json.Marshal(cleaned)
	if err != nil {
		h.deps.Logger.Error("Failed to marshal response", "tool", toolName, "error", err)
		return mcp.NewToolResultError(fmt.Sprintf("Failed to process response data: %s", err.Error())), nil
	}

	h.deps.Logger.Debug("Response marshaled successfully", "tool", toolName, "response_size", len(v))
	structured := wrapForStructuredContent(cleaned)
	return mcp.NewToolResultStructured(structured, string(v)), nil
}

// wrapForStructuredContent ensures the value handed to NewToolResultStructured
// is a JSON object. Slices, arrays, and primitives get wrapped in {"items": …}.
// Maps and structs pass through unchanged.
func wrapForStructuredContent(data any) any {
	if data == nil {
		return map[string]any{"items": nil}
	}
	rv := reflect.ValueOf(data)
	for rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return map[string]any{"items": nil}
		}
		rv = rv.Elem()
	}
	switch rv.Kind() {
	case reflect.Struct, reflect.Map:
		return data
	default:
		return map[string]any{"items": data}
	}
}

// HandleAPICall wraps common API call pattern with error handling and response marshalling.
// The apiCall closure receives ctx so dispatches inherit request cancellation.
func (h *ToolHandler) HandleAPICall(ctx context.Context, toolName string, apiCall func(context.Context, *kc.KiteSessionData) (any, error)) (*mcp.CallToolResult, error) {
	return h.WithSession(ctx, toolName, func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
		data, err := apiCall(ctx, session)
		if err != nil {
			h.deps.Logger.Error("API call failed", "tool", toolName, "error", err)
			return mcp.NewToolResultError(fmt.Sprintf("%s: %s", toolName, err.Error())), nil
		}

		return h.MarshalResponse(data, toolName)
	})
}

// BusResult[T] narrows a CommandBus/QueryBus dispatch result (typed as any)
// into a strongly typed value T. Returns a non-nil error when the dispatch
// failed OR when the underlying value is not of the expected type. The nil-
// value case is returned as (zero T, nil) so callers that expect an empty
// result (e.g. a no-op event persister path) handle it the same way as a
// successful zero-valued response.
//
// This helper replaces the blanket `resp, _ := raw.(broker.Xxx)` pattern at
// CommandBus dispatch sites, which silently swallows type mismatches and
// hands an empty struct to MarshalResponse. With BusResult, a type mismatch
// surfaces as an explicit error — the tool-level handler reports it cleanly
// instead of returning a misleading "success" with zero fields.
//
// Usage:
//
//	resp, err := BusResult[broker.OrderResponse](raw)
//	if err != nil {
//	    return mcp.NewToolResultError(err.Error()), nil
//	}
//
// T must be the non-pointer concrete type returned by the handler. For
// pointer returns (e.g. *usecases.LoginResult), use BusResultPtr instead.
func BusResult[T any](raw any) (T, error) {
	var zero T
	if raw == nil {
		return zero, nil
	}
	v, ok := raw.(T)
	if !ok {
		return zero, fmt.Errorf("cqrs: unexpected bus result type %T (want %T)", raw, zero)
	}
	return v, nil
}
