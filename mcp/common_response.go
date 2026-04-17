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
func (h *ToolHandler) MarshalResponse(data any, toolName string) (*mcp.CallToolResult, error) {
	v, err := json.Marshal(data)
	if err != nil {
		h.deps.Logger.Error("Failed to marshal response", "tool", toolName, "error", err)
		return mcp.NewToolResultError(fmt.Sprintf("Failed to process response data: %s", err.Error())), nil
	}

	h.deps.Logger.Debug("Response marshaled successfully", "tool", toolName, "response_size", len(v))
	structured := wrapForStructuredContent(data)
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

// HandleAPICall wraps common API call pattern with error handling and response marshalling
func (h *ToolHandler) HandleAPICall(ctx context.Context, toolName string, apiCall func(*kc.KiteSessionData) (any, error)) (*mcp.CallToolResult, error) {
	return h.WithSession(ctx, toolName, func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
		data, err := apiCall(session)
		if err != nil {
			h.deps.Logger.Error("API call failed", "tool", toolName, "error", err)
			return mcp.NewToolResultError(fmt.Sprintf("%s: %s", toolName, err.Error())), nil
		}

		return h.MarshalResponse(data, toolName)
	})
}
