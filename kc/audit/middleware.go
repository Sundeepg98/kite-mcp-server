package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// Middleware returns mcp-go ToolHandlerMiddleware that logs every tool call.
func Middleware(store *Store) server.ToolHandlerMiddleware {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
			start := time.Now()
			toolName := request.Params.Name
			args := request.GetArguments()

			// Execute the actual tool handler.
			result, err := next(ctx, request)

			// Compute timing.
			end := time.Now()
			durationMs := end.Sub(start).Milliseconds()

			// Extract identity from context.
			email := oauth.EmailFromContext(ctx)
			sessionID := ""
			if sess := server.ClientSessionFromContext(ctx); sess != nil { // COVERAGE: unreachable in unit tests — requires full MCP server transport context
				sessionID = sess.SessionID()
			}

			// Build audit entry.
			entry := &ToolCall{
				CallID:       uuid.New().String(),
				Email:        email,
				SessionID:    sessionID,
				ToolName:     toolName,
				ToolCategory: ToolCategory(toolName),
				InputSummary: SummarizeInput(toolName, args),
				StartedAt:    start,
				CompletedAt:  end,
				DurationMs:   durationMs,
			}

			// Sanitize and store params as JSON.
			sanitized := SanitizeParams(args)
			if paramJSON, jsonErr := json.Marshal(sanitized); jsonErr == nil {
				entry.InputParams = string(paramJSON)
			}

			// Capture output.
			if err != nil {
				entry.IsError = true
				entry.ErrorMessage = err.Error()
				entry.ErrorType = "handler_error"
			} else if result != nil {
				entry.OutputSummary = SummarizeOutput(toolName, result)
				if result.IsError {
					entry.IsError = true
					entry.ErrorMessage = entry.OutputSummary
					entry.ErrorType = "tool_error"
				}
				// Estimate output size.
				if outJSON, jsonErr := json.Marshal(result); jsonErr == nil {
					entry.OutputSize = len(outJSON)
				}
			}

			// Extract order_id from order placement/modification responses.
			if toolName == "place_order" || toolName == "modify_order" || toolName == "place_gtt_order" {
				if text := extractText(result); text != "" {
					// Try to parse as JSON and extract order_id.
					var resp map[string]any
					if json.Unmarshal([]byte(text), &resp) == nil {
						if oid, ok := resp["order_id"]; ok {
							entry.OrderID = fmt.Sprintf("%v", oid)
						}
						// Also check nested data.order_id
						if entry.OrderID == "" {
							if data, ok := resp["data"].(map[string]any); ok {
								if oid, ok := data["order_id"]; ok {
									entry.OrderID = fmt.Sprintf("%v", oid)
								}
							}
						}
					}
				}
			}

			// Write to DB via buffered channel (non-blocking, graceful shutdown).
			store.Enqueue(entry)

			return result, err
		}
	}
}
