package audit

import (
	"context"
	"encoding/json"
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
			if sess := server.ClientSessionFromContext(ctx); sess != nil {
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

			// Write to DB via buffered channel (non-blocking, graceful shutdown).
			store.Enqueue(entry)

			return result, err
		}
	}
}
