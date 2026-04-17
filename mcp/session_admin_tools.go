package mcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// ─────────────────────────────────────────────────────────────────────────────
// Per-user session management
//
// These tools let each authenticated user see and revoke their own MCP
// sessions. They are NOT admin-only — scope is implicit from the OAuth JWT
// (oauth.EmailFromContext). An admin-scoped view exists elsewhere
// (admin_server_status); this pair is for self-service.
// ─────────────────────────────────────────────────────────────────────────────

// sessionIDDisplayHead and sessionIDDisplayTail control the length of the
// truncated session ID shown to users. 12 prefix + "…" + 4 suffix matches the
// `kitemcp-abc1…d4f2` format described in the brief.
const (
	sessionIDDisplayHead = 12
	sessionIDDisplayTail = 4
)

// truncateSessionID renders a session ID as `<first-12>…<last-4>` for display.
// Short IDs are returned unchanged.
func truncateSessionID(id string) string {
	if len(id) <= sessionIDDisplayHead+sessionIDDisplayTail {
		return id
	}
	return id[:sessionIDDisplayHead] + "…" + id[len(id)-sessionIDDisplayTail:]
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool: list_mcp_sessions (read-only, per-user)
// ─────────────────────────────────────────────────────────────────────────────

// ListMCPSessionsTool lists the caller's own active MCP sessions, merged with
// recent audit activity to produce a richer per-session view.
type ListMCPSessionsTool struct{}

func (*ListMCPSessionsTool) Tool() mcp.Tool {
	return mcp.NewTool("list_mcp_sessions",
		mcp.WithDescription("List your own active MCP sessions across clients (Claude Code, Desktop, web). Each entry includes the session's client hint, timestamps, and recent tool activity."),
		mcp.WithTitleAnnotation("List my MCP sessions"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
	)
}

type mcpSessionEntry struct {
	SessionID        string `json:"session_id"`         // truncated for display
	SessionIDFull    string `json:"session_id_full"`    // full ID, needed to revoke
	CreatedAt        string `json:"created_at"`
	ExpiresAt        string `json:"expires_at"`
	LastActivity     string `json:"last_activity,omitempty"`
	ClientHint       string `json:"client_hint"`
	RecentToolCalls  int    `json:"recent_tool_calls"` // count in the last hour
}

type listMCPSessionsResponse struct {
	Email    string            `json:"email"`
	Count    int               `json:"count"`
	Sessions []mcpSessionEntry `json:"sessions"`
}

func (*ListMCPSessionsTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "list_mcp_sessions")

		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return mcp.NewToolResultError(ErrAuthRequired), nil
		}
		emailLower := strings.ToLower(email)

		reg := manager.SessionManager()
		if reg == nil {
			return mcp.NewToolResultError("Session registry not available."), nil
		}

		all := reg.ListActiveSessions()
		auditStore := handler.deps.Audit.AuditStore()
		now := time.Now()
		cutoff := now.Add(-1 * time.Hour)

		entries := make([]mcpSessionEntry, 0, len(all))
		for _, s := range all {
			kd, ok := s.Data.(*kc.KiteSessionData)
			if !ok || kd == nil {
				continue
			}
			if !strings.EqualFold(kd.Email, emailLower) {
				continue
			}

			hint := s.ClientHint
			if hint == "" {
				hint = "Unknown"
			}

			entry := mcpSessionEntry{
				SessionID:     truncateSessionID(s.ID),
				SessionIDFull: s.ID,
				CreatedAt:     s.CreatedAt.UTC().Format(time.RFC3339),
				ExpiresAt:     s.ExpiresAt.UTC().Format(time.RFC3339),
				ClientHint:    hint,
			}

			// Merge with audit log — count recent tool calls for this session
			// and surface the most recent activity timestamp. The audit store
			// is optional: if unavailable (no DB), leave recent fields empty.
			if auditStore != nil {
				calls, _, err := auditStore.List(email, audit.ListOptions{
					Limit: 10,
					Since: cutoff,
				})
				if err == nil {
					recent := 0
					var lastAct time.Time
					for _, c := range calls {
						if c.SessionID != s.ID {
							continue
						}
						recent++
						if c.StartedAt.After(lastAct) {
							lastAct = c.StartedAt
						}
					}
					entry.RecentToolCalls = recent
					if !lastAct.IsZero() {
						entry.LastActivity = lastAct.UTC().Format(time.RFC3339)
					}
				} else {
					handler.deps.Logger.Warn("list_mcp_sessions: audit list failed",
						"email", email, "session_id", s.ID, "error", err)
				}
			}

			entries = append(entries, entry)
		}

		return handler.MarshalResponse(&listMCPSessionsResponse{
			Email:    email,
			Count:    len(entries),
			Sessions: entries,
		}, "list_mcp_sessions")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool: revoke_mcp_session (destructive, per-user)
// ─────────────────────────────────────────────────────────────────────────────

// RevokeMCPSessionTool terminates a specific session owned by the caller.
// Ownership (email match) is enforced before termination — users cannot revoke
// sessions that belong to other users.
type RevokeMCPSessionTool struct{}

func (*RevokeMCPSessionTool) Tool() mcp.Tool {
	return mcp.NewTool("revoke_mcp_session",
		mcp.WithDescription("Terminate one of your MCP sessions by ID. Only sessions owned by you can be revoked; attempting to revoke another user's session returns an error."),
		mcp.WithTitleAnnotation("Revoke my MCP session"),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("session_id",
			mcp.Description("Full session ID to revoke (the session_id_full field from list_mcp_sessions)."),
			mcp.Required(),
		),
	)
}

type revokeMCPSessionResponse struct {
	Status    string `json:"status"`
	SessionID string `json:"session_id"`
}

func (*RevokeMCPSessionTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "revoke_mcp_session")

		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return mcp.NewToolResultError(ErrAuthRequired), nil
		}

		sessionID := NewArgParser(request.GetArguments()).String("session_id", "")
		if sessionID == "" {
			return mcp.NewToolResultError("session_id is required."), nil
		}

		reg := manager.SessionManager()
		if reg == nil {
			return mcp.NewToolResultError("Session registry not available."), nil
		}

		// Ownership check — fetch the session and compare its email with the
		// caller's email BEFORE terminating. GetSession returns an error if
		// the session does not exist. We use a generic "not found" message
		// for both missing and not-owned cases so this tool does not leak
		// existence of other users' session IDs.
		s, err := reg.GetSession(sessionID)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Session not found: %s", truncateSessionID(sessionID))), nil
		}
		kd, ok := s.Data.(*kc.KiteSessionData)
		if !ok || kd == nil || !strings.EqualFold(kd.Email, email) {
			handler.deps.Logger.Warn("revoke_mcp_session: ownership mismatch",
				"caller_email", email, "session_id", sessionID)
			return mcp.NewToolResultError(fmt.Sprintf("Session not found: %s", truncateSessionID(sessionID))), nil
		}

		if _, err := reg.Terminate(sessionID); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to revoke session: %s", err.Error())), nil
		}

		return handler.MarshalResponse(&revokeMCPSessionResponse{
			Status:    "revoked",
			SessionID: sessionID,
		}, "revoke_mcp_session")
	}
}
