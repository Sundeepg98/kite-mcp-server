// Package ports holds the bounded-context interfaces (hexagonal ports)
// that Manager satisfies. Consumers should depend on a port rather
// than on *kc.Manager directly — this keeps the package graph pointing
// inward toward the domain and prevents tool handlers from reaching
// beyond their bounded context.
//
// Five ports live here: Session, Credential, Alert, Order, Instrument.
// Each mirrors the narrow contract already in kc/manager_interfaces.go
// (SessionProvider, CredentialResolver, AlertStoreProvider, …) and is
// a superset compiled from the methods actually called at consumer
// sites (interface-segregation — don't export what no one calls).
//
// Compile-time satisfaction is asserted in kc/ports/assertions.go,
// which imports kc. The kc package does NOT import kc/ports — so the
// import graph stays acyclic even though ports reference kc types.
package ports

import "github.com/zerodha/kite-mcp-server/kc"

// SessionPort is the bounded-context contract for MCP session
// lifecycle operations — creation, lookup, teardown, and the login
// URL / callback completion flow. It is the union of the methods
// actually reached through *kc.Manager at consumer sites:
//
//   - mcp/setup_tools.go (ClearSessionData, GetOrCreateSessionWithEmail)
//   - mcp/alert_tools.go, mcp/watchlist_tools.go (GetOrCreateSessionWithEmail)
//   - mcp/admin_server_tools.go, mcp/ext_apps.go,
//     mcp/observability_tool.go (GetActiveSessionCount)
//   - mcp/common.go via ToolHandlerDeps.Sessions (already abstracted)
//   - kc/callback_handler.go (CompleteSession)
//   - kc/usecases/setup_usecases.go via urls.SessionLoginURL
//
// The method set is an exact mirror of kc.SessionProvider — the old
// interface is retained in manager_interfaces.go as a deprecated alias
// until cqrs/ddd teammates migrate their call sites in Phase B/D.
type SessionPort interface {
	// GetOrCreateSession retrieves an existing Kite session or creates a new one.
	GetOrCreateSession(mcpSessionID string) (*kc.KiteSessionData, bool, error)

	// GetOrCreateSessionWithEmail retrieves or creates a session with email context.
	GetOrCreateSessionWithEmail(mcpSessionID, email string) (*kc.KiteSessionData, bool, error)

	// GetSession retrieves an existing Kite session by MCP session ID.
	GetSession(mcpSessionID string) (*kc.KiteSessionData, error)

	// GenerateSession creates a new MCP session and returns the session ID.
	GenerateSession() string

	// ClearSession terminates a session, triggering cleanup hooks.
	ClearSession(sessionID string)

	// ClearSessionData clears session data without terminating the session.
	ClearSessionData(sessionID string) error

	// SessionLoginURL returns the Kite login URL for the given session.
	SessionLoginURL(mcpSessionID string) (string, error)

	// CompleteSession completes Kite authentication using the request token.
	CompleteSession(mcpSessionID, kiteRequestToken string) error

	// GetActiveSessionCount returns the number of active sessions.
	GetActiveSessionCount() int
}
