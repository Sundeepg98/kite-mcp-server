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
//
// Anchor 5 Wave B-2 closure (PRs 5.3+5.5+5.7): four of the six port
// files (alert.go, credential.go, instrument.go, session.go) now have
// ZERO kc-parent imports. Two retain their kc-parent imports BY
// DESIGN per anchor-5-prs-design.md:
//
//   - assertions.go MUST import kc to verify *kc.Manager satisfies
//     the ports at compile time. The compile-time check can ONLY live
//     in a package that imports kc, and ports is the appropriate
//     location.
//
//   - order.go retains *kc.OrderService for now — OrderService is a
//     write-side service type with method receivers that Anchor 6
//     will redesign as part of the kc-root god-struct cleanup.
//     Inverting it ahead of that cleanup would force a premature
//     OrderService relocation.
package ports

import "github.com/algo2go/kite-mcp-domain"

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
// Anchor 5 PR 5.7 (Wave B-2): the *kc.KiteSessionData return type
// references were rewritten to *domain.KiteSessionData, referencing
// the canonical declaration directly (PR 5.6, commit e44c070 had
// relocated KiteSessionData to kc/domain/session.go and left a type
// alias `kc.KiteSessionData = domain.KiteSessionData` in kc/manager.go
// for backward compat). The 56-file reverse-dep set continues to
// build unchanged because kc.KiteSessionData and domain.KiteSessionData
// are the same underlying type via the alias.
//
// The method set is an exact mirror of kc.SessionProvider — the old
// interface is retained in manager_interfaces.go as a deprecated alias
// until cqrs/ddd teammates migrate their call sites in Phase B/D.
type SessionPort interface {
	// GetOrCreateSession retrieves an existing Kite session or creates a new one.
	GetOrCreateSession(mcpSessionID string) (*domain.KiteSessionData, bool, error)

	// GetOrCreateSessionWithEmail retrieves or creates a session with email context.
	GetOrCreateSessionWithEmail(mcpSessionID, email string) (*domain.KiteSessionData, bool, error)

	// GetSession retrieves an existing Kite session by MCP session ID.
	GetSession(mcpSessionID string) (*domain.KiteSessionData, error)

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
