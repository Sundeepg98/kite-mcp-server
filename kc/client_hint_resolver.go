package kc

import (
	"net/http"
)

// ─────────────────────────────────────────────────────────────────────────────
// SessionIdManagerResolver wiring for ClientHint
//
// The mcp-go library calls SessionIdManagerResolver.ResolveSessionIdManager(r)
// with the incoming HTTP request BEFORE it calls Generate() on the returned
// manager. We use that hook to extract the User-Agent (and any other request
// signals) and return a request-scoped wrapper whose Generate() calls
// GenerateWithDataAndHint on the underlying SessionRegistry.
//
// This is the "OAuth-token stash" approach from the session handoff memory,
// simplified: instead of threading the hint through the OAuth token, we
// attach it to the session at the exact moment the transport creates one.
// The hint is then visible to every downstream consumer (admin tools,
// dashboard, audit log enrichment) via MCPSession.ClientHint.
//
// The wrapper also delegates Validate and Terminate to the underlying
// registry so all existing behavior is preserved.
// ─────────────────────────────────────────────────────────────────────────────

// ClientHintResolver is a SessionIdManagerResolver that derives a ClientHint
// from each incoming HTTP request and records it on the MCPSession the
// library is about to generate.
type ClientHintResolver struct {
	registry *SessionRegistry
}

// NewClientHintResolver constructs a resolver backed by the given registry.
func NewClientHintResolver(registry *SessionRegistry) *ClientHintResolver {
	return &ClientHintResolver{registry: registry}
}

// ResolveSessionIdManager is the mcp-go hook. It inspects the request to
// determine the client hint, then returns a request-scoped wrapper around
// the underlying SessionRegistry.
//
// Nil r is handled — the mcp-go idle-TTL sweeper passes a nil request, in
// which case we return the bare registry (Generate-path will produce an
// empty hint, which renders as "Unknown").
func (r *ClientHintResolver) ResolveSessionIdManager(req *http.Request) SessionIdManagerShim {
	hint := ClientHintFromRequest(req)
	return &hintedSessionIdManager{
		registry: r.registry,
		hint:     hint,
	}
}

// SessionIdManagerShim mirrors mcp-go's SessionIdManager interface without
// importing the mcp-go server package (which would create an import cycle
// between kc and mcp-go). The app-level wire code in app/http.go casts
// this shim to the library's interface; they're structurally identical.
type SessionIdManagerShim interface {
	Generate() string
	Validate(sessionID string) (isTerminated bool, err error)
	Terminate(sessionID string) (isNotAllowed bool, err error)
}

// hintedSessionIdManager is a request-scoped wrapper that populates
// ClientHint via GenerateWithDataAndHint on Generate(), and otherwise
// delegates to the underlying SessionRegistry.
type hintedSessionIdManager struct {
	registry *SessionRegistry
	hint     string
}

// Generate creates a new session with the captured ClientHint applied.
// The session Data is nil here because mcp-go's session-id generation
// happens before any Kite data is attached — Kite data is written later
// via UpdateSessionData/GetOrCreateSessionData once the OAuth bearer is
// validated and the email is known.
func (h *hintedSessionIdManager) Generate() string {
	return h.registry.GenerateWithDataAndHint(nil, h.hint)
}

// Validate delegates to the registry.
func (h *hintedSessionIdManager) Validate(sessionID string) (isTerminated bool, err error) {
	return h.registry.Validate(sessionID)
}

// Terminate delegates to the registry.
func (h *hintedSessionIdManager) Terminate(sessionID string) (isNotAllowed bool, err error) {
	return h.registry.Terminate(sessionID)
}
