package kc

import (
	"time"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// manager_accessors.go holds the Manager's service-accessor methods —
// getters and setters for the decomposed Clean-Architecture sub-services,
// the CQRS buses, and the session/MCP wiring. Extracted from manager.go
// in the SOLID-S split so the core Manager struct + constructor sit in
// one file and these read-only (mostly) passthroughs sit in another.
//
// Every method here is a one-line field-returner. No logic moved.

// ---------------------------------------------------------------------------
// Focused sub-services (Clean Architecture)
// ---------------------------------------------------------------------------

// CredentialSvc returns the credential resolution service.
func (m *Manager) CredentialSvc() *CredentialService {
	return m.credentialSvc
}

// SessionSvc returns the session lifecycle service.
func (m *Manager) SessionSvc() *SessionService {
	return m.sessionSvc
}

// PortfolioSvc returns the portfolio query service.
func (m *Manager) PortfolioSvc() *PortfolioService {
	return m.portfolioSvc
}

// OrderSvc returns the order management service.
func (m *Manager) OrderSvc() *OrderService {
	return m.orderSvc
}

// AlertSvc returns the alert lifecycle service.
func (m *Manager) AlertSvc() *AlertService {
	return m.alertSvc
}

// FamilyService returns the family billing service, or nil if not configured.
func (m *Manager) FamilyService() *FamilyService {
	return m.familyService
}

// SetFamilyService sets the family billing service.
func (m *Manager) SetFamilyService(fs *FamilyService) {
	m.familyService = fs
}

// ---------------------------------------------------------------------------
// CQRS buses
// ---------------------------------------------------------------------------

// CommandBus returns the CQRS command bus for write-side dispatches.
func (m *Manager) CommandBus() *cqrs.InMemoryBus {
	return m.commandBus
}

// QueryBus returns the CQRS query bus for read-side dispatches.
func (m *Manager) QueryBus() *cqrs.InMemoryBus {
	return m.queryBus
}

// ---------------------------------------------------------------------------
// Session registry + signer
// ---------------------------------------------------------------------------

// SessionManager returns the MCP session manager instance.
func (m *Manager) SessionManager() *SessionRegistry {
	return m.sessionManager
}

// ManagedSessionSvc returns the thin session facade for active-count and terminate-by-email.
func (m *Manager) ManagedSessionSvc() *ManagedSessionService {
	return m.managedSessionSvc
}

// SessionSigner returns the session signer instance.
func (m *Manager) SessionSigner() *SessionSigner {
	return m.sessionSigner
}

// UpdateSessionSignerExpiry updates the signature expiry duration.
func (m *Manager) UpdateSessionSignerExpiry(duration time.Duration) {
	m.sessionSigner.SetSignatureExpiry(duration)
}

// ---------------------------------------------------------------------------
// MCP server handle (for elicitation)
// ---------------------------------------------------------------------------

// SetMCPServer stores a reference to the MCP server for elicitation support.
func (m *Manager) SetMCPServer(srv any) {
	m.mcpServer = srv
}

// MCPServer returns the stored MCP server reference, or nil.
func (m *Manager) MCPServer() any {
	return m.mcpServer
}
