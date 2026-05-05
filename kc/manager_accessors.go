package kc

import (
	"time"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
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

// GetBrokerForEmail resolves the broker.Client for the given email
// by delegating to the underlying SessionService. Anchor 6 PR 6.4
// (per .research/anchor-6-pr-6-4-broker-resolver-redesign.md commit
// a2a11db): added so *Manager satisfies the narrowed
// BrokerResolverProvider interface (kc/manager_interfaces.go:95-114)
// directly, without exposing the *SessionService wrapper. Replaces
// the prior `manager.SessionSvc().GetBrokerForEmail(email)` two-hop
// at all 4 cross-package call sites.
func (m *Manager) GetBrokerForEmail(email string) (broker.Client, error) {
	return m.SessionSvc.GetBrokerForEmail(email)
}

// HasBrokerFactory reports whether the underlying SessionService has
// an explicit broker.Factory wired. Anchor 6 PR 6.4: added so
// *Manager satisfies BrokerResolverProvider directly. Replaces the
// prior `manager.SessionSvc().HasBrokerFactory()` two-hop at the
// app/http.go:720 call site.
func (m *Manager) HasBrokerFactory() bool {
	return m.SessionSvc.HasBrokerFactory()
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

// LoggerPort returns m.Logger wrapped in the kc/logger.Logger port.
// New code that wants to depend on the abstract Logger contract (instead
// of the concrete *slog.Logger) should call this accessor; the
// underlying Logger field is preserved for the existing call-site set
// so the migration can proceed file-by-file without a big-bang
// rewrite. Returns a no-op when m.Logger is nil so the result is
// always safe to use.
func (m *Manager) LoggerPort() logport.Logger {
	if m.Logger == nil {
		return logport.NewNoop()
	}
	return logport.NewSlog(m.Logger)
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
