package mcp

import (
	"log/slog"
	"time"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/ports"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
)

// ToolHandlerDeps holds the injected services for ToolHandler, replacing
// the service-locator pattern of reaching into *kc.Manager for each call.
//
// Consumers should depend on the narrowest Provider interface they need.
// *kc.Manager satisfies every Provider, so call sites can continue passing
// a Manager, but individual tool Handler functions must reach through these
// typed Provider fields rather than invoking accessors on *kc.Manager.
type ToolHandlerDeps struct {
	Logger      *slog.Logger
	TokenStore  kc.TokenStoreInterface
	UserStore   kc.UserStoreInterface // may be nil
	Sessions    ports.SessionPort
	Credentials ports.CredentialPort
	Metrics     kc.MetricsRecorder
	Config      kc.AppConfigProvider

	// Narrow store-provider interfaces (ISP). Each is a one-method accessor
	// onto the underlying store; consumers invoke e.g. `Tokens.TokenStore()`
	// at the point of use. Providers are preferred over raw store interfaces
	// because they can return nil when a subsystem is disabled without the
	// caller needing to know the disable semantics up front.
	Tokens         kc.TokenStoreProvider
	CredStore      kc.CredentialStoreProvider
	Alerts         kc.AlertStoreProvider
	Telegram       kc.TelegramStoreProvider
	Watchlist      kc.WatchlistStoreProvider
	Users          kc.UserStoreProvider
	Registry       kc.RegistryStoreProvider
	Audit          kc.AuditStoreProvider
	Billing        kc.BillingStoreProvider
	Ticker         kc.TickerServiceProvider
	Paper          kc.PaperEngineProvider
	Instruments    kc.InstrumentsManagerProvider
	AlertDB        kc.AlertDBProvider
	RiskGuard      kc.RiskGuardProvider
	MCPServer      kc.MCPServerProvider
	BrokerResolver kc.BrokerResolverProvider
	TrailingStop   kc.TrailingStopManagerProvider
	Events         kc.EventDispatcherProvider

	// CQRS bus providers — handlers that dispatch commands/queries
	// depend on these narrow ports rather than pulling the full
	// *Manager through manager.CommandBus() / manager.QueryBus().
	CommandBusP kc.CommandBusProvider
	QueryBusP   kc.QueryBusProvider
}

// ToolHandler provides common functionality for all MCP tools.
// It holds focused service interfaces instead of the full Manager.
// The manager field is retained for backward compatibility while individual
// tool Handler methods are migrated incrementally.
type ToolHandler struct {
	manager          *kc.Manager                   // retained for tool-level backward compat
	deps             ToolHandlerDeps               // injected services for common.go
	IsTokenExpiredFn func(storedAt time.Time) bool // injectable for testing; nil = kc.IsKiteTokenExpired
}

// NewToolHandler creates a new tool handler, extracting focused interfaces
// from the given manager. Individual tool files can still access h.manager
// until they are migrated.
func NewToolHandler(manager *kc.Manager) *ToolHandler {
	return &ToolHandler{
		manager: manager,
		deps: ToolHandlerDeps{
			Logger:      manager.Logger,
			TokenStore:  manager.TokenStore(),
			UserStore:   manager.UserStore(),
			Sessions:    manager,
			Credentials: manager,
			Metrics:     manager,
			Config:      manager,
			// Narrow providers — *kc.Manager satisfies every one.
			Tokens:         manager,
			CredStore:      manager,
			Alerts:         manager,
			Telegram:       manager,
			Watchlist:      manager,
			Users:          manager,
			Registry:       manager,
			Audit:          manager,
			Billing:        manager,
			Ticker:         manager,
			Paper:          manager,
			Instruments:    manager,
			AlertDB:        manager,
			RiskGuard:      manager,
			MCPServer:      manager,
			BrokerResolver: manager,
			TrailingStop:   manager,
			Events:         manager,
			CommandBusP:    manager,
			QueryBusP:      manager,
		},
	}
}

// ---------------------------------------------------------------------
// Narrow accessors on *ToolHandler — handlers reach through these
// rather than through h.manager.X(). Each accessor returns the
// relevant narrow provider's value, threading through ToolHandlerDeps
// so the underlying Manager stays behind an interface surface.
// ---------------------------------------------------------------------

// CommandBus returns the CQRS command bus. Prefer over h.manager.CommandBus().
func (h *ToolHandler) CommandBus() *cqrs.InMemoryBus {
	return h.deps.CommandBusP.CommandBus()
}

// QueryBus returns the CQRS query bus. Prefer over h.manager.QueryBus().
func (h *ToolHandler) QueryBus() *cqrs.InMemoryBus {
	return h.deps.QueryBusP.QueryBus()
}

// Logger returns the structured logger. Preferred accessor so handlers
// can log without reaching through h.manager.Logger.
func (h *ToolHandler) Logger() *slog.Logger {
	return h.deps.Logger
}

// RiskGuard returns the configured risk guard, or nil if disabled. Phase
// 3a Batch 6: prefer over h.manager.RiskGuard() so handlers depend on the
// narrow RiskGuardProvider port through ToolHandlerDeps.
func (h *ToolHandler) RiskGuard() *riskguard.Guard {
	if h.deps.RiskGuard == nil {
		return nil
	}
	return h.deps.RiskGuard.RiskGuard()
}

// AlertStore returns the per-user alert store, or nil if not configured.
// Phase 3a Batch 6: prefer over h.manager.AlertStore() so handlers depend
// on the narrow AlertStoreProvider port through ToolHandlerDeps.
func (h *ToolHandler) AlertStore() kc.AlertStoreInterface {
	if h.deps.Alerts == nil {
		return nil
	}
	return h.deps.Alerts.AlertStore()
}

// AlertDB returns the optional SQLite database used by the alerts subsystem.
// Phase 3a Batch 6: prefer over h.manager.AlertDB() so handlers depend on
// the narrow AlertDBProvider port through ToolHandlerDeps.
func (h *ToolHandler) AlertDB() *alerts.DB {
	if h.deps.AlertDB == nil {
		return nil
	}
	return h.deps.AlertDB.AlertDB()
}

// WatchlistStore returns the per-user watchlist store, or nil if not
// configured. Phase 3a Batch 6: prefer over h.manager.WatchlistStore() so
// handlers depend on the narrow WatchlistStoreProvider port through
// ToolHandlerDeps.
func (h *ToolHandler) WatchlistStore() kc.WatchlistStoreInterface {
	if h.deps.Watchlist == nil {
		return nil
	}
	return h.deps.Watchlist.WatchlistStore()
}
