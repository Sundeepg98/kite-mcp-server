package mcp

import (
	"log/slog"
	"time"

	"github.com/zerodha/kite-mcp-server/kc"
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
	Sessions    kc.SessionProvider
	Credentials kc.CredentialResolver
	Metrics     kc.MetricsRecorder
	Config      kc.AppConfigProvider

	// Narrow store-provider interfaces (ISP). Each is a one-method accessor
	// onto the underlying store; consumers invoke e.g. `Tokens.TokenStore()`
	// at the point of use. Providers are preferred over raw store interfaces
	// because they can return nil when a subsystem is disabled without the
	// caller needing to know the disable semantics up front.
	Tokens      kc.TokenStoreProvider
	CredStore   kc.CredentialStoreProvider
	Alerts      kc.AlertStoreProvider
	Telegram    kc.TelegramStoreProvider
	Watchlist   kc.WatchlistStoreProvider
	Users       kc.UserStoreProvider
	Registry    kc.RegistryStoreProvider
	Audit       kc.AuditStoreProvider
	Billing     kc.BillingStoreProvider
	Ticker      kc.TickerServiceProvider
	Paper       kc.PaperEngineProvider
	Instruments kc.InstrumentsManagerProvider
	AlertDB     kc.AlertDBProvider
	RiskGuard   kc.RiskGuardProvider
	MCPServer   kc.MCPServerProvider
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
			Tokens:      manager,
			CredStore:   manager,
			Alerts:      manager,
			Telegram:    manager,
			Watchlist:   manager,
			Users:       manager,
			Registry:    manager,
			Audit:       manager,
			Billing:     manager,
			Ticker:      manager,
			Paper:       manager,
			Instruments: manager,
			AlertDB:     manager,
			RiskGuard:   manager,
			MCPServer:   manager,
		},
	}
}
