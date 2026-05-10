package common

import (
	"time"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/algo2go/kite-mcp-alerts"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	logport "github.com/algo2go/kite-mcp-logger"
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
//
// LoggerPort field carries the kc/logger.Logger port for ctx-aware
// structured logging. The duplicate slog Logger field was retired
// during the SOLID 99→100 deprecation-shim sweep — all 58
// consumer call sites migrated through Wave D Packages 6b-6e
// already use LoggerPort with ctx threading. The 2 residual sites
// (handler_methods.go:profileUC constructor, handler_deps.go:Logger()
// accessor) bridge to *slog.Logger via logport.AsSlog at the seam
// where the underlying API still consumes slog directly.
type ToolHandlerDeps struct {
	LoggerPort  logport.Logger
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
	Tokens           kc.TokenStoreProvider
	CredStore        kc.CredentialStoreProvider
	Browser          kc.BrowserOpener
	Alerts           ports.AlertPort
	Telegram         kc.TelegramStoreProvider
	TelegramNotifier ports.AlertPort
	Watchlist        kc.WatchlistStoreProvider
	Users            kc.UserStoreProvider
	Registry         kc.RegistryStoreProvider
	Audit            kc.AuditStoreProvider
	Billing          kc.BillingStoreProvider
	Ticker           kc.TickerServiceProvider
	Paper            kc.PaperEngineProvider
	Instruments      ports.InstrumentPort
	AlertDB          ports.AlertPort
	RiskGuard        kc.RiskGuardProvider
	MCPServer        kc.MCPServerProvider
	BrokerResolver   kc.BrokerResolverProvider
	TrailingStop     ports.AlertPort
	Events           kc.EventDispatcherProvider
	PnL              ports.AlertPort

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
//
// Anchor 1 PR 1.1: the previously-unexported `deps` field is now
// exported as `Deps` (capital D) so cross-package callers
// (`handler.Deps.Billing.X()` style) can reach the dependency
// container without going through an accessor method that would
// otherwise return a struct copy on every call. The `manager` field
// stays unexported because cross-package consumers should reach for
// narrow Provider ports through Deps.* — direct *kc.Manager access
// is a backward-compat seam, not a long-term API.
type ToolHandler struct {
	manager          *kc.Manager                   // retained for tool-level backward compat
	Deps             ToolHandlerDeps               // injected services for handler methods
	IsTokenExpiredFn func(storedAt time.Time) bool // injectable for testing; nil = kc.IsKiteTokenExpired
}

// Manager exposes the underlying *kc.Manager for backward compat with
// tool-handler code that still reaches for the full manager surface
// during incremental migration.
func (h *ToolHandler) Manager() *kc.Manager {
	return h.manager
}

// NewToolHandler creates a new tool handler, extracting focused interfaces
// from the given manager. Individual tool files can still access h.manager
// until they are migrated.
//
// Investment K (per .research/agent-concurrency-decoupling-plan.md §K):
// the ToolHandlerDeps struct is populated by composing five per-context
// builders (session_deps.go / alert_deps.go / order_deps.go / admin_deps.go
// / read_deps.go). Adding a new field for a single bounded context now
// only touches that context's file; this constructor's body is stable.
// The unified struct itself remains so existing tool code reading
// h.Deps.X keeps compiling unchanged.
func NewToolHandler(manager *kc.Manager) *ToolHandler {
	sd := newSessionDeps(manager)
	ad := newAlertDeps(manager)
	od := newOrderDeps(manager)
	mn := newAdminDeps(manager)
	rd := newReadDeps(manager)
	return &ToolHandler{
		manager: manager,
		Deps: ToolHandlerDeps{
			// SessionDepsFields
			Sessions:    sd.Sessions,
			Credentials: sd.Credentials,
			UserStore:   sd.UserStore,
			TokenStore:  sd.TokenStore,
			Tokens:      sd.Tokens,
			CredStore:   sd.CredStore,
			Users:       sd.Users,
			Browser:     sd.Browser,
			// AlertDepsFields
			Alerts:           ad.Alerts,
			Telegram:         ad.Telegram,
			TelegramNotifier: ad.TelegramNotifier,
			AlertDB:          ad.AlertDB,
			TrailingStop:     ad.TrailingStop,
			PnL:              ad.PnL,
			// OrderDepsFields
			RiskGuard:      od.RiskGuard,
			BrokerResolver: od.BrokerResolver,
			Paper:          od.Paper,
			Events:         od.Events,
			// AdminDepsFields
			Registry:  mn.Registry,
			Audit:     mn.Audit,
			Billing:   mn.Billing,
			MCPServer: mn.MCPServer,
			// ReadDepsFields
			LoggerPort:  rd.LoggerPort,
			Metrics:     rd.Metrics,
			Config:      rd.Config,
			CommandBusP: rd.CommandBusP,
			QueryBusP:   rd.QueryBusP,
			Watchlist:   rd.Watchlist,
			Ticker:      rd.Ticker,
			Instruments: rd.Instruments,
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
	return h.Deps.CommandBusP.CommandBus()
}

// QueryBus returns the CQRS query bus. Prefer over h.manager.QueryBus().
func (h *ToolHandler) QueryBus() *cqrs.InMemoryBus {
	return h.Deps.QueryBusP.QueryBus()
}

// LoggerPort returns the kc/logger.Logger port for ctx-aware structured
// logging. The legacy Logger() *slog.Logger accessor was retired during
// the SOLID 99→100 deprecation-shim sweep — all consumer call sites
// now depend on this port. The few remaining seams that still need
// *slog.Logger directly (e.g. usecase constructors that wrap internally)
// bridge via logport.AsSlog at the call site.
func (h *ToolHandler) LoggerPort() logport.Logger {
	return h.Deps.LoggerPort
}

// RiskGuard returns the configured risk guard, or nil if disabled. Phase
// 3a Batch 6: prefer over h.manager.RiskGuard() so handlers depend on the
// narrow RiskGuardProvider port through ToolHandlerDeps.
func (h *ToolHandler) RiskGuard() *riskguard.Guard {
	if h.Deps.RiskGuard == nil {
		return nil
	}
	return h.Deps.RiskGuard.RiskGuard()
}

// AlertStore returns the per-user alert store, or nil if not configured.
// Phase 3a Batch 6: prefer over h.manager.AlertStore() so handlers depend
// on the narrow AlertStoreProvider port through ToolHandlerDeps.
func (h *ToolHandler) AlertStore() kc.AlertStoreInterface {
	if h.Deps.Alerts == nil {
		return nil
	}
	return h.Deps.Alerts.AlertStore()
}

// AlertDB returns the optional SQLite database used by the alerts subsystem.
// Phase 3a Batch 6: prefer over h.manager.AlertDB() so handlers depend on
// the narrow AlertDBProvider port through ToolHandlerDeps.
func (h *ToolHandler) AlertDB() *alerts.DB {
	if h.Deps.AlertDB == nil {
		return nil
	}
	return h.Deps.AlertDB.AlertDB()
}

// WatchlistStore returns the per-user watchlist store, or nil if not
// configured. Phase 3a Batch 6: prefer over h.manager.WatchlistStore() so
// handlers depend on the narrow WatchlistStoreProvider port through
// ToolHandlerDeps.
func (h *ToolHandler) WatchlistStore() kc.WatchlistStoreInterface {
	if h.Deps.Watchlist == nil {
		return nil
	}
	return h.Deps.Watchlist.WatchlistStore()
}

// Instruments returns the instruments manager port. Phase 3a Batch 1
// (read-only consumers): prefer over h.manager.Instruments field access so
// handlers depend on the narrow InstrumentsManagerProvider port through
// ToolHandlerDeps. Returns nil only when InstrumentsManagerProvider was
// not configured (test scaffolding); production callers should treat nil
// as "instruments not yet loaded" and degrade accordingly.
func (h *ToolHandler) Instruments() kc.InstrumentManagerInterface {
	if h.Deps.Instruments == nil {
		return nil
	}
	return h.Deps.Instruments.InstrumentsManager()
}

// AuditStore returns the audit-trail store. Phase 3a Batch 1 (admin
// read-only consumers): prefer over h.manager.AuditStoreConcrete() so
// admin tools that only need methods on the AuditStoreInterface
// (GetTopErrorUsers, List, GetGlobalStats, etc.) depend on the narrow
// AuditStoreProvider port through ToolHandlerDeps. Returns nil if the
// audit subsystem is disabled.
//
// Tools that need concrete-only methods (UserOrderStats,
// StatsCacheHitRate) must continue to reach for h.manager.AuditStoreConcrete()
// — those forensics methods are intentionally NOT on the interface
// surface. See admin_baseline_tool.go and admin_cache_info_tool.go for
// the documented exceptions.
func (h *ToolHandler) AuditStore() kc.AuditStoreInterface {
	if h.Deps.Audit == nil {
		return nil
	}
	return h.Deps.Audit.AuditStore()
}
