package kc

import (
	"github.com/algo2go/kite-mcp-broker"
	"github.com/algo2go/kite-mcp-alerts"
	"github.com/algo2go/kite-mcp-cqrs"
	"github.com/algo2go/kite-mcp-domain"
	"github.com/algo2go/kite-mcp-riskguard"
)

// ---------------------------------------------------------------------------
// Focused Manager interfaces — Interface Segregation Principle
// ---------------------------------------------------------------------------
// These interfaces decompose the monolithic Manager into focused contracts,
// enabling consumers to depend only on the capabilities they need.

// ---------------------------------------------------------------------------
// Focused store-provider interfaces (ISP)
// ---------------------------------------------------------------------------
// Each provider exposes access to exactly one store type. Consumers should
// depend on the narrowest provider they need rather than the aggregate
// StoreAccessor, so their dependencies remain explicit and tests can supply
// minimal fakes.

// TokenStoreProvider exposes the per-email Kite token store.
type TokenStoreProvider interface {
	TokenStore() TokenStoreInterface
}

// CredentialStoreProvider exposes the per-email Kite credential store.
type CredentialStoreProvider interface {
	CredentialStore() CredentialStoreInterface
}


// TelegramStoreProvider exposes the per-user Telegram chat ID store.
type TelegramStoreProvider interface {
	TelegramStore() TelegramStoreInterface
}

// WatchlistStoreProvider exposes the per-user watchlist store.
type WatchlistStoreProvider interface {
	WatchlistStore() WatchlistStoreInterface
}

// UserStoreProvider exposes the user identity store.
type UserStoreProvider interface {
	UserStore() UserStoreInterface
}

// RegistryStoreProvider exposes the key registry store.
type RegistryStoreProvider interface {
	RegistryStore() RegistryStoreInterface
}

// AuditStoreProvider exposes the audit trail store. Returns nil if disabled.
type AuditStoreProvider interface {
	AuditStore() AuditStoreInterface
}

// BillingStoreProvider exposes the billing store. Returns nil if disabled.
type BillingStoreProvider interface {
	BillingStore() BillingStoreInterface
}

// TickerServiceProvider exposes the per-user WebSocket ticker service.
type TickerServiceProvider interface {
	TickerService() TickerServiceInterface
}

// PaperEngineProvider exposes the paper trading engine. Returns nil if disabled.
type PaperEngineProvider interface {
	PaperEngine() PaperEngineInterface
}

// RiskGuardProvider exposes the risk guard. Returns nil if disabled.
type RiskGuardProvider interface {
	RiskGuard() *riskguard.Guard
}

// EventDispatcherProvider exposes the domain event dispatcher. Returns nil
// when event-sourcing is disabled (no AlertDB / no event store wiring).
// Authored to unblock Phase 3a Batch 5 — ext_apps.go + admin_risk_tools.go
// reach manager.EventDispatcher() directly; this provider lets them go
// through ToolHandlerDeps.Events instead.
type EventDispatcherProvider interface {
	EventDispatcher() *domain.EventDispatcher
}

// MCPServerProvider exposes the stored MCP server reference. Returns nil before
// the server has been attached.
type MCPServerProvider interface {
	MCPServer() any
}

// BrokerResolverProvider exposes the broker-resolution surface that
// use cases and HTTP handlers need without forcing callers to reach
// for the full *SessionService. Anchor 6 PR 6.4 (per .research/anchor-
// 6-pr-6-4-broker-resolver-redesign.md commit a2a11db) narrowed the
// interface from a single SessionSvc() *SessionService method to the
// two methods consumers actually use:
//
//   - GetBrokerForEmail (4 callsites: mcp/ext_apps.go,
//     kc/manager_commands_admin.go, app/wire.go via the
//     FillWatcherResolverFromBroker constructor, plus in-package
//     CQRS use-case constructors via this interface)
//   - HasBrokerFactory  (1 callsite: app/http.go's auth-gate guard)
//
// The narrower interface is satisfied by both *kc.SessionService
// (its existing methods) AND *kc.Manager (via the passthrough
// methods declared in kc/manager_accessors.go below). This dual-
// satisfaction lets PR 6.4 delete the Manager.SessionSvc() accessor
// while preserving the use-case-level BrokerResolver contract that
// kc/usecases/ports.go declares (one-method narrower port).
type BrokerResolverProvider interface {
	GetBrokerForEmail(email string) (broker.Client, error)
	HasBrokerFactory() bool
}

// StoreAccessor is the aggregate composition of every Manager-implemented
// store-provider interface, retained for consumers that legitimately need
// broad access (e.g. the Manager itself, admin tooling, and registration
// code). New code should depend on the narrowest port (kc/ports) or
// provider it needs instead of the aggregate.
//
// Note: TelegramNotifier, TrailingStopManager, and PnLService are
// intentionally excluded — those three accessors live on AlertService
// (obtain them via m.AlertSvc().TelegramNotifier() etc.) and are not
// exposed on Manager itself after the Round 3 decomposition. Consumers
// that need them depend on ports.AlertPort directly (which mirrors
// AlertService's surface), not on StoreAccessor.
type StoreAccessor interface {
	TokenStoreProvider
	CredentialStoreProvider
	TelegramStoreProvider
	WatchlistStoreProvider
	UserStoreProvider
	RegistryStoreProvider
	AuditStoreProvider
	BillingStoreProvider
	TickerServiceProvider
	PaperEngineProvider

	// AlertStore() + AlertDB() + InstrumentsManager() inlined here
	// (Phase B/D F1 close): the previous AlertStoreProvider /
	// AlertDBProvider / InstrumentsManagerProvider single-method
	// aliases were deleted in favor of ports.AlertPort + ports.
	// InstrumentPort at consumer sites. StoreAccessor lives in package
	// kc and cannot embed kc/ports types without creating a cycle
	// (kc/ports already imports kc), so each accessor is inlined here
	// directly. *kc.Manager satisfies the corresponding ports via its
	// existing method implementations — see kc/ports/alert.go:25,
	// kc/ports/instrument.go:32, and kc/ports/assertions.go.
	AlertStore() AlertStoreInterface
	AlertDB() *alerts.DB
	InstrumentsManager() InstrumentManagerInterface

	RiskGuardProvider
	MCPServerProvider
}

// AppConfigProvider provides application-level configuration.
type AppConfigProvider interface {
	// IsLocalMode returns true when running in STDIO mode.
	IsLocalMode() bool

	// DevMode returns true when the server runs with a mock broker.
	DevMode() bool

	// ExternalURL returns the configured external URL.
	ExternalURL() string

	// AdminSecretPath returns the configured admin secret path.
	AdminSecretPath() string

	// APIKey returns the global Kite API key.
	APIKey() string
}

// MetricsRecorder records operational metrics.
type MetricsRecorder interface {
	// HasMetrics returns true if metrics manager is available.
	HasMetrics() bool

	// IncrementMetric increments a metric counter by 1.
	IncrementMetric(key string)

	// TrackDailyUser records a unique user interaction.
	TrackDailyUser(userID string)

	// IncrementDailyMetric increments a daily metric counter.
	IncrementDailyMetric(key string)
}

// CommandBusProvider exposes the CQRS command bus for write dispatches.
// Handlers depend on this narrow port rather than pulling the full
// *Manager to reach CommandBus() — closes the last composition-root leak
// for write-side bus consumers.
type CommandBusProvider interface {
	CommandBus() *cqrs.InMemoryBus
}

// QueryBusProvider exposes the CQRS query bus for read dispatches.
// Paired with CommandBusProvider; most tool handlers will depend on
// both because the same closure often issues a command then a confirming
// query.
type QueryBusProvider interface {
	QueryBus() *cqrs.InMemoryBus
}

// ManagerLifecycle manages the lifecycle of the Manager and its sub-components.
type ManagerLifecycle interface {
	// Shutdown gracefully shuts down the manager and all its components.
	Shutdown()

	// OpenBrowser opens a URL in the user's default browser (local mode only).
	OpenBrowser(rawURL string) error

	// CleanupExpiredSessions manually triggers cleanup of expired sessions.
	CleanupExpiredSessions() int

	// StopCleanupRoutine stops the background cleanup routine.
	StopCleanupRoutine()
}

// BrowserOpener exposes the local-mode browser-open helper. Phase 3a
// Batch 2 narrow port for setup_tools.go (auto-open Kite login URL +
// dashboard URL on local STDIO runs). Hosted Fly.io callers depend on
// this being a no-op or returning an error — production safety.
type BrowserOpener interface {
	OpenBrowser(rawURL string) error
}

// ---------------------------------------------------------------------------
// Compile-time interface satisfaction checks
// ---------------------------------------------------------------------------

var (
	_ StoreAccessor = (*Manager)(nil)
	_ AppConfigProvider  = (*Manager)(nil)
	_ MetricsRecorder    = (*Manager)(nil)
	_ ManagerLifecycle   = (*Manager)(nil)

	// Narrow provider assertions — each Provider is a real production dependency
	// in mcp.ToolHandlerDeps. Keeping them here prevents accidental removal if
	// consumers are refactored.
	_ TokenStoreProvider         = (*Manager)(nil)
	_ CredentialStoreProvider    = (*Manager)(nil)
	_ TelegramStoreProvider      = (*Manager)(nil)
	_ WatchlistStoreProvider     = (*Manager)(nil)
	_ UserStoreProvider          = (*Manager)(nil)
	_ RegistryStoreProvider      = (*Manager)(nil)
	_ AuditStoreProvider         = (*Manager)(nil)
	_ BillingStoreProvider       = (*Manager)(nil)
	_ TickerServiceProvider      = (*Manager)(nil)
	_ PaperEngineProvider        = (*Manager)(nil)
	_ RiskGuardProvider          = (*Manager)(nil)
	_ MCPServerProvider          = (*Manager)(nil)

	// Round 4 narrow providers — used by mcp.ToolHandlerDeps to replace
	// remaining service-locator calls (manager.SessionSvc()).
	_ BrokerResolverProvider     = (*Manager)(nil)

	// Phase 3a Batch 2 narrow ports.
	_ BrowserOpener = (*Manager)(nil)
)
