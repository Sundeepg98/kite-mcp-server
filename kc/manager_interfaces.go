package kc

import (
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
)

// ---------------------------------------------------------------------------
// Focused Manager interfaces — Interface Segregation Principle
// ---------------------------------------------------------------------------
// These interfaces decompose the monolithic Manager into focused contracts,
// enabling consumers to depend only on the capabilities they need.

// SessionProvider retrieves and manages MCP sessions with associated Kite data.
type SessionProvider interface {
	// GetOrCreateSession retrieves an existing Kite session or creates a new one.
	GetOrCreateSession(mcpSessionID string) (*KiteSessionData, bool, error)

	// GetOrCreateSessionWithEmail retrieves or creates a session with email context.
	GetOrCreateSessionWithEmail(mcpSessionID, email string) (*KiteSessionData, bool, error)

	// GetSession retrieves an existing Kite session by MCP session ID.
	GetSession(mcpSessionID string) (*KiteSessionData, error)

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

// CredentialResolver resolves per-user or global API credentials and tokens.
type CredentialResolver interface {
	// GetAPIKeyForEmail returns the API key: per-user if registered, otherwise global.
	GetAPIKeyForEmail(email string) string

	// GetAPISecretForEmail returns the API secret: per-user if registered, otherwise global.
	GetAPISecretForEmail(email string) string

	// GetAccessTokenForEmail returns the cached access token for a given email.
	GetAccessTokenForEmail(email string) string

	// HasPreAuth returns true if the manager has a pre-set access token.
	HasPreAuth() bool

	// HasCachedToken returns true if there's a cached Kite token for the email.
	HasCachedToken(email string) bool

	// HasUserCredentials returns true if per-user credentials exist.
	HasUserCredentials(email string) bool

	// HasGlobalCredentials returns true if global API key/secret are configured.
	HasGlobalCredentials() bool

	// IsTokenValid returns true if the user has a valid (non-expired) cached token.
	IsTokenValid(email string) bool
}

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

// AlertStoreProvider exposes the per-user alert store (alert CRUD).
type AlertStoreProvider interface {
	AlertStore() AlertStoreInterface
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

// InstrumentsManagerProvider exposes the instruments manager.
type InstrumentsManagerProvider interface {
	InstrumentsManager() InstrumentManagerInterface
}

// AlertDBProvider exposes the optional SQLite database used by the alerts subsystem.
type AlertDBProvider interface {
	AlertDB() *alerts.DB
}

// RiskGuardProvider exposes the risk guard. Returns nil if disabled.
type RiskGuardProvider interface {
	RiskGuard() *riskguard.Guard
}

// TelegramNotifierProvider exposes the Telegram notifier. Returns nil if unconfigured.
type TelegramNotifierProvider interface {
	TelegramNotifier() *alerts.TelegramNotifier
}

// TrailingStopManagerProvider exposes the trailing stop manager.
type TrailingStopManagerProvider interface {
	TrailingStopManager() *alerts.TrailingStopManager
}

// PnLServiceProvider exposes the P&L snapshot service.
type PnLServiceProvider interface {
	PnLService() *alerts.PnLSnapshotService
}

// MCPServerProvider exposes the stored MCP server reference. Returns nil before
// the server has been attached.
type MCPServerProvider interface {
	MCPServer() any
}

// BrokerResolverProvider exposes the session service used by use cases to
// resolve a broker.Client for a given email. Consumers depend on the narrow
// *SessionService type because it already implements the usecases.BrokerResolver
// interface — passing this into NewXxxUseCase(...) constructors replaces the
// service-locator pattern of calling manager.SessionSvc() inline.
type BrokerResolverProvider interface {
	SessionSvc() *SessionService
}

// StoreAccessor is the aggregate composition of every Manager-implemented
// store-provider interface, retained for consumers that legitimately need
// broad access (e.g. the Manager itself, admin tooling, and registration
// code). New code should depend on the narrowest provider(s) it needs
// instead.
//
// Note: TelegramNotifierProvider, TrailingStopManagerProvider, and
// PnLServiceProvider are intentionally excluded — those three accessors live
// on AlertService (obtain them via m.AlertSvc().TelegramNotifier() etc.) and
// are not exposed on Manager itself after the Round 3 decomposition.
type StoreAccessor interface {
	TokenStoreProvider
	CredentialStoreProvider
	AlertStoreProvider
	TelegramStoreProvider
	WatchlistStoreProvider
	UserStoreProvider
	RegistryStoreProvider
	AuditStoreProvider
	BillingStoreProvider
	TickerServiceProvider
	PaperEngineProvider
	InstrumentsManagerProvider
	AlertDBProvider
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

// ---------------------------------------------------------------------------
// Compile-time interface satisfaction checks
// ---------------------------------------------------------------------------

var (
	_ SessionProvider    = (*Manager)(nil)
	_ CredentialResolver = (*CredentialService)(nil) // Round 3: delegated to CredentialService; obtain via m.CredentialSvc()
	_ StoreAccessor      = (*Manager)(nil)
	_ AppConfigProvider  = (*Manager)(nil)
	_ MetricsRecorder    = (*Manager)(nil)
	_ ManagerLifecycle   = (*Manager)(nil)

	// Narrow provider assertions — each Provider is a real production dependency
	// in mcp.ToolHandlerDeps. Keeping them here prevents accidental removal if
	// consumers are refactored.
	_ TokenStoreProvider         = (*Manager)(nil)
	_ CredentialStoreProvider    = (*Manager)(nil)
	_ AlertStoreProvider         = (*Manager)(nil)
	_ TelegramStoreProvider      = (*Manager)(nil)
	_ WatchlistStoreProvider     = (*Manager)(nil)
	_ UserStoreProvider          = (*Manager)(nil)
	_ RegistryStoreProvider      = (*Manager)(nil)
	_ AuditStoreProvider         = (*Manager)(nil)
	_ BillingStoreProvider       = (*Manager)(nil)
	_ TickerServiceProvider      = (*Manager)(nil)
	_ PaperEngineProvider        = (*Manager)(nil)
	_ InstrumentsManagerProvider = (*Manager)(nil)
	_ AlertDBProvider            = (*Manager)(nil)
	_ RiskGuardProvider          = (*Manager)(nil)
	_ MCPServerProvider          = (*Manager)(nil)

	// Round 4 narrow providers — used by mcp.ToolHandlerDeps to replace
	// remaining service-locator calls (manager.SessionSvc(), manager.TrailingStopManager()).
	_ BrokerResolverProvider     = (*Manager)(nil)
	_ TrailingStopManagerProvider = (*Manager)(nil)
)
