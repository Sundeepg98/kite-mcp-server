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

// StoreAccessor provides access to all data stores managed by the Manager.
// Returns interface types to decouple consumers from concrete implementations
// (Dependency Inversion Principle). Consumers should prefer the focused
// interfaces (e.g., AlertStoreInterface) when they only need specific capabilities.
type StoreAccessor interface {
	// TokenStore returns the per-email token store.
	TokenStore() TokenStoreInterface

	// CredentialStore returns the per-email Kite credential store.
	CredentialStore() CredentialStoreInterface

	// AlertStore returns the per-user alert store (alert CRUD).
	AlertStore() AlertStoreInterface

	// TelegramStore returns the per-user Telegram chat ID store.
	TelegramStore() TelegramStoreInterface

	// WatchlistStore returns the per-user watchlist store.
	WatchlistStore() WatchlistStoreInterface

	// UserStore returns the user identity store.
	UserStore() UserStoreInterface

	// RegistryStore returns the key registry store.
	RegistryStore() RegistryStoreInterface

	// AuditStore returns the audit trail store, or nil.
	AuditStore() AuditStoreInterface

	// BillingStore returns the billing store, or nil.
	BillingStore() BillingStoreInterface

	// TickerService returns the per-user WebSocket ticker service.
	TickerService() TickerServiceInterface

	// PaperEngine returns the paper trading engine, or nil.
	PaperEngine() PaperEngineInterface

	// InstrumentsManager returns the instruments manager.
	InstrumentsManager() InstrumentManagerInterface

	// AlertDB returns the optional SQLite database.
	AlertDB() *alerts.DB

	// RiskGuard returns the riskguard instance, or nil.
	RiskGuard() *riskguard.Guard

	// TelegramNotifier returns the Telegram notifier (nil if not configured).
	TelegramNotifier() *alerts.TelegramNotifier

	// TrailingStopManager returns the trailing stop manager.
	TrailingStopManager() *alerts.TrailingStopManager

	// PnLService returns the P&L snapshot service.
	PnLService() *alerts.PnLSnapshotService

	// MCPServer returns the stored MCP server reference, or nil.
	MCPServer() any
}

// AppConfigProvider provides application-level configuration.
type AppConfigProvider interface {
	// IsLocalMode returns true when running in STDIO mode.
	IsLocalMode() bool

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
	_ SessionProvider   = (*Manager)(nil)
	_ CredentialResolver = (*Manager)(nil)
	_ StoreAccessor     = (*Manager)(nil)
	_ AppConfigProvider = (*Manager)(nil)
	_ MetricsRecorder   = (*Manager)(nil)
	_ ManagerLifecycle  = (*Manager)(nil)
)
