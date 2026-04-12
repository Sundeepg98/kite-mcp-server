// Package kc provides store interfaces for hexagonal architecture.
//
// Each interface defines the contract that other packages depend on, allowing
// concrete implementations to be swapped (e.g., in-memory vs. SQLite vs. mock).
// Compile-time verification ensures the concrete types satisfy these interfaces.
package kc

import (
	"time"

	kiteticker "github.com/zerodha/gokiteconnect/v4/ticker"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
	"github.com/zerodha/kite-mcp-server/kc/registry"
	"github.com/zerodha/kite-mcp-server/kc/ticker"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/kc/watchlist"
)

// ---------------------------------------------------------------------------
// AlertStoreInterface — price alert management (SRP: alerts only)
// ---------------------------------------------------------------------------

// AlertStoreInterface defines operations for managing per-user price alerts.
// Telegram chat ID operations are separated into TelegramStoreInterface.
type AlertStoreInterface interface {
	// Add creates a new alert and returns its ID.
	Add(email, tradingsymbol, exchange string, instrumentToken uint32, targetPrice float64, direction alerts.Direction) (string, error)

	// AddWithReferencePrice creates a new alert with an optional reference price.
	AddWithReferencePrice(email, tradingsymbol, exchange string, instrumentToken uint32, targetPrice float64, direction alerts.Direction, referencePrice float64) (string, error)

	// Delete removes an alert by ID for the given email.
	Delete(email, alertID string) error

	// DeleteByEmail removes all alerts for the given email.
	DeleteByEmail(email string)

	// List returns all alerts for the given email.
	List(email string) []*alerts.Alert

	// GetByToken returns all active (non-triggered) alerts matching the instrument token.
	GetByToken(instrumentToken uint32) []*alerts.Alert

	// MarkTriggered marks an alert as triggered with the current price.
	MarkTriggered(alertID string, currentPrice float64) bool

	// MarkNotificationSent records when a Telegram notification was sent.
	MarkNotificationSent(alertID string, sentAt time.Time)

	// ListAll returns all alerts grouped by email.
	ListAll() map[string][]*alerts.Alert

	// ActiveCount returns the number of active alerts for a user.
	ActiveCount(email string) int
}

// ---------------------------------------------------------------------------
// TelegramStoreInterface — Telegram chat ID mappings (SRP: telegram only)
// ---------------------------------------------------------------------------

// TelegramStoreInterface defines operations for managing per-user Telegram
// chat ID mappings. Separated from AlertStoreInterface per Single Responsibility.
type TelegramStoreInterface interface {
	// SetTelegramChatID sets the Telegram chat ID for a user.
	SetTelegramChatID(email string, chatID int64)

	// GetTelegramChatID returns the Telegram chat ID for a user.
	GetTelegramChatID(email string) (int64, bool)

	// GetEmailByChatID performs a reverse lookup from chat ID to email.
	GetEmailByChatID(chatID int64) (string, bool)

	// ListAllTelegram returns all Telegram chat ID mappings.
	ListAllTelegram() map[string]int64
}

// ---------------------------------------------------------------------------
// AuditStoreInterface — tool call audit trail
// ---------------------------------------------------------------------------
// Split into focused sub-interfaces per Interface Segregation Principle.
// Consumers should depend on the narrowest interface they need.

// AuditWriter provides write operations for audit records.
type AuditWriter interface {
	// Enqueue adds a tool call to the async write buffer.
	Enqueue(entry *audit.ToolCall)

	// Record inserts a tool call synchronously.
	Record(entry *audit.ToolCall) error

	// DeleteOlderThan removes tool_calls older than the given time.
	DeleteOlderThan(before time.Time) (int64, error)
}

// AuditReader provides read and query operations for audit records.
type AuditReader interface {
	// List retrieves tool call records for a given email with filtering/pagination.
	List(email string, opts audit.ListOptions) ([]*audit.ToolCall, int, error)

	// ListOrders returns tool calls with order IDs for the given email.
	ListOrders(email string, since time.Time) ([]*audit.ToolCall, error)

	// GetOrderAttribution returns the decision trace for a given order.
	GetOrderAttribution(email, orderID string) ([]*audit.ToolCall, error)

	// GetStats returns aggregate stats for a given email since the given time.
	// Optional category and errorsOnly filters scope the results.
	GetStats(email string, since time.Time, category string, errorsOnly bool) (*audit.Stats, error)

	// GetToolCounts returns tool_name -> count for the given email.
	// Optional category and errorsOnly filters scope the results.
	GetToolCounts(email string, since time.Time, category string, errorsOnly bool) (map[string]int, error)

	// GetToolMetrics returns per-tool aggregate metrics since the given time.
	GetToolMetrics(since time.Time) ([]audit.ToolMetric, error)

	// GetGlobalStats returns aggregate stats across all users.
	GetGlobalStats(since time.Time) (*audit.Stats, error)

	// GetTopErrorUsers returns the top N users with the most errors since the given time.
	GetTopErrorUsers(since time.Time, limit int) ([]audit.UserErrorCount, error)

	// VerifyChain walks the hash chain and checks integrity.
	VerifyChain() (*audit.ChainVerification, error)
}

// AuditStreamer provides real-time activity streaming via listeners.
type AuditStreamer interface {
	// AddActivityListener registers a listener for real-time activity streaming.
	AddActivityListener(id string) chan *audit.ToolCall

	// RemoveActivityListener unregisters and closes a listener.
	RemoveActivityListener(id string)
}

// AuditStoreInterface defines operations for recording and querying MCP tool
// call audit records. Composed from focused sub-interfaces.
type AuditStoreInterface interface {
	AuditWriter
	AuditReader
	AuditStreamer
}

// ---------------------------------------------------------------------------
// BillingStoreInterface — subscription and tier management
// ---------------------------------------------------------------------------

// BillingStoreInterface defines operations for managing user billing subscriptions
// and tier enforcement.
type BillingStoreInterface interface {
	// GetTier returns the current billing tier for an email.
	GetTier(email string) billing.Tier

	// SetSubscription creates or updates a subscription.
	SetSubscription(sub *billing.Subscription) error

	// GetSubscription returns the subscription for an email, or nil.
	GetSubscription(email string) *billing.Subscription

	// GetEmailByCustomerID returns the email for a Stripe customer ID.
	GetEmailByCustomerID(customerID string) string

	// IsEventProcessed returns true if a webhook event has been handled.
	IsEventProcessed(eventID string) bool

	// MarkEventProcessed records that an event has been processed.
	MarkEventProcessed(eventID, eventType string) error

	// GetTierForUser returns the tier checking both direct subscription and admin linkage.
	GetTierForUser(email string, adminEmailFn func(string) string) billing.Tier
}

// ---------------------------------------------------------------------------
// UserStoreInterface — user identity, RBAC, lifecycle
// ---------------------------------------------------------------------------
// Split into focused sub-interfaces per Interface Segregation Principle.
// Consumers should depend on the narrowest interface they need.

// UserReader provides read-only access to user data.
type UserReader interface {
	// Get retrieves a user by email.
	Get(email string) (*users.User, bool)

	// GetByEmail is an alias for Get.
	GetByEmail(email string) (*users.User, bool)

	// Exists returns true if a user with the given email exists.
	Exists(email string) bool

	// GetStatus returns the user's status (empty if not found).
	GetStatus(email string) string

	// GetRole returns the user's role (empty if not found).
	GetRole(email string) string

	// List returns all users as a slice.
	List() []*users.User

	// Count returns the number of registered users.
	Count() int

	// ListByAdminEmail returns all users linked to this admin.
	ListByAdminEmail(adminEmail string) []*users.User

	// EnsureUser creates a user if they don't exist, returning the user.
	EnsureUser(email, kiteUID, displayName, onboardedBy string) *users.User

	// EnsureAdmin creates or upgrades a user to admin role.
	EnsureAdmin(email string)
}

// UserWriter provides write operations on user data.
type UserWriter interface {
	// Create inserts a new user. Returns error if user already exists.
	Create(u *users.User) error

	// Delete removes a user from the store.
	Delete(email string)

	// UpdateLastLogin records the current time as the user's last login.
	UpdateLastLogin(email string)

	// UpdateRole changes the user's role.
	UpdateRole(email, role string) error

	// UpdateStatus changes the user's status.
	UpdateStatus(email, status string) error

	// UpdateKiteUID sets the Kite user ID for a user.
	UpdateKiteUID(email, kiteUID string)

	// SetAdminEmail links a user to their admin for family billing.
	SetAdminEmail(email, adminEmail string) error

	// SetPasswordHash stores a bcrypt password hash for the given user.
	SetPasswordHash(email, hash string) error
}

// UserAuthChecker provides authentication and authorization checks.
type UserAuthChecker interface {
	// IsAdmin returns true if the email belongs to an active admin.
	IsAdmin(email string) bool

	// HasPassword returns true if the user has a non-empty password hash.
	HasPassword(email string) bool

	// VerifyPassword checks plaintext password against stored hash.
	VerifyPassword(email, password string) (bool, error)
}

// UserStoreInterface defines operations for user registration, authentication,
// and role-based access control. Composed from focused sub-interfaces.
type UserStoreInterface interface {
	UserReader
	UserWriter
	UserAuthChecker
}

// ---------------------------------------------------------------------------
// RegistryStoreInterface — pre-registered Kite app credentials
// ---------------------------------------------------------------------------
// Split into focused sub-interfaces per Interface Segregation Principle.
// Consumers should depend on the narrowest interface they need.

// RegistryReader provides read-only access to registry data.
type RegistryReader interface {
	// Get retrieves a registration by ID.
	Get(id string) (*registry.AppRegistration, bool)

	// GetByAPIKey finds an active registration by API key.
	GetByAPIKey(apiKey string) (*registry.AppRegistration, bool)

	// GetByAPIKeyAnyStatus finds a registration by API key regardless of status.
	GetByAPIKeyAnyStatus(apiKey string) (*registry.AppRegistration, bool)

	// GetByEmail finds the most recently updated active registration for an email.
	GetByEmail(email string) (*registry.AppRegistration, bool)

	// List returns a redacted summary of all registered apps.
	List() []registry.AppRegistrationSummary

	// Count returns the number of registry entries.
	Count() int

	// HasEntries returns true if the registry has any entries.
	HasEntries() bool
}

// RegistryWriter provides write operations on registry data.
type RegistryWriter interface {
	// Register adds a new app registration.
	Register(reg *registry.AppRegistration) error

	// Update modifies a registration's mutable fields.
	Update(id string, assignedTo, label, status string) error

	// UpdateLastUsedAt records the most recent token exchange for an API key.
	UpdateLastUsedAt(apiKey string)

	// MarkStatus sets the status of a registration found by API key.
	MarkStatus(apiKey, status string)

	// Delete removes a registration by ID.
	Delete(id string) error
}

// RegistryStoreInterface defines operations for the Kite app key registry,
// used for zero-config onboarding where admins pre-register API credentials.
// Composed from focused sub-interfaces.
type RegistryStoreInterface interface {
	RegistryReader
	RegistryWriter
}

// ---------------------------------------------------------------------------
// CredentialStoreInterface — per-user Kite developer app credentials
// ---------------------------------------------------------------------------

// CredentialStoreInterface defines operations for storing per-user Kite
// developer app credentials (API key + secret).
type CredentialStoreInterface interface {
	// Get retrieves stored credentials for the given email.
	Get(email string) (*KiteCredentialEntry, bool)

	// Set stores credentials for the given email.
	Set(email string, entry *KiteCredentialEntry)

	// Delete removes credentials for the given email.
	Delete(email string)

	// ListAll returns a redacted summary of all stored credentials.
	ListAll() []KiteCredentialSummary

	// ListAllRaw returns all credentials unredacted (for internal operations).
	ListAllRaw() []RawCredentialEntry

	// GetSecretByAPIKey finds the API secret for a given API key.
	GetSecretByAPIKey(apiKey string) (apiSecret string, ok bool)

	// Count returns the number of stored credential entries.
	Count() int
}

// ---------------------------------------------------------------------------
// TokenStoreInterface — per-user Kite access token cache
// ---------------------------------------------------------------------------

// TokenStoreInterface defines operations for caching per-user Kite access
// tokens so users only need to login once per day.
type TokenStoreInterface interface {
	// Get retrieves a stored token for the given email.
	Get(email string) (*KiteTokenEntry, bool)

	// Set stores a token for the given email and notifies observers.
	Set(email string, entry *KiteTokenEntry)

	// Delete removes a token for the given email.
	Delete(email string)

	// OnChange registers a callback that fires when a token is stored or updated.
	OnChange(cb TokenChangeCallback)

	// ListAll returns a redacted summary of all cached tokens.
	ListAll() []KiteTokenSummary

	// Count returns the number of stored tokens.
	Count() int
}

// ---------------------------------------------------------------------------
// WatchlistStoreInterface — per-user watchlist management
// ---------------------------------------------------------------------------

// WatchlistStoreInterface defines operations for managing named instrument
// watchlists per user.
type WatchlistStoreInterface interface {
	// CreateWatchlist creates a new named watchlist for the user.
	CreateWatchlist(email, name string) (string, error)

	// DeleteWatchlist removes a watchlist and all its items.
	DeleteWatchlist(email, watchlistID string) error

	// DeleteByEmail removes all watchlists for the given email.
	DeleteByEmail(email string)

	// ListWatchlists returns all watchlists for the given email.
	ListWatchlists(email string) []*watchlist.Watchlist

	// ItemCount returns the number of items in a watchlist.
	ItemCount(watchlistID string) int

	// AddItem adds an instrument to a watchlist.
	AddItem(email, watchlistID string, item *watchlist.WatchlistItem) error

	// RemoveItem removes an instrument from a watchlist by item ID.
	RemoveItem(email, watchlistID, itemID string) error

	// GetItems returns copies of all items in a watchlist.
	GetItems(watchlistID string) []*watchlist.WatchlistItem

	// GetAllItems returns all items across all watchlists for a user.
	GetAllItems(email string) []*watchlist.WatchlistItem

	// FindWatchlistByName returns the watchlist with the given name for the user.
	FindWatchlistByName(email, name string) *watchlist.Watchlist

	// FindItemBySymbol finds an item by exchange:tradingsymbol in a watchlist.
	FindItemBySymbol(watchlistID, exchange, tradingsymbol string) *watchlist.WatchlistItem
}

// ---------------------------------------------------------------------------
// TickerServiceInterface — per-user WebSocket ticker connections
// ---------------------------------------------------------------------------

// TickerServiceInterface defines operations for managing per-user WebSocket
// ticker connections for real-time market data.
type TickerServiceInterface interface {
	// Start creates and starts a WebSocket ticker for the given user.
	Start(email, apiKey, accessToken string) error

	// Stop stops the ticker for the given user.
	Stop(email string) error

	// UpdateToken stops and restarts a ticker with a fresh token.
	UpdateToken(email, apiKey, accessToken string) error

	// Subscribe subscribes the user's ticker to instrument tokens.
	Subscribe(email string, tokens []uint32, mode kiteticker.Mode) error

	// Unsubscribe removes instrument tokens from the user's ticker.
	Unsubscribe(email string, tokens []uint32) error

	// GetStatus returns the current status of a user's ticker.
	GetStatus(email string) (*ticker.Status, error)

	// IsRunning returns true if a ticker is active for the given email.
	IsRunning(email string) bool

	// ListAll returns a summary of all active ticker connections.
	ListAll() []ticker.UserTickerInfo

	// Shutdown stops all running tickers.
	Shutdown()
}

// ---------------------------------------------------------------------------
// PaperEngineInterface — virtual/paper trading engine
// ---------------------------------------------------------------------------

// PaperEngineInterface defines operations for virtual portfolio trading,
// allowing users to practice without real money.
type PaperEngineInterface interface {
	// IsEnabled returns whether paper trading is enabled for the given email.
	IsEnabled(email string) bool

	// Enable activates paper trading with the specified initial cash.
	Enable(email string, initialCash float64) error

	// Disable deactivates paper trading.
	Disable(email string) error

	// Reset clears all paper trading data and resets cash.
	Reset(email string) error

	// Status returns a summary of the paper trading account.
	Status(email string) (map[string]any, error)

	// PlaceOrder places a paper order. Returns a Kite-compatible response map.
	PlaceOrder(email string, params map[string]any) (map[string]any, error)

	// ModifyOrder modifies an open paper order.
	ModifyOrder(email, orderID string, params map[string]any) (map[string]any, error)

	// CancelOrder cancels an open paper order.
	CancelOrder(email, orderID string) (map[string]any, error)

	// GetOrders returns all paper orders in Kite API format.
	GetOrders(email string) (any, error)

	// GetPositions returns all paper positions in Kite API format.
	GetPositions(email string) (any, error)

	// GetHoldings returns all paper holdings in Kite API format.
	GetHoldings(email string) (any, error)

	// GetMargins returns paper margin info in Kite API format.
	GetMargins(email string) (any, error)
}

// ---------------------------------------------------------------------------
// InstrumentManagerInterface — instrument data lookup
// ---------------------------------------------------------------------------

// InstrumentManagerInterface defines operations for looking up instrument
// metadata (symbols, tokens, ISIN, etc.).
type InstrumentManagerInterface interface {
	// GetByID returns an instrument using the symbol (exchange:tradingsymbol).
	GetByID(id string) (instruments.Instrument, error)

	// GetByTradingsymbol returns an instrument using exchange and trading symbol.
	GetByTradingsymbol(exchange, tradingsymbol string) (instruments.Instrument, error)

	// GetByISIN returns instruments matching the given ISIN.
	GetByISIN(isin string) ([]instruments.Instrument, error)

	// GetByInstToken returns an instrument using its instrument token.
	GetByInstToken(token uint32) (instruments.Instrument, error)

	// GetByExchToken returns an instrument using exchange and exchange token.
	GetByExchToken(exch string, exchToken uint32) (instruments.Instrument, error)

	// Filter returns instruments matching the given filter function.
	Filter(filter func(instruments.Instrument) bool) []instruments.Instrument

	// GetAllByUnderlying returns F&O instruments for the given underlying.
	GetAllByUnderlying(exchange, underlying string) ([]instruments.Instrument, error)

	// Count returns the number of instruments loaded.
	Count() int

	// GetUpdateStats returns current update statistics.
	GetUpdateStats() instruments.UpdateStats

	// UpdateInstruments fetches and updates instrument data.
	UpdateInstruments() error

	// ForceUpdateInstruments forces an instrument update regardless of timing.
	ForceUpdateInstruments() error

	// Shutdown gracefully shuts down the instruments manager.
	Shutdown()
}

// ---------------------------------------------------------------------------
// Compile-time interface satisfaction checks
// ---------------------------------------------------------------------------

var (
	_ AlertStoreInterface        = (*alerts.Store)(nil)
	_ TelegramStoreInterface     = (*alerts.Store)(nil)
	_ AuditStoreInterface        = (*audit.Store)(nil)
	_ BillingStoreInterface      = (*billing.Store)(nil)
	_ UserStoreInterface         = (*users.Store)(nil)
	_ RegistryStoreInterface     = (*registry.Store)(nil)
	_ CredentialStoreInterface   = (*KiteCredentialStore)(nil)
	_ TokenStoreInterface        = (*KiteTokenStore)(nil)
	_ WatchlistStoreInterface    = (*watchlist.Store)(nil)
	_ TickerServiceInterface     = (*ticker.Service)(nil)
	_ PaperEngineInterface       = (*papertrading.PaperEngine)(nil)
	_ InstrumentManagerInterface = (*instruments.Manager)(nil)

	// Sub-interface satisfaction checks (ISP splits)
	_ UserReader        = (*users.Store)(nil)
	_ UserWriter        = (*users.Store)(nil)
	_ UserAuthChecker   = (*users.Store)(nil)
	_ AuditWriter       = (*audit.Store)(nil)
	_ AuditReader       = (*audit.Store)(nil)
	_ AuditStreamer      = (*audit.Store)(nil)
	_ RegistryReader    = (*registry.Store)(nil)
	_ RegistryWriter    = (*registry.Store)(nil)
)
