package kc

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"time"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/gokiteconnect/v4/models"
	"github.com/zerodha/kite-mcp-server/app/metrics"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/registry"
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/templates"
	"github.com/zerodha/kite-mcp-server/kc/ticker"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/kc/watchlist"
)

// Config holds configuration for creating a new kc Manager
type Config struct {
	APIKey             string                    // required
	APISecret          string                    // required
	AccessToken        string                    // optional: pre-set access token to bypass browser login
	Logger             *slog.Logger              // required
	InstrumentsConfig  *instruments.UpdateConfig // optional - defaults to instruments.DefaultUpdateConfig()
	InstrumentsManager *instruments.Manager      // optional - if provided, skips creating new instruments manager
	SessionSigner      *SessionSigner            // optional - if nil, creates new session signer
	Metrics            *metrics.Manager          // optional - for tracking user metrics
	TelegramBotToken   string                    // optional - for Telegram price alert notifications
	AlertDBPath        string                    // optional - SQLite path for alert persistence
	AppMode            string                    // optional - "stdio", "http", "sse"
	ExternalURL        string                    // optional - e.g. "https://kite-mcp-server.fly.dev"
	AdminSecretPath    string                    // optional - admin endpoint secret for ops dashboard URL
	EncryptionSecret   string                    // optional - secret for encrypting credentials at rest (typically OAUTH_JWT_SECRET)
}

// New creates a new kc Manager with the given configuration
func New(cfg Config) (*Manager, error) {
	// Validate required fields
	if cfg.Logger == nil {
		return nil, errors.New("logger is required")
	}
	if cfg.APIKey == "" || cfg.APISecret == "" {
		cfg.Logger.Warn("No Kite API credentials configured")
	}

	// Create or use provided instruments manager
	var instrumentsManager *instruments.Manager
	if cfg.InstrumentsManager != nil {
		instrumentsManager = cfg.InstrumentsManager
	} else {
		var err error
		instrumentsManager, err = instruments.New(instruments.Config{
			UpdateConfig: cfg.InstrumentsConfig,
			Logger:       cfg.Logger,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create instruments manager: %w", err)
		}
	}

	m := &Manager{
		apiKey:          cfg.APIKey,
		apiSecret:       cfg.APISecret,
		accessToken:     cfg.AccessToken,
		Logger:          cfg.Logger,
		metrics:         cfg.Metrics,
		appMode:         cfg.AppMode,
		externalURL:     cfg.ExternalURL,
		adminSecretPath: cfg.AdminSecretPath,
		tokenStore:      NewKiteTokenStore(),
		credentialStore: NewKiteCredentialStore(),
	}

	// Initialize alert system: store → notifier → evaluator → ticker
	m.alertStore = alerts.NewStore(func(alert *alerts.Alert, currentPrice float64) {
		if m.telegramNotifier != nil {
			m.telegramNotifier.Notify(alert, currentPrice)
		}
		// Log alert trigger to audit trail for SSE browser notifications.
		if m.auditStore != nil {
			now := time.Now()
			m.auditStore.Enqueue(&audit.ToolCall{
				CallID:        fmt.Sprintf("alert-%s-%d", alert.ID, now.UnixNano()),
				Email:         alert.Email,
				ToolName:      "alert_triggered",
				ToolCategory:  "notification",
				InputSummary:  fmt.Sprintf("%s:%s %s %.2f", alert.Exchange, alert.Tradingsymbol, alert.Direction, alert.TargetPrice),
				OutputSummary: fmt.Sprintf("Triggered at %.2f, notified via Telegram", currentPrice),
				StartedAt:     now,
				CompletedAt:   now,
			})
		}
	})
	m.alertStore.SetLogger(cfg.Logger)

	// Optional: SQLite persistence for alerts
	if cfg.AlertDBPath != "" {
		alertDB, dbErr := alerts.OpenDB(cfg.AlertDBPath)
		if dbErr != nil {
			cfg.Logger.Error("Failed to open alert DB, using in-memory only", "error", dbErr)
		} else {
			m.alertDB = alertDB
			// Set up credential encryption if a secret is provided
			if cfg.EncryptionSecret != "" {
				encKey, encErr := alerts.EnsureEncryptionSalt(alertDB, cfg.EncryptionSecret)
				if encErr != nil {
					cfg.Logger.Error("Failed to derive encryption key with salt", "error", encErr)
				} else {
					alertDB.SetEncryptionKey(encKey)
					cfg.Logger.Info("Credential encryption enabled (with HKDF salt)")
				}
			}
			m.alertStore.SetDB(alertDB)
			if err := m.alertStore.LoadFromDB(); err != nil {
				cfg.Logger.Error("Failed to load alerts from DB", "error", err)
			} else {
				cfg.Logger.Info("Alerts loaded from database", "path", cfg.AlertDBPath)
			}
			// Token persistence: share the same DB
			m.tokenStore.SetDB(alertDB)
			m.tokenStore.SetLogger(cfg.Logger)
			if err := m.tokenStore.LoadFromDB(); err != nil {
				cfg.Logger.Error("Failed to load tokens from DB", "error", err)
			} else {
				cfg.Logger.Info("Tokens loaded from database", "count", m.tokenStore.Count())
			}
			// Credential persistence: share the same DB
			m.credentialStore.SetDB(alertDB)
			m.credentialStore.SetLogger(cfg.Logger)
			if err := m.credentialStore.LoadFromDB(); err != nil {
				cfg.Logger.Error("Failed to load credentials from DB", "error", err)
			} else {
				cfg.Logger.Info("Credentials loaded from database", "count", m.credentialStore.Count())
			}
		}
	}

	// Wire credential → token invalidation: when a user's API key changes,
	// delete the cached Kite token (it was issued for the old app).
	m.credentialStore.OnTokenInvalidate(func(email string) {
		m.tokenStore.Delete(email)
	})

	if cfg.TelegramBotToken != "" {
		notifier, tgErr := alerts.NewTelegramNotifier(cfg.TelegramBotToken, m.alertStore, cfg.Logger)
		if tgErr != nil {
			cfg.Logger.Warn("Telegram notifier failed to initialize", "error", tgErr)
		} else {
			m.telegramNotifier = notifier
		}
	}

	m.alertEvaluator = alerts.NewEvaluator(m.alertStore, cfg.Logger)

	// Initialize trailing stop manager
	m.trailingStopMgr = alerts.NewTrailingStopManager(cfg.Logger)
	if m.alertDB != nil {
		m.trailingStopMgr.SetDB(m.alertDB)
		if err := m.trailingStopMgr.LoadFromDB(); err != nil {
			cfg.Logger.Error("Failed to load trailing stops from DB", "error", err)
		}
	}

	// Initialize watchlist store
	m.watchlistStore = watchlist.NewStore()
	m.watchlistStore.SetLogger(cfg.Logger)
	if m.alertDB != nil {
		if err := watchlist.InitTables(m.alertDB); err != nil {
			cfg.Logger.Error("Failed to create watchlist tables", "error", err)
		} else {
			m.watchlistStore.SetDB(m.alertDB)
			if err := m.watchlistStore.LoadFromDB(); err != nil {
				cfg.Logger.Error("Failed to load watchlists from DB", "error", err)
			} else {
				cfg.Logger.Info("Watchlists loaded from database")
			}
		}
	}

	// Initialize user store (RBAC, lifecycle)
	m.userStore = users.NewStore()
	m.userStore.SetLogger(cfg.Logger)
	if m.alertDB != nil {
		m.userStore.SetDB(m.alertDB)
		if err := m.userStore.InitTable(); err != nil {
			cfg.Logger.Error("Failed to create users table", "error", err)
		} else if err := m.userStore.LoadFromDB(); err != nil {
			cfg.Logger.Error("Failed to load users from DB", "error", err)
		} else {
			cfg.Logger.Info("Users loaded from database", "count", m.userStore.Count())
		}
	}
	// Initialize key registry store (zero-config onboarding)
	m.registryStore = registry.New()
	m.registryStore.SetLogger(cfg.Logger)
	if m.alertDB != nil {
		m.registryStore.SetDB(m.alertDB)
		if err := m.registryStore.LoadFromDB(); err != nil {
			cfg.Logger.Error("Failed to load registry from DB", "error", err)
		} else {
			cfg.Logger.Info("App registry loaded from database", "count", m.registryStore.Count())
		}
	}

	// Initialize focused services (Clean Architecture)
	m.credentialSvc = NewCredentialService(CredentialServiceConfig{
		APIKey:          cfg.APIKey,
		APISecret:       cfg.APISecret,
		AccessToken:     cfg.AccessToken,
		CredentialStore: m.credentialStore,
		TokenStore:      m.tokenStore,
		RegistryStore:   m.registryStore,
		Logger:          cfg.Logger,
	})

	// Backfill registry from existing credentials (handles pre-registry self-provisioned keys)
	m.credentialSvc.BackfillRegistryFromCredentials()

	// Wire the order modifier: creates a Kite client from cached tokens
	m.trailingStopMgr.SetModifier(func(email string) (alerts.KiteOrderModifier, error) {
		apiKey := m.GetAPIKeyForEmail(email)
		accessToken := m.GetAccessTokenForEmail(email)
		if accessToken == "" {
			return nil, fmt.Errorf("no Kite access token for %s", email)
		}
		client := kiteconnect.New(apiKey)
		client.SetAccessToken(accessToken)
		return client, nil
	})

	// Wire trailing stop modification notification to Telegram
	m.trailingStopMgr.SetOnModify(func(ts *alerts.TrailingStop, oldStop, newStop float64) {
		// Log trailing stop modification to audit trail for SSE browser notifications.
		if m.auditStore != nil {
			now := time.Now()
			trailDesc := fmt.Sprintf("%.2f", ts.TrailAmount)
			if ts.TrailPct > 0 {
				trailDesc = fmt.Sprintf("%.1f%%", ts.TrailPct)
			}
			m.auditStore.Enqueue(&audit.ToolCall{
				CallID:        fmt.Sprintf("trail-%s-%d", ts.ID, now.UnixNano()),
				Email:         ts.Email,
				ToolName:      "trailing_stop_modified",
				ToolCategory:  "notification",
				InputSummary:  fmt.Sprintf("%s:%s SL moved %.2f -> %.2f", ts.Exchange, ts.Tradingsymbol, oldStop, newStop),
				OutputSummary: fmt.Sprintf("High: %.2f, Trail: %s", ts.HighWaterMark, trailDesc),
				StartedAt:     now,
				CompletedAt:   now,
			})
		}

		if m.telegramNotifier == nil {
			return
		}
		chatID, ok := m.alertStore.GetTelegramChatID(ts.Email)
		if !ok {
			return
		}
		arrow := "\u2B06\uFE0F" // up arrow
		if newStop < oldStop {
			arrow = "\u2B07\uFE0F" // down arrow
		}
		msg := fmt.Sprintf(
			"%s <b>Trailing Stop Modified</b>\n\n"+
				"%s:%s (%s)\n"+
				"SL: \u20B9%.2f \u2192 \u20B9%.2f\n"+
				"High water mark: \u20B9%.2f\n"+
				"Modifications: %d",
			arrow,
			ts.Exchange, ts.Tradingsymbol, ts.Direction,
			oldStop, newStop,
			ts.HighWaterMark,
			ts.ModifyCount,
		)
		if err := m.telegramNotifier.SendHTMLMessage(chatID, msg); err != nil {
			m.Logger.Warn("Failed to send trailing stop Telegram notification",
				"email", ts.Email, "error", err)
		}
	})

	// Initialize ticker with alert evaluator + trailing stop manager as OnTick callbacks
	m.tickerService = ticker.New(ticker.Config{
		Logger: cfg.Logger,
		OnTick: func(email string, tick models.Tick) {
			m.alertEvaluator.Evaluate(email, tick)
			m.trailingStopMgr.Evaluate(email, tick)
		},
	})

	if err := m.initializeTemplates(); err != nil {
		return nil, fmt.Errorf("failed to initialize Kite manager: %w", err)
	}

	if err := m.initializeSessionSigner(cfg.SessionSigner); err != nil {
		return nil, fmt.Errorf("failed to initialize session signer: %w", err)
	}

	m.Instruments = instrumentsManager
	m.initializeSessionManager()

	// Initialize session service (uses credential service + session manager)
	var metricsImpl metricsTracker
	if cfg.Metrics != nil {
		metricsImpl = cfg.Metrics
	}
	m.sessionSvc = NewSessionService(SessionServiceConfig{
		CredentialSvc: m.credentialSvc,
		TokenStore:    m.tokenStore,
		SessionSigner: m.sessionSigner,
		AlertStore:    m.alertStore,
		Logger:        cfg.Logger,
		Metrics:       metricsImpl,
	})
	m.sessionSvc.SetSessionManager(m.sessionManager)

	// Initialize portfolio and order services
	m.portfolioSvc = NewPortfolioService(m.sessionSvc, cfg.Logger)
	m.orderSvc = NewOrderService(m.sessionSvc, cfg.Logger)

	// Session persistence: share the same DB (if available)
	if m.alertDB != nil {
		m.sessionManager.SetDB(&sessionDBAdapter{db: m.alertDB})
		if err := m.sessionManager.LoadFromDB(); err != nil {
			cfg.Logger.Error("Failed to load sessions from DB", "error", err)
		} else {
			cfg.Logger.Info("Sessions loaded from database")
		}
	}

	// Wire token rotation observer: when a user's token changes, update their ticker
	m.tokenStore.OnChange(func(email string, entry *KiteTokenEntry) {
		if m.tickerService.IsRunning(email) {
			apiKey := m.GetAPIKeyForEmail(email)
			if err := m.tickerService.UpdateToken(email, apiKey, entry.AccessToken); err != nil {
				m.Logger.Error("Failed to update ticker token", "email", email, "error", err)
			} else {
				m.Logger.Info("Ticker token rotated automatically", "email", email)
			}
		}
	})

	return m, nil
}

// KiteConnect wraps the Kite Connect client
type KiteConnect struct {
	// Add fields here
	// Client is the authenticated Kite Connect client. Exported because 23+ tool handlers access it directly.
	Client *kiteconnect.Client
}

// NewKiteConnect creates a new KiteConnect instance
func NewKiteConnect(apiKey string) *KiteConnect {
	client := kiteconnect.New(apiKey)

	return &KiteConnect{
		Client: client,
	}
}

const (
	// Template names
	indexTemplate = "login_success.html"

	// HTTP error messages
	missingParamsMessage  = "missing MCP session_id or Kite request_token"
	sessionErrorMessage   = "error completing Kite session"
	templateNotFoundError = "template not found"
)

var (
	ErrSessionNotFound  = errors.New("MCP session not found or Kite session not associated, try to login again")
	ErrInvalidSessionID = errors.New("invalid MCP session ID, please try logging in again")
)

type KiteSessionData struct {
	Kite   *KiteConnect
	Broker broker.Client // broker-agnostic interface (wraps Kite.Client via zerodha adapter)
	Email  string        // Google-authenticated email (empty for local dev)
}

type Manager struct {
	apiKey      string
	apiSecret   string
	accessToken string
	Logger      *slog.Logger
	metrics     *metrics.Manager

	templates map[string]*template.Template

	// Focused service objects (Clean Architecture)
	credentialSvc  *CredentialService  // credential resolution (per-user + global)
	sessionSvc     *SessionService     // MCP session lifecycle
	portfolioSvc   *PortfolioService   // portfolio queries (holdings, positions, margins, profile)
	orderSvc       *OrderService       // order placement, modification, cancellation

	Instruments    *instruments.Manager
	sessionManager *SessionRegistry
	sessionSigner  *SessionSigner
	tokenStore         *KiteTokenStore           // per-email Kite token cache
	credentialStore    *KiteCredentialStore      // per-email Kite developer app credentials
	tickerService      *ticker.Service                // per-user WebSocket ticker connections
	alertStore         *alerts.Store                  // per-user price alerts
	alertEvaluator     *alerts.Evaluator              // tick-to-alert matcher
	trailingStopMgr    *alerts.TrailingStopManager    // trailing stop-loss manager
	pnlService         *alerts.PnLSnapshotService     // daily P&L snapshots
	watchlistStore     *watchlist.Store               // per-user watchlists
	userStore          *users.Store                   // registered users (RBAC, lifecycle)
	registryStore      *registry.Store                // pre-registered Kite app credentials (key registry)
	telegramNotifier   *alerts.TelegramNotifier       // Telegram alert sender
	alertDB            *alerts.DB                     // optional: SQLite persistence for alerts
	auditStore         *audit.Store                   // optional: audit trail for synthetic events
	riskGuard          *riskguard.Guard               // optional: financial safety controls
	paperEngine        *papertrading.PaperEngine      // optional: virtual trading engine
	billingStore       *billing.Store                 // optional: billing tier enforcement
	mcpServer          any                            // *server.MCPServer — stored as any to avoid circular import
	appMode            string
	externalURL        string
	adminSecretPath    string
}

// NewManager creates a new manager with default configuration.
//
// Deprecated: Use New(Config{APIKey: apiKey, APISecret: apiSecret, Logger: logger}) instead.
// NOTE: Still used by kc/manager_test.go (TestNewManager). Remove once tests are migrated to New().
func NewManager(apiKey, apiSecret string, logger *slog.Logger) (*Manager, error) {
	return New(Config{
		APIKey:    apiKey,
		APISecret: apiSecret,
		Logger:    logger,
	})
}

// ---------------------------------------------------------------------------
// Service accessors (Clean Architecture)
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

// IsLocalMode returns true when running in STDIO mode (local process, not remote HTTP).
func (m *Manager) IsLocalMode() bool {
	return m.appMode == "" || m.appMode == "stdio"
}

// ExternalURL returns the configured external URL (e.g. "https://kite-mcp-server.fly.dev").
func (m *Manager) ExternalURL() string {
	return m.externalURL
}

// AdminSecretPath returns the configured admin secret path.
func (m *Manager) AdminSecretPath() string {
	return m.adminSecretPath
}

// OpenBrowser opens the given URL in the user's default browser.
// Only works in local/STDIO mode where the server runs on the user's machine.
func (m *Manager) OpenBrowser(rawURL string) error {
	if !m.IsLocalMode() {
		return nil
	}

	// Validate URL scheme to prevent command injection via crafted URIs
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("invalid URL scheme: only http and https are allowed")
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL) // #nosec G204 -- URL is validated above (scheme whitelist)
	case "darwin":
		cmd = exec.Command("open", rawURL) // #nosec G204 -- URL is validated above (scheme whitelist)
	default:
		cmd = exec.Command("xdg-open", rawURL) // #nosec G204 -- URL is validated above (scheme whitelist)
	}
	return cmd.Start()
}

// initializeTemplates sets up HTML templates
func (m *Manager) initializeTemplates() error {
	templates, err := setupTemplates()
	if err != nil {
		return fmt.Errorf("failed to setup templates: %w", err)
	}
	m.templates = templates
	return nil
}

// initializeSessionSigner sets up HMAC session signing
func (m *Manager) initializeSessionSigner(customSigner *SessionSigner) error {
	if customSigner != nil {
		m.sessionSigner = customSigner
		return nil
	}

	signer, err := NewSessionSigner()
	if err != nil {
		return fmt.Errorf("failed to create session signer: %w", err)
	}
	m.sessionSigner = signer
	return nil
}

// initializeSessionManager sets up the session manager with cleanup hooks
// initializeSessionManager creates and configures the session manager
func (m *Manager) initializeSessionManager() {
	sessionManager := NewSessionRegistry(m.Logger)

	// Add cleanup hook for Kite sessions
	sessionManager.AddCleanupHook(m.kiteSessionCleanupHook)

	// Start cleanup routine
	sessionManager.StartCleanupRoutine(context.Background())

	m.sessionManager = sessionManager
}

// kiteSessionCleanupHook handles cleanup of Kite sessions
func (m *Manager) kiteSessionCleanupHook(session *MCPSession) {
	if kiteData, ok := session.Data.(*KiteSessionData); ok && kiteData != nil && kiteData.Kite != nil {
		m.Logger.Debug("Cleaning up Kite session for MCP session ID", "session_id", session.ID)
		if _, err := kiteData.Kite.Client.InvalidateAccessToken(); err != nil {
			m.Logger.Warn("Failed to invalidate access token", "session_id", session.ID, "error", err)
		}
	}
}

// HasPreAuth returns true if the manager has a pre-set access token.
// Delegates to CredentialService.
func (m *Manager) HasPreAuth() bool {
	return m.credentialSvc.HasPreAuth()
}

// HasCachedToken returns true if there's a cached Kite token for the given email.
// Delegates to CredentialService.
func (m *Manager) HasCachedToken(email string) bool {
	return m.credentialSvc.HasCachedToken(email)
}

// TokenStore returns the per-email token store.
func (m *Manager) TokenStore() *KiteTokenStore {
	return m.tokenStore
}


// HasGlobalCredentials returns true if global API key/secret are configured (from env vars).
// Delegates to CredentialService.
func (m *Manager) HasGlobalCredentials() bool {
	return m.credentialSvc.HasGlobalCredentials()
}

// TickerService returns the per-user WebSocket ticker service.
func (m *Manager) TickerService() *ticker.Service {
	return m.tickerService
}

// AlertStore returns the per-user alert store.
func (m *Manager) AlertStore() *alerts.Store {
	return m.alertStore
}

// WatchlistStore returns the per-user watchlist store.
func (m *Manager) WatchlistStore() *watchlist.Store {
	return m.watchlistStore
}

// APIKey returns the global Kite API key.
func (m *Manager) APIKey() string {
	return m.apiKey
}

// CredentialStore returns the per-email Kite credential store.
func (m *Manager) CredentialStore() *KiteCredentialStore {
	return m.credentialStore
}

// UserStore returns the user identity store (RBAC, lifecycle).
func (m *Manager) UserStore() *users.Store {
	return m.userStore
}

// RegistryStore returns the key registry store for zero-config onboarding.
func (m *Manager) RegistryStore() *registry.Store {
	return m.registryStore
}

// AlertDB returns the optional SQLite database used for persistence.
// Returns nil if no database path was configured.
func (m *Manager) AlertDB() *alerts.DB {
	return m.alertDB
}

// SetMCPServer stores a reference to the MCP server for elicitation support.
func (m *Manager) SetMCPServer(srv any) {
	m.mcpServer = srv
}

// MCPServer returns the stored MCP server reference, or nil.
func (m *Manager) MCPServer() any {
	return m.mcpServer
}

// truncKey safely returns the first n characters of a string, or the whole string if shorter.
func truncKey(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}


// TelegramNotifier returns the Telegram notifier (nil if not configured).
func (m *Manager) TelegramNotifier() *alerts.TelegramNotifier {
	return m.telegramNotifier
}

// InstrumentsManager returns the instruments manager.
func (m *Manager) InstrumentsManager() *instruments.Manager {
	return m.Instruments
}

// IsTokenValid returns true if the user has a cached Kite token that has not expired.
// Delegates to CredentialService.
func (m *Manager) IsTokenValid(email string) bool {
	return m.credentialSvc.IsTokenValid(email)
}

// TrailingStopManager returns the trailing stop manager (nil if not initialized).
func (m *Manager) TrailingStopManager() *alerts.TrailingStopManager {
	return m.trailingStopMgr
}

// PnLService returns the P&L snapshot service (nil if not initialized).
func (m *Manager) PnLService() *alerts.PnLSnapshotService {
	return m.pnlService
}

// SetPnLService sets the P&L snapshot service (called from app layer after initialization).
func (m *Manager) SetPnLService(svc *alerts.PnLSnapshotService) {
	m.pnlService = svc
}

// AuditStore returns the audit trail store, or nil if not configured.
func (m *Manager) AuditStore() *audit.Store {
	return m.auditStore
}

// SetAuditStore wires the audit store into alert trigger and trailing stop
// modification callbacks so that these events appear in the SSE activity stream.
func (m *Manager) SetAuditStore(store *audit.Store) {
	m.auditStore = store
}

// SetRiskGuard sets the riskguard for financial safety controls.
func (m *Manager) SetRiskGuard(guard *riskguard.Guard) {
	m.riskGuard = guard
}

// RiskGuard returns the riskguard instance, or nil if not configured.
func (m *Manager) RiskGuard() *riskguard.Guard {
	return m.riskGuard
}

// SetPaperEngine sets the paper trading engine.
func (m *Manager) SetPaperEngine(e *papertrading.PaperEngine) {
	m.paperEngine = e
}

// PaperEngine returns the paper trading engine, or nil if not configured.
func (m *Manager) PaperEngine() *papertrading.PaperEngine {
	return m.paperEngine
}

// SetBillingStore sets the billing store for tier enforcement.
func (m *Manager) SetBillingStore(store *billing.Store) {
	m.billingStore = store
}

// BillingStore returns the billing store, or nil if not configured.
func (m *Manager) BillingStore() *billing.Store {
	return m.billingStore
}

// HasUserCredentials returns true if per-user Kite credentials exist for the given email.
// Delegates to CredentialService.
func (m *Manager) HasUserCredentials(email string) bool {
	return m.credentialSvc.HasUserCredentials(email)
}

// GetAPIKeyForEmail returns the API key: per-user if registered, otherwise global.
// Delegates to CredentialService.
func (m *Manager) GetAPIKeyForEmail(email string) string {
	return m.credentialSvc.GetAPIKeyForEmail(email)
}

// GetAPISecretForEmail returns the API secret: per-user if registered, otherwise global.
// Delegates to CredentialService.
func (m *Manager) GetAPISecretForEmail(email string) string {
	return m.credentialSvc.GetAPISecretForEmail(email)
}

// GetAccessTokenForEmail returns the cached access token for a given email.
// Delegates to CredentialService.
func (m *Manager) GetAccessTokenForEmail(email string) string {
	return m.credentialSvc.GetAccessTokenForEmail(email)
}


// GetOrCreateSession retrieves an existing Kite session or creates a new one atomically.
// Delegates to SessionService.
func (m *Manager) GetOrCreateSession(mcpSessionID string) (*KiteSessionData, bool, error) {
	return m.sessionSvc.GetOrCreateSession(mcpSessionID)
}

// GetOrCreateSessionWithEmail retrieves or creates a Kite session with email context.
// Delegates to SessionService.
func (m *Manager) GetOrCreateSessionWithEmail(mcpSessionID, email string) (*KiteSessionData, bool, error) {
	return m.sessionSvc.GetOrCreateSessionWithEmail(mcpSessionID, email)
}

// GetSession retrieves an existing Kite session by MCP session ID.
// Delegates to SessionService.
func (m *Manager) GetSession(mcpSessionID string) (*KiteSessionData, error) {
	return m.sessionSvc.GetSession(mcpSessionID)
}

// ClearSession terminates a session, triggering cleanup hooks.
// Delegates to SessionService.
func (m *Manager) ClearSession(sessionID string) {
	m.sessionSvc.ClearSession(sessionID)
}

// ClearSessionData clears the session data without terminating the session.
// Delegates to SessionService.
func (m *Manager) ClearSessionData(sessionID string) error {
	return m.sessionSvc.ClearSessionData(sessionID)
}

// GenerateSession creates a new MCP session with Kite data and returns the session ID.
// Delegates to SessionService.
func (m *Manager) GenerateSession() string {
	return m.sessionSvc.GenerateSession()
}

// SessionLoginURL returns the Kite login URL for the given session.
// Delegates to SessionService.
func (m *Manager) SessionLoginURL(mcpSessionID string) (string, error) {
	return m.sessionSvc.SessionLoginURL(mcpSessionID)
}

// CompleteSession completes Kite authentication using the request token.
// Delegates to SessionService.
func (m *Manager) CompleteSession(mcpSessionID, kiteRequestToken string) error {
	return m.sessionSvc.CompleteSession(mcpSessionID, kiteRequestToken)
}

// Session management utility methods

// GetActiveSessionCount returns the number of active sessions.
// Delegates to SessionService.
func (m *Manager) GetActiveSessionCount() int {
	return m.sessionSvc.GetActiveSessionCount()
}

// CleanupExpiredSessions manually triggers cleanup of expired MCP sessions.
// Delegates to SessionService.
func (m *Manager) CleanupExpiredSessions() int {
	return m.sessionSvc.CleanupExpiredSessions()
}

// StopCleanupRoutine stops the background cleanup routine.
// Delegates to SessionService.
func (m *Manager) StopCleanupRoutine() {
	m.sessionSvc.StopCleanupRoutine()
}

// HasMetrics returns true if metrics manager is available
func (m *Manager) HasMetrics() bool {
	return m.metrics != nil
}

// IncrementMetric increments a metric counter by 1
func (m *Manager) IncrementMetric(key string) {
	if m.metrics != nil {
		m.metrics.Increment(key)
	}
}

// TrackDailyUser records a unique user interaction for today's counter
func (m *Manager) TrackDailyUser(userID string) {
	if m.metrics != nil {
		m.metrics.TrackDailyUser(userID)
	}
}

// IncrementDailyMetric increments a daily metric counter by 1
func (m *Manager) IncrementDailyMetric(key string) {
	if m.metrics != nil {
		m.metrics.IncrementDaily(key)
	}
}

// sessionDBAdapter bridges alerts.DB to the SessionDB interface expected by SessionRegistry.
type sessionDBAdapter struct {
	db *alerts.DB
}

func (a *sessionDBAdapter) SaveSession(sessionID, email string, createdAt, expiresAt time.Time, terminated bool) error {
	return a.db.SaveSession(sessionID, email, createdAt, expiresAt, terminated)
}

func (a *sessionDBAdapter) LoadSessions() ([]*SessionLoadEntry, error) {
	entries, err := a.db.LoadSessions()
	if err != nil {
		return nil, err
	}
	result := make([]*SessionLoadEntry, len(entries))
	for i, e := range entries {
		result[i] = &SessionLoadEntry{
			SessionID:  e.SessionID,
			Email:      e.Email,
			CreatedAt:  e.CreatedAt,
			ExpiresAt:  e.ExpiresAt,
			Terminated: e.Terminated,
		}
	}
	return result, nil
}

func (a *sessionDBAdapter) DeleteSession(sessionID string) error {
	return a.db.DeleteSession(sessionID)
}

// Shutdown gracefully shuts down the manager and all its components
func (m *Manager) Shutdown() {
	m.Logger.Info("Shutting down Kite manager...")

	// Stop session cleanup routines
	m.sessionManager.StopCleanupRoutine()

	// Shutdown metrics manager (stops cleanup routine)
	if m.metrics != nil {
		m.metrics.Shutdown()
	}

	// Shutdown ticker service (stops all WebSocket connections)
	m.tickerService.Shutdown()

	// Close alert DB after ticker (ticker's OnTick writes through to DB)
	if m.alertDB != nil {
		if err := m.alertDB.Close(); err != nil {
			m.Logger.Error("Failed to close alert DB", "error", err)
		}
	}

	// Shutdown instruments manager (stops scheduler)
	m.Instruments.Shutdown()

	m.Logger.Info("Kite manager shutdown complete")
}

// GetInstrumentsStats returns current instruments update statistics
func (m *Manager) GetInstrumentsStats() instruments.UpdateStats {
	return m.Instruments.GetUpdateStats()
}

// UpdateInstrumentsConfig updates the instruments manager configuration
func (m *Manager) UpdateInstrumentsConfig(config *instruments.UpdateConfig) {
	m.Instruments.UpdateConfig(config)
}

// ForceInstrumentsUpdate forces an immediate instruments update
func (m *Manager) ForceInstrumentsUpdate() error {
	return m.Instruments.ForceUpdateInstruments()
}

// SessionManager returns the MCP session manager instance
func (m *Manager) SessionManager() *SessionRegistry {
	return m.sessionManager
}

// SessionSigner returns the session signer instance
func (m *Manager) SessionSigner() *SessionSigner {
	return m.sessionSigner
}

// UpdateSessionSignerExpiry updates the signature expiry duration
func (m *Manager) UpdateSessionSignerExpiry(duration time.Duration) {
	m.sessionSigner.SetSignatureExpiry(duration)
}

func setupTemplates() (map[string]*template.Template, error) {
	out := map[string]*template.Template{}

	templateList := []string{indexTemplate}

	for _, templateName := range templateList {
		// Parse template with base template for composition support
		templ, err := template.ParseFS(templates.FS, "base.html", templateName)
		if err != nil {
			return out, fmt.Errorf("error parsing %s: %w", templateName, err)
		}
		out[templateName] = templ
	}

	return out, nil
}

// handleCallbackError handles error responses for callback processing.
// keyvals must be slog-style key-value pairs (e.g. "key", value, "key2", value2).
func (m *Manager) handleCallbackError(w http.ResponseWriter, message string, statusCode int, logMessage string, keyvals ...any) {
	m.Logger.Error(logMessage, keyvals...)
	http.Error(w, message, statusCode)
}

// HandleKiteCallback returns an HTTP handler for Kite authentication callbacks
func (m *Manager) HandleKiteCallback() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		m.Logger.Debug("Received Kite callback request", "url", r.URL.String())
		requestToken, mcpSessionID, err := m.extractCallbackParams(r)
		if err != nil {
			m.handleCallbackError(w, missingParamsMessage, http.StatusBadRequest, "Invalid callback parameters", "error", err)
			return
		}

		m.Logger.Debug("Processing Kite callback for MCP session ID", "session_id", mcpSessionID, "request_token", requestToken)

		if err := m.CompleteSession(mcpSessionID, requestToken); err != nil {
			m.handleCallbackError(w, sessionErrorMessage, http.StatusInternalServerError, "Error completing Kite session", "session_id", mcpSessionID, "error", err)
			return
		}

		m.Logger.Info("Kite session completed successfully", "session_id", mcpSessionID)

		if err := m.renderSuccessTemplate(w); err != nil {
			m.Logger.Error("Template failed to load - this is a fatal error", "error", err)
			http.Error(w, "Internal server error: template not available", http.StatusInternalServerError)
			return
		}

		m.Logger.Info("Kite callback completed successfully", "session_id", mcpSessionID)
	}
}

// extractCallbackParams extracts and validates callback parameters with signature verification
func (m *Manager) extractCallbackParams(r *http.Request) (kiteRequestToken, mcpSessionID string, err error) {
	qVals := r.URL.Query()
	kiteRequestToken = qVals.Get("request_token")
	signedSessionID := qVals.Get("session_id")

	if signedSessionID == "" || kiteRequestToken == "" {
		return "", "", errors.New("missing required parameters (MCP session_id or Kite request_token)")
	}

	// Verify the signed session ID
	mcpSessionID, err = m.sessionSigner.VerifySessionID(signedSessionID)
	if err != nil {
		m.Logger.Error("Failed to verify session signature", "error", err)
		return "", "", fmt.Errorf("invalid or tampered session parameter: %w", err)
	}

	return kiteRequestToken, mcpSessionID, nil
}

// TemplateData holds data for template rendering
type TemplateData struct {
	Title string
}

// renderSuccessTemplate renders the success page template
func (m *Manager) renderSuccessTemplate(w http.ResponseWriter) error {
	templ, ok := m.templates[indexTemplate]
	if !ok {
		return errors.New(templateNotFoundError)
	}

	data := TemplateData{
		Title: "Login Successful",
	}

	return templ.ExecuteTemplate(w, "base", data)
}
