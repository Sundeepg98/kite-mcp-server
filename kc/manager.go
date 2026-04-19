package kc

import (
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/url"
	"os/exec"
	"runtime"
	"time"

	"github.com/zerodha/gokiteconnect/v4/models"
	"github.com/zerodha/kite-mcp-server/app/metrics"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/broker/zerodha"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/eventsourcing"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
	"github.com/zerodha/kite-mcp-server/kc/registry"
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
	DevMode            bool                      // optional - use mock broker, no real Kite login required
	// InstrumentsSkipFetch causes the auto-created instruments manager to
	// skip the HTTP prefetch of api.kite.trade/instruments.json and load an
	// empty instrument map instead. Intended for tests that exercise the
	// full wiring (initializeServices) but do not need live instrument data
	// — isolates the test suite from external-API rate limits / outages.
	// Ignored when InstrumentsManager is already provided.
	InstrumentsSkipFetch bool
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
		instrumentsCfg := instruments.Config{
			UpdateConfig: cfg.InstrumentsConfig,
			Logger:       cfg.Logger,
		}
		// Test-isolation seam: when InstrumentsSkipFetch is true, pass an
		// empty TestData map so instruments.New skips the HTTP fetch. This
		// keeps the full Manager wiring exercised (registries, services,
		// event dispatcher) while eliminating the external dependency that
		// causes flaky CI under api.kite.trade rate limits.
		if cfg.InstrumentsSkipFetch {
			instrumentsCfg.TestData = map[uint32]*instruments.Instrument{}
		}
		var err error
		instrumentsManager, err = instruments.New(instrumentsCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create instruments manager: %w", err)
		}
	}

	m := &Manager{
		apiKey:            cfg.APIKey,
		apiSecret:         cfg.APISecret,
		accessToken:       cfg.AccessToken,
		Logger:            cfg.Logger,
		metrics:           cfg.Metrics,
		appMode:           cfg.AppMode,
		externalURL:       cfg.ExternalURL,
		adminSecretPath:   cfg.AdminSecretPath,
		devMode:           cfg.DevMode,
		kiteClientFactory: &defaultKiteClientFactory{},
		tokenStore:        NewKiteTokenStore(),
		credentialStore:   NewKiteCredentialStore(),
		commandBus:        cqrs.NewInMemoryBus(cqrs.LoggingMiddleware(cfg.Logger)),
		queryBus:          cqrs.NewInMemoryBus(cqrs.LoggingMiddleware(cfg.Logger)),
	}

	// Initialize the decomposed facades. They hold a back-pointer to Manager,
	// so each accessor reads the current field value (no stale snapshot).
	m.stores = newStoreRegistry(m)
	m.eventing = newEventingService(m)
	m.brokers = newBrokerServices(m)
	m.scheduling = newSchedulingService(m)
	m.sessionLifecycle = newSessionLifecycleService(m)

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
		// Dispatch domain event for alert trigger.
		if m.eventDispatcher != nil {
			m.eventDispatcher.Dispatch(domain.AlertTriggeredEvent{
				Email:        alert.Email,
				AlertID:      alert.ID,
				Instrument:   domain.NewInstrumentKey(alert.Exchange, alert.Tradingsymbol),
				TargetPrice:  domain.NewINR(alert.TargetPrice),
				CurrentPrice: domain.NewINR(currentPrice),
				Direction:    string(alert.Direction),
				Timestamp:    time.Now().UTC(),
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
		apiKey := m.credentialSvc.GetAPIKeyForEmail(email)
		accessToken := m.credentialSvc.GetAccessTokenForEmail(email)
		if accessToken == "" {
			return nil, fmt.Errorf("no Kite access token for %s", email)
		}
		client := m.kiteClientFactory.NewClientWithToken(apiKey, accessToken)
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
	m.scheduling.initialize()

	// Initialize session service (uses credential service + session manager)
	var metricsImpl metricsTracker
	if cfg.Metrics != nil {
		metricsImpl = cfg.Metrics
	}
	m.sessionSvc = NewSessionService(SessionServiceConfig{
		CredentialSvc: m.credentialSvc,
		TokenStore:    m.tokenStore,
		SessionSigner: m.sessionSigner,
		Logger:        cfg.Logger,
		Metrics:       metricsImpl,
		DevMode:       cfg.DevMode,
	})
	m.sessionSvc.SetSessionManager(m.sessionManager)
	m.managedSessionSvc = NewManagedSessionService(m.sessionManager)

	// Initialize portfolio and order services
	m.portfolioSvc = NewPortfolioService(m.sessionSvc, cfg.Logger)
	m.orderSvc = NewOrderService(m.sessionSvc, cfg.Logger)

	// Initialize alert service (wraps alert-related components)
	m.alertSvc = NewAlertService(AlertServiceConfig{
		AlertStore:       m.alertStore,
		AlertEvaluator:   m.alertEvaluator,
		TrailingStopMgr:  m.trailingStopMgr,
		TelegramNotifier: m.telegramNotifier,
	})

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
			apiKey := m.credentialSvc.GetAPIKeyForEmail(email)
			if err := m.tickerService.UpdateToken(email, apiKey, entry.AccessToken); err != nil {
				m.Logger.Error("Failed to update ticker token", "email", email, "error", err)
			} else {
				m.Logger.Info("Ticker token rotated automatically", "email", email)
			}
		}
	})

	// Initialize the read-side projection. The projector is empty until
	// SetEventDispatcher wires it to a real dispatcher in app/wire.go; tests
	// that skip dispatcher setup still get a usable empty projector.
	m.projector = eventsourcing.NewProjector()

	// Register CQRS handlers on the bus. Tool handlers dispatch queries through
	// manager.QueryBus() rather than constructing use cases inline.
	if err := m.registerCQRSHandlers(); err != nil {
		return nil, fmt.Errorf("failed to register CQRS handlers: %w", err)
	}

	return m, nil
}

// registerCQRSHandlers lives in kc/manager_cqrs_register.go — the ~285 LOC of
// bus wiring was extracted so manager.go can stay focused on the struct
// definition, constructor, and core accessors.

// Event-sourced read-side serializers + reconstitution helpers
// (orderAggregateToProjectionResult, reconstituteOrderHistory,
// reconstituteAlertHistory) live in kc/manager_reconstitution.go.

// KiteConnect wraps the Kite Connect client.
//
// The Client field holds a zerodha.KiteSDK (interface) rather than a
// concrete *kiteconnect.Client so background services and tool handlers
// both consume the same hexagonal port — the broker-owned interface
// collapses the former two SDK construction sites (kc/kite_client.go
// and broker/zerodha/sdk_adapter.go) into one, and lets tests swap in
// zerodha.MockKiteSDK without touching HTTP.
type KiteConnect struct {
	// Client is the authenticated Kite SDK. Exported because 23+ tool handlers access it directly.
	Client zerodha.KiteSDK
}

// NewKiteConnect creates a new KiteConnect instance.
// All SDK instantiation routes through the KiteClientFactory interface.
func NewKiteConnect(apiKey string, factory ...KiteClientFactory) *KiteConnect {
	var f KiteClientFactory
	if len(factory) > 0 && factory[0] != nil {
		f = factory[0]
	} else {
		f = &defaultKiteClientFactory{}
	}
	return &KiteConnect{
		Client: f.NewClient(apiKey),
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
	credentialSvc     *CredentialService     // credential resolution (per-user + global)
	sessionSvc        *SessionService        // MCP session lifecycle
	managedSessionSvc *ManagedSessionService // thin session facade (active count, terminate-by-email)
	portfolioSvc      *PortfolioService      // portfolio queries (holdings, positions, margins, profile)
	orderSvc          *OrderService          // order placement, modification, cancellation
	alertSvc          *AlertService          // alert lifecycle (CRUD, evaluation, trailing stops, Telegram, P&L)
	familyService     *FamilyService         // family billing (invite, remove, list, tier resolution)

	// Decomposed facades over the raw fields below (Task 7 — Manager decomposition)
	stores           *StoreRegistry           // all persistence stores
	eventing         *EventingService         // domain event dispatcher + append-only store
	brokers          *BrokerServices          // kite factory, instruments, ticker, paper, riskguard
	scheduling       *SchedulingService       // cleanup routines, session cleanup hooks, metrics recording
	sessionLifecycle *SessionLifecycleService // MCP session lifecycle facade (get/create/clear/complete)

	Instruments       *instruments.Manager
	sessionManager    *SessionRegistry
	sessionSigner     *SessionSigner
	tokenStore        *KiteTokenStore             // per-email Kite token cache
	credentialStore   *KiteCredentialStore        // per-email Kite developer app credentials
	tickerService     *ticker.Service             // per-user WebSocket ticker connections
	alertStore        *alerts.Store               // per-user price alerts
	alertEvaluator    *alerts.Evaluator           // tick-to-alert matcher
	trailingStopMgr   *alerts.TrailingStopManager // trailing stop-loss manager
	watchlistStore    *watchlist.Store            // per-user watchlists
	userStore         *users.Store                // registered users (RBAC, lifecycle)
	registryStore     *registry.Store             // pre-registered Kite app credentials (key registry)
	telegramNotifier  *alerts.TelegramNotifier    // Telegram alert sender
	alertDB           *alerts.DB                  // optional: SQLite persistence for alerts
	auditStore        *audit.Store                // optional: audit trail for synthetic events
	riskGuard         *riskguard.Guard            // optional: financial safety controls
	paperEngine       *papertrading.PaperEngine   // optional: virtual trading engine
	billingStore      *billing.Store              // optional: billing tier enforcement
	invitationStore   *users.InvitationStore      // optional: family invitation management
	eventDispatcher   *domain.EventDispatcher     // optional: domain event pub/sub
	eventStore        *eventsourcing.EventStore   // optional: domain audit log (append-only, not used for state reconstitution)
	projector         *eventsourcing.Projector    // read-side projection of order/alert/position aggregates; subscribes to eventDispatcher
	mcpServer         any                         // *server.MCPServer — stored as any to avoid circular import
	kiteClientFactory KiteClientFactory           // creates zerodha.KiteSDK instances; mockable in tests
	commandBus        *cqrs.InMemoryBus           // CQRS command bus (nil until wired by app/wire.go)
	queryBus          *cqrs.InMemoryBus           // CQRS query bus (nil until wired by app/wire.go)
	appMode           string
	externalURL       string
	adminSecretPath   string
	devMode           bool
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

// CommandBus returns the CQRS command bus for write-side dispatches.
func (m *Manager) CommandBus() *cqrs.InMemoryBus {
	return m.commandBus
}

// QueryBus returns the CQRS query bus for read-side dispatches.
func (m *Manager) QueryBus() *cqrs.InMemoryBus {
	return m.queryBus
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

// DevMode returns true if the server is running in development mode with mock broker.
func (m *Manager) DevMode() bool {
	return m.devMode
}

// APIKey returns the global Kite API key.
func (m *Manager) APIKey() string {
	return m.apiKey
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

// SessionManager returns the MCP session manager instance
func (m *Manager) SessionManager() *SessionRegistry {
	return m.sessionManager
}

// ManagedSessionSvc returns the thin session facade for active-count and terminate-by-email.
func (m *Manager) ManagedSessionSvc() *ManagedSessionService {
	return m.managedSessionSvc
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

// HandleKiteCallback, handleCallbackError, extractCallbackParams,
// renderSuccessTemplate, and TemplateData live in callback_handler.go.
