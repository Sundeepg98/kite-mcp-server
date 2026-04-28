package kc

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log/slog"

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
	"github.com/zerodha/kite-mcp-server/kc/ticker"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
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

	// BotFactory is an optional per-Manager Telegram bot factory. When
	// non-nil, alerts.NewTelegramNotifierWithFactory is used to construct
	// the notifier — bypassing the kc/alerts package-level newBotFunc
	// global. Tests pass a fake-server-backed factory here to avoid the
	// global-mutex OverrideNewBotFunc pattern, unblocking t.Parallel.
	// Production wiring leaves this nil so the default tgbotapi.NewBotAPI
	// path is used.
	BotFactory alerts.BotFactory

	// AlertDB is an optional pre-opened SQLite database. When non-nil,
	// initPersistence uses this DB directly instead of calling
	// alerts.OpenDB(AlertDBPath). This is the inversion seam that lets
	// app/wire.go open the DB once and construct DB-backed stores
	// (audit, riskguard, billing, invitation) BEFORE kc.NewWithOptions —
	// breaking the cycle where those stores were post-wired via SetX
	// setters from the manager's own AlertDB() accessor. AlertDBPath is
	// ignored when this is non-nil (the manager does not close a DB it
	// did not open).
	AlertDB *alerts.DB

	// AuditStore, RiskGuard, BillingStore, InvitationStore are optional
	// pre-constructed stores. When non-nil, the manager populates the
	// matching field directly during init, replacing the post-construction
	// SetX setter pattern (which is retained as deprecated shims for
	// backward compatibility with the ~70+ test sites that still use it).
	//
	// Production wiring (app/wire.go) uses these in combination with
	// AlertDB to break the construction cycle. Tests that don't need
	// these stores can leave them nil and the manager runs without them
	// (matching legacy behaviour).
	AuditStore      *audit.Store
	RiskGuard       *riskguard.Guard
	BillingStore    *billing.Store
	InvitationStore *users.InvitationStore
}

// New creates a new kc Manager with the given configuration.
//
// Deprecated: prefer NewWithOptions(ctx, opts...) which uses the
// functional-options pattern consistent with the rest of the codebase
// (testutil/kcfixture, kc/ticker/config.go, kc/scheduler/provider.go).
// This function is retained as a thin backward-compat shim because
// 40+ test files across app/, mcp/, and kc/ops/ call it directly with
// literal kc.Config{…} structs; forcing all of them to migrate at once
// would ripple through three scopes owned by other active agents.
//
// New is equivalent to NewWithOptions(context.Background(), WithConfig(cfg)).
// It validates cfg.Logger is non-nil (matching pre-shim behaviour) before
// delegating — preserving the error class "logger is required" so
// existing tests that rely on that exact error message keep passing.
func New(cfg Config) (*Manager, error) {
	if cfg.Logger == nil {
		return nil, errors.New("logger is required")
	}
	return NewWithOptions(context.Background(), WithConfig(cfg))
}

// NewWithOptions creates a new kc Manager from a base context plus a
// list of functional options. Primary constructor for the Manager —
// backward-compat paths flow through New(Config) above.
//
// The body is a thin orchestrator over the init* helpers in
// kc/manager_init.go. Each helper is documented at its declaration
// site; the order below is load-bearing — downstream phases read
// state that earlier phases wrote. Do not reorder without re-reading
// the helper docs.
//
// ctx is currently stashed on the options payload for future use
// (cancellable init, tracing spans, deadline propagation); no init
// phase consumes it yet, but the plumbing is in place so that flip
// does not later become a breaking change.
func NewWithOptions(ctx context.Context, opts ...Option) (*Manager, error) {
	o := &options{Ctx: ctx}
	for _, opt := range opts {
		if opt != nil {
			opt(o)
		}
	}
	if o.Ctx == nil {
		o.Ctx = context.Background()
	}

	cfg := o.Config
	if cfg.Logger == nil {
		return nil, errors.New("logger is required")
	}
	if cfg.APIKey == "" || cfg.APISecret == "" {
		cfg.Logger.Warn("No Kite API credentials configured")
	}

	instrumentsManager, err := initInstrumentsManager(cfg)
	if err != nil {
		return nil, err
	}

	m := newEmptyManager(cfg)

	m.initAlertSystem(cfg)
	m.initPersistence(cfg)
	m.initCredentialWiring()
	m.initTelegramNotifier(cfg)
	m.initAlertEvaluator(cfg)
	m.initTrailingStop(cfg)
	m.initSideStores(cfg)
	m.initInjectedStores(cfg) // populate auditStore/riskGuard/billingStore/invitationStore from cfg
	m.initCredentialService(cfg) // also wires trailing-stop order modifier
	m.initTickerService(cfg)

	if err := m.initializeTemplates(); err != nil {
		return nil, fmt.Errorf("failed to initialize Kite manager: %w", err)
	}
	if err := m.initializeSessionSigner(cfg.SessionSigner); err != nil {
		return nil, fmt.Errorf("failed to initialize session signer: %w", err)
	}

	m.initFocusedServices(cfg, instrumentsManager)
	m.initSessionPersistence(cfg)
	m.initTokenRotation()
	m.initProjector()

	// Wave D Slice D2: hoist order-write use cases from per-request
	// construction in registerOrderCommands to startup-once Manager fields.
	// Must run AFTER initFocusedServices (provides sessionSvc) and BEFORE
	// registerCQRSHandlers (consumes the fields).
	m.initOrderUseCases()

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
	ownsAlertDB       bool                        // true => Manager.Shutdown closes alertDB; false when supplied via Config.AlertDB
	encryptionKey     []byte                      // AES-256 key derived via HKDF from cfg.EncryptionSecret; mirrors alertDB.encryptionKey for stores that encrypt outside the alerts.DB layer (e.g. users.Store TOTP secrets)
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

	// Wave D Phase 1 Slice D2: order-write use cases hoisted from
	// per-request construction inside CommandBus handlers to startup-once
	// fields. The handlers in kc/manager_commands_orders.go reach through
	// these instead of calling usecases.NewXxx() per dispatch. Constructed
	// in initOrderUseCases (kc/manager_use_cases.go) after the Manager has
	// sessionSvc / riskGuard / eventing.Dispatcher available — see the
	// init helper for the full preconditions list. Wire/fx-compatible by
	// design: each field is a startup-once value with stable dependencies.
	//
	// Naming convention: <domain>UC for the use-case fields. By the
	// end of Wave D Phase 1 (Slice D7), all 13 previously per-request
	// use cases either live on Manager (12 fields below) or stay
	// per-dispatch for principled reasons (Activity widget +
	// ctx-bound audit-store override, Orders widget same).
	placeOrderUC  *usecases.PlaceOrderUseCase
	modifyOrderUC *usecases.ModifyOrderUseCase
	cancelOrderUC *usecases.CancelOrderUseCase

	// Wave D Phase 1 Slice D3: GTT (Good Till Triggered) write use cases
	// hoisted from per-request construction. Same pattern as the order
	// triple above. GTT use cases additionally consume the
	// eventDispatcher for typed GTTPlaced/Modified/Cancelled events
	// (wired at construction in initOrderUseCases).
	placeGTTUC  *usecases.PlaceGTTUseCase
	modifyGTTUC *usecases.ModifyGTTUseCase
	deleteGTTUC *usecases.DeleteGTTUseCase

	// Wave D Phase 1 Slice D4: position-exit write use cases hoisted
	// from per-request construction. ClosePosition closes one position
	// by placing an opposite MARKET order; CloseAllPositions iterates
	// through filtered positions placing one opposite per slot. Both
	// run riskguard before the broker call.
	closePositionUC     *usecases.ClosePositionUseCase
	closeAllPositionsUC *usecases.CloseAllPositionsUseCase

	// Wave D Phase 1 Slice D5: margin-query use cases hoisted from
	// per-request construction. All three are read-side queries
	// (estimate margin / charges before placing an order); broker
	// resolution flows through m.sessionSvc on dispatch.
	getOrderMarginsUC  *usecases.GetOrderMarginsUseCase
	getBasketMarginsUC *usecases.GetBasketMarginsUseCase
	getOrderChargesUC  *usecases.GetOrderChargesUseCase

	// Wave D Phase 1 Slice D6: widget read-side use cases.
	//
	// GetPortfolioForWidget — clean hoist: only depends on the broker
	// resolver. Constructed once in initOrderUseCases.
	//
	// GetAlertsForWidget — hoist: depends on broker resolver +
	// alertStore (a Manager field, stable for the manager's lifetime
	// after initAlertSystem runs). Constructed once.
	//
	// GetOrdersForWidget is intentionally NOT hoisted: its second
	// dependency (audit store) can come either from a ctx-bound
	// override (test-isolation contract via cqrs.WithWidgetAuditStore)
	// OR from the Manager's audit store. Hoisting at startup would
	// lock the audit store choice and break the test fixture. The
	// handler keeps per-dispatch use case construction but uses
	// m.sessionSvc as the BrokerResolver (post-Wave-D pattern).
	// GetActivityForWidget has no broker resolver dimension at all so
	// it's not a Wave D site; it stays per-dispatch construction.
	getPortfolioForWidgetUC *usecases.GetPortfolioForWidgetUseCase
	getAlertsForWidgetUC    *usecases.GetAlertsForWidgetUseCase
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

// Service accessors (CredentialSvc, SessionSvc, PortfolioSvc, OrderSvc,
// AlertSvc, FamilyService + SetFamilyService, CommandBus, QueryBus,
// SessionManager, ManagedSessionSvc, SessionSigner, UpdateSessionSignerExpiry,
// SetMCPServer, MCPServer) live in kc/manager_accessors.go — pure
// field-returning passthroughs.
//
// IsLocalMode, ExternalURL, AdminSecretPath, DevMode, APIKey, and
// OpenBrowser live in kc/config_manager.go — pure config accessors +
// the local-mode browser opener.

// initializeTemplates, initializeSessionSigner, Shutdown, setupTemplates,
// and the sessionDBAdapter bridge live in kc/manager_lifecycle.go —
// the Manager's startup/shutdown surface.

// truncKey safely returns the first n characters of a string, or the whole string if shorter.
func truncKey(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// HandleKiteCallback, handleCallbackError, extractCallbackParams,
// renderSuccessTemplate, and TemplateData live in callback_handler.go.
