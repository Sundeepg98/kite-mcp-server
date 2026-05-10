package kc

import (
	"errors"
	"html/template"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/app/metrics"
	"github.com/algo2go/kite-mcp-alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/algo2go/kite-mcp-domain"
	"github.com/zerodha/kite-mcp-server/kc/eventsourcing"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
	"github.com/zerodha/kite-mcp-server/kc/registry"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/ticker"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
	"github.com/algo2go/kite-mcp-users"
	"github.com/zerodha/kite-mcp-server/kc/watchlist"
)

// manager_struct.go holds the Manager state declaration plus the small set
// of package-level constants and sentinel errors that surround it.
//
// Anchor 6 PR 6.15 relocated this from kc/manager.go so manager.go can
// stay focused on the constructor surface (New / NewWithOptions /
// NewManager). Pure file move — no behaviour change.

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

// KiteSessionData is the transient runtime state of an authenticated MCP
// session. Anchor 5 PR 5.6 relocated the canonical declaration to
// kc/domain/session.go (its proper bounded-context home — see
// anchor-5-prs-design.md). This alias preserves the legacy
// kc.KiteSessionData reference path so the 56-file reverse-dep set
// continues to compile via existing imports.
//
// The PR also collapsed the kc.KiteConnect wrapper indirection: the
// Kite field is now zerodha.KiteSDK (interface) directly, not
// *KiteConnect (one-field struct holding the same SDK). All callsites
// migrated from `.Kite.Client.METHOD(...)` to `.Kite.METHOD(...)`.
// The kc.KiteConnect type + NewKiteConnect helper remain available
// (see kc/kite_connect.go) for the few callers that still need a
// *KiteConnect pointer; the field type change is a deliberate decoupling
// so kc/domain can host KiteSessionData without depending on the kc
// parent package.
type KiteSessionData = domain.KiteSessionData

type Manager struct {
	apiKey      string
	apiSecret   string
	accessToken string
	Logger      *slog.Logger
	metrics     *metrics.Manager

	templates map[string]*template.Template

	// Focused service objects (Clean Architecture)
	CredentialSvc     *CredentialService     // credential resolution (per-user + global)
	SessionSvc        *SessionService        // MCP session lifecycle
	managedSessionSvc *ManagedSessionService // thin session facade (active count, terminate-by-email)
	PortfolioSvc      *PortfolioService      // portfolio queries (holdings, positions, margins, profile)
	OrderSvc          *OrderService          // order placement, modification, cancellation
	AlertSvc          *AlertService          // alert lifecycle (CRUD, evaluation, trailing stops, Telegram, P&L)
	FamilyService     *FamilyService         // family billing (invite, remove, list, tier resolution)

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
	// resolution flows through m.SessionSvc on dispatch.
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
	// m.SessionSvc as the BrokerResolver (post-Wave-D pattern).
	// GetActivityForWidget has no broker resolver dimension at all so
	// it's not a Wave D site; it stays per-dispatch construction.
	getPortfolioForWidgetUC *usecases.GetPortfolioForWidgetUseCase
	getAlertsForWidgetUC    *usecases.GetAlertsForWidgetUseCase
}
