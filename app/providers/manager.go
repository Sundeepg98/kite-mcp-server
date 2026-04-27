package providers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"go.uber.org/fx"

	"github.com/zerodha/kite-mcp-server/app/metrics"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/users"
)

// manager.go — Wave D Phase 2 Slice P2.5a. Provides inner-Manager
// construction as an Fx graph node.
//
// LEGACY BEHAVIOUR PRESERVED
//
// The composition site (app/wire.go:100-118) currently calls
// kc.NewWithOptions(...) directly with 17 With* helpers. P2.5a
// wraps that exact call as an Fx provider so the Manager joins the
// graph alongside the existing Phase-2 leaf providers.
//
// The 16 init helpers in kc/manager_init.go are NOT touched by
// P2.5a. The decision in ADR 0006 §"What was rejected" was that
// kc/manager_init.go's Mode-2 conflict probability is empirically
// low (~3 commits/month vs wire.go's 48/month). The user's override
// authorized this slice anyway; the lightest-touch interpretation
// is to add the OUTER Fx seam — same pattern as scheduler.go,
// riskguard.go, audit_init.go. Subsequent clusters (P2.5b/c/d) can
// iterate on the inner factoring once the seam is proven.
//
// CONFIG
//
// ManagerConfig captures the subset of app.Config fields kc.Manager
// construction needs. The composition site projects app.Config into
// ManagerConfig at the supply-into-graph boundary (matches
// AuditConfig and RiskGuardConfig conventions).
//
// WRAPPER
//
// InitializedManager wraps the post-construction *kc.Manager.
// Following the audit_init.go / riskguard.go / scheduler.go
// convention, the wrapper exists ONLY to give Fx a distinct type
// for "post-construction Manager" vs any raw *kc.Manager that
// might appear elsewhere in the graph (currently no other source,
// but the wrapper costs nothing and forecloses graph-conflict
// errors as the graph grows).
//
// LIFECYCLE
//
// kc.Manager exposes Shutdown() for graceful resource release. P2.5a
// does NOT register a lifecycle hook here — the existing
// app/wire.go:registerLifecycle (lines 818-897) already wires
// Manager-owned subsystems (telegram_bot, paper_monitor, audit_store,
// scheduler, etc.) into app.lifecycle. Hoisting Manager.Shutdown
// into fx.Lifecycle is a P2.5b candidate; for the beachhead, the
// existing lifecycle wiring is preserved unchanged.

// ManagerConfig captures the inputs kc.NewWithOptions needs. The
// shape mirrors the With* setter list at kc/options.go:60-290 plus
// the four pre-constructed sub-stores that app/wire.go threads in
// via the WithAuditStore / WithRiskGuard / WithBillingStore /
// WithInvitationStore options.
//
// Fields are declared in three groups for readability:
//   - identity:      logger, kite credentials, app mode
//   - persistence:   alertDB + path, encryption secret
//   - injected:      pre-constructed sub-stores threaded from
//                    earlier providers in the graph
type ManagerConfig struct {
	// --- identity ---

	// Logger is the structured logger. Required — BuildManager
	// returns an error when Logger is nil, matching kc.New's
	// "logger is required" contract.
	Logger *slog.Logger

	// Metrics is the optional metrics manager. Nil disables.
	Metrics *metrics.Manager

	// KiteAPIKey + KiteAPISecret are the Kite Connect app
	// credentials. Empty values produce a Logger.Warn at
	// kc.NewWithOptions but do not error — matches legacy
	// behaviour for unauthenticated dev runs.
	KiteAPIKey      string
	KiteAPISecret   string
	KiteAccessToken string

	// AppMode drives transport selection ("stdio" / "http" / "sse").
	AppMode string

	// ExternalURL is the server's externally-reachable URL
	// (used for OAuth redirects + dashboard link emission).
	ExternalURL string

	// AdminSecretPath gates the admin endpoint's path segment.
	AdminSecretPath string

	// TelegramBotToken enables alert-side Telegram notifications.
	// Empty disables the notifier (kc/manager_init.go:233-249).
	TelegramBotToken string

	// DevMode toggles the mock-broker path for local dev / tests
	// without Kite credentials.
	DevMode bool

	// InstrumentsSkipFetch is the test-isolation seam: when true,
	// the auto-created instruments manager skips the HTTP fetch of
	// api.kite.trade/instruments.json. Always false in production;
	// always true in tests.
	InstrumentsSkipFetch bool

	// --- persistence ---

	// AlertDB is the externally-opened *alerts.DB shared by audit /
	// riskguard / billing / invitation stores. When non-nil,
	// kc.Manager does NOT own its lifecycle; the composition site
	// (app/wire.go) closes via app.lifecycle.
	AlertDB *alerts.DB

	// AlertDBPath is the legacy alternative to AlertDB. When AlertDB
	// is nil and AlertDBPath is non-empty, kc.Manager opens the DB
	// internally and owns its lifecycle. Kept for backward compat
	// with test fixtures that haven't migrated to externally-owned DB.
	AlertDBPath string

	// EncryptionSecret derives the credential-encryption key via
	// HKDF in alerts.EnsureEncryptionSalt. Typically the same value
	// as OAUTH_JWT_SECRET. Empty disables credential encryption at
	// rest — safe for dev, fatal for production (caller enforces).
	EncryptionSecret string

	// --- injected (pre-constructed sub-stores) ---

	// AuditStore is the pre-constructed *audit.Store. When non-nil,
	// threaded into Manager via kc.WithAuditStore — replaces the
	// post-init kcManager.SetAuditStore call site.
	AuditStore *audit.Store

	// RiskGuard is the pre-constructed *riskguard.Guard. Same
	// inversion-seam contract as AuditStore.
	RiskGuard *riskguard.Guard

	// BillingStore is the pre-constructed *billing.Store.
	BillingStore *billing.Store

	// InvitationStore is the pre-constructed *users.InvitationStore.
	InvitationStore *users.InvitationStore
}

// InitializedManager wraps the post-construction *kc.Manager. The
// wrapper exists ONLY to give Fx a distinct type for graph
// resolution — the Manager field is the same pointer
// kc.NewWithOptions returned, no defensive copy.
//
// Per the wrapper-type convention (audit_init.go, riskguard.go,
// scheduler.go): the wrapper is structural, not behavioural. All
// call sites that need the Manager unwrap via the Manager field.
type InitializedManager struct {
	// Manager is the post-construction *kc.Manager. Always non-nil
	// when the wrapper itself is non-nil (BuildManager returns
	// nil-wrapper on error).
	Manager *kc.Manager
}

// managerInput is the Fx fan-in struct convention. Following the
// audit_init.go (auditInitInput) and scheduler.go (schedulerInput,
// not yet declared but anticipated) precedent, this groups the
// fx.Supply'd inputs so the BuildManager signature stays a single
// argument.
//
// Ctx is included because kc.NewWithOptions takes a base context as
// its first positional argument. Fx supplies it via fx.Supply at
// the composition site.
type managerInput struct {
	fx.In

	Ctx    context.Context
	Config ManagerConfig
}

// BuildManager constructs the inner *kc.Manager via the existing
// kc.NewWithOptions orchestrator. P2.5a contract:
//
//	(*InitializedManager, nil) — Manager constructed successfully.
//	                              Wrapper.Manager is the live pointer.
//	(nil, error)                — Construction failed. Error message
//	                              preserves the kc-package error class
//	                              (e.g. "logger is required") so log-
//	                              search rules / alerts continue to
//	                              match.
//
// The 17 With* setters that wire ManagerConfig fields into
// kc.NewWithOptions match the 17 call sites at app/wire.go:101-117.
// Field-by-field correspondence is documented inline so a future
// audit can verify no field is silently dropped.
func BuildManager(in managerInput) (*InitializedManager, error) {
	cfg := in.Config

	// Nil-logger short-circuit. kc.NewWithOptions performs the same
	// check internally, but surfacing it here lets the Fx graph
	// fail at the provider boundary rather than deeper inside
	// kc.Manager construction. Error text preserved verbatim so
	// existing test assertions (kc.New "logger is required") still
	// match downstream consumers that observe the error message.
	if cfg.Logger == nil {
		return nil, errors.New("logger is required")
	}

	ctx := in.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	// Field-by-field projection of ManagerConfig into the With*
	// setter chain. Mirrors app/wire.go:101-117 exactly. Order
	// follows the kc/options.go declaration order for readability.
	mgr, err := kc.NewWithOptions(ctx,
		kc.WithLogger(cfg.Logger),
		kc.WithKiteCredentials(cfg.KiteAPIKey, cfg.KiteAPISecret),
		kc.WithAccessToken(cfg.KiteAccessToken),
		kc.WithMetrics(cfg.Metrics),
		kc.WithTelegramBotToken(cfg.TelegramBotToken),
		kc.WithAlertDB(cfg.AlertDB),
		kc.WithAlertDBPath(cfg.AlertDBPath),
		kc.WithAppMode(cfg.AppMode),
		kc.WithExternalURL(cfg.ExternalURL),
		kc.WithAdminSecretPath(cfg.AdminSecretPath),
		kc.WithEncryptionSecret(cfg.EncryptionSecret),
		kc.WithDevMode(cfg.DevMode),
		kc.WithInstrumentsSkipFetch(cfg.InstrumentsSkipFetch),
		kc.WithAuditStore(cfg.AuditStore),
		kc.WithRiskGuard(cfg.RiskGuard),
		kc.WithBillingStore(cfg.BillingStore),
		kc.WithInvitationStore(cfg.InvitationStore),
	)
	if err != nil {
		// Wrap with the same prefix wire.go:120 uses so log-search
		// rules continue to match: "failed to create Kite Connect
		// manager:".
		return nil, fmt.Errorf("failed to create Kite Connect manager: %w", err)
	}

	return &InitializedManager{Manager: mgr}, nil
}
