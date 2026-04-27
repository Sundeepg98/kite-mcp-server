package app

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/eventsourcing"
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/mcp"
	"github.com/zerodha/kite-mcp-server/plugins/rolegate"
	"github.com/zerodha/kite-mcp-server/plugins/telegramnotify"
	stripe "github.com/stripe/stripe-go/v82"
	"go.uber.org/fx"

	"github.com/zerodha/kite-mcp-server/app/providers"
)

// emailHasherAdapter bridges kc/audit.HashEmail to the usecases.EmailHasher
// port. Trivial passthrough — exists only because importing audit from the
// usecases package would create a cycle (audit → usecases → audit).
type emailHasherAdapter struct{}

func (emailHasherAdapter) HashEmail(email string) string { return audit.HashEmail(email) }

func (app *App) initializeServices() (*kc.Manager, *server.MCPServer, error) {
	if err := app.envCheck(); err != nil {
		return nil, nil, fmt.Errorf("environment validation failed: %w", err)
	}
	app.logger.Info("Creating Kite Connect manager...")
	// InstrumentsSkipFetch is a test-only seam that causes the instruments
	// manager to load an empty map instead of fetching
	// api.kite.trade/instruments.json at startup. Populated from the
	// INSTRUMENTS_SKIP_FETCH env var by ConfigFromEnv; tests that drop
	// t.Setenv in favour of t.Parallel pass it via the Config struct
	// literal instead. Never set in production.
	skipInstrumentsFetch := app.Config.InstrumentsSkipFetch

	// AlertDB cycle inversion (step 3): open the SQLite DB BEFORE
	// kc.NewWithOptions so DB-backed stores (audit/riskguard/billing/
	// invitation) can be constructed and threaded through as With*
	// options instead of post-wired via SetX setters. The DB lifecycle
	// is owned by app/lifecycle here (registered below) — the manager
	// honors cfg.AlertDB by setting ownsAlertDB=false on its side.
	//
	// Failure modes:
	//   - empty path: in-memory mode, alertDB stays nil (matches legacy).
	//   - open error: log + fall through with nil alertDB; same downgrade
	//     path as before (manager would have logged the same error).
	var alertDB *alerts.DB
	if app.Config.AlertDBPath != "" {
		if opened, dbErr := alerts.OpenDB(app.Config.AlertDBPath); dbErr != nil {
			app.logger.Error("Failed to open alert DB, using in-memory only", "error", dbErr)
		} else {
			alertDB = opened
			app.alertDB = opened // lifecycle "alert_db" closes this on shutdown
		}
	}

	// Pre-construct the 4 cycle-affected stores so they can be passed
	// via With* options. Gate each one on the SAME conditions the
	// legacy post-NewWithOptions wiring used, so kcManager.X() accessors
	// return the same nil/non-nil shape as before:
	//   - audit / invitation: gated on alertDB != nil (legacy: same).
	//   - billing: additionally gated on Stripe key + non-DevMode
	//     (legacy: line 504's stripeKey != "" && !app.DevMode).
	//   - riskGuard: always allocated (legacy: line 218 unconditional).
	// InitTable / LoadFromDB calls run AFTER NewWithOptions on the same
	// pointer — the alert-trigger closure in kc/manager_init.go reads
	// m.auditStore lazily, so allocation-vs-InitTable order is moot.
	var preAuditStore *audit.Store
	var preBillingStore *billing.Store
	var preInvStore *users.InvitationStore
	preRiskGuard := riskguard.NewGuard(app.logger)
	if alertDB != nil {
		preAuditStore = audit.New(alertDB)
		preInvStore = users.NewInvitationStore(alertDB)
		if app.Config.StripeSecretKey != "" && !app.DevMode {
			preBillingStore = billing.NewStore(alertDB, app.logger)
		}
	}

	// Migrated to kc.NewWithOptions — the functional-options pattern
	// aligns with the rest of the codebase (testutil/kcfixture,
	// kc/ticker/config.go, kc/scheduler/provider.go). Each With* helper
	// documents the one field it sets; granular setters compose cleanly
	// at the composition-root boundary.
	kcManager, err := kc.NewWithOptions(context.Background(),
		kc.WithLogger(app.logger),
		kc.WithKiteCredentials(app.Config.KiteAPIKey, app.Config.KiteAPISecret),
		kc.WithAccessToken(app.Config.KiteAccessToken),
		kc.WithMetrics(app.metrics),
		kc.WithTelegramBotToken(app.Config.TelegramBotToken),
		kc.WithAlertDB(alertDB),
		kc.WithAlertDBPath(app.Config.AlertDBPath),
		kc.WithAppMode(app.Config.AppMode),
		kc.WithExternalURL(app.Config.ExternalURL),
		kc.WithAdminSecretPath(app.Config.AdminSecretPath),
		kc.WithEncryptionSecret(app.Config.OAuthJWTSecret),
		kc.WithDevMode(app.DevMode),
		kc.WithInstrumentsSkipFetch(skipInstrumentsFetch),
		kc.WithAuditStore(preAuditStore),
		kc.WithRiskGuard(preRiskGuard),
		kc.WithBillingStore(preBillingStore),
		kc.WithInvitationStore(preInvStore),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create Kite Connect manager: %w", err)
	}

	// Store reference for template data
	app.kcManager = kcManager

	// Register lifecycle stops up front. Each closure nil-checks its target
	// field at Shutdown time, so registering before the workers are wired
	// is safe — and registering early lets the success-defer below collapse
	// to a single lifecycle.Shutdown() call. T2.3: closes 5 leak holes
	// (telegram_bot, oauth_handler, invitation_cleanup, rate_limiters,
	// metrics) that the prior 7-line manual unwind missed because they
	// hadn't been added to the defer when those workers were introduced.
	app.registerLifecycle(kcManager)

	// Track whether initializeServices returns a live manager or one of its
	// error paths. Without this, a failure AFTER kcManager construction
	// (e.g., the "audit trail required in production" guard below) leaks
	// the Kite manager's background goroutines AND any app-level workers
	// (scheduler, audit, paperMonitor, hashPublisher) that were wired
	// before the failure. Callers cannot reach Shutdown on a nil return.
	//
	// Phase A scheduler+hashPublisher run inline (block new work before
	// any in-flight drain — same posture as setupGracefulShutdown). Phase
	// C is owned by the lifecycle manager — sync.Once-guarded, idempotent
	// vs setupGracefulShutdown which calls lifecycle.Shutdown() too.
	success := false
	defer func() {
		if !success {
			if app.scheduler != nil {
				app.scheduler.Stop()
			}
			if app.hashPublisherCancel != nil {
				app.hashPublisherCancel()
			}
			app.lifecycle.Shutdown()
		}
	}()

	// Initialize the status template early for the status page
	if err := app.initStatusPageTemplate(); err != nil {
		app.logger.Warn("Failed to initialize status template", "error", err)
	}

	app.logger.Debug("Kite Connect manager created successfully")

	// Audit store: the pointer was constructed pre-NewWithOptions and
	// already threaded into the manager via WithAuditStore (cycle inversion
	// step 3). app.auditStore tracks the same pointer so post-construction
	// setup (InitTable / encryption / StartWorker / middleware build) keeps
	// working unchanged. The previous kcManager.SetAuditStore(app.auditStore)
	// call site is now redundant — the manager's m.auditStore field was
	// populated by initInjectedStores during NewWithOptions.
	//
	// H1 fix (phase 2i): audit trail is a compliance requirement. In production
	// mode, fail fast if the audit table cannot be created — silently running
	// without audit middleware hides every tool call from the regulator. In
	// DevMode, log and continue so local dev without a DB still works.
	//
	// Wave D Phase 2 Slice P2.3b: the imperative chain that used to
	// live here (InitTable + EnsureEncryptionSalt + SetEncryptionKey +
	// SeedChain + SetLogger + StartWorker + audit.Middleware + hash-
	// publisher) is now an Fx-resolved provider graph. Two providers:
	//
	//   providers.InitializeAuditStore — runs the init chain and
	//     returns the SAME *audit.Store pointer iff init fully
	//     succeeded; nil if DevMode swallowed an error. Production
	//     failures bubble through as fx.New(...).Err().
	//
	//   providers.ProvideAuditMiddleware — pure function; given the
	//     post-init store (possibly nil), returns the middleware
	//     (possibly nil). Wired by the type graph to consume only
	//     the post-init store, so middleware is dropped iff init
	//     skipped (DevMode-init-failed path).
	//
	// app.auditStore / auditMiddleware / app.hashPublisherCancel keep
	// the same shape downstream — only the construction style
	// changed. Lifecycle hooks for store.Stop and alert_db.Close
	// already live in app.registerLifecycle (lines 825-855); not
	// duplicated here. hash-publisher cancel stays on
	// app.hashPublisherCancel for the existing wire.go:151-153
	// success-defer path; not lifecycled.
	var auditMiddleware server.ToolHandlerMiddleware
	var initialized *providers.InitializedAuditStore
	app.auditStore = preAuditStore
	alertDBForAudit := kcManager.AlertDB()
	if alertDBForAudit == nil && !app.DevMode {
		return nil, nil, fmt.Errorf("audit trail required in production: no alert DB configured (set ALERT_DB_PATH)")
	}

	auditCfg := providers.AuditConfig{
		OAuthJWTSecret: app.Config.OAuthJWTSecret,
		DevMode:        app.DevMode,
	}
	auditFxApp := fx.New(
		fx.NopLogger,
		fx.Supply(app.auditStore),
		fx.Supply(alertDBForAudit),
		fx.Supply(auditCfg),
		fx.Supply(app.logger),
		fx.Provide(providers.InitializeAuditStore),
		fx.Provide(providers.ProvideAuditMiddleware),
		fx.Populate(&initialized, &auditMiddleware),
	)
	if err := auditFxApp.Err(); err != nil {
		// fx.New surfaces the production-mode startup-error class
		// from InitializeAuditStore. The error message preserves the
		// "audit trail required in production:" prefix from the
		// legacy code so log/alerting rules continue to match.
		return nil, nil, err
	}

	// In the DevMode-init-failed path, initialized.Store is nil and
	// auditMiddleware is nil — drop app.auditStore so downstream
	// readers (riskGuard baseline, anomaly cache, register-tools, etc.)
	// see a nil store and skip audit-dependent wiring. Matches the
	// legacy "audit trail disabled" behavior at wire.go:184 + 220.
	if initialized != nil {
		app.auditStore = initialized.Store
	} else {
		app.auditStore = nil
	}

	// Hash-publisher: kept at composition site per HASH-PUBLISHER NOTE
	// in providers/audit_init.go. SEBI CSCRF: publishing the chain tip
	// to external storage prevents an attacker with DB write access
	// from rewriting the audit log history undetected.
	if app.auditStore != nil {
		app.hashPublisherCancel = providers.StartAuditHashPublisher(app.auditStore, auditCfg, app.logger)
	}

	// Initialize DPDP Act 2023 consent log (separate table from tool-call audit).
	// Shares the alerts.DB connection pool — no new *sql.DB. Fails open in
	// DevMode (matches the tool-call audit behaviour above) but fails hard in
	// production: a missing consent log is a compliance gap the Data Protection
	// Board may flag during an audit.
	if alertDB := kcManager.AlertDB(); alertDB != nil {
		app.consentStore = audit.NewConsentStore(alertDB)
		if err := app.consentStore.InitTable(); err != nil {
			if !app.DevMode {
				return nil, nil, fmt.Errorf("consent log required in production: init table: %w", err)
			}
			app.logger.Error("Failed to initialize consent log table (DevMode: continuing)", "error", err)
			app.consentStore = nil
		} else {
			app.logger.Info("DPDP consent log enabled")
		}
	}

	// PR-D Item 1: register the WithdrawConsentCommand bus handler.
	// We do it here in app/wire.go (not kc/manager_commands_*.go)
	// because consentStore lives in the app package — the alternative
	// is plumbing it through the manager, but the consent log is
	// strictly an audit concern with no manager-side consumers.
	if app.consentStore != nil {
		bus := kcManager.CommandBus()
		if bus != nil {
			err := bus.Register(reflect.TypeFor[cqrs.WithdrawConsentCommand](), func(ctx context.Context, msg any) (any, error) {
				cmd, ok := msg.(cqrs.WithdrawConsentCommand)
				if !ok {
					return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
				}
				uc := usecases.NewWithdrawConsentUseCase(
					app.consentStore,
					emailHasherAdapter{},
					kcManager.EventDispatcher(),
					app.logger,
				)
				return uc.Execute(ctx, cmd)
			})
			if err != nil {
				app.logger.Error("Failed to register WithdrawConsentCommand handler", "error", err)
			}
		}
	}

	// Initialize riskguard for financial safety controls.
	//
	// H2 fix (phase 2i): LoadLimits failure used to silently fall back to
	// in-memory defaults — which would WIPE a user-configured kill switch and
	// allow trading to proceed without their limits. Fail fast in production.
	//
	// Cycle inversion step 3: riskGuard was constructed pre-NewWithOptions
	// (preRiskGuard) and threaded into the manager via WithRiskGuard. The
	// reassignment here keeps the local name 'riskGuard' for the rest of
	// the setup block (auto-freeze closure) without changing semantics —
	// same pointer the manager holds.
	//
	// Wave D Phase 2 Slice P2.4c: DB init + LoadLimits + lookup wiring +
	// plugin discovery delegated to providers.InitializeRiskGuard via an
	// Fx graph. The auto-freeze closure stays at the composition site
	// because it captures kcManager (for lazy EventDispatcher resolution)
	// and AdminEmails (app-package state). Same split rationale as the
	// scheduler P2.4b BriefingService construction.
	riskGuard := preRiskGuard

	var rgInit *providers.InitializedRiskGuard
	{
		var freezeLookup riskguard.FreezeQuantityLookup
		if im := kcManager.InstrumentsManagerConcrete(); im != nil {
			freezeLookup = &instrumentsFreezeAdapter{mgr: im}
		}
		var ltpLookup riskguard.LTPLookup = &riskguardLTPAdapter{manager: kcManager}
		rgCfg := providers.RiskGuardConfig{
			DevMode:   app.DevMode,
			PluginDir: app.Config.RiskguardPluginDir,
		}
		fxApp := fx.New(
			fx.NopLogger,
			fx.Supply(riskGuard),
			fx.Provide(func() *alerts.DB { return kcManager.AlertDB() }),
			fx.Provide(func() riskguard.FreezeQuantityLookup { return freezeLookup }),
			fx.Provide(func() riskguard.LTPLookup { return ltpLookup }),
			fx.Provide(func() *audit.Store { return app.auditStore }),
			fx.Supply(rgCfg),
			fx.Supply(app.logger),
			fx.Provide(providers.InitializeRiskGuard),
			fx.Populate(&rgInit),
		)
		if err := fxApp.Err(); err != nil {
			return nil, nil, err
		}
	}
	app.riskLimitsLoaded = rgInit.LimitsLoaded
	app.riskGuard = riskGuard

	// Wire auto-freeze Telegram admin notification + domain event dispatch.
	// STAYS at composition site: closure captures kcManager (for lazy
	// EventDispatcher resolution), notifier (snapshot at construction
	// time), and admin emails — all app-package state that doesn't
	// belong inside providers/.
	{
		adminEmails := strings.Split(app.Config.AdminEmails, ",")
		notifier := kcManager.TelegramNotifier()
		riskGuard.SetAutoFreezeNotifier(func(email, reason string) {
			// Dispatch domain event (eventDispatcher is set on kcManager after this closure is created,
			// but the closure captures kcManager by reference so it picks up the dispatcher once wired).
			if d := kcManager.EventDispatcher(); d != nil {
				d.Dispatch(domain.UserFrozenEvent{
					Email:    email,
					FrozenBy: "riskguard:circuit-breaker",
					Reason:   reason,
					Timestamp: time.Now().UTC(),
				})
			}
			// Telegram admin notification.
			if notifier == nil {
				return
			}
			for _, adminEmail := range adminEmails {
				adminEmail = strings.TrimSpace(strings.ToLower(adminEmail))
				if adminEmail == "" {
					continue
				}
				chatID, ok := kcManager.TelegramStore().GetTelegramChatID(adminEmail)
				if !ok {
					continue
				}
				msg := fmt.Sprintf("<b>RiskGuard Alert</b>\nAuto-froze trading for <b>%s</b>\nReason: %s", email, reason)
				if err := notifier.SendHTMLMessage(chatID, msg); err != nil {
					app.logger.Error("Failed to send auto-freeze Telegram alert to admin", "admin", adminEmail, "error", err)
				}
			}
		})
		if notifier != nil {
			app.logger.Info("RiskGuard auto-freeze Telegram notifications wired")
		}
	}
	// Note: kcManager.SetRiskGuard(riskGuard) is no longer needed — the
	// manager's riskGuard field was populated by initInjectedStores via
	// WithRiskGuard at construction time (cycle inversion step 3).

	// Initialize domain event dispatcher and audit log.
	// Events flow: use case -> EventDispatcher.Dispatch() -> makeEventPersister() -> domain_events table.
	// This is a write-only audit trail — events are never read back for state reconstitution.
	eventDispatcher := domain.NewEventDispatcher()
	kcManager.SetEventDispatcher(eventDispatcher)
	// Riskguard counters aggregate emits typed Riskguard*Event values
	// (kill-switch trip/lift, daily-counter reset, rejection recorded)
	// onto the same dispatcher. Nil-safe — calling SetEventDispatcher
	// before subscribers are registered is fine; dispatch is synchronous
	// and the dispatcher's handler map is empty until subscriptions land
	// below. See kc/riskguard/lifecycle.go for the emit sites.
	if riskGuard != nil {
		riskGuard.SetEventDispatcher(eventDispatcher)
	}
	// Anomaly cache aggregate emits typed AnomalyCache*Event values
	// (baseline snapshot, user-scoped invalidation, per-entry eviction)
	// onto the shared dispatcher. Nil-safe — auditStore may be nil in
	// DevMode without ALERT_DB_PATH, and the cache itself tolerates a
	// nil dispatcher. See kc/audit/anomaly_cache.go for the emit sites.
	if app.auditStore != nil {
		app.auditStore.SetAnomalyCacheEventDispatcher(eventDispatcher)
	}
	if alertDB := kcManager.AlertDB(); alertDB != nil {
		eventStore := eventsourcing.NewEventStore(alertDB)
		if err := eventStore.InitTable(); err != nil {
			app.logger.Error("Failed to initialize domain_events table", "error", err)
		} else {
			// PR-B: outbox staging table + async pump for hot mutation
			// paths. Drains event_outbox → domain_events every 100ms,
			// recovers leftover entries from a previous crashed process
			// at startup. Hot use cases (place/modify/cancel/create_alert)
			// write to the outbox first; the pump consumes asynchronously.
			if err := eventStore.InitOutboxTable(); err != nil {
				app.logger.Error("Failed to initialize event_outbox table", "error", err)
			} else {
				app.outboxPump = eventsourcing.NewOutboxPump(eventStore, app.logger)
				app.logger.Info("Event outbox pump started")
			}
			kcManager.SetEventStore(eventStore)

			// Wave D Phase 2 Slice P2.4f: the 36 imperative
			// Subscribe calls that used to live here are delegated
			// to providers.BuildEventSubscriptions. The full list
			// (event-type, aggregate-type) is the public
			// providers.CanonicalPersisterSubscriptions slice; see
			// that file for the per-event rationale comments that
			// previously inlined here. Order, count, and per-event
			// aggregate-type mapping are preserved exactly.
			//
			// makeEventPersister stays in app/adapters.go (depends
			// on package-private deriveAggregateID + deriveEmailHash)
			// — composition closes over eventStore + logger and
			// supplies the closure as PersisterBuilder.
			var edInit *providers.InitializedEventDispatcher
			edFxApp := fx.New(
				fx.NopLogger,
				fx.Supply(providers.EventDispatcherDeps{
					Dispatcher: eventDispatcher,
					PersisterBuilder: func(aggType string) func(domain.Event) {
						return makeEventPersister(eventStore, aggType, app.logger)
					},
				}),
				fx.Provide(providers.BuildEventSubscriptions),
				fx.Populate(&edInit),
			)
			if err := edFxApp.Err(); err != nil {
				app.logger.Error("Failed to wire event dispatcher subscriptions", "error", err)
			} else {
				app.logger.Info("Domain event store initialized and subscribed",
					"subscription_count", edInit.SubscriptionCount)
			}
		}
	}

	// Wire the shared event dispatcher into the billing store so
	// SetSubscription emits TierChangedEvent on real tier transitions.
	// Billing store is constructed earlier (line ~90) and may be nil
	// in DEV_MODE or when STRIPE_SECRET_KEY is unset; the SetEventDispatcher
	// helper is nil-safe via the dispatcher field on Store.
	if preBillingStore != nil {
		preBillingStore.SetEventDispatcher(eventDispatcher)
	}

	// Initialize paper trading engine.
	var paperEngine *papertrading.PaperEngine
	if alertDB := kcManager.AlertDB(); alertDB != nil {
		paperStore := papertrading.NewStore(alertDB, app.logger)
		if err := paperStore.InitTables(); err != nil {
			app.logger.Error("Failed to initialize paper trading tables", "error", err)
		}
		paperEngine = papertrading.NewEngine(paperStore, app.logger)
		// Thread the shared domain event dispatcher so paper fills emit
		// OrderPlaced/OrderFilled/PositionOpened through the same audit
		// and projection pipeline as live trades.
		paperEngine.SetDispatcher(eventDispatcher)
		kcManager.SetPaperEngine(paperEngine)
	}

	// Wire the OrderFilledEvent real-flow bridge. The fill watcher
	// subscribes to OrderPlacedEvent and polls broker.GetOrderHistory
	// until the order reaches COMPLETE or the budget expires. Stopgap
	// until a push channel (postback URL or ticker order-update feed)
	// lands — see kc/fill_watcher.go for the full design note.
	//
	// Only wired when we have a sessionSvc to resolve per-email brokers.
	// In DEV_MODE (no real sessions), the resolver is still usable; the
	// mock broker satisfies broker.Client the same way a real one does.
	if resolver := kc.FillWatcherResolverFromSessionSvc(kcManager.SessionSvc()); resolver != nil {
		app.fillWatcher = kc.NewFillWatcher(kc.FillWatcherConfig{
			Resolver:   resolver,
			Dispatcher: eventDispatcher,
			Logger:     app.logger,
			// Clock defaults to testutil.RealClock{}; poll/budget use
			// production defaults (5s / 60s).
		})
		app.fillWatcher.Start()
		app.logger.Info("OrderFilledEvent fill-watcher wired (stopgap pre-websocket)")
	}

	// Create MCP server
	app.logger.Info("Creating MCP server...")

	// Wave D Phase 2 Slice P2.4d+e: middleware-chain assembly +
	// server construction delegated to providers.BuildMiddlewareChain
	// + providers.BuildMCPServer. The composition site builds the
	// middleware "raw materials" (CircuitBreaker, RateLimiter, Billing
	// middleware) and registers plugin hooks on app.registry as
	// side-effects, then fans the constructed middlewares into a
	// MiddlewareDeps struct that the provider consumes. Per-feature
	// gates (Stripe billing, paper trading, audit DevMode) preserve
	// the legacy nil-skip semantics via the provider's nil-skip
	// contract.
	mwDeps := providers.MiddlewareDeps{
		Correlation: mcp.CorrelationMiddleware(),
		Timeout:     mcp.TimeoutMiddleware(30 * time.Second),
		Audit:       auditMiddleware, // may be nil — provider skips
	}

	// Plugin hooks middleware runs registered before/after hooks around tool calls.
	// Register the rolegate plugin before wiring the middleware so its hook is
	// active from the first tool call. First production consumer of the plugin
	// system — family viewers get role-gated tool access via mcp.ToolHook.
	//
	// B77: hooks register on the App-scoped registry (app.registry) instead of
	// the package-level mcp.DefaultRegistry. Two parallel App tests can each
	// carry their own hook chain without polluting each other's. The
	// HookMiddlewareFor below consults the same per-App registry — production
	// behavior is identical, only the storage moves from a package global to
	// an App field.
	app.registry.OnBeforeToolExecution(rolegate.Hook(kcManager.UserStoreConcrete()))
	// Second production consumer — telegramnotify sends an after-hook DM to
	// the family admin when a family member runs a trade-affecting tool.
	// Demonstrates the OnAfterToolExecution half of the plugin API (rolegate
	// uses the Before side). Any nil dep disables the plugin (fail-open).
	app.registry.OnAfterToolExecution(telegramnotify.Hook(telegramnotify.Deps{
		Users:   kcManager.UserStoreConcrete(),
		ChatIDs: kcManager.AlertStoreConcrete(),
		Sender:  kcManager.TelegramNotifier(),
		Logger:  app.logger,
	}))
	mwDeps.Hooks = mcp.HookMiddlewareFor(app.registry)
	// Circuit breaker protects against cascading failures from Kite API outages.
	circuitBreaker := mcp.NewCircuitBreaker(5, 30*time.Second)
	mwDeps.CircuitBreaker = circuitBreaker.Middleware()
	// Riskguard middleware blocks orders exceeding safety limits.
	mwDeps.RiskGuard = riskguard.Middleware(riskGuard)
	// Per-tool rate limiter prevents abuse of order-related tools.
	toolRateLimiter := mcp.NewToolRateLimiter(map[string]int{
		"place_order":     10,
		"modify_order":    10,
		"cancel_order":    20,
		"place_gtt_order": 5,
		"set_alert":       10,
	})
	mwDeps.RateLimiter = toolRateLimiter.Middleware()

	// SIGHUP hot-reload for per-tool rate-limit caps. Operators can
	// retune throttles mid-incident without redeploying: edit
	// KITE_RATELIMIT, signal the process, and the new caps land
	// atomically with in-flight counters preserved.
	//
	// Wire a per-App stop channel so the goroutine exits at graceful
	// shutdown rather than living for the process lifetime. Production
	// used to run with a nil stopCh (goroutine died with the process);
	// this closed an annoying hole in the test leak-audit because
	// every test that exercised wire.go leaked this goroutine. See
	// app/ratelimit_reload.go for the env format and design rationale.
	// No-op on Windows where signal.Notify(SIGHUP) is a platform no-op.
	app.rateLimitReloadStop = make(chan struct{})
	_, rateLimitReloadDone := startRateLimitReloadLoop(toolRateLimiter, app.logger, app.rateLimitReloadStop)
	app.rateLimitReloadDone = rateLimitReloadDone
	app.logger.Info("SIGHUP rate-limit hot-reload wired", "env_var", "KITE_RATELIMIT")
	// Billing tier middleware gates tools by subscription level (opt-in via
	// app.Config.StripeSecretKey, populated from STRIPE_SECRET_KEY env by
	// ConfigFromEnv). Skipped entirely in DEV_MODE — all tools are free tier.
	//
	// Cycle inversion step 3: billingStore was pre-constructed (preBillingStore)
	// when StripeSecretKey + non-DevMode + alertDB conditions all hold, and
	// threaded into the manager via WithBillingStore. The reassignment here
	// keeps the local name 'billingStore' for the rest of the block — same
	// pointer the manager holds. The previous kcManager.SetBillingStore call
	// is now redundant (manager's billingStore field was populated by
	// initInjectedStores during NewWithOptions).
	if stripeKey := app.Config.StripeSecretKey; stripeKey != "" && !app.DevMode && preBillingStore != nil {
		stripe.Key = stripeKey
		billingStore := preBillingStore
		if err := billingStore.InitTable(); err != nil {
			app.logger.Error("Failed to initialize billing table", "error", err)
		} else if err := billingStore.LoadFromDB(); err != nil {
			app.logger.Error("Failed to load billing data from DB", "error", err)
		}
		// Create adminEmailFn closure for family tier resolution.
		adminEmailFn := func(email string) string {
			u, ok := kcManager.UserStore().Get(email)
			if !ok || u.AdminEmail == "" {
				return ""
			}
			return u.AdminEmail
		}
		mwDeps.Billing = billing.Middleware(billingStore, adminEmailFn)
		// Wire tier-aware throttling into the already-registered rate limiter.
		// Late-binding via WithTierMultiplier — toolRateLimiter.Middleware()
		// reads tierMult on every request via mutex, so this mutation
		// takes effect on the next dispatch even after Middleware() was
		// called (verified at mcp/ratelimit_middleware.go).
		toolRateLimiter.WithTierMultiplier(func(email string) int {
			return tierRateMultiplier(billingStore.GetTierForUser(email, adminEmailFn))
		})
		app.logger.Info("Billing tier enforcement enabled")
		if app.Config.StripePricePro == "" || app.Config.StripePricePremium == "" {
			app.logger.Warn("STRIPE_SECRET_KEY is set but STRIPE_PRICE_PRO and/or STRIPE_PRICE_PREMIUM are missing. Webhook tier mapping will default to Pro.")
		}
	}

	// Initialize family invitation store.
	//
	// Cycle inversion step 3: invStore was pre-constructed (preInvStore)
	// when alertDB != nil, and threaded into the manager via
	// WithInvitationStore. The local name 'invStore' below points to the
	// same pointer the manager holds; the previous kcManager.SetInvitationStore
	// call is now redundant.
	if alertDB := kcManager.AlertDB(); alertDB != nil {
		invStore := preInvStore
		if err := invStore.InitTable(); err != nil {
			app.logger.Error("Failed to initialize invitations table", "error", err)
		} else if err := invStore.LoadFromDB(); err != nil {
			app.logger.Error("Failed to load invitations from DB", "error", err)
		}

		// Wire family service (extracts family billing logic from manager).
		famSvc := kc.NewFamilyService(kcManager.UserStore(), kcManager.BillingStore(), invStore)
		kcManager.SetFamilyService(famSvc)

		// Background cleanup of expired invitations (runs every 6 hours).
		// The goroutine is stoppable via app.invitationCleanupCancel, which is
		// invoked during graceful shutdown. Without it, the goroutine leaks
		// across every NewApp()+initializeServices call in tests (282 tests
		// in the app package).
		invCtx, invCancel := context.WithCancel(context.Background())
		app.invitationCleanupCancel = invCancel
		go func() {
			ticker := time.NewTicker(6 * time.Hour)
			defer ticker.Stop()
			for {
				select {
				case <-invCtx.Done():
					return
				case <-ticker.C:
					if is := kcManager.InvitationStore(); is != nil {
						if n := is.CleanupExpired(); n > 0 {
							app.logger.Info("Cleaned up expired invitations", "count", n)
						}
					}
				}
			}
		}()
	}

	// Paper trading middleware intercepts order tools when the user has paper mode enabled.
	if paperEngine != nil {
		mwDeps.PaperTrading = papertrading.Middleware(paperEngine)
	}
	// Dashboard URL middleware auto-appends a dashboard_url hint to tool
	// responses that have a relevant dashboard page.
	mwDeps.DashboardURL = mcp.DashboardURLMiddleware(kcManager)

	// Wave D Phase 2 Slice P2.4d+e: build the chain + server via Fx.
	// The provider appends Elicitation + MCP Apps UI extension hooks
	// internally (production-required), so the composition site only
	// supplies the canonical 10-layer middleware chain via mwDeps.
	var mcpServer *server.MCPServer
	{
		fxApp := fx.New(
			fx.NopLogger,
			fx.Supply(mwDeps),
			fx.Provide(providers.BuildMiddlewareChain),
			fx.Provide(func(opts []server.ServerOption) *server.MCPServer {
				return providers.BuildMCPServer(providers.MCPServerInput{
					Name:    "Kite MCP Server",
					Version: app.Version,
					Options: opts,
				})
			}),
			fx.Populate(&mcpServer),
		)
		if err := fxApp.Err(); err != nil {
			return nil, nil, fmt.Errorf("mcp server fx graph: %w", err)
		}
	}
	app.logger.Debug("MCP server created successfully")

	// Wire MCPServer into Manager so tool handlers can call RequestElicitation.
	kcManager.SetMCPServer(mcpServer)

	// Wire paper trading LTP provider and start the background monitor.
	// The monitor reference is stored on the App so that graceful shutdown
	// (and test cleanup) can call paperMonitor.Stop() — without this, each
	// NewApp+initializeServices call leaks the monitor goroutine.
	if paperEngine != nil {
		paperEngine.SetLTPProvider(&paperLTPAdapter{manager: kcManager})
		app.paperMonitor = papertrading.NewMonitor(paperEngine, 5*time.Second, app.logger)
		app.paperMonitor.Start()
		app.logger.Info("Paper trading engine and monitor initialized")
	}

	// Register tools that will interact with MCP sessions and Kite API.
	// B77 Phase 2: pass app.registry so App-scoped plugins (registered
	// via app.Registry().RegisterPlugin) surface in the live MCP server.
	// Strictly isolated — DefaultRegistry plugins do NOT leak in.
	app.logger.Info("Registering MCP tools...")
	mcp.RegisterToolsForRegistry(mcpServer, kcManager, app.Config.ExcludedTools, app.auditStore, app.logger, app.Config.EnableTrading, app.registry)
	app.logger.Debug("MCP tools registered successfully")

	// Initialize scheduled Telegram briefings (morning + daily P&L).
	app.initScheduler(kcManager)

	// T2.3: registerLifecycle is now called UP FRONT (right after the
	// kcManager allocation) so the success-defer can collapse to a single
	// lifecycle.Shutdown() call. This closes 5 leak holes (telegram_bot,
	// oauth_handler, invitation_cleanup, rate_limiters, metrics) that the
	// prior 7-line manual unwind missed because workers added after the
	// initial defer were never backfilled into it.

	success = true
	return kcManager, mcpServer, nil
}

// registerLifecycle declares the graceful-shutdown order for every
// background worker initializeServices wires. Each Append is nil-safe
// at call time (the wrapped Stop/Cancel func gets a nil-check before
// invoke), so conditionally-allocated workers can be unconditionally
// registered.
//
// Phasing model — the production graceful shutdown in app/http.go has
// THREE phases that lifecycle does not collapse:
//
//   Phase A (block new work): scheduler.Stop, hashPublisher cancel.
//     Stays in setupGracefulShutdown — must run BEFORE the HTTP server
//     starts draining so no new tool calls / no new audit publish
//     attempts hit the in-flight drain.
//   Phase B (HTTP drain): srv.Shutdown(timeout).
//     Per-mode (different *http.Server per AppMode); cannot abstract
//     cleanly. Stays in setupGracefulShutdown.
//   Phase C (drain in-flight + tear down workers): everything below.
//     Owned by lifecycle. setupGracefulShutdown calls lifecycle.Shutdown()
//     after Phase B completes.
//
// Order within Phase C matches app/http.go:96-141 exactly. When that
// function migrates to delegate via lifecycle.Shutdown (next commit),
// this list becomes the single source of truth.
func (app *App) registerLifecycle(kcManager *kc.Manager) {
	app.lifecycle.Append("outbox_pump", func() error {
		if app.outboxPump != nil {
			app.outboxPump.Stop()
		}
		return nil
	})
	app.lifecycle.Append("audit_store", func() error {
		if app.auditStore != nil {
			app.auditStore.Stop()
		}
		return nil
	})
	app.lifecycle.Append("telegram_bot", func() error {
		if app.telegramBot != nil {
			app.telegramBot.Shutdown()
		}
		return nil
	})
	app.lifecycle.Append("kc_manager", func() error {
		kcManager.Shutdown()
		return nil
	})
	// Cycle inversion step 3: app/wire.go opens the alert DB itself
	// (preceded kc.NewWithOptions) so app/lifecycle owns the close.
	// Runs AFTER kc_manager so no manager-side write can race a closed
	// connection. Manager.Shutdown sets ownsAlertDB=false → it does
	// NOT close the DB itself (responsibility now lives here).
	app.lifecycle.Append("alert_db", func() error {
		if app.alertDB != nil {
			if err := app.alertDB.Close(); err != nil {
				app.logger.Error("Failed to close alert DB", "error", err)
			}
		}
		return nil
	})
	app.lifecycle.Append("oauth_handler", func() error {
		if app.oauthHandler != nil {
			app.oauthHandler.Close()
		}
		return nil
	})
	// rate_limiters is registered by setupMux (see app/http.go) at the
	// allocation site, so it's wired even for tests that bypass
	// initializeServices entirely (server_edge_lifecycle_test.go).
	app.lifecycle.Append("rate_limit_reload", func() error {
		app.stopRateLimitReload()
		return nil
	})
	app.lifecycle.Append("invitation_cleanup", func() error {
		if app.invitationCleanupCancel != nil {
			app.invitationCleanupCancel()
		}
		return nil
	})
	app.lifecycle.Append("paper_monitor", func() error {
		if app.paperMonitor != nil {
			app.paperMonitor.Stop()
		}
		return nil
	})
	// T3.B85: fill_watcher poll goroutines exit promptly via Stop signal
	// instead of orphaning for up to MaxDuration (60s default). Phase C
	// runs after HTTP drain so no new OrderPlacedEvents will spawn new
	// pollers while we're stopping.
	app.lifecycle.Append("fill_watcher", func() error {
		if app.fillWatcher != nil {
			app.fillWatcher.Stop()
		}
		return nil
	})
	app.lifecycle.Append("metrics", func() error {
		if app.metrics != nil {
			app.metrics.Shutdown()
		}
		return nil
	})
}

// initScheduler wires the Telegram morning briefing, daily P&L summary, and
// audit trail retention cleanup tasks.
//
// Wave D Phase 2 Slice P2.4b: task wiring delegated to
// providers.BuildScheduler via an Fx graph. The composition site
// (this function) still constructs the BriefingService and
// PnLSnapshotService inline because they require the unexported
// briefingTokenAdapter / briefingCredAdapter shims that can't move
// into app/providers/ without an import cycle. After construction,
// the services + audit store are fx.Supply'd to the graph and
// BuildScheduler conditionally adds tasks. The kcManager.SetPnLService
// side effect stays at the composition site.
func (app *App) initScheduler(kcManager *kc.Manager) {
	// --- Construct services that need unexported adapters ---

	var briefingSvc *alerts.BriefingService
	var taskNames []string
	notifier := kcManager.TelegramNotifier()
	if notifier != nil {
		tokenAdapter := &briefingTokenAdapter{store: kcManager.TokenStoreConcrete()}
		credAdapter := &briefingCredAdapter{manager: kcManager}
		briefingSvc = alerts.NewBriefingService(notifier, kcManager.AlertStoreConcrete(), tokenAdapter, credAdapter, app.logger)
		if briefingSvc != nil {
			briefingSvc.SetKiteClientFactory(kcManager.KiteClientFactory())
			taskNames = append(taskNames, "morning_briefing(09:00)", "mis_warning(14:30)", "daily_summary(15:35)")
		}
	} else {
		app.logger.Info("Telegram not configured, skipping briefing tasks")
	}

	var pnlService *alerts.PnLSnapshotService
	if alertDB := kcManager.AlertDB(); alertDB != nil {
		tokenAdapter := &briefingTokenAdapter{store: kcManager.TokenStoreConcrete()}
		credAdapter := &briefingCredAdapter{manager: kcManager}
		pnlService = alerts.NewPnLSnapshotService(alertDB, tokenAdapter, credAdapter, app.logger)
		if pnlService != nil {
			pnlService.SetKiteClientFactory(kcManager.KiteClientFactory())
			// Side effect kept at composition site: pnlService is exposed
			// via kcManager for the get_pnl_journal MCP tool. Provider
			// stays pure.
			kcManager.SetPnLService(pnlService)
			taskNames = append(taskNames, "pnl_snapshot(15:40)")
			app.logger.Info("P&L journal snapshot service enabled")
		}
	}

	if app.auditStore != nil {
		taskNames = append(taskNames, "audit_cleanup(03:00)")
	}

	// --- Build the scheduler via Fx graph ---

	var initialized *providers.InitializedScheduler
	fxApp := fx.New(
		fx.NopLogger,
		// Use fx.Provide(func returning T) instead of fx.Supply(T) for
		// nullable pointers — fx.Supply rejects typed-nil values
		// because reflect can't determine the type from a nil interface.
		fx.Provide(func() *alerts.BriefingService { return briefingSvc }),
		fx.Provide(func() *alerts.PnLSnapshotService { return pnlService }),
		fx.Provide(func() *audit.Store { return app.auditStore }),
		fx.Supply(providers.AuditCleanupConfig{}), // RetentionDays==0 → defaults to 1825 days (SEBI 5y)
		fx.Supply(app.logger),
		fx.Provide(providers.BuildScheduler),
		fx.Populate(&initialized),
	)
	if err := fxApp.Err(); err != nil {
		app.logger.Error("Failed to wire scheduler graph", "error", err)
		return
	}
	if initialized == nil || initialized.Scheduler == nil {
		app.logger.Info("No scheduled tasks configured")
		return
	}

	app.scheduler = initialized.Scheduler
	app.logger.Info("Scheduler started", "tasks", taskNames)
}

// briefingTokenAdapter bridges kc.KiteTokenStore to alerts.TokenChecker.
