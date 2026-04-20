package app

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/eventsourcing"
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/scheduler"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/mcp"
	"github.com/zerodha/kite-mcp-server/plugins/rolegate"
	"github.com/zerodha/kite-mcp-server/plugins/telegramnotify"
	gomcp "github.com/mark3labs/mcp-go/mcp"
	stripe "github.com/stripe/stripe-go/v82"
)

func (app *App) initializeServices() (*kc.Manager, *server.MCPServer, error) {
	if err := app.envCheck(); err != nil {
		return nil, nil, fmt.Errorf("environment validation failed: %w", err)
	}
	app.logger.Info("Creating Kite Connect manager...")
	// INSTRUMENTS_SKIP_FETCH=true is a test-only seam that causes the
	// instruments manager to load an empty map instead of fetching
	// api.kite.trade/instruments.json at startup. Used by newTestApp(t)
	// to isolate the test suite from external API rate limits. Never set
	// in production.
	skipInstrumentsFetch := strings.EqualFold(os.Getenv("INSTRUMENTS_SKIP_FETCH"), "true")

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
		kc.WithAlertDBPath(app.Config.AlertDBPath),
		kc.WithAppMode(app.Config.AppMode),
		kc.WithExternalURL(app.Config.ExternalURL),
		kc.WithAdminSecretPath(app.Config.AdminSecretPath),
		kc.WithEncryptionSecret(app.Config.OAuthJWTSecret),
		kc.WithDevMode(app.DevMode),
		kc.WithInstrumentsSkipFetch(skipInstrumentsFetch),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create Kite Connect manager: %w", err)
	}

	// Track whether initializeServices returns a live manager or one of its
	// error paths. Without this, a failure AFTER kcManager construction
	// (e.g., the "audit trail required in production" guard below) leaks
	// the Kite manager's background goroutines AND any app-level workers
	// (scheduler, audit, paperMonitor, hashPublisher) that were wired
	// before the failure. Callers cannot reach Shutdown on a nil return.
	success := false
	defer func() {
		if !success {
			// Tear down app-level workers first (mirror setupGracefulShutdown
			// order), then the manager last. Every Stop/Shutdown is nil-safe.
			if app.scheduler != nil {
				app.scheduler.Stop()
			}
			if app.hashPublisherCancel != nil {
				app.hashPublisherCancel()
			}
			if app.auditStore != nil {
				app.auditStore.Stop()
			}
			if app.paperMonitor != nil {
				app.paperMonitor.Stop()
			}
			app.stopRateLimitReload()
			kcManager.Shutdown()
		}
	}()

	// Store reference for template data
	app.kcManager = kcManager

	// Initialize the status template early for the status page
	if err := app.initStatusPageTemplate(); err != nil {
		app.logger.Warn("Failed to initialize status template", "error", err)
	}

	app.logger.Debug("Kite Connect manager created successfully")

	// Create audit store (reuse the same SQLite DB used for alerts).
	//
	// H1 fix (phase 2i): audit trail is a compliance requirement. In production
	// mode, fail fast if the audit table cannot be created — silently running
	// without audit middleware hides every tool call from the regulator. In
	// DevMode, log and continue so local dev without a DB still works.
	var auditMiddleware server.ToolHandlerMiddleware
	if alertDB := kcManager.AlertDB(); alertDB != nil {
		app.auditStore = audit.New(alertDB)
		if err := app.auditStore.InitTable(); err != nil {
			if !app.DevMode {
				return nil, nil, fmt.Errorf("audit trail required in production: init table: %w", err)
			}
			app.logger.Error("Failed to initialize audit table (DevMode: continuing without audit)", "error", err)
		} else {
			// Wire encryption key for HMAC email hashing, AES-GCM email encryption,
			// and HMAC-SHA256 hash chaining.
			if app.Config.OAuthJWTSecret != "" {
				encKey, err := alerts.EnsureEncryptionSalt(alertDB, app.Config.OAuthJWTSecret)
				if err != nil {
					if !app.DevMode {
						return nil, nil, fmt.Errorf("audit trail required in production: derive encryption key: %w", err)
					}
					app.logger.Error("Failed to derive audit encryption key (DevMode: continuing)", "error", err)
				} else {
					app.auditStore.SetEncryptionKey(encKey)
					app.auditStore.SeedChain()
					app.logger.Info("Audit trail encryption and hash chaining enabled")
				}
			}
			app.auditStore.SetLogger(app.logger)
			app.auditStore.StartWorker()
			app.logger.Info("Audit trail enabled")
			auditMiddleware = audit.Middleware(app.auditStore)

			// Wire audit store into manager for alert trigger + trailing stop notifications.
			kcManager.SetAuditStore(app.auditStore)

			// Start audit hash-chain external publisher. Opt-in via
			// AUDIT_HASH_PUBLISH_* env vars — disabled (no-op) otherwise.
			// SEBI CSCRF: publishing the chain tip to external storage
			// prevents an attacker with DB write access from rewriting the
			// audit log history undetected.
			hpCfg := audit.LoadHashPublishConfig([]byte(app.Config.OAuthJWTSecret))
			hpCtx, hpCancel := context.WithCancel(context.Background())
			app.hashPublisherCancel = hpCancel
			audit.StartHashPublisher(hpCtx, app.auditStore, hpCfg, app.logger)
		}
	} else if !app.DevMode {
		return nil, nil, fmt.Errorf("audit trail required in production: no alert DB configured (set ALERT_DB_PATH)")
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

	// Initialize riskguard for financial safety controls.
	//
	// H2 fix (phase 2i): LoadLimits failure used to silently fall back to
	// in-memory defaults — which would WIPE a user-configured kill switch and
	// allow trading to proceed without their limits. Fail fast in production.
	riskGuard := riskguard.NewGuard(app.logger)
	// Default to "loaded" — if there's no DB (DevMode without ALERT_DB_PATH)
	// the guard runs with SystemDefaults, which is the intended DevMode path;
	// we only flip this to false when LoadLimits is actually attempted and fails.
	app.riskLimitsLoaded = true
	if alertDB := kcManager.AlertDB(); alertDB != nil {
		riskGuard.SetDB(alertDB)
		if err := riskGuard.InitTable(); err != nil {
			if !app.DevMode {
				return nil, nil, fmt.Errorf("riskguard required in production: init risk_limits table: %w", err)
			}
			app.logger.Error("Failed to initialize risk_limits table (DevMode: continuing)", "error", err)
			app.riskLimitsLoaded = false
		}
		if err := riskGuard.LoadLimits(); err != nil {
			if !app.DevMode {
				return nil, nil, fmt.Errorf("riskguard required in production: load limits (refusing to start without user-configured limits): %w", err)
			}
			app.logger.Error("Failed to load risk limits (DevMode: continuing with defaults)", "error", err)
			app.riskLimitsLoaded = false
		}
	} else if !app.DevMode {
		return nil, nil, fmt.Errorf("riskguard required in production: no alert DB configured (set ALERT_DB_PATH)")
	}
	app.riskGuard = riskGuard
	if kcManager.InstrumentsManagerConcrete() != nil {
		// Wrap instruments manager as FreezeQuantityLookup
		riskGuard.SetFreezeQuantityLookup(&instrumentsFreezeAdapter{mgr: kcManager.InstrumentsManagerConcrete()})
	}
	// Wire the anomaly-detection baseline. audit.Store.UserOrderStats matches
	// riskguard.BaselineProvider exactly (same signature), so it's a direct
	// assignment — no adapter shim needed. Without this wire the anomaly
	// check in checkAnomalyMultiplier silently no-ops (fail-open) because
	// g.baseline is nil. When auditStore is nil (DevMode without ALERT_DB_PATH),
	// we leave baseline unset and the fail-open behaviour continues.
	if app.auditStore != nil {
		riskGuard.SetBaselineProvider(app.auditStore)
		app.logger.Info("riskguard anomaly baseline wired", "provider", "audit")
	}
	// Wire auto-freeze Telegram admin notification + domain event dispatch.
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
	kcManager.SetRiskGuard(riskGuard)

	// Initialize domain event dispatcher and audit log.
	// Events flow: use case -> EventDispatcher.Dispatch() -> makeEventPersister() -> domain_events table.
	// This is a write-only audit trail — events are never read back for state reconstitution.
	eventDispatcher := domain.NewEventDispatcher()
	kcManager.SetEventDispatcher(eventDispatcher)
	if alertDB := kcManager.AlertDB(); alertDB != nil {
		eventStore := eventsourcing.NewEventStore(alertDB)
		if err := eventStore.InitTable(); err != nil {
			app.logger.Error("Failed to initialize domain_events table", "error", err)
		} else {
			kcManager.SetEventStore(eventStore)
			// Subscribe the domain audit log to persist all dispatched events.
			eventDispatcher.Subscribe("order.placed", makeEventPersister(eventStore, "Order", app.logger))
			eventDispatcher.Subscribe("order.modified", makeEventPersister(eventStore, "Order", app.logger))
			eventDispatcher.Subscribe("order.cancelled", makeEventPersister(eventStore, "Order", app.logger))
			eventDispatcher.Subscribe("order.filled", makeEventPersister(eventStore, "Order", app.logger))
			eventDispatcher.Subscribe("position.opened", makeEventPersister(eventStore, "Position", app.logger))
			eventDispatcher.Subscribe("position.closed", makeEventPersister(eventStore, "Position", app.logger))
			// Phase C ES: alert.created and alert.deleted are appended to the
			// audit log by the use cases themselves (CreateAlertUseCase /
			// DeleteAlertUseCase) via eventStore.Append — subscribing the
			// persister here would double-write. alert.triggered is still
			// fired from manager_init.go's polling loop (not a use case),
			// so it stays on the dispatcher→persister path.
			eventDispatcher.Subscribe("alert.triggered", makeEventPersister(eventStore, "Alert", app.logger))
			eventDispatcher.Subscribe("user.frozen", makeEventPersister(eventStore, "User", app.logger))
			eventDispatcher.Subscribe("user.suspended", makeEventPersister(eventStore, "User", app.logger))
			eventDispatcher.Subscribe("global.freeze", makeEventPersister(eventStore, "Global", app.logger))
			eventDispatcher.Subscribe("family.invited", makeEventPersister(eventStore, "Family", app.logger))
			eventDispatcher.Subscribe("family.member_removed", makeEventPersister(eventStore, "Family", app.logger))
			eventDispatcher.Subscribe("risk.limit_breached", makeEventPersister(eventStore, "RiskGuard", app.logger))
			eventDispatcher.Subscribe("session.created", makeEventPersister(eventStore, "Session", app.logger))
			app.logger.Info("Domain event store initialized and subscribed")
		}
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
		fillWatcher := kc.NewFillWatcher(kc.FillWatcherConfig{
			Resolver:   resolver,
			Dispatcher: eventDispatcher,
			Logger:     app.logger,
			// Clock defaults to testutil.RealClock{}; poll/budget use
			// production defaults (5s / 60s).
		})
		fillWatcher.Start()
		app.logger.Info("OrderFilledEvent fill-watcher wired (stopgap pre-websocket)")
	}

	// Create MCP server
	app.logger.Info("Creating MCP server...")
	var serverOpts []server.ServerOption
	// Correlation ID middleware injects a unique ID per tool call for tracing.
	serverOpts = append(serverOpts, server.WithToolHandlerMiddleware(mcp.CorrelationMiddleware()))
	// Timeout middleware kills tool handlers that exceed 30 seconds.
	serverOpts = append(serverOpts, server.WithToolHandlerMiddleware(mcp.TimeoutMiddleware(30*time.Second)))
	if auditMiddleware != nil {
		serverOpts = append(serverOpts, server.WithToolHandlerMiddleware(auditMiddleware))
	}
	// Plugin hooks middleware runs registered before/after hooks around tool calls.
	// Register the rolegate plugin before wiring the middleware so its hook is
	// active from the first tool call. First production consumer of the plugin
	// system — family viewers get role-gated tool access via mcp.ToolHook.
	mcp.OnBeforeToolExecution(rolegate.Hook(kcManager.UserStoreConcrete()))
	// Second production consumer — telegramnotify sends an after-hook DM to
	// the family admin when a family member runs a trade-affecting tool.
	// Demonstrates the OnAfterToolExecution half of the plugin API (rolegate
	// uses the Before side). Any nil dep disables the plugin (fail-open).
	mcp.OnAfterToolExecution(telegramnotify.Hook(telegramnotify.Deps{
		Users:   kcManager.UserStoreConcrete(),
		ChatIDs: kcManager.AlertStoreConcrete(),
		Sender:  kcManager.TelegramNotifier(),
		Logger:  app.logger,
	}))
	serverOpts = append(serverOpts, server.WithToolHandlerMiddleware(mcp.HookMiddleware()))
	// Circuit breaker protects against cascading failures from Kite API outages.
	circuitBreaker := mcp.NewCircuitBreaker(5, 30*time.Second)
	serverOpts = append(serverOpts, server.WithToolHandlerMiddleware(circuitBreaker.Middleware()))
	// Riskguard middleware blocks orders exceeding safety limits.
	serverOpts = append(serverOpts, server.WithToolHandlerMiddleware(riskguard.Middleware(riskGuard)))
	// Per-tool rate limiter prevents abuse of order-related tools.
	toolRateLimiter := mcp.NewToolRateLimiter(map[string]int{
		"place_order":     10,
		"modify_order":    10,
		"cancel_order":    20,
		"place_gtt_order": 5,
		"set_alert":       10,
	})
	serverOpts = append(serverOpts, server.WithToolHandlerMiddleware(toolRateLimiter.Middleware()))

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
	// Billing tier middleware gates tools by subscription level (opt-in via STRIPE_SECRET_KEY).
	// Skipped entirely in DEV_MODE — all tools are free tier.
	if stripeKey := os.Getenv("STRIPE_SECRET_KEY"); stripeKey != "" && !app.DevMode {
		stripe.Key = stripeKey
		billingStore := billing.NewStore(kcManager.AlertDB(), app.logger)
		if err := billingStore.InitTable(); err != nil {
			app.logger.Error("Failed to initialize billing table", "error", err)
		} else if err := billingStore.LoadFromDB(); err != nil {
			app.logger.Error("Failed to load billing data from DB", "error", err)
		}
		kcManager.SetBillingStore(billingStore)
		// Create adminEmailFn closure for family tier resolution.
		adminEmailFn := func(email string) string {
			u, ok := kcManager.UserStore().Get(email)
			if !ok || u.AdminEmail == "" {
				return ""
			}
			return u.AdminEmail
		}
		serverOpts = append(serverOpts, server.WithToolHandlerMiddleware(billing.Middleware(billingStore, adminEmailFn)))
		// Wire tier-aware throttling into the already-registered rate limiter.
		// Late-binding via WithTierMultiplier keeps the middleware layer count
		// unchanged (still 10) — the resolver is consulted per-request, so the
		// order in which middleware was appended to serverOpts is preserved.
		toolRateLimiter.WithTierMultiplier(func(email string) int {
			return tierRateMultiplier(billingStore.GetTierForUser(email, adminEmailFn))
		})
		app.logger.Info("Billing tier enforcement enabled")
		if os.Getenv("STRIPE_PRICE_PRO") == "" || os.Getenv("STRIPE_PRICE_PREMIUM") == "" {
			app.logger.Warn("STRIPE_SECRET_KEY is set but STRIPE_PRICE_PRO and/or STRIPE_PRICE_PREMIUM are missing. Webhook tier mapping will default to Pro.")
		}
	}

	// Initialize family invitation store.
	if alertDB := kcManager.AlertDB(); alertDB != nil {
		invStore := users.NewInvitationStore(alertDB)
		if err := invStore.InitTable(); err != nil {
			app.logger.Error("Failed to initialize invitations table", "error", err)
		} else if err := invStore.LoadFromDB(); err != nil {
			app.logger.Error("Failed to load invitations from DB", "error", err)
		}
		kcManager.SetInvitationStore(invStore)

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
		serverOpts = append(serverOpts, server.WithToolHandlerMiddleware(papertrading.Middleware(paperEngine)))
	}
	// Dashboard URL middleware auto-appends a dashboard_url hint to tool
	// responses that have a relevant dashboard page.
	serverOpts = append(serverOpts, server.WithToolHandlerMiddleware(mcp.DashboardURLMiddleware(kcManager)))

	// Enable elicitation so tool handlers can request user confirmation before
	// placing orders. Clients that don't support elicitation will gracefully
	// degrade (fail open — orders proceed without confirmation).
	serverOpts = append(serverOpts, server.WithElicitation())

	// Declare the MCP Apps UI extension so that MCP App hosts (Cowork,
	// claude.ai) know this server supports inline rendering of ui:// resources.
	// mcp-go doesn't have a WithExtensions option yet, so we inject it via an
	// OnAfterInitialize hook that modifies the InitializeResult.
	uiHooks := &server.Hooks{}
	uiHooks.AddAfterInitialize(func(_ context.Context, _ any, _ *gomcp.InitializeRequest, result *gomcp.InitializeResult) {
		if result.Capabilities.Extensions == nil {
			result.Capabilities.Extensions = make(map[string]any)
		}
		result.Capabilities.Extensions["io.modelcontextprotocol/ui"] = map[string]any{}
	})
	serverOpts = append(serverOpts, server.WithHooks(uiHooks))

	mcpServer := server.NewMCPServer(
		"Kite MCP Server",
		app.Version,
		serverOpts...,
	)
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

	// Register tools that will interact with MCP sessions and Kite API
	app.logger.Info("Registering MCP tools...")
	mcp.RegisterTools(mcpServer, kcManager, app.Config.ExcludedTools, app.auditStore, app.logger, app.Config.EnableTrading)
	app.logger.Debug("MCP tools registered successfully")

	// Initialize scheduled Telegram briefings (morning + daily P&L).
	app.initScheduler(kcManager)

	success = true
	return kcManager, mcpServer, nil
}

// initScheduler wires the Telegram morning briefing, daily P&L summary, and
// audit trail retention cleanup tasks.
func (app *App) initScheduler(kcManager *kc.Manager) {
	sched := scheduler.New(app.logger)
	var taskNames []string

	// --- Telegram briefings (opt-in: requires TELEGRAM_BOT_TOKEN) ---
	notifier := kcManager.TelegramNotifier()
	if notifier != nil {
		tokenAdapter := &briefingTokenAdapter{store: kcManager.TokenStoreConcrete()}
		credAdapter := &briefingCredAdapter{manager: kcManager}
		briefingSvc := alerts.NewBriefingService(notifier, kcManager.AlertStoreConcrete(), tokenAdapter, credAdapter, app.logger)
		if briefingSvc != nil {
			briefingSvc.SetKiteClientFactory(kcManager.KiteClientFactory())
			sched.Add(scheduler.Task{
				Name:   "morning_briefing",
				Hour:   9,
				Minute: 0,
				Fn:     briefingSvc.SendMorningBriefings,
			})
			sched.Add(scheduler.Task{
				Name:   "mis_warning",
				Hour:   14,
				Minute: 30,
				Fn:     briefingSvc.SendMISWarnings,
			})
			sched.Add(scheduler.Task{
				Name:   "daily_summary",
				Hour:   15,
				Minute: 35,
				Fn:     briefingSvc.SendDailySummaries,
			})
			taskNames = append(taskNames, "morning_briefing(09:00)", "mis_warning(14:30)", "daily_summary(15:35)")
		}
	} else {
		app.logger.Info("Telegram not configured, skipping briefing tasks")
	}

	// --- Audit trail retention cleanup — daily at 3:00 AM IST ---
	if app.auditStore != nil {
		const retentionDays = 1825 // 5 years — SEBI algo trading audit trail requirement
		sched.Add(scheduler.Task{
			Name:   "audit_cleanup",
			Hour:   3,
			Minute: 0,
			Fn: func() {
				cutoff := time.Now().AddDate(0, 0, -retentionDays)
				deleted, err := app.auditStore.DeleteOlderThan(cutoff)
				if err != nil {
					app.logger.Error("Audit cleanup failed", "error", err)
				} else if deleted > 0 {
					app.logger.Info("Audit cleanup completed", "deleted", deleted, "retention_days", retentionDays)
				}
			},
		})
		taskNames = append(taskNames, "audit_cleanup(03:00)")
	}

	// --- Daily P&L snapshot — 3:40 PM IST (after market close, after Telegram summary) ---
	if alertDB := kcManager.AlertDB(); alertDB != nil {
		tokenAdapter := &briefingTokenAdapter{store: kcManager.TokenStoreConcrete()}
		credAdapter := &briefingCredAdapter{manager: kcManager}
		pnlService := alerts.NewPnLSnapshotService(alertDB, tokenAdapter, credAdapter, app.logger)
		if pnlService != nil {
			pnlService.SetKiteClientFactory(kcManager.KiteClientFactory())
			kcManager.SetPnLService(pnlService)
			sched.Add(scheduler.Task{
				Name:   "pnl_snapshot",
				Hour:   15,
				Minute: 40,
				Fn:     pnlService.TakeSnapshots,
			})
			taskNames = append(taskNames, "pnl_snapshot(15:40)")
			app.logger.Info("P&L journal snapshot service enabled")
		}
	}

	// Only start the scheduler if there are tasks to run.
	if len(taskNames) == 0 {
		app.logger.Info("No scheduled tasks configured")
		return
	}

	sched.Start()
	app.scheduler = sched
	app.logger.Info("Scheduler started", "tasks", taskNames)
}

// briefingTokenAdapter bridges kc.KiteTokenStore to alerts.TokenChecker.
