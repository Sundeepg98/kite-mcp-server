package kc

import (
	"context"
	"fmt"
	"time"

	"github.com/zerodha/gokiteconnect/v4/models"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/eventsourcing"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/registry"
	"github.com/zerodha/kite-mcp-server/kc/ticker"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/kc/watchlist"
)

// manager_init.go holds the private init helpers that together compose
// Manager.New. The helpers were split out of a ~360-LOC constructor so
// each concern lives in a named, reviewable unit. The split is strictly
// structural — phase ordering, mutation targets, and error semantics
// are preserved verbatim.
//
// Phase order is load-bearing:
//
//  1. initInstrumentsManager  — create or accept pre-built instruments mgr
//  2. newEmptyManager         — allocate struct + facades + bus instances
//  3. initAlertSystem         — alert store + audit/telegram/event callbacks
//  4. initPersistence         — SQLite-backed stores (alert, token, cred)
//  5. initCredentialWiring    — credential→token invalidation hook
//  6. initTelegramNotifier    — optional Telegram bot
//  7. initAlertEvaluator      — alerts.Evaluator on top of alertStore
//  8. initTrailingStop        — trailing stop manager + SetModifier/SetOnModify
//  9. initSideStores          — watchlist / user / registry stores
//  10. initCredentialService  — CredentialService + registry backfill +
//                               trailing-stop modifier wiring (needs credSvc)
//  11. initTickerService      — ticker.Service with alert+trailing callbacks
//  12. Lifecycle: templates + session signer (existing methods)
//  13. initFocusedServices    — session/portfolio/order/alert sub-services
//  14. initSessionPersistence — wire session DB adapter
//  15. initTokenRotation      — OnChange observer to refresh live tickers
//  16. Projector + CQRS handler registration (existing methods)
//
// Every helper takes the Config by value so callers pass the same struct
// they received at the top of New(); no helper introduces a new error
// mode that wasn't already produced at the matching inline line.

// initInstrumentsManager returns the instruments.Manager to assign to
// Manager.Instruments. If the caller already provided one via
// Config.InstrumentsManager we pass it through unchanged; otherwise we
// build one honoring the InstrumentsSkipFetch test-isolation seam.
func initInstrumentsManager(cfg Config) (*instruments.Manager, error) {
	if cfg.InstrumentsManager != nil {
		return cfg.InstrumentsManager, nil
	}
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
	mgr, err := instruments.New(instrumentsCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create instruments manager: %w", err)
	}
	return mgr, nil
}

// newEmptyManager allocates the Manager struct, fills the fields that
// come straight from Config, and wires the decomposed facades. After
// this helper returns, every subsequent init* method can rely on
// m.Logger, m.tokenStore, m.credentialStore, and the five facade
// services being non-nil.
func newEmptyManager(cfg Config) *Manager {
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
	return m
}

// initAlertSystem wires the alert store and its trigger callback
// (Telegram + audit enqueue + domain-event dispatch). Must run before
// initAlertEvaluator — the evaluator takes alertStore as a dependency.
func (m *Manager) initAlertSystem(cfg Config) {
	// Initialize alert system: store → notifier → evaluator → ticker
	m.alertStore = alerts.NewStore(func(alert *alerts.Alert, currentPrice float64) {
		if m.telegramNotifier != nil {
			m.telegramNotifier.Notify(alert, currentPrice)
		}
		// Log alert trigger to audit trail for SSE browser notifications.
		// Alert-trigger callback runs from the alerts evaluator goroutine
		// with no request ctx in scope; service-ctx fallback is correct.
		if m.auditStore != nil {
			now := time.Now()
			m.auditStore.EnqueueCtx(context.Background(), &audit.ToolCall{
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
}

// initPersistence wires an alert DB into the alert / token / credential
// stores. Credential encryption is enabled when Config.EncryptionSecret
// is supplied. Errors at each step are logged and tolerated — the
// server falls back to in-memory storage rather than failing startup
// (matches the prior inline behaviour).
//
// DB sourcing precedence:
//  1. cfg.AlertDB (externally-opened) — used as-is, manager does NOT
//     own its lifecycle. This is the inversion seam for app/wire.go,
//     which opens the DB once and constructs DB-backed stores
//     (audit/riskguard/billing/invitation) before kc.NewWithOptions.
//  2. cfg.AlertDBPath (legacy) — manager opens via alerts.OpenDB and
//     owns the lifecycle (closes on Manager.Shutdown).
//  3. Both empty — in-memory mode, no persistence.
func (m *Manager) initPersistence(cfg Config) {
	var alertDB *alerts.DB
	if cfg.AlertDB != nil {
		alertDB = cfg.AlertDB
		m.ownsAlertDB = false
	} else {
		if cfg.AlertDBPath == "" {
			return
		}
		opened, dbErr := alerts.OpenDB(cfg.AlertDBPath)
		if dbErr != nil {
			cfg.Logger.Error("Failed to open alert DB, using in-memory only", "error", dbErr)
			return
		}
		alertDB = opened
		m.ownsAlertDB = true
	}
	m.alertDB = alertDB
	// Set up credential encryption if a secret is provided
	if cfg.EncryptionSecret != "" {
		encKey, encErr := alerts.EnsureEncryptionSalt(alertDB, cfg.EncryptionSecret)
		if encErr != nil {
			cfg.Logger.Error("Failed to derive encryption key with salt", "error", encErr)
		} else {
			alertDB.SetEncryptionKey(encKey)
			// Cache the key on Manager so initStores can wire it into
			// userStore (TOTP MFA secrets are AES-256-GCM-encrypted with
			// the same key — see kc/users/mfa.go).
			m.encryptionKey = encKey
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

// initCredentialWiring installs the cross-store hook that clears a
// user's cached Kite token when their API key changes. Tiny helper
// but kept separate so the tight dependency — credentialStore hook
// reads m.tokenStore — is visible on one line.
func (m *Manager) initCredentialWiring() {
	// Wire credential → token invalidation: when a user's API key changes,
	// delete the cached Kite token (it was issued for the old app).
	m.credentialStore.OnTokenInvalidate(func(email string) {
		m.tokenStore.Delete(email)
	})
}

// initTelegramNotifier wires the Telegram bot when a token is provided.
// Failure is non-fatal; the server runs without Telegram notifications.
//
// When cfg.BotFactory is non-nil (test injection), the per-Manager factory
// is used directly — bypassing the kc/alerts package-level newBotFunc global.
// Production wiring leaves BotFactory nil and the package-default tgbotapi
// factory is consulted.
func (m *Manager) initTelegramNotifier(cfg Config) {
	if cfg.TelegramBotToken == "" {
		return
	}
	var notifier *alerts.TelegramNotifier
	var tgErr error
	if cfg.BotFactory != nil {
		notifier, tgErr = alerts.NewTelegramNotifierWithFactory(cfg.TelegramBotToken, m.alertStore, cfg.Logger, cfg.BotFactory)
	} else {
		notifier, tgErr = alerts.NewTelegramNotifier(cfg.TelegramBotToken, m.alertStore, cfg.Logger)
	}
	if tgErr != nil {
		cfg.Logger.Warn("Telegram notifier failed to initialize", "error", tgErr)
		return
	}
	m.telegramNotifier = notifier
}

// initAlertEvaluator builds the tick→alert matcher. Depends on
// alertStore existing (initAlertSystem runs earlier).
func (m *Manager) initAlertEvaluator(cfg Config) {
	m.alertEvaluator = alerts.NewEvaluator(m.alertStore, cfg.Logger)
}

// initTrailingStop creates the trailing stop manager and wires the
// "modification" audit + Telegram notification callback. The Kite
// client modifier hook is wired separately from initCredentialService
// because it needs credentialSvc, which isn't constructed yet at this
// point in the phase order.
func (m *Manager) initTrailingStop(cfg Config) {
	m.trailingStopMgr = alerts.NewTrailingStopManager(cfg.Logger)
	if m.alertDB != nil {
		m.trailingStopMgr.SetDB(m.alertDB)
		if err := m.trailingStopMgr.LoadFromDB(); err != nil {
			cfg.Logger.Error("Failed to load trailing stops from DB", "error", err)
		}
	}

	// Wire trailing stop modification notification to Telegram + audit.
	m.trailingStopMgr.SetOnModify(func(ts *alerts.TrailingStop, oldStop, newStop float64) {
		// Log trailing stop modification to audit trail for SSE browser notifications.
		// Trailing-stop callback runs from the trailing-stop manager
		// goroutine with no request ctx in scope; service-ctx fallback.
		if m.auditStore != nil {
			now := time.Now()
			trailDesc := fmt.Sprintf("%.2f", ts.TrailAmount)
			if ts.TrailPct > 0 {
				trailDesc = fmt.Sprintf("%.1f%%", ts.TrailPct)
			}
			m.auditStore.EnqueueCtx(context.Background(), &audit.ToolCall{
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
}

// initSideStores brings up the watchlist, user, and key-registry stores.
// All three share the same SQLite DB (m.alertDB) when persistence is
// enabled and fall back to in-memory when it isn't.
func (m *Manager) initSideStores(cfg Config) {
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
	// Wire the encryption key for TOTP MFA secrets. Same HKDF-derived key
	// the rest of T1 storage uses — rotation via cmd/rotate-key already
	// handles the round-trip migration. SetEncryptionKey is a no-op when
	// the key is empty (DEV_MODE without OAUTH_JWT_SECRET).
	if len(m.encryptionKey) > 0 {
		m.userStore.SetEncryptionKey(m.encryptionKey)
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
}

// initInjectedStores populates the four DB-backed store fields
// (auditStore, riskGuard, billingStore, invitationStore) from the
// matching Config fields when supplied via With* options. This is the
// constructor-injection seam that replaces the post-init SetX setters
// for production wiring (app/wire.go); the SetX setters remain as
// deprecated shims for the ~70+ test sites that mutate the manager
// after construction.
//
// nil-tolerant: any field left nil on Config is a no-op here, matching
// the legacy "store wired later via SetX or never wired at all" path.
func (m *Manager) initInjectedStores(cfg Config) {
	if cfg.AuditStore != nil {
		m.auditStore = cfg.AuditStore
	}
	if cfg.RiskGuard != nil {
		m.riskGuard = cfg.RiskGuard
	}
	if cfg.BillingStore != nil {
		m.billingStore = cfg.BillingStore
	}
	if cfg.InvitationStore != nil {
		m.invitationStore = cfg.InvitationStore
	}
}

// initCredentialService builds the focused CredentialService on top of
// the three stores (credentialStore, tokenStore, registryStore) and
// wires it into the trailing-stop order-modifier hook. The backfill
// pass brings pre-registry self-provisioned keys into the new registry
// store so later lookups are uniform.
func (m *Manager) initCredentialService(cfg Config) {
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

	// Wire the order modifier: creates a Kite client from cached tokens.
	// This depends on credentialSvc existing — that's why it lives here
	// rather than in initTrailingStop above.
	m.trailingStopMgr.SetModifier(func(email string) (alerts.KiteOrderModifier, error) {
		apiKey := m.credentialSvc.GetAPIKeyForEmail(email)
		accessToken := m.credentialSvc.GetAccessTokenForEmail(email)
		if accessToken == "" {
			return nil, fmt.Errorf("no Kite access token for %s", email)
		}
		client := m.kiteClientFactory.NewClientWithToken(apiKey, accessToken)
		return client, nil
	})
}

// initTickerService constructs the per-user WebSocket ticker with the
// alert-evaluator + trailing-stop-manager as OnTick callbacks.
func (m *Manager) initTickerService(cfg Config) {
	m.tickerService = ticker.New(ticker.Config{
		Logger: cfg.Logger,
		OnTick: func(email string, tick models.Tick) {
			m.alertEvaluator.Evaluate(email, tick)
			m.trailingStopMgr.Evaluate(email, tick)
		},
	})
}

// initFocusedServices builds the Clean-Architecture sub-services on
// top of the raw stores/clients wired by the earlier phases. Order
// matters within this method: sessionSvc depends on sessionManager
// (built in newEmptyManager via newSessionLifecycleService); portfolio
// and order services depend on sessionSvc.
func (m *Manager) initFocusedServices(cfg Config, instrumentsManager *instruments.Manager) {
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
}

// initSessionPersistence threads the shared alert DB into the session
// registry so MCP sessions survive restart. No-op when persistence is
// disabled.
func (m *Manager) initSessionPersistence(cfg Config) {
	if m.alertDB == nil {
		return
	}
	m.sessionManager.SetDB(&sessionDBAdapter{db: m.alertDB})
	if err := m.sessionManager.LoadFromDB(); err != nil {
		cfg.Logger.Error("Failed to load sessions from DB", "error", err)
	} else {
		cfg.Logger.Info("Sessions loaded from database")
	}
}

// initTokenRotation registers the token→ticker update observer so a
// refreshed Kite token seamlessly propagates to any live ticker.
func (m *Manager) initTokenRotation() {
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
}

// initProjector allocates the read-side projector. Kept in a named
// helper so the parent New() stays purely a composition sequence.
func (m *Manager) initProjector() {
	// The projector is empty until SetEventDispatcher wires it to a
	// real dispatcher in app/wire.go; tests that skip dispatcher setup
	// still get a usable empty projector.
	m.projector = eventsourcing.NewProjector()
}
