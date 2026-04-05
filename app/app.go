package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/mark3labs/mcp-go/util"
	"github.com/zerodha/kite-mcp-server/app/metrics"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/ops"
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
	"github.com/zerodha/kite-mcp-server/kc/registry"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/scheduler"
	"github.com/zerodha/kite-mcp-server/kc/users"
	tgbot "github.com/zerodha/kite-mcp-server/kc/telegram"
	"github.com/zerodha/kite-mcp-server/kc/templates"
	"github.com/zerodha/kite-mcp-server/kc/ticker"
	"github.com/zerodha/kite-mcp-server/kc/watchlist"
	"github.com/zerodha/kite-mcp-server/mcp"
	"github.com/zerodha/kite-mcp-server/oauth"
	"golang.org/x/crypto/bcrypt"
)

// App represents the main application structure
type App struct {
	Config         *Config
	Version        string
	startTime      time.Time
	kcManager      *kc.Manager
	oauthHandler   *oauth.Handler
	statusTemplate  *template.Template
	landingTemplate *template.Template
	legalTemplate   *template.Template
	logger         *slog.Logger
	metrics        *metrics.Manager
	logBuffer      *ops.LogBuffer
	rateLimiters   *rateLimiters
	auditStore     *audit.Store
	scheduler      *scheduler.Scheduler
	telegramBot    *tgbot.BotHandler
}

// StatusPageData holds template data for the status page
type StatusPageData struct {
	Title        string
	Version      string
	Mode         string
	OAuthEnabled bool
	ToolCount    int
}

// cookieName must match the JWT cookie name used by oauth.RequireAuthBrowser.
const cookieName = "kite_jwt"

// Config holds the application configuration
type Config struct {
	KiteAPIKey      string
	KiteAPISecret   string
	KiteAccessToken string
	AppMode         string
	AppPort       string
	AppHost       string

	ExcludedTools   string
	AdminSecretPath string

	// OAuth 2.1 (opt-in: set OAUTH_JWT_SECRET to enable)
	OAuthJWTSecret string
	ExternalURL    string

	// Telegram (opt-in: set TELEGRAM_BOT_TOKEN to enable price alert notifications)
	TelegramBotToken string

	// Alert persistence (opt-in: set ALERT_DB_PATH to enable SQLite persistence)
	AlertDBPath string

	// Admin emails (comma-separated list of admin emails for ops dashboard)
	AdminEmails string

	// Google SSO (opt-in: set GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET to enable)
	GoogleClientID     string
	GoogleClientSecret string
}

// Server mode constants
const (
	ModeSSE    = "sse"    // Server-Sent Events mode
	ModeStdIO  = "stdio"  // Standard IO mode
	ModeHTTP   = "http"   // Streamable HTTP mode for MCP endpoint
	ModeHybrid = "hybrid" // Combined mode with both SSE and MCP endpoints

	DefaultPort    = "8080"
	DefaultHost    = "localhost"
	DefaultAppMode = "http"
)

// NewApp creates and initializes a new App instance
// NewApp creates a new application instance with logger
func NewApp(logger *slog.Logger) *App {
	adminSecretPath := os.Getenv("ADMIN_ENDPOINT_SECRET_PATH")

	return &App{
		Config: &Config{
			KiteAPIKey:      os.Getenv("KITE_API_KEY"),
			KiteAPISecret:   os.Getenv("KITE_API_SECRET"),
			KiteAccessToken: os.Getenv("KITE_ACCESS_TOKEN"),
			AppMode:         os.Getenv("APP_MODE"),
			AppPort:       os.Getenv("APP_PORT"),
			AppHost:       os.Getenv("APP_HOST"),

			ExcludedTools:   os.Getenv("EXCLUDED_TOOLS"),
			AdminSecretPath: adminSecretPath,

			OAuthJWTSecret: os.Getenv("OAUTH_JWT_SECRET"),
			ExternalURL:    os.Getenv("EXTERNAL_URL"),

			TelegramBotToken: os.Getenv("TELEGRAM_BOT_TOKEN"),
			AlertDBPath:      os.Getenv("ALERT_DB_PATH"),
			AdminEmails:      os.Getenv("ADMIN_EMAILS"),

			GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		},
		Version:   "v0.0.0", // Ideally injected at build time
		startTime: time.Now(),
		logger:    logger,
		metrics: metrics.New(metrics.Config{
			ServiceName:     "kite-mcp-server",
			AdminSecretPath: adminSecretPath,
			AutoCleanup:     true,
		}),
	}
}

// SetVersion sets the server version
func (app *App) SetVersion(version string) {
	app.Version = version
}

// SetLogBuffer sets the log buffer for the ops dashboard SSE stream.
func (app *App) SetLogBuffer(buf *ops.LogBuffer) {
	app.logBuffer = buf
}

// LoadConfig loads and validates the application configuration
func (app *App) LoadConfig() error {
	if app.Config.AppMode == "" {
		app.Config.AppMode = DefaultAppMode
	}

	if app.Config.AppPort == "" {
		app.Config.AppPort = DefaultPort
	}

	if app.Config.AppHost == "" {
		app.Config.AppHost = DefaultHost
	}

	if app.Config.KiteAPIKey == "" || app.Config.KiteAPISecret == "" {
		if app.Config.OAuthJWTSecret == "" {
			return fmt.Errorf("KITE_API_KEY and KITE_API_SECRET are required (or enable OAuth with OAUTH_JWT_SECRET for per-user credentials)")
		}
		app.logger.Info("No global Kite credentials — per-user credentials required via MCP client config (oauth_client_id/oauth_client_secret)")
	}

	// EXTERNAL_URL is required when OAuth is enabled (multi-user mode).
	if app.Config.OAuthJWTSecret != "" && app.Config.ExternalURL == "" {
		return fmt.Errorf("EXTERNAL_URL is required when OAUTH_JWT_SECRET is set")
	}

	return nil
}

// RunServer initializes and starts the server based on the configured mode
func (app *App) RunServer() error {
	url := app.buildServerURL()
	app.configureHTTPClient()

	kcManager, mcpServer, err := app.initializeServices()
	if err != nil {
		return err
	}

	// Initialize OAuth handler if configured (uses Kite as identity provider)
	if app.Config.OAuthJWTSecret != "" {
		oauthCfg := &oauth.Config{
			KiteAPIKey:  app.Config.KiteAPIKey,
			JWTSecret:   app.Config.OAuthJWTSecret,
			ExternalURL: app.Config.ExternalURL,
			Logger:      app.logger,
		}
		if err := oauthCfg.Validate(); err != nil {
			return fmt.Errorf("invalid OAuth config: %w", err)
		}
		signer := &signerAdapter{signer: kcManager.SessionSigner()}
		exchanger := &kiteExchangerAdapter{
			apiKey:          app.Config.KiteAPIKey,
			apiSecret:       app.Config.KiteAPISecret,
			tokenStore:      kcManager.TokenStoreConcrete(),
			credentialStore: kcManager.CredentialStoreConcrete(),
			registryStore:   kcManager.RegistryStoreConcrete(),
			userStore:       kcManager.UserStoreConcrete(),
			logger:          app.logger,
		}
		app.oauthHandler = oauth.NewHandler(oauthCfg, signer, exchanger)

		// Wire Kite token expiry check into OAuth middleware.
		// When a cached Kite token expires (~6 AM IST daily), RequireAuth returns 401,
		// forcing mcp-remote to re-authenticate — which includes a fresh Kite login.
		// Three states:
		//   1. Valid token cached → pass through (tools work)
		//   2. Expired/missing token BUT credentials exist → 401 (force re-auth)
		//   3. No credentials at all → pass through (first-time user, tool handler prompts)
		tokenStore := kcManager.TokenStore()
		credStore := kcManager.CredentialStore()
		uStore := kcManager.UserStore()
		app.oauthHandler.SetKiteTokenChecker(func(email string) bool {
			if email == "" {
				return true
			}
			// Reject suspended or offboarded users
			if uStore != nil {
				status := uStore.GetStatus(email)
				if status == users.StatusSuspended || status == users.StatusOffboarded {
					return false
				}
			}
			// Check if a valid (non-expired) Kite token exists
			entry, hasToken := tokenStore.Get(email)
			if hasToken && !kc.IsKiteTokenExpired(entry.StoredAt) {
				return true // valid token, pass through
			}
			// No valid token. If user has stored credentials, they're a returning
			// user whose token expired or was cleaned up — force re-auth via 401.
			if _, hasCredentials := credStore.Get(email); hasCredentials {
				return false
			}
			// No credentials = first-time user, let tool handlers deal with onboarding
			return true
		})

		// Wire OAuth client registration persistence
		if alertDB := kcManager.AlertDB(); alertDB != nil {
			app.oauthHandler.SetClientPersister(&clientPersisterAdapter{db: alertDB}, app.logger)
			if err := app.oauthHandler.LoadClientsFromDB(); err != nil {
				app.logger.Error("Failed to load OAuth clients from DB", "error", err)
			} else {
				app.logger.Info("OAuth clients loaded from database")
			}
		}

		// Wire key registry for zero-config onboarding
		if regStore := kcManager.RegistryStoreConcrete(); regStore != nil {
			app.oauthHandler.SetRegistry(&registryAdapter{store: regStore})
			app.logger.Info("Key registry wired into OAuth handler", "entries", regStore.Count())
		}

		app.logger.Info("OAuth 2.1 enabled (Kite identity provider)", "external_url", app.Config.ExternalURL)
	}

	srv := app.createHTTPServer(url)
	app.setupGracefulShutdown(srv, kcManager)

	return app.startServer(srv, kcManager, mcpServer, url)
}

// buildServerURL constructs the server URL from host and port
func (app *App) buildServerURL() string {
	return app.Config.AppHost + ":" + app.Config.AppPort
}

// httpClient is a package-level HTTP client with a timeout, used instead of
// modifying the global http.DefaultClient which would affect all code.
var httpClient = &http.Client{Timeout: 30 * time.Second}

// configureHTTPClient logs that the package-level HTTP client is ready.
func (app *App) configureHTTPClient() {
	app.logger.Debug("HTTP client timeout set to 30 seconds")
}

// initializeServices creates and configures Kite Connect manager and MCP server
func (app *App) initializeServices() (*kc.Manager, *server.MCPServer, error) {
	app.logger.Info("Creating Kite Connect manager...")
	kcManager, err := kc.New(kc.Config{
		APIKey:           app.Config.KiteAPIKey,
		APISecret:        app.Config.KiteAPISecret,
		AccessToken:      app.Config.KiteAccessToken,
		Logger:           app.logger,
		Metrics:          app.metrics,
		TelegramBotToken: app.Config.TelegramBotToken,
		AlertDBPath:      app.Config.AlertDBPath,
		AppMode:          app.Config.AppMode,
		ExternalURL:      app.Config.ExternalURL,
		AdminSecretPath:  app.Config.AdminSecretPath,
		EncryptionSecret: app.Config.OAuthJWTSecret,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create Kite Connect manager: %w", err)
	}

	// Store reference for template data
	app.kcManager = kcManager

	// Initialize the status template early for the status page
	if err := app.initStatusPageTemplate(); err != nil {
		app.logger.Warn("Failed to initialize status template", "error", err)
	}

	app.logger.Debug("Kite Connect manager created successfully")

	// Create audit store (reuse the same SQLite DB used for alerts).
	var auditMiddleware server.ToolHandlerMiddleware
	if alertDB := kcManager.AlertDB(); alertDB != nil {
		app.auditStore = audit.New(alertDB)
		if err := app.auditStore.InitTable(); err != nil {
			app.logger.Error("Failed to initialize audit table", "error", err)
		} else {
			// Wire encryption key for HMAC email hashing, AES-GCM email encryption,
			// and HMAC-SHA256 hash chaining.
			if app.Config.OAuthJWTSecret != "" {
				if encKey, err := alerts.EnsureEncryptionSalt(alertDB, app.Config.OAuthJWTSecret); err == nil {
					app.auditStore.SetEncryptionKey(encKey)
					app.auditStore.SeedChain()
					app.logger.Info("Audit trail encryption and hash chaining enabled")
				} else {
					app.logger.Error("Failed to derive audit encryption key", "error", err)
				}
			}
			app.auditStore.SetLogger(app.logger)
			app.auditStore.StartWorker()
			app.logger.Info("Audit trail enabled")
			auditMiddleware = audit.Middleware(app.auditStore)

			// Wire audit store into manager for alert trigger + trailing stop notifications.
			kcManager.SetAuditStore(app.auditStore)
		}
	}

	// Initialize riskguard for financial safety controls.
	riskGuard := riskguard.NewGuard(app.logger)
	if alertDB := kcManager.AlertDB(); alertDB != nil {
		riskGuard.SetDB(alertDB)
		if err := riskGuard.InitTable(); err != nil {
			app.logger.Error("Failed to initialize risk_limits table", "error", err)
		}
		if err := riskGuard.LoadLimits(); err != nil {
			app.logger.Error("Failed to load risk limits", "error", err)
		}
	}
	if kcManager.InstrumentsManagerConcrete() != nil {
		// Wrap instruments manager as FreezeQuantityLookup
		riskGuard.SetFreezeQuantityLookup(&instrumentsFreezeAdapter{mgr: kcManager.InstrumentsManagerConcrete()})
	}
	// Wire auto-freeze Telegram admin notification.
	if notifier := kcManager.TelegramNotifier(); notifier != nil {
		adminEmails := strings.Split(app.Config.AdminEmails, ",")
		riskGuard.SetAutoFreezeNotifier(func(email, reason string) {
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
		app.logger.Info("RiskGuard auto-freeze Telegram notifications wired")
	}
	kcManager.SetRiskGuard(riskGuard)

	// Initialize paper trading engine.
	var paperEngine *papertrading.PaperEngine
	if alertDB := kcManager.AlertDB(); alertDB != nil {
		paperStore := papertrading.NewStore(alertDB, app.logger)
		if err := paperStore.InitTables(); err != nil {
			app.logger.Error("Failed to initialize paper trading tables", "error", err)
		}
		paperEngine = papertrading.NewEngine(paperStore, app.logger)
		kcManager.SetPaperEngine(paperEngine)
	}

	// Create MCP server
	app.logger.Info("Creating MCP server...")
	var serverOpts []server.ServerOption
	if auditMiddleware != nil {
		serverOpts = append(serverOpts, server.WithToolHandlerMiddleware(auditMiddleware))
	}
	// Riskguard middleware blocks orders exceeding safety limits.
	serverOpts = append(serverOpts, server.WithToolHandlerMiddleware(riskguard.Middleware(riskGuard)))
	// Billing tier middleware gates tools by subscription level (opt-in via STRIPE_SECRET_KEY).
	if os.Getenv("STRIPE_SECRET_KEY") != "" {
		billingStore := billing.NewStore(kcManager.AlertDB(), app.logger)
		if err := billingStore.InitTable(); err != nil {
			app.logger.Error("Failed to initialize billing table", "error", err)
		} else if err := billingStore.LoadFromDB(); err != nil {
			app.logger.Error("Failed to load billing data from DB", "error", err)
		}
		kcManager.SetBillingStore(billingStore)
		serverOpts = append(serverOpts, server.WithToolHandlerMiddleware(billing.Middleware(billingStore)))
		app.logger.Info("Billing tier enforcement enabled")
		if os.Getenv("STRIPE_PRICE_PRO") == "" || os.Getenv("STRIPE_PRICE_PREMIUM") == "" {
			app.logger.Warn("STRIPE_SECRET_KEY is set but STRIPE_PRICE_PRO and/or STRIPE_PRICE_PREMIUM are missing. Webhook tier mapping will default to Pro.")
		}
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
	if paperEngine != nil {
		paperEngine.SetLTPProvider(&paperLTPAdapter{manager: kcManager})
		paperMonitor := papertrading.NewMonitor(paperEngine, 5*time.Second, app.logger)
		paperMonitor.Start()
		app.logger.Info("Paper trading engine and monitor initialized")
	}

	// Register tools that will interact with MCP sessions and Kite API
	app.logger.Info("Registering MCP tools...")
	mcp.RegisterTools(mcpServer, kcManager, app.Config.ExcludedTools, app.auditStore, app.logger)
	app.logger.Debug("MCP tools registered successfully")

	// Initialize scheduled Telegram briefings (morning + daily P&L).
	app.initScheduler(kcManager)

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
type briefingTokenAdapter struct {
	store *kc.KiteTokenStore
}

func (a *briefingTokenAdapter) GetToken(email string) (string, time.Time, bool) {
	entry, ok := a.store.Get(email)
	if !ok {
		return "", time.Time{}, false
	}
	return entry.AccessToken, entry.StoredAt, true
}

func (a *briefingTokenAdapter) IsExpired(storedAt time.Time) bool {
	return kc.IsKiteTokenExpired(storedAt)
}

// briefingCredAdapter bridges kc.Manager to alerts.CredentialGetter.
type briefingCredAdapter struct {
	manager *kc.Manager
}

func (a *briefingCredAdapter) GetAPIKey(email string) string {
	return a.manager.GetAPIKeyForEmail(email)
}

// paperLTPAdapter bridges kc.Manager to papertrading.LTPProvider by using
// any active session's Kite client for read-only LTP lookups.
type paperLTPAdapter struct {
	manager *kc.Manager
}

func (a *paperLTPAdapter) GetLTP(instruments ...string) (map[string]float64, error) {
	sessions := a.manager.SessionManager().ListActiveSessions()
	if len(sessions) == 0 {
		return nil, fmt.Errorf("no active Kite sessions for LTP lookup")
	}
	for _, sess := range sessions {
		data, ok := sess.Data.(*kc.KiteSessionData)
		if !ok || data == nil || data.Kite == nil || data.Kite.Client == nil {
			continue
		}
		ltps, err := data.Kite.Client.GetLTP(instruments...)
		if err != nil {
			continue
		}
		result := make(map[string]float64, len(ltps))
		for k, v := range ltps {
			result[k] = v.LastPrice
		}
		return result, nil
	}
	return nil, fmt.Errorf("no Kite client available for LTP")
}

// instrumentsFreezeAdapter wraps instruments.Manager to implement riskguard.FreezeQuantityLookup.
type instrumentsFreezeAdapter struct {
	mgr *instruments.Manager
}

func (a *instrumentsFreezeAdapter) GetFreezeQuantity(exchange, tradingsymbol string) (uint32, bool) {
	inst, err := a.mgr.GetByTradingsymbol(exchange, tradingsymbol)
	if err != nil {
		return 0, false
	}
	return inst.FreezeQuantity, inst.FreezeQuantity > 0
}

// createHTTPServer creates and configures the HTTP server
func (app *App) createHTTPServer(url string) *http.Server {
	return &http.Server{
		Addr:              url,
		ReadHeaderTimeout: 30 * time.Second,
		WriteTimeout:      120 * time.Second,
	}
}

// setupGracefulShutdown configures graceful shutdown for the server.
// Note: stop() is deferred inside the goroutine. If the server exits without
// receiving a signal (e.g., startup error), the goroutine and signal registration
// are cleaned up by process exit. This is acceptable for a long-running server.
func (app *App) setupGracefulShutdown(srv *http.Server, kcManager *kc.Manager) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	go func() {
		defer stop()
		<-ctx.Done()
		app.logger.Info("Shutting down server...")

		// Stop briefing scheduler first (prevent new Kite API calls).
		if app.scheduler != nil {
			app.scheduler.Stop()
		}

		// Shutdown HTTP server first (stop accepting new requests, drain in-flight)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			app.logger.Error("Server shutdown error", "error", err)
		}

		// Then drain audit buffer (all in-flight requests have completed)
		if app.auditStore != nil {
			app.auditStore.Stop()
		}

		// Shutdown Telegram bot cleanup goroutine.
		if app.telegramBot != nil {
			app.telegramBot.Shutdown()
		}

		// Then shutdown Kite manager (session cleanup and instruments scheduler)
		kcManager.Shutdown()

		// Close OAuth auth code store cleanup goroutine
		if app.oauthHandler != nil {
			app.oauthHandler.Close()
		}

		app.logger.Info("Server shutdown complete")
	}()
}

// startServer selects the appropriate server mode to start
func (app *App) startServer(srv *http.Server, kcManager *kc.Manager, mcpServer *server.MCPServer, url string) error {
	switch app.Config.AppMode {
	default:
		return fmt.Errorf("invalid APP_MODE: %s", app.Config.AppMode)

	case ModeHybrid:
		app.startHybridServer(srv, kcManager, mcpServer, url)

	case ModeStdIO:
		app.startStdIOServer(srv, kcManager, mcpServer)

	case ModeSSE:
		app.startSSEServer(srv, kcManager, mcpServer, url)

	case ModeHTTP:
		app.startHTTPServer(srv, kcManager, mcpServer, url)
	}

	return nil
}

// setupMux creates and configures a new HTTP mux with common handlers.
func (app *App) setupMux(kcManager *kc.Manager) *http.ServeMux {
	mux := http.NewServeMux()

	// Initialize per-IP rate limiters (cleanup goroutine runs in background)
	app.rateLimiters = newRateLimiters()

	// Unified /callback handler: dispatches by flow param
	// - flow=oauth → MCP OAuth callback (Kite → JWT → MCP auth code)
	// - flow=browser → Browser auth callback (Kite → JWT cookie for ops dashboard)
	// - default      → Login tool re-auth (existing session_id flow)
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		requestToken := r.URL.Query().Get("request_token")
		flow := r.URL.Query().Get("flow")
		switch flow {
		case "oauth":
			if app.oauthHandler != nil {
				app.oauthHandler.HandleKiteOAuthCallback(w, r, requestToken)
			} else {
				http.Error(w, "OAuth not configured", http.StatusInternalServerError)
			}
		case "browser":
			if app.oauthHandler != nil {
				app.oauthHandler.HandleBrowserAuthCallback(w, r, requestToken)
			} else {
				http.Error(w, "OAuth not configured", http.StatusInternalServerError)
			}
		default:
			kcManager.HandleKiteCallback()(w, r)
		}
	})

	if app.Config.AdminSecretPath != "" {
		mux.HandleFunc("/admin/", app.metrics.AdminHTTPHandler())
	}
	// Ops dashboard: protected by OAuth if available, otherwise by secret path
	// Seed admin users from ADMIN_EMAILS env var into the user store.
	// Only seed on fresh database (no existing users) so that runtime
	// role changes (e.g. demotions via admin console) are not overridden.
	userStore := kcManager.UserStoreConcrete()
	if userStore != nil && app.Config.AdminEmails != "" {
		adminEmails := strings.Split(app.Config.AdminEmails, ",")
		if userStore.Count() == 0 {
			for _, email := range adminEmails {
				email = strings.TrimSpace(strings.ToLower(email))
				if email == "" {
					continue
				}
				userStore.EnsureAdmin(email)
				app.logger.Info("Admin role seeded from ADMIN_EMAILS env var", "email", email)
			}
			app.logger.Info("Admin users seeded on fresh database", "count", len(adminEmails))
		} else {
			app.logger.Info("Skipping admin seeding — users table already populated", "user_count", userStore.Count())
		}
	}

	// Seed admin password from ADMIN_PASSWORD env var (first boot only).
	if adminPassword := os.Getenv("ADMIN_PASSWORD"); adminPassword != "" && userStore != nil && app.Config.AdminEmails != "" {
		adminEmails := strings.Split(app.Config.AdminEmails, ",")
		if len(adminEmails) > 1 {
			app.logger.Warn("ADMIN_PASSWORD is shared across all admin emails. Consider setting individual passwords via the admin console after first login.")
		}
		for _, email := range adminEmails {
			email = strings.TrimSpace(email)
			if email == "" {
				continue
			}
			if !userStore.HasPassword(email) {
				hash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), 12)
				if err != nil {
					app.logger.Error("Failed to hash admin password", "email", email, "error", err)
					continue
				}
				if err := userStore.SetPasswordHash(email, string(hash)); err != nil {
					app.logger.Error("Failed to set admin password hash", "email", email, "error", err)
				} else {
					app.logger.Info("Admin password set", "email", email)
				}
			}
		}
		app.logger.Warn("ADMIN_PASSWORD env var is set. Consider unsetting it after first boot for security.")
	}

	// Wire user store into OAuth handler for admin login
	if app.oauthHandler != nil && userStore != nil {
		app.oauthHandler.SetUserStore(userStore)
	}

	// Wire Google SSO for admin login (opt-in via env vars)
	if app.oauthHandler != nil && app.Config.GoogleClientID != "" && app.Config.GoogleClientSecret != "" {
		app.oauthHandler.SetGoogleSSO(&oauth.GoogleSSOConfig{
			ClientID:     app.Config.GoogleClientID,
			ClientSecret: app.Config.GoogleClientSecret,
			RedirectURL:  app.Config.ExternalURL + "/auth/google/callback",
		})
		app.logger.Info("Google SSO enabled for admin login")
	}

	opsHandler := ops.New(kcManager, app.metrics, app.logBuffer, app.logger, app.Version, app.startTime, userStore, app.auditStore)
	// Admin auth middleware: checks kite_jwt cookie, redirects to /auth/admin-login if missing,
	// and requires the authenticated email to be in ADMIN_EMAILS.
	adminAuth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var email string
			// If OAuth handler is available, try extracting email from JWT cookie
			if app.oauthHandler != nil {
				// Try cookie
				if cookie, err := r.Cookie("kite_jwt"); err == nil && cookie.Value != "" {
					if claims, err := app.oauthHandler.JWTManager().ValidateToken(cookie.Value, "dashboard"); err == nil {
						email = claims.Subject
					}
				}
			}
			if email == "" {
				// Redirect to admin login page
				redirect := r.URL.Path
				if !strings.HasPrefix(redirect, "/") || strings.HasPrefix(redirect, "//") {
					redirect = "/admin/ops"
				}
				http.Redirect(w, r, "/auth/admin-login?redirect="+url.QueryEscape(redirect), http.StatusFound)
				return
			}
			if userStore == nil || !userStore.IsAdmin(email) {
				http.Error(w, "Forbidden: admin access required", http.StatusForbidden)
				return
			}
			// Set email in context for downstream handlers
			ctx := oauth.ContextWithEmail(r.Context(), email)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	if app.oauthHandler != nil || userStore != nil {
		opsHandler.RegisterRoutes(mux, adminAuth)
	} else if app.Config.AdminSecretPath != "" {
		// Fallback for local dev: use identity middleware (no auth)
		opsHandler.RegisterRoutes(mux, func(next http.Handler) http.Handler { return next })
	}
	// User dashboard: protected by OAuth if available, otherwise identity middleware
	dashHandler := ops.NewDashboardHandler(kcManager, app.logger, app.auditStore)
	if userStore != nil {
		dashHandler.SetAdminCheck(userStore.IsAdmin)
	}
	if bs := kcManager.BillingStore(); bs != nil {
		dashHandler.SetBillingStore(bs)
	}
	if app.oauthHandler != nil {
		dashHandler.RegisterRoutes(mux, app.oauthHandler.RequireAuthBrowser)
	} else {
		dashHandler.RegisterRoutes(mux, func(h http.Handler) http.Handler { return h })
	}

	// Serve security.txt for responsible disclosure (RFC 9116)
	mux.HandleFunc("/.well-known/security.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("Contact: mailto:sundeepg8@gmail.com\nExpires: 2027-04-02T00:00:00.000Z\nPreferred-Languages: en\n"))
	})

	// MCP Server Card for auto-discovery (SEP-1649)
	mux.HandleFunc("/.well-known/mcp/server-card.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"$schema":         "https://modelcontextprotocol.io/schemas/server-card/v1.0",
			"version":         "1.0",
			"protocolVersion": "2025-06-18",
			"serverInfo": map[string]any{
				"name":        "Kite Trading MCP Server",
				"version":     app.Version,
				"description": fmt.Sprintf("Indian stock market trading via Zerodha Kite Connect. %d tools for order execution, portfolio analytics, options Greeks, paper trading, backtesting, technical indicators, price alerts with Telegram, watchlists, tax harvesting, and SEBI compliance.", len(mcp.GetAllTools())),
				"homepage":    "https://github.com/Sundeepg98/kite-mcp-server",
			},
			"transport": map[string]any{
				"type": "streamable-http",
				"url":  "/mcp",
			},
			"capabilities": map[string]any{
				"tools":     true,
				"resources": true,
				"prompts":   true,
			},
			"authentication": map[string]any{
				"required": true,
				"schemes":  []string{"oauth2"},
			},
		})
	})

	// Register OAuth 2.1 endpoints if enabled (with per-IP rate limiting)
	if app.oauthHandler != nil {
		mux.HandleFunc("/.well-known/oauth-protected-resource", app.oauthHandler.ResourceMetadata)
		mux.HandleFunc("/.well-known/oauth-authorization-server", app.oauthHandler.AuthServerMetadata)
		mux.Handle("/oauth/register", rateLimitFunc(app.rateLimiters.auth, app.oauthHandler.Register))
		mux.Handle("/oauth/authorize", rateLimitFunc(app.rateLimiters.auth, app.oauthHandler.Authorize))
		mux.Handle("/oauth/token", rateLimitFunc(app.rateLimiters.token, app.oauthHandler.Token))
		mux.Handle("/oauth/email-lookup", rateLimitFunc(app.rateLimiters.auth, app.oauthHandler.HandleEmailLookup))
	}
	// Register browser login routes for dashboard auth (requires OAuth)
	if app.oauthHandler != nil {
		mux.Handle("/auth/login", rateLimitFunc(app.rateLimiters.auth, app.oauthHandler.HandleLoginChoice))
		mux.Handle("/auth/browser-login", rateLimitFunc(app.rateLimiters.auth, app.oauthHandler.HandleBrowserLogin))
		mux.Handle("/auth/admin-login", rateLimitFunc(app.rateLimiters.auth, app.oauthHandler.HandleAdminLogin))
		mux.Handle("/auth/google/login", rateLimitFunc(app.rateLimiters.auth, app.oauthHandler.HandleGoogleLogin))
		mux.Handle("/auth/google/callback", rateLimitFunc(app.rateLimiters.auth, app.oauthHandler.HandleGoogleCallback))
	}

	// Register Stripe webhook endpoint (no auth — Stripe calls this with a signed payload).
	if webhookSecret := os.Getenv("STRIPE_WEBHOOK_SECRET"); webhookSecret != "" {
		if bs := kcManager.BillingStoreConcrete(); bs != nil {
			if err := bs.InitEventLogTable(); err != nil {
				app.logger.Error("Failed to initialize webhook_events table", "error", err)
			}
			mux.Handle("/webhooks/stripe", billing.WebhookHandler(bs, webhookSecret, app.logger))
			app.logger.Info("Stripe webhook endpoint registered at /webhooks/stripe")
		} else {
			app.logger.Warn("STRIPE_WEBHOOK_SECRET set but billing store not initialized (need STRIPE_SECRET_KEY)")
		}
	}

	// Register Telegram bot webhook if configured.
	app.registerTelegramWebhook(mux, kcManager)

	// Health check endpoint for load balancers and container orchestration.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"uptime":  time.Since(app.startTime).Truncate(time.Second).String(),
			"version": app.Version,
			"tools":   len(mcp.GetAllTools()),
		})
	})

	app.serveLegalPages(mux)
	app.serveStatusPage(mux)
	return mux
}

// registerTelegramWebhook registers the Telegram bot webhook endpoint and
// sets up bot commands with BotFather. The webhook URL contains a secret
// derived from OAUTH_JWT_SECRET to prevent unauthorized requests.
func (app *App) registerTelegramWebhook(mux *http.ServeMux, kcManager *kc.Manager) {
	notifier := kcManager.TelegramNotifier()
	if notifier == nil || notifier.Bot() == nil {
		return
	}
	if app.Config.OAuthJWTSecret == "" || app.Config.ExternalURL == "" {
		app.logger.Info("Telegram webhook: skipping (no OAUTH_JWT_SECRET or EXTERNAL_URL)")
		return
	}

	// Derive a deterministic webhook secret from the JWT secret.
	hash := sha256.Sum256([]byte(app.Config.OAuthJWTSecret + "telegram-webhook"))
	webhookSecret := hex.EncodeToString(hash[:])[:32]

	// Create bot command handler. The telegramManagerAdapter bridges *kc.Manager
	// to telegram.KiteManager, adapting interface return types.
	botHandler := tgbot.NewBotHandler(notifier.Bot(), webhookSecret, &telegramManagerAdapter{m: kcManager}, app.logger)
	app.telegramBot = botHandler

	// Register the webhook endpoint (the secret in the path prevents spoofing).
	webhookPath := "/telegram/webhook/" + webhookSecret
	mux.Handle(webhookPath, botHandler)

	// Register webhook URL with Telegram API.
	webhookURL := app.Config.ExternalURL + webhookPath
	wh, err := tgbotapi.NewWebhook(webhookURL)
	if err != nil {
		app.logger.Error("Telegram webhook: failed to create webhook config", "error", err)
		return
	}
	wh.MaxConnections = 10
	wh.AllowedUpdates = []string{"message", "callback_query"}
	if _, err := notifier.Bot().Request(wh); err != nil {
		app.logger.Error("Telegram webhook: failed to register with Telegram", "error", err)
		return
	}

	// Register bot commands with BotFather for autocomplete.
	commands := tgbotapi.NewSetMyCommands(
		tgbotapi.BotCommand{Command: "price", Description: "Check stock price"},
		tgbotapi.BotCommand{Command: "portfolio", Description: "Holdings summary"},
		tgbotapi.BotCommand{Command: "positions", Description: "Open positions"},
		tgbotapi.BotCommand{Command: "orders", Description: "Today's orders"},
		tgbotapi.BotCommand{Command: "pnl", Description: "Today's P&L"},
		tgbotapi.BotCommand{Command: "alerts", Description: "Active alerts"},
		tgbotapi.BotCommand{Command: "watchlist", Description: "Watchlist prices"},
		tgbotapi.BotCommand{Command: "status", Description: "Token and system status"},
		tgbotapi.BotCommand{Command: "help", Description: "Command list"},
	)
	if _, err := notifier.Bot().Request(commands); err != nil {
		app.logger.Error("Telegram webhook: failed to register bot commands", "error", err)
	}

	app.logger.Info("Telegram bot webhook registered", "url", webhookURL)
}

// serveHTTPServer starts the HTTP server with error handling
func (app *App) serveHTTPServer(srv *http.Server) {
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		app.logger.Error("HTTP server error", "error", err)
	}
}

// createSSEServer creates and configures an SSE server
func (app *App) createSSEServer(mcpServer *server.MCPServer, url string) *server.SSEServer {
	return server.NewSSEServer(mcpServer,
		server.WithBaseURL(url),
		server.WithKeepAlive(true),
	)
}

// createStreamableHTTPServer creates and configures a streamable HTTP server
func (app *App) createStreamableHTTPServer(mcpServer *server.MCPServer, kcManager *kc.Manager) *server.StreamableHTTPServer {
	return server.NewStreamableHTTPServer(mcpServer,
		server.WithSessionIdManager(kcManager.SessionManager()),
		server.WithLogger(util.DefaultLogger()),
	)
}

// withSessionType adds session type to context based on URL path
func withSessionType(sessionType string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := mcp.WithSessionType(r.Context(), sessionType)
		r = r.WithContext(ctx)
		handler(w, r)
	}
}

// registerSSEEndpoints registers SSE-specific endpoints on the mux
func (app *App) registerSSEEndpoints(mux *http.ServeMux, sse *server.SSEServer) {
	sseHandler := withSessionType(mcp.SessionTypeSSE, sse.ServeHTTP)

	if app.oauthHandler != nil {
		mux.Handle("/sse", rateLimit(app.rateLimiters.mcp)(app.oauthHandler.RequireAuth(http.HandlerFunc(sseHandler))))
		mux.Handle("/message", rateLimit(app.rateLimiters.mcp)(app.oauthHandler.RequireAuth(http.HandlerFunc(sseHandler))))
	} else {
		mux.Handle("/sse", rateLimitFunc(app.rateLimiters.mcp, sseHandler))
		mux.Handle("/message", rateLimitFunc(app.rateLimiters.mcp, sseHandler))
	}
}

// securityHeaders wraps a handler with standard security headers.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

// configureAndStartServer sets up server handler and starts it
func (app *App) configureAndStartServer(srv *http.Server, mux *http.ServeMux) {
	srv.Handler = securityHeaders(mux)
	app.serveHTTPServer(srv)
}


// startHybridServer starts a server with both SSE and MCP endpoints
func (app *App) startHybridServer(srv *http.Server, kcManager *kc.Manager, mcpServer *server.MCPServer, url string) {
	app.logger.Info("Starting Hybrid MCP server with both SSE and MCP endpoints", "url", "http://"+url)

	// Initialize both server types
	sse := app.createSSEServer(mcpServer, url)
	streamable := app.createStreamableHTTPServer(mcpServer, kcManager)

	// Setup mux with common handlers
	mux := app.setupMux(kcManager)

	// Register endpoints
	app.registerSSEEndpoints(mux, sse)
	mcpHandler := withSessionType(mcp.SessionTypeMCP, streamable.ServeHTTP)
	if app.oauthHandler != nil {
		mux.Handle("/mcp", rateLimit(app.rateLimiters.mcp)(app.oauthHandler.RequireAuth(http.HandlerFunc(mcpHandler))))
	} else {
		mux.Handle("/mcp", rateLimitFunc(app.rateLimiters.mcp, mcpHandler))
	}

	app.logger.Info("Hybrid mode enabled with both SSE and MCP endpoints on the same server")
	app.logger.Info("SSE endpoints available", "url", fmt.Sprintf("http://%s/sse and http://%s/message", url, url))
	app.logger.Info("MCP endpoint available", "url", fmt.Sprintf("http://%s/mcp", url))

	app.configureAndStartServer(srv, mux)
}

// startStdIOServer starts a server in STDIO mode
func (app *App) startStdIOServer(srv *http.Server, kcManager *kc.Manager, mcpServer *server.MCPServer) {
	app.logger.Info("Starting STDIO MCP server...")
	stdio := server.NewStdioServer(mcpServer)

	// Setup mux with common handlers
	mux := app.setupMux(kcManager)

	go app.configureAndStartServer(srv, mux)

	ctx := context.Background()
	if err := stdio.Listen(ctx, os.Stdin, os.Stdout); err != nil {
		app.logger.Error("STDIO server error", "error", err)
	}
}

// startSSEServer starts a server in SSE mode
func (app *App) startSSEServer(srv *http.Server, kcManager *kc.Manager, mcpServer *server.MCPServer, url string) {
	app.logger.Info("Starting SSE MCP server", "url", "http://"+url)
	sse := app.createSSEServer(mcpServer, url)

	// Setup mux with common handlers
	mux := app.setupMux(kcManager)
	app.registerSSEEndpoints(mux, sse)

	app.logger.Info("Active MCP and Kite sessions will be monitored and cleaned up automatically")
	app.configureAndStartServer(srv, mux)
}

// startHTTPServer starts a server in HTTP mode
func (app *App) startHTTPServer(srv *http.Server, kcManager *kc.Manager, mcpServer *server.MCPServer, url string) {
	app.logger.Info("Starting Streamable HTTP MCP server", "url", "http://"+url)
	streamable := app.createStreamableHTTPServer(mcpServer, kcManager)

	// Setup mux with common handlers
	mux := app.setupMux(kcManager)

	// Register /mcp with optional OAuth middleware (rate limited)
	mcpHandler := withSessionType(mcp.SessionTypeMCP, streamable.ServeHTTP)
	if app.oauthHandler != nil {
		mux.Handle("/mcp", rateLimit(app.rateLimiters.mcp)(app.oauthHandler.RequireAuth(http.HandlerFunc(mcpHandler))))
		app.logger.Info("OAuth middleware enabled for /mcp endpoint")
	} else {
		mux.Handle("/mcp", rateLimitFunc(app.rateLimiters.mcp, mcpHandler))
	}

	app.logger.Info("MCP session manager configured with automatic cleanup for both MCP and Kite sessions")
	app.logger.Info("MCP Session manager configured", "session_expiry", kc.DefaultSessionDuration)
	app.logger.Info("Serving documentation at root URL")

	app.configureAndStartServer(srv, mux)
}

// initStatusPageTemplate initializes the status and landing templates
func (app *App) initStatusPageTemplate() error {
	tmpl, err := template.ParseFS(templates.FS, "base.html", "status.html")
	if err != nil {
		return fmt.Errorf("failed to parse status template: %w", err)
	}
	app.statusTemplate = tmpl

	landing, err := template.ParseFS(templates.FS, "landing.html")
	if err != nil {
		return fmt.Errorf("failed to parse landing template: %w", err)
	}
	app.landingTemplate = landing

	legal, err := template.ParseFS(templates.FS, "legal.html")
	if err != nil {
		return fmt.Errorf("failed to parse legal template: %w", err)
	}
	app.legalTemplate = legal
	app.logger.Info("Status, landing, and legal templates initialized successfully")
	return nil
}

// getStatusData returns template data for the status page
func (app *App) getStatusData() StatusPageData {
	return StatusPageData{
		Title:     "Status",
		Version:   app.Version,
		Mode:      app.Config.AppMode,
		ToolCount: len(mcp.GetAllTools()),
	}
}

// legalPageData holds template data for the legal pages (Terms, Privacy).
type legalPageData struct {
	Title   string
	Content template.HTML
}

// serveLegalPages registers /terms and /privacy routes.
func (app *App) serveLegalPages(mux *http.ServeMux) {
	if app.legalTemplate == nil {
		return
	}

	serve := func(title string, content template.HTML) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var buf bytes.Buffer
			if err := app.legalTemplate.ExecuteTemplate(&buf, "legal", legalPageData{
				Title:   title,
				Content: content,
			}); err != nil {
				app.logger.Error("Failed to execute legal template", "page", title, "error", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "public, max-age=86400")
			_, _ = buf.WriteTo(w)
		}
	}

	mux.HandleFunc("/terms", serve("Terms of Service", termsHTML))
	mux.HandleFunc("/privacy", serve("Privacy Policy", privacyHTML))
	app.logger.Info("Legal pages registered at /terms and /privacy")
}

// serveStatusPage configures the HTTP mux to serve status page using templates.
// If OAuth is enabled and the user has a valid cookie, redirects to /dashboard.
// Otherwise shows the status page with login links.
func (app *App) serveStatusPage(mux *http.ServeMux) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Only serve status page at root path
		if path != "/" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("Not Found"))
			return
		}

		// If OAuth is configured, check for an existing valid dashboard cookie.
		// Authenticated users get redirected straight to the dashboard.
		if app.oauthHandler != nil {
			if cookie, err := r.Cookie(cookieName); err == nil && cookie.Value != "" {
				if _, err := app.oauthHandler.JWTManager().ValidateToken(cookie.Value, "dashboard"); err == nil {
					http.Redirect(w, r, "/dashboard", http.StatusFound)
					return
				}
			}
		}

		// Serve landing page for unauthenticated users
		data := app.getStatusData()
		data.OAuthEnabled = app.oauthHandler != nil

		// Use landing template if available, fall back to status template
		tmpl := app.landingTemplate
		if tmpl == nil {
			tmpl = app.statusTemplate
		}
		if tmpl == nil {
			// Fallback to simple text if no template loaded
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Kite MCP Server - Status template not available"))
			return
		}

		var buf bytes.Buffer
		if err := tmpl.ExecuteTemplate(&buf, "base", data); err != nil {
			app.logger.Error("Failed to execute landing template", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if _, err := buf.WriteTo(w); err != nil {
			app.logger.Error("Failed to write status page", "error", err)
		}
	})

	app.logger.Info("Template-based status page configured to be served at root URL")
}

// --- OAuth adapter types ---

// signerAdapter wraps kc.SessionSigner to implement oauth.Signer.
type signerAdapter struct {
	signer *kc.SessionSigner
}

// truncKey safely returns the first n characters of a string, or the whole string if shorter.
func truncKey(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (s *signerAdapter) Sign(data string) string {
	return s.signer.SignSessionID(data)
}

func (s *signerAdapter) Verify(signed string) (string, error) {
	return s.signer.VerifySessionID(signed)
}

// kiteExchangerAdapter exchanges a Kite request_token for user identity.
type kiteExchangerAdapter struct {
	apiKey          string
	apiSecret       string
	tokenStore      *kc.KiteTokenStore
	credentialStore *kc.KiteCredentialStore
	registryStore   *registry.Store
	userStore       *users.Store
	logger          *slog.Logger
}

// provisionUser auto-provisions a user on first OAuth login and checks status.
// Returns an error if the user is suspended or offboarded.
func (a *kiteExchangerAdapter) provisionUser(email, kiteUID, displayName string) error {
	if a.userStore == nil {
		return nil
	}
	email = strings.ToLower(email)

	// Check if user exists and their status
	status := a.userStore.GetStatus(email)
	if status == users.StatusSuspended {
		return fmt.Errorf("user account is suspended: %s", email)
	}
	if status == users.StatusOffboarded {
		return fmt.Errorf("user account has been offboarded: %s", email)
	}

	// Auto-provision new users as traders
	u := a.userStore.EnsureUser(email, kiteUID, displayName, "self")
	if u != nil {
		a.userStore.UpdateLastLogin(email)
		if kiteUID != "" && u.KiteUID == "" {
			a.userStore.UpdateKiteUID(email, kiteUID)
		}
	}
	return nil
}

func (a *kiteExchangerAdapter) ExchangeRequestToken(requestToken string) (string, error) {
	client := kiteconnect.New(a.apiKey)
	userSess, err := client.GenerateSession(requestToken, a.apiSecret)
	if err != nil {
		return "", fmt.Errorf("kite generate session: %w", err)
	}

	// UserSession embeds UserProfile — Email available directly
	email := userSess.Email
	if email == "" {
		email = userSess.UserID
	}

	// Auto-provision user and check status
	if err := a.provisionUser(email, userSess.UserID, userSess.UserName); err != nil {
		return "", err
	}

	a.logger.Debug("Kite token exchange successful", "email", email, "user_id", userSess.UserID)

	// Cache the access token keyed by email
	a.tokenStore.Set(strings.ToLower(email), &kc.KiteTokenEntry{
		AccessToken: userSess.AccessToken,
		UserID:      userSess.UserID,
		UserName:    userSess.UserName,
	})

	// Update last-used timestamp for the global API key in the registry
	if a.registryStore != nil && a.apiKey != "" {
		a.registryStore.UpdateLastUsedAt(a.apiKey)
	}

	return email, nil
}

func (a *kiteExchangerAdapter) ExchangeWithCredentials(requestToken, apiKey, apiSecret string) (string, error) {
	client := kiteconnect.New(apiKey)
	userSess, err := client.GenerateSession(requestToken, apiSecret)
	if err != nil {
		return "", fmt.Errorf("kite generate session with per-user credentials: %w", err)
	}

	email := userSess.Email
	if email == "" {
		email = userSess.UserID
	}

	// Auto-provision user and check status
	if err := a.provisionUser(email, userSess.UserID, userSess.UserName); err != nil {
		return "", err
	}

	a.logger.Debug("Kite token exchange (per-user credentials) successful", "email", email, "user_id", userSess.UserID)

	// Cache the access token keyed by email
	a.tokenStore.Set(strings.ToLower(email), &kc.KiteTokenEntry{
		AccessToken: userSess.AccessToken,
		UserID:      userSess.UserID,
		UserName:    userSess.UserName,
	})

	// Store per-user credentials so all future operations use them
	lowerEmail := strings.ToLower(email)
	a.credentialStore.Set(lowerEmail, &kc.KiteCredentialEntry{
		APIKey:    apiKey,
		APISecret: apiSecret,
	})

	// Auto-register self-provisioned keys in the registry (single source of truth).
	if a.registryStore != nil {
		// Check if user previously had a DIFFERENT key — must check before registering new one.
		oldEntry, oldFound := a.registryStore.GetByEmail(lowerEmail)
		if oldFound && oldEntry.APIKey != apiKey {
			a.registryStore.MarkStatus(oldEntry.APIKey, registry.StatusReplaced)
			a.logger.Info("Marked old registry key as replaced",
				"email", lowerEmail, "old_key", truncKey(oldEntry.APIKey, 8)+"...", "new_key", truncKey(apiKey, 8)+"...")
		}

		existing, found := a.registryStore.GetByAPIKeyAnyStatus(apiKey)
		if !found {
			// New key — register it
			regID := fmt.Sprintf("self-%s-%s", lowerEmail, truncKey(apiKey, 8))
			if err := a.registryStore.Register(&registry.AppRegistration{
				ID:           regID,
				APIKey:       apiKey,
				APISecret:    apiSecret,
				AssignedTo:   lowerEmail,
				Label:        "Self-provisioned",
				Status:       registry.StatusActive,
				Source:       registry.SourceSelfProvisioned,
				RegisteredBy: lowerEmail,
			}); err != nil {
				a.logger.Warn("Failed to auto-register self-provisioned key in registry",
					"email", lowerEmail, "error", err)
			} else {
				a.logger.Info("Auto-registered self-provisioned key in registry",
					"email", lowerEmail, "api_key", truncKey(apiKey, 8)+"...")
			}
		} else if existing.AssignedTo != lowerEmail {
			// Key exists but assigned to a different user — update assignment
			_ = a.registryStore.Update(existing.ID, lowerEmail, "", "")
		}
		// Record last used time for this key
		a.registryStore.UpdateLastUsedAt(apiKey)
	}

	return email, nil
}

func (a *kiteExchangerAdapter) GetCredentials(email string) (string, string, bool) {
	email = strings.ToLower(email)
	entry, ok := a.credentialStore.Get(email)
	if !ok {
		// Fall back to global credentials if available
		if a.apiKey != "" && a.apiSecret != "" {
			return a.apiKey, a.apiSecret, true
		}
		return "", "", false
	}
	return entry.APIKey, entry.APISecret, true
}

func (a *kiteExchangerAdapter) GetSecretByAPIKey(apiKey string) (string, bool) {
	return a.credentialStore.GetSecretByAPIKey(apiKey)
}

// clientPersisterAdapter bridges alerts.DB to oauth.ClientPersister.
type clientPersisterAdapter struct {
	db *alerts.DB
}

func (a *clientPersisterAdapter) SaveClient(clientID, clientSecret, redirectURIsJSON, clientName string, createdAt time.Time, isKiteKey bool) error {
	return a.db.SaveClient(clientID, clientSecret, redirectURIsJSON, clientName, createdAt, isKiteKey)
}

func (a *clientPersisterAdapter) LoadClients() ([]*oauth.ClientLoadEntry, error) {
	entries, err := a.db.LoadClients()
	if err != nil {
		return nil, err
	}
	result := make([]*oauth.ClientLoadEntry, len(entries))
	for i, e := range entries {
		result[i] = &oauth.ClientLoadEntry{
			ClientID:     e.ClientID,
			ClientSecret: e.ClientSecret,
			RedirectURIs: e.RedirectURIs,
			ClientName:   e.ClientName,
			CreatedAt:    e.CreatedAt,
			IsKiteAPIKey: e.IsKiteAPIKey,
		}
	}
	return result, nil
}

func (a *clientPersisterAdapter) DeleteClient(clientID string) error {
	return a.db.DeleteClient(clientID)
}

// registryAdapter bridges registry.Store to oauth.KeyRegistry.
type registryAdapter struct {
	store *registry.Store
}

func (a *registryAdapter) HasEntries() bool {
	return a.store.HasEntries()
}

func (a *registryAdapter) GetByEmail(email string) (apiKey, apiSecret string, ok bool) {
	reg, found := a.store.GetByEmail(email)
	if !found {
		return "", "", false
	}
	return reg.APIKey, reg.APISecret, true
}

func (a *registryAdapter) GetSecretByAPIKey(apiKey string) (apiSecret string, ok bool) {
	reg, found := a.store.GetByAPIKey(apiKey)
	if !found {
		return "", false
	}
	return reg.APISecret, true
}

// telegramManagerAdapter bridges *kc.Manager to telegram.KiteManager.
// It adapts interface return types so *kc.Manager satisfies the telegram-local interface.
type telegramManagerAdapter struct {
	m *kc.Manager
}

func (a *telegramManagerAdapter) TelegramStore() tgbot.TelegramLookup {
	return a.m.TelegramStore()
}
func (a *telegramManagerAdapter) AlertStoreConcrete() *alerts.Store {
	return a.m.AlertStoreConcrete()
}
func (a *telegramManagerAdapter) WatchlistStoreConcrete() *watchlist.Store {
	return a.m.WatchlistStoreConcrete()
}
func (a *telegramManagerAdapter) GetAPIKeyForEmail(email string) string {
	return a.m.GetAPIKeyForEmail(email)
}
func (a *telegramManagerAdapter) GetAccessTokenForEmail(email string) string {
	return a.m.GetAccessTokenForEmail(email)
}
func (a *telegramManagerAdapter) TelegramNotifier() *alerts.TelegramNotifier {
	return a.m.TelegramNotifier()
}
func (a *telegramManagerAdapter) InstrumentsManagerConcrete() *instruments.Manager {
	return a.m.InstrumentsManagerConcrete()
}
func (a *telegramManagerAdapter) IsTokenValid(email string) bool {
	return a.m.IsTokenValid(email)
}
func (a *telegramManagerAdapter) RiskGuard() *riskguard.Guard {
	return a.m.RiskGuard()
}
func (a *telegramManagerAdapter) PaperEngineConcrete() *papertrading.PaperEngine {
	return a.m.PaperEngineConcrete()
}
func (a *telegramManagerAdapter) TickerServiceConcrete() *ticker.Service {
	return a.m.TickerServiceConcrete()
}
