package app

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/zerodha/kite-mcp-server/app/metrics"
	"github.com/zerodha/kite-mcp-server/broker/zerodha"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/ops"
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/scheduler"
	tgbot "github.com/zerodha/kite-mcp-server/kc/telegram"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/oauth"
)


// App represents the main application structure
type App struct {
	Config         *Config
	DevMode        bool
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
	consentStore   *audit.ConsentStore
	scheduler      *scheduler.Scheduler
	telegramBot    *tgbot.BotHandler
	// riskGuard is the initialized risk-management engine. nil means it
	// wasn't wired (shouldn't happen in production since initializeServices
	// returns an error, but kept as a defensive check for ops visibility).
	riskGuard *riskguard.Guard
	// riskLimitsLoaded is true when LoadLimits succeeded at startup. When
	// false in DevMode, the guard is running with SystemDefaults only and
	// any user-configured kill switches / custom limits are ignored.
	// Production startup fails when LoadLimits fails, so this is only
	// observable in DevMode.
	riskLimitsLoaded bool
	shutdownCh       chan struct{} // injectable shutdown trigger for testing (nil = OS signals)
	// hashPublisherCancel cancels the audit hash-chain publisher goroutine
	// at shutdown. nil when the publisher is disabled (no storage configured).
	hashPublisherCancel context.CancelFunc
	// paperMonitor runs the paper-trading order-fill monitor when paper
	// trading is enabled. nil otherwise. Stopped via paperMonitor.Stop()
	// during graceful shutdown (sync.Once-guarded — safe to call twice).
	paperMonitor *papertrading.Monitor
	// invitationCleanupCancel signals the invitation-cleanup goroutine to
	// exit. nil when the goroutine was never started (no alert DB). Cancel
	// is idempotent — calling it twice is a no-op.
	invitationCleanupCancel context.CancelFunc
	// rateLimitReloadStop signals the SIGHUP rate-limit reload loop to
	// exit. Closed during setupGracefulShutdown (and cleanupInitializeServices
	// in tests). rateLimitReloadStopOnce guards the close so teardown is
	// idempotent — production and test paths can both call without panic.
	rateLimitReloadStop     chan struct{}
	rateLimitReloadStopOnce sync.Once
	// rateLimitReloadDone is closed by the reload-loop goroutine when it
	// exits. stopRateLimitReload waits on it so goleak sentinels observe
	// the goroutine has actually terminated, not just been signalled.
	rateLimitReloadDone <-chan struct{}
	// gracefulShutdownDone is closed by setupGracefulShutdown's teardown
	// goroutine after it has run every component's Stop/Shutdown. Tests
	// that inject shutdownCh can <- this channel after closing shutdownCh
	// to synchronise with the teardown's completion — otherwise
	// goleak-style sentinels race the async teardown.
	gracefulShutdownDone chan struct{}
	// shutdownOnce guards the one-shot close of shutdownCh performed by
	// TriggerShutdown. Multiple SIGUSR2 in quick succession, or a
	// SIGUSR2 racing with the normal SIGTERM path, must NOT panic
	// with "close of closed channel".
	shutdownOnce sync.Once
	// preboundListener is a test-only seam: when non-nil, serveHTTPServer
	// calls srv.Serve(preboundListener) instead of srv.ListenAndServe().
	// Production callers leave this nil and rely on srv.Addr; tests pass
	// a kernel-allocated listener (net.Listen "127.0.0.1:0") to eliminate
	// the close-then-rebind port race that made parallel RunServer tests
	// flake under heavy load.
	preboundListener net.Listener
}

// TriggerShutdown initiates a graceful shutdown without requiring an
// OS signal. Used by the graceful-restart handler: once the child
// process signals ready, the parent calls TriggerShutdown to hand
// off new traffic and drain in-flight handlers. Safe to call
// multiple times — only the first call closes the channel.
//
// If shutdownCh is nil (the default production path uses
// signal.NotifyContext instead of an injectable channel), this
// method lazily creates the channel AND wires it into the next
// setupGracefulShutdown call. That path is racy if setupGracefulShutdown
// has already started its goroutine with signal.NotifyContext —
// future callers who need guaranteed trigger semantics should call
// SetShutdownChannel(ch) before RunServer(). For the graceful-
// restart use case this race is acceptable: the parent process
// reacts to SIGUSR2 AFTER its http.Server is serving, so the
// shutdown goroutine is already running under signal.NotifyContext
// and TriggerShutdown's fallback (send SIGTERM to self) is the
// right behaviour.
func (app *App) TriggerShutdown() {
	app.shutdownOnce.Do(func() {
		if app.shutdownCh != nil {
			close(app.shutdownCh)
			return
		}
		// No injectable channel — fall back to sending SIGTERM to
		// ourselves, which the signal.NotifyContext in
		// setupGracefulShutdown is already listening for.
		if p, err := os.FindProcess(os.Getpid()); err == nil {
			_ = p.Signal(syscall.SIGTERM)
		}
	})
}

// stopRateLimitReload closes rateLimitReloadStop exactly once, signalling
// the SIGHUP reload goroutine to exit, and waits for that goroutine to
// finish. Safe to call multiple times and from multiple paths (graceful
// shutdown, test cleanup, unit tests that wire rate-limit middleware
// without a full server).
func (app *App) stopRateLimitReload() {
	if app.rateLimitReloadStop == nil {
		return
	}
	app.rateLimitReloadStopOnce.Do(func() {
		close(app.rateLimitReloadStop)
	})
	// Wait for the goroutine to exit so goleak sentinels observe
	// the post-condition "goroutine gone", not just "signal sent".
	if app.rateLimitReloadDone != nil {
		<-app.rateLimitReloadDone
	}
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

const pricingPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pricing - Kite MCP</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui;background:#0a0c10;color:#e2e8f0;min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:60px 20px}
h1{font-size:2rem;margin-bottom:8px}
.subtitle{color:#94a3b8;margin-bottom:48px;font-size:1.1rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:24px;max-width:960px;width:100%}
.card{border:1px solid #1e293b;border-radius:12px;padding:32px 24px;text-align:center}
.card.featured{border-color:#22d3ee;background:rgba(34,211,238,0.04)}
.tier{font-size:1.3rem;font-weight:700;margin-bottom:8px}
.price{font-size:2.5rem;font-weight:700;color:#22d3ee}
.price span{font-size:1rem;color:#94a3b8}
.period{color:#64748b;font-size:0.9rem;margin-bottom:24px}
ul{list-style:none;text-align:left;margin-bottom:28px}
li{padding:8px 0;font-size:0.9rem;color:#94a3b8;border-bottom:1px solid #1e293b}
li:before{content:"✓ ";color:#34d399;font-weight:700}
.btn{display:inline-block;width:100%;padding:12px;border-radius:6px;font-weight:600;font-size:0.9rem;cursor:pointer;border:1px solid #1e293b;text-decoration:none;text-align:center}
.btn-free{background:transparent;color:#94a3b8}
.btn-pay{background:#22d3ee;color:#0a0c10;border-color:#22d3ee}
.btn-pay:hover{opacity:0.9}
</style>
</head>
<body data-current="free">
<h1>Simple, Transparent Pricing</h1>
<p class="subtitle">AI-powered trading tools for your family.</p>
<div class="grid">
<div class="card" data-plan="free">
<div class="tier">Free</div>
<div class="price">₹0<span>/mo</span></div>
<div class="period">1 user, forever free</div>
<ul><li>Read-only market data</li><li>Paper trading</li><li>Watchlists</li><li>Basic portfolio view</li></ul>
<a class="btn btn-pay" onclick="checkout('free')">Get Started</a>
</div>
<div class="card featured" data-plan="solo_pro">
<div class="tier">Solo Pro</div>
<div class="price">₹199<span>/mo</span></div>
<div class="period">1 user, full trading</div>
<ul><li>Live order execution</li><li>GTT orders</li><li>Price alerts + Telegram</li><li>Trailing stops</li><li>Advanced analytics</li></ul>
<a class="btn btn-pay" onclick="checkout('solo_pro')">Get Started</a>
</div>
<div class="card" data-plan="pro">
<div class="tier">Family Pro</div>
<div class="price">₹349<span>/mo</span></div>
<div class="period">Up to 5 family members</div>
<ul><li>Live order execution</li><li>GTT orders</li><li>Price alerts + Telegram</li><li>Trailing stops</li><li>Advanced analytics</li></ul>
<a class="btn btn-pay" onclick="checkout('pro')">Get Started</a>
</div>
<div class="card" data-plan="premium">
<div class="tier">Premium</div>
<div class="price">₹699<span>/mo</span></div>
<div class="period">Up to 20 family members</div>
<ul><li>Everything in Pro</li><li>Backtesting</li><li>Options strategies</li><li>Technical indicators</li><li>Tax harvesting</li><li>SEBI compliance</li></ul>
<a class="btn btn-pay" onclick="checkout('premium')">Get Started</a>
</div>
</div>
<script>
function checkout(plan){
  fetch('/billing/checkout?plan='+plan,{method:'POST',credentials:'include'})
  .then(r=>{if(r.status===401){window.location='/auth/login?redirect=/pricing';return}return r.json()})
  .then(d=>{if(d&&d.checkout_url)window.location=d.checkout_url})
  .catch(e=>alert('Checkout error: '+e.message))
}
(function(){
  var current = document.body.getAttribute('data-current') || 'free';
  document.querySelectorAll('.card').forEach(function(card){
    if(card.getAttribute('data-plan') === current){
      var btn = card.querySelector('.btn');
      btn.textContent = 'Current Plan';
      btn.className = 'btn btn-free';
      btn.onclick = null;
      btn.removeAttribute('onclick');
      btn.style.cursor = 'default';
    }
  });
})();
</script>
</body>
</html>`

const checkoutSuccessHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Welcome to Pro - Kite MCP</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui;background:#0a0c10;color:#e2e8f0;min-height:100vh;display:flex;justify-content:center;align-items:center;padding:40px 20px}
.card{max-width:500px;width:100%;background:#0f1218;border:1px solid #1e293b;border-radius:12px;padding:40px;text-align:center}
h1{color:#22d3ee;font-size:1.8rem;margin-bottom:8px}
.subtitle{color:#94a3b8;margin-bottom:32px}
.features{text-align:left;margin-bottom:32px}
.feature{display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid #1e293b;font-size:14px;color:#94a3b8}
.feature:last-child{border-bottom:none}
.check{color:#34d399;font-weight:700;font-size:16px}
.actions{display:flex;flex-direction:column;gap:12px}
.btn{display:block;padding:12px;border-radius:6px;font-weight:600;font-size:14px;text-decoration:none;text-align:center}
.btn-primary{background:#22d3ee;color:#0a0c10}
.btn-secondary{background:transparent;color:#94a3b8;border:1px solid #1e293b}
.btn:hover{opacity:0.9}
</style>
</head>
<body>
<div class="card">
<h1>Welcome to Pro!</h1>
<p class="subtitle">Your subscription is active. Here's what you unlocked:</p>
<div class="features">
<div class="feature"><span class="check">&#10003;</span> Live order execution</div>
<div class="feature"><span class="check">&#10003;</span> GTT orders</div>
<div class="feature"><span class="check">&#10003;</span> Price alerts + Telegram</div>
<div class="feature"><span class="check">&#10003;</span> Trailing stops</div>
<div class="feature"><span class="check">&#10003;</span> Advanced analytics</div>
<div class="feature"><span class="check">&#10003;</span> Up to 5 family members</div>
</div>
<div class="actions">
<a href="/dashboard" class="btn btn-primary">Go to Dashboard</a>
<a href="/dashboard/billing" class="btn btn-secondary">Manage Subscription</a>
</div>
</div>
</body>
</html>`

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

	// EnableTrading gates all order-placement tools (place_order,
	// modify_order, GTT, MF, trailing stops, native alerts, etc.).
	// Default FALSE so a hosted multi-user deployment (Fly.io) that
	// forgets to set the var does not silently accept orders — and
	// thus does not fall under the NSE/INVG/69255 Annexure I Para 2.8
	// "Algo Provider" classification ("all orders received via API
	// from clients / Algo Provider's platform shall be considered as
	// Algo and will be required to be tagged"). Local single-user
	// builds set ENABLE_TRADING=true to unlock order placement.
	EnableTrading bool

	// InstrumentsSkipFetch is a test-only seam (INSTRUMENTS_SKIP_FETCH env
	// var) that causes the instruments manager to load an empty map instead
	// of fetching api.kite.trade/instruments.json at startup. Lives on the
	// Config so tests can set it via struct literal and drop t.Setenv, which
	// unblocks t.Parallel for any test that calls initializeServices.
	//
	// Must never be set in production.
	InstrumentsSkipFetch bool

	// AdminPassword seeds first-boot admin password for the ADMIN_EMAILS
	// users (ADMIN_PASSWORD env var). Empty means no seeding; admins
	// authenticate via OAuth only on first boot. Field lives on Config so
	// tests drop t.Setenv and can t.Parallel the dashboard setup path.
	AdminPassword string

	// StripeWebhookSecret is the signing secret for Stripe's webhook
	// endpoint (STRIPE_WEBHOOK_SECRET env var). Empty means the webhook
	// handler is not registered. Field lives on Config so tests that
	// exercise the webhook path drop t.Setenv and can t.Parallel.
	StripeWebhookSecret string

	// StripeSecretKey gates billing tier middleware (STRIPE_SECRET_KEY env
	// var). Empty or DevMode skips billing entirely. Field on Config so
	// tests that exercise the billing path drop t.Setenv and can t.Parallel.
	StripeSecretKey string

	// StripePricePro and StripePricePremium are the Stripe price IDs for
	// webhook tier mapping (STRIPE_PRICE_PRO, STRIPE_PRICE_PREMIUM env
	// vars). Empty means the webhook defaults to Pro tier. Fields on
	// Config so tests drop t.Setenv.
	StripePricePro     string
	StripePricePremium string

	// DevMode is the app-wide debug toggle (DEV_MODE env var). When true,
	// the mock broker is wired in (no real Kite credentials needed),
	// pprof endpoints are exposed, billing is disabled, etc. Field on
	// Config so tests drop t.Setenv("DEV_MODE", "true") and can t.Parallel.
	DevMode bool
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

// NewApp creates and initializes a new App instance from the ambient
// environment. Thin wrapper over NewAppWithConfig(ConfigFromEnv(), logger)
// plus the DEV_MODE env read (dev mode is not a Config field — it's an
// app-wide debug toggle that influences wiring decisions, not a value
// threaded through handlers).
//
// Prefer NewAppWithConfig in new tests so they can construct a Config
// directly (dropping t.Setenv) and run with t.Parallel(). NewApp stays
// as a back-compat shim for existing callers (main.go + ~280 tests);
// Phase E.2 migrates those incrementally.
func NewApp(logger *slog.Logger) *App {
	return NewAppWithConfig(ConfigFromEnv(), logger)
}

// NewAppWithConfig creates a new App instance from an explicit Config.
// Every env read now flows through the Config parameter — including
// DevMode, which is sourced from cfg.DevMode (populated upstream by
// ConfigFromMap or set directly by tests).
//
// cfg may be nil — a nil Config is replaced with a zero-valued Config
// (treated as "everything empty"). Callers that want defaults should
// pass cfg.WithDefaults().
func NewAppWithConfig(cfg *Config, logger *slog.Logger) *App {
	if cfg == nil {
		cfg = &Config{}
	}

	return &App{
		Config:    cfg,
		DevMode:   cfg.DevMode,
		Version:   "v0.0.0", // Ideally injected at build time
		startTime: time.Now(),
		logger:    logger,
		metrics: metrics.New(metrics.Config{
			ServiceName:     "kite-mcp-server",
			AdminSecretPath: cfg.AdminSecretPath,
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
		if app.DevMode {
			app.logger.Info("DEV_MODE: Kite credentials not required — mock broker will be used")
		} else if app.Config.OAuthJWTSecret == "" {
			return fmt.Errorf("KITE_API_KEY and KITE_API_SECRET are required (or enable OAuth with OAUTH_JWT_SECRET for per-user credentials)")
		} else {
			app.logger.Info("No global Kite credentials — per-user credentials required via MCP client config (oauth_client_id/oauth_client_secret)")
		}
	}

	// EXTERNAL_URL is required when OAuth is enabled (multi-user mode).
	if app.Config.OAuthJWTSecret != "" && app.Config.ExternalURL == "" {
		return fmt.Errorf("EXTERNAL_URL is required when OAUTH_JWT_SECRET is set")
	}

	return nil
}

// RunServer initializes and starts the server based on the configured mode
func (app *App) RunServer() error {
	if app.DevMode {
		app.logger.Warn("DEV MODE ENABLED — billing disabled, all tools free, pprof endpoints active")
	}

	url := app.buildServerURL()
	app.configureHTTPClient()

	kcManager, mcpServer, err := app.initializeServices()
	if err != nil {
		return err
	}

	// RunServer owns the Manager lifecycle. Any error-return past this
	// point (oauth config, startServer) must shut down the partially-
	// wired components — otherwise we leak every background goroutine
	// kcManager + app.auditStore + app.oauthHandler spawned. Production
	// graceful shutdown also owns this chain via setupGracefulShutdown;
	// the defer here covers the error-before-serve gap.
	runSuccess := false
	defer func() {
		if !runSuccess {
			// Mirror the teardown order from setupGracefulShutdown /
			// cleanupInitializeServices. Every Stop is idempotent / nil-safe.
			if app.scheduler != nil {
				app.scheduler.Stop()
			}
			if app.hashPublisherCancel != nil {
				app.hashPublisherCancel()
			}
			if app.auditStore != nil {
				app.auditStore.Stop()
			}
			if app.telegramBot != nil {
				app.telegramBot.Shutdown()
			}
			kcManager.Shutdown()
			if app.oauthHandler != nil {
				app.oauthHandler.Close()
			}
			if app.rateLimiters != nil {
				app.rateLimiters.Stop()
			}
			app.stopRateLimitReload()
			if app.invitationCleanupCancel != nil {
				app.invitationCleanupCancel()
			}
			if app.paperMonitor != nil {
				app.paperMonitor.Stop()
			}
		}
	}()

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
			authenticator:   zerodha.NewAuth(),
			commandBus:      kcManager.CommandBus(), // CQRS: every write dispatches via bus
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
			// Check if a valid (non-expired) Kite token exists. The
			// "has token AND not expired" rule is encapsulated on the
			// domain Session aggregate so the middleware stays thin.
			if entry, hasToken := tokenStore.Get(email); hasToken {
				if kc.ToDomainSession(email, entry).IsAuthenticated() {
					return true // valid token, pass through
				}
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
			app.oauthHandler.SetClientPersister(&clientPersisterAdapter{
				db:         alertDB,
				commandBus: kcManager.CommandBus(), // CQRS: writes dispatch via bus
				logger:     app.logger,
			}, app.logger)
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

		// DPDP Act 2023 consent log: persist a grant event on every successful
		// OAuth callback. noDeref guard: the store is nil in DevMode without
		// ALERT_DB_PATH, in which case the recorder is a no-op and the
		// handler's SetConsentRecorder keeps consentRecorder = nil.
		if app.consentStore != nil {
			logger := app.logger
			consentStore := app.consentStore
			app.oauthHandler.SetConsentRecorder(func(email, ip, ua string) {
				// Scopes granted at OAuth: aligned with the 4 categories surfaced
				// in the privacy notice (app/legal.go §1.2). noticeVersion tracks
				// app/legal.go — bump when the notice copy changes.
				const noticeVersion = "1.0"
				scopes := []string{"profile", "trading", "alerts", "telegram"}
				scopeJSON, _ := json.Marshal(scopes)
				// proofHash binds the notice version to the action. An auditor
				// re-hashing our legal.go notice + this action string must get
				// the same digest — that's the evidence of what the user saw.
				proof := audit.ComputeProofHash(
					"kite-mcp-privacy-notice/v"+noticeVersion,
					"grant scopes="+string(scopeJSON)+" method=oauth_callback",
				)
				entry := &audit.ConsentLogEntry{
					UserEmailHash: audit.HashEmail(email),
					TimestampUTC:  time.Now().UTC(),
					IPAddress:     ip,
					UserAgent:     ua,
					NoticeVersion: noticeVersion,
					ConsentAction: audit.ConsentActionGrant,
					Scope:         string(scopeJSON),
					Method:        audit.ConsentMethodOAuthCallback,
					ProofHash:     proof,
				}
				if err := consentStore.Insert(entry); err != nil {
					// Fail-open: log and move on. OAuth must not break on a
					// consent-log outage — the tool-call audit still captures
					// the authentication event.
					logger.Error("Failed to record DPDP consent", "email_hash", entry.UserEmailHash, "error", err)
					return
				}
				logger.Debug("DPDP consent grant recorded", "email_hash", entry.UserEmailHash, "notice_version", noticeVersion)
			})
			app.logger.Info("DPDP consent recorder wired into OAuth handler")
		}

		app.logger.Info("OAuth 2.1 enabled (Kite identity provider)", "external_url", app.Config.ExternalURL)
	}

	srv := app.createHTTPServer(url)

	// Note: setupGracefulShutdown is invoked inside startXxxServer AFTER
	// setupMux has populated app.rateLimiters (and any other fields the
	// shutdown goroutine reads). The `go` statement inside setupGracefulShutdown
	// establishes the happens-before edge that the race detector requires;
	// calling setupGracefulShutdown here (before startServer) would race on
	// those fields because setupMux runs on the main goroutine AFTER this
	// point while the shutdown goroutine is already spawned.
	//
	// If startServer returns successfully (signal-triggered graceful shutdown
	// ran), the teardown-on-error defer above is a no-op because
	// setupGracefulShutdown's deferred chain already stopped every
	// component. Setting runSuccess=true signals the defer to skip.
	if err := app.startServer(srv, kcManager, mcpServer, url); err != nil {
		// startServer failed before serving. setupGracefulShutdown may not
		// have been called (AppMode default case returns before wiring).
		// The RunServer defer above will unwind every wired component.
		return err
	}
	// startServer returned without error — setupGracefulShutdown's
	// teardown has already run (triggered by signal or shutdownCh).
	// Signal the defer to skip duplicate teardown.
	runSuccess = true
	return nil
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

