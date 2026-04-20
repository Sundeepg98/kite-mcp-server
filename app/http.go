package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/mark3labs/mcp-go/server"
	"github.com/mark3labs/mcp-go/util"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/ops"
	tgbot "github.com/zerodha/kite-mcp-server/kc/telegram"
	"github.com/zerodha/kite-mcp-server/kc/templates"
	"github.com/zerodha/kite-mcp-server/mcp"
	"github.com/zerodha/kite-mcp-server/oauth"
	"golang.org/x/crypto/bcrypt"
)

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
	// Use injected shutdown channel if available (for testing), else listen for OS signals.
	var ctx context.Context
	var stop context.CancelFunc
	if app.shutdownCh != nil {
		ctx, stop = context.WithCancel(context.Background())
		go func() {
			select {
			case <-app.shutdownCh:
				stop()
			case <-ctx.Done():
			}
		}()
	} else {
		ctx, stop = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	}

	// gracefulShutdownDone signals teardown completion so tests can
	// wait on it after closing shutdownCh. Always initialised — nil
	// readers just skip.
	app.gracefulShutdownDone = make(chan struct{})

	go func() {
		defer close(app.gracefulShutdownDone)
		defer stop()
		<-ctx.Done()
		app.logger.Info("Shutting down server...")

		// Stop briefing scheduler first (prevent new Kite API calls).
		if app.scheduler != nil {
			app.scheduler.Stop()
		}

		// Stop audit hash-chain publisher (no-op if never started).
		if app.hashPublisherCancel != nil {
			app.hashPublisherCancel()
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

		// Stop rate limiter cleanup goroutine
		if app.rateLimiters != nil {
			app.rateLimiters.Stop()
		}

		// Stop the SIGHUP rate-limit hot-reload goroutine (idempotent no-op
		// if never wired — stopRateLimitReload guards the channel internally).
		app.stopRateLimitReload()

		// Stop the invitation-cleanup goroutine (idempotent no-op if never started).
		if app.invitationCleanupCancel != nil {
			app.invitationCleanupCancel()
		}

		// Stop the paper-trading monitor goroutine (sync.Once-guarded, blocks
		// until the loop exits so the process can cleanly terminate).
		if app.paperMonitor != nil {
			app.paperMonitor.Stop()
		}

		// Stop the metrics auto-cleanup goroutine (sync.Once-guarded).
		if app.metrics != nil {
			app.metrics.Shutdown()
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

	// Seed admin password from Config.AdminPassword (populated from
	// ADMIN_PASSWORD env by ConfigFromEnv). First-boot path only.
	if adminPassword := app.Config.AdminPassword; adminPassword != "" && userStore != nil && app.Config.AdminEmails != "" {
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

	// Family invitation acceptance (public — invitee clicks link).
	if invStore := kcManager.InvitationStore(); invStore != nil {
		mux.HandleFunc("/auth/accept-invite", func(w http.ResponseWriter, r *http.Request) {
			token := r.URL.Query().Get("token")
			if token == "" {
				http.Error(w, "missing token", http.StatusBadRequest)
				return
			}
			inv := invStore.Get(token)
			if inv == nil {
				http.Error(w, "invitation not found", http.StatusNotFound)
				return
			}
			if inv.Status != "pending" {
				http.Error(w, "invitation already "+inv.Status, http.StatusGone)
				return
			}
			if time.Now().After(inv.ExpiresAt) {
				http.Error(w, "invitation expired", http.StatusGone)
				return
			}
			// Auto-create user if needed and link to admin.
			uStore := kcManager.UserStoreConcrete()
			if uStore != nil {
				uStore.EnsureUser(inv.InvitedEmail, "", "", "family_invite")
				if err := uStore.SetAdminEmail(inv.InvitedEmail, inv.AdminEmail); err != nil {
					app.logger.Error("Failed to link family member", "invited", inv.InvitedEmail, "admin", inv.AdminEmail, "error", err)
				}
			}
			if err := invStore.Accept(token); err != nil {
				app.logger.Error("Failed to accept invitation", "token", token, "error", err)
			}
			// Redirect to login.
			http.Redirect(w, r, "/auth/login?msg=welcome", http.StatusFound)
		})
	}

	// Register Stripe webhook endpoint (no auth — Stripe calls this with a signed payload).
	if webhookSecret := app.Config.StripeWebhookSecret; webhookSecret != "" {
		if bs := kcManager.BillingStoreConcrete(); bs != nil {
			if err := bs.InitEventLogTable(); err != nil {
				app.logger.Error("Failed to initialize webhook_events table", "error", err)
			}
			adminUpgrade := func(email string) {
				if uStore := kcManager.UserStoreConcrete(); uStore != nil {
					if err := uStore.UpdateRole(email, "admin"); err != nil {
						app.logger.Error("Failed to upgrade payer to admin", "email", email, "error", err)
					}
				}
			}
			mux.Handle("/webhooks/stripe", billing.WebhookHandler(bs, webhookSecret, app.logger, adminUpgrade))
			app.logger.Info("Stripe webhook endpoint registered at /webhooks/stripe")
		} else {
			app.logger.Warn("STRIPE_WEBHOOK_SECRET set but billing store not initialized (need STRIPE_SECRET_KEY)")
		}
	}

	// Pricing page (public, but detects logged-in user's tier).
	mux.HandleFunc("/pricing", func(w http.ResponseWriter, r *http.Request) {
		currentTier := "free"
		if app.oauthHandler != nil {
			if cookie, err := r.Cookie(cookieName); err == nil && cookie.Value != "" {
				if claims, err := app.oauthHandler.JWTManager().ValidateToken(cookie.Value, "dashboard"); err == nil && claims.Subject != "" {
					if bs := kcManager.BillingStoreConcrete(); bs != nil {
						tier := bs.GetTier(claims.Subject)
						switch tier {
						case billing.TierPro:
							currentTier = "pro"
						case billing.TierPremium:
							currentTier = "premium"
						}
					}
				}
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		html := strings.Replace(pricingPageHTML, `data-current="free"`, `data-current="`+currentTier+`"`, 1)
		fmt.Fprint(w, html)
	})

	// Post-purchase welcome page.
	mux.HandleFunc("/checkout/success", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, checkoutSuccessHTML)
	})

	// Checkout + Stripe portal handlers (require browser auth).
	if app.oauthHandler != nil {
		if bs := kcManager.BillingStoreConcrete(); bs != nil {
			mux.Handle("/billing/checkout", app.oauthHandler.RequireAuthBrowser(
				billing.CheckoutHandler(bs, app.logger)))
			mux.Handle("/stripe-portal", app.oauthHandler.RequireAuthBrowser(
				billing.PortalHandler(bs, app.logger)))
		}
	}

	// Register Telegram bot webhook if configured.
	app.registerTelegramWebhook(mux, kcManager)

	// Health check endpoint for load balancers and container orchestration.
	//
	// Two response shapes, selected by the ?format=json query param:
	//
	//   GET /healthz              → always 200 with a flat JSON liveness body.
	//                               Shape is unchanged for legacy callers
	//                               (status, uptime, version, tools).
	//   GET /healthz?format=json  → 200 with a richer component-level body
	//                               that surfaces degraded states (audit
	//                               disabled, audit buffer dropping, risk
	//                               limits not loaded, etc.). Ops use this
	//                               to detect silent failures without
	//                               waiting for user complaints.
	//
	// The endpoint does NOT perform any runtime probes — all data is read
	// from accessors already populated during startup, so response time
	// stays well under 5ms.
	mux.HandleFunc("/healthz", app.handleHealthz)

	// Favicon — serve SVG from embedded static files.
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		data, err := templates.FS.ReadFile("static/favicon.svg")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=604800")
		_, _ = w.Write(data)
	})

	// robots.txt — allow landing and legal pages, block everything else.
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "User-agent: *\nDisallow: /dashboard/\nDisallow: /admin/\nDisallow: /auth/\nDisallow: /oauth/\nDisallow: /mcp\nDisallow: /sse\nAllow: /\nAllow: /terms\nAllow: /privacy\n")
	})

	// DEV_MODE: expose pprof profiling endpoints for debugging.
	if app.DevMode {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		mux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
		mux.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
		mux.Handle("/debug/pprof/allocs", pprof.Handler("allocs"))
		mux.Handle("/debug/pprof/block", pprof.Handler("block"))
		mux.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
		app.logger.Info("pprof endpoints registered at /debug/pprof/")
	}

	app.serveLegalPages(mux)
	app.serveStatusPage(mux)
	return mux
}

// handleHealthz serves the /healthz endpoint. Behaviour:
//
//   - Default (no ?format=json): returns the legacy flat JSON body. Existing
//     load balancers, container orchestrators, and uptime checkers keep
//     working unchanged.
//   - ?format=json: returns a richer component-level body. Ops tooling uses
//     this to detect silent failures (audit disabled, audit buffer dropping
//     entries, riskguard running on defaults only in DevMode, etc.).
//
// The endpoint always returns 200 when the process is alive. A top-level
// status of "degraded" signals that one or more components are unhealthy
// but the process itself is responding. There is no "failed" path from
// here — if the process can't serve the request, it wouldn't respond at
// all (5xx or connection refused).
func (app *App) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if r.URL.Query().Get("format") == "json" {
		_ = json.NewEncoder(w).Encode(app.buildHealthzReport())
		return
	}

	// Legacy flat response — preserved verbatim for callers that don't
	// know about the richer format.
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "ok",
		"uptime":  time.Since(app.startTime).Truncate(time.Second).String(),
		"version": app.Version,
		"tools":   len(mcp.GetAllTools()),
	})
}

// healthzComponent is a single entry in the healthz components map.
//
// Field usage is component-specific: audit sets DroppedCount, anomaly_cache
// sets HitRate + MaxEntries, etc. Pointer fields distinguish "not set by
// this component" (nil → omitted from JSON) from "set, value happens to
// be zero" (non-nil zero → emitted). Operators parse the wire format
// without a Go struct, so `hit_rate: 0` needs to render even on a cold
// start when the cache has yet to be hit.
type healthzComponent struct {
	Status       string   `json:"status"`
	DroppedCount int64    `json:"dropped_count,omitempty"`
	HitRate      *float64 `json:"hit_rate,omitempty"`
	MaxEntries   *int64   `json:"max_entries,omitempty"`
	Note         string   `json:"note,omitempty"`
}

// healthzReport is the shape returned by /healthz?format=json.
type healthzReport struct {
	Status     string                      `json:"status"`
	UptimeS    int64                       `json:"uptime_s"`
	Version    string                      `json:"version"`
	Components map[string]healthzComponent `json:"components"`
}

// buildHealthzReport assembles the component-level health report from
// existing accessors. It performs no I/O and no runtime probes — all data
// is sourced from state populated at startup.
func (app *App) buildHealthzReport() healthzReport {
	components := map[string]healthzComponent{
		"audit":     app.auditComponentStatus(),
		"riskguard": app.riskguardComponentStatus(),
		"kite_connectivity": {
			Status: "unknown",
			Note:   "not checked — no active session to probe",
		},
		"litestream": {
			Status: "unknown",
			Note:   "external binary — no in-process accessor available",
		},
	}

	// anomaly_cache is only surfaced when the audit store is wired — if
	// audit is nil the cache doesn't exist either, and reporting a second
	// "disabled" entry would be noise. The audit component above already
	// signals the underlying failure.
	if app.auditStore != nil {
		components["anomaly_cache"] = app.anomalyCacheComponentStatus()
	}

	// Top-level status degrades if any component is not ok/unknown.
	// unknown is treated as non-degrading so we don't cry wolf on
	// components we can't probe yet.
	topStatus := "ok"
	for _, c := range components {
		switch c.Status {
		case "ok", "unknown":
			// healthy or unprobed — no change.
		default:
			topStatus = "degraded"
		}
	}

	return healthzReport{
		Status:     topStatus,
		UptimeS:    int64(time.Since(app.startTime).Seconds()),
		Version:    app.Version,
		Components: components,
	}
}

// auditComponentStatus reports the audit trail health.
func (app *App) auditComponentStatus() healthzComponent {
	if app.auditStore == nil {
		return healthzComponent{
			Status: "disabled",
			Note:   "audit store init failed — no compliance logging",
		}
	}
	if dropped := app.auditStore.DroppedCount(); dropped > 0 {
		return healthzComponent{
			Status:       "dropping",
			DroppedCount: dropped,
			Note:         "audit buffer overflow — compliance gap",
		}
	}
	return healthzComponent{Status: "ok"}
}

// riskguardComponentStatus reports the risk guard health.
func (app *App) riskguardComponentStatus() healthzComponent {
	if app.riskGuard == nil {
		// Should not happen in production (initializeServices returns an
		// error before this point); surface it explicitly for DevMode.
		return healthzComponent{
			Status: "defaults-only",
			Note:   "riskguard not wired — operating with SystemDefaults",
		}
	}
	if !app.riskLimitsLoaded {
		return healthzComponent{
			Status: "defaults-only",
			Note:   "dev mode — user-configured limits not loaded",
		}
	}
	return healthzComponent{Status: "ok"}
}

// anomalyCacheHitRateDegradedThreshold is the hit-rate floor below which
// the UserOrderStats cache is flagged as degraded. Under steady state an
// active user fires multiple anomaly checks per 15-minute window, so the
// cache should hit well above 50%. A sustained sub-50% rate indicates the
// invalidation logic is firing too aggressively or the cache is thrashing
// on eviction — both worth an operator glance.
const anomalyCacheHitRateDegradedThreshold = 0.5

// anomalyCacheComponentStatus reports the UserOrderStats cache health.
//
// Hit rate classification:
//   - hit_rate == 0: no traffic yet (cold start, fresh deploy, idle
//     server). Report "ok" — we'd otherwise false-alarm every restart.
//   - hit_rate > threshold: healthy, traffic is repeated enough that
//     the cache is earning its keep.
//   - 0 < hit_rate <= threshold: cache is not amortising the 30-day
//     SQL scan; surface as degraded so ops can investigate.
//
// The caller guarantees app.auditStore != nil before invoking this.
func (app *App) anomalyCacheComponentStatus() healthzComponent {
	rate := app.auditStore.StatsCacheHitRate()
	maxEntries := int64(audit.DefaultMaxStatsCacheEntries)
	c := healthzComponent{
		HitRate:    &rate,
		MaxEntries: &maxEntries,
	}
	switch {
	case rate == 0:
		// No traffic sampled yet (or pure-miss cold start). Treat as
		// healthy — otherwise every post-deploy window reports degraded.
		c.Status = "ok"
		c.Note = "no traffic yet — hit rate will populate as orders flow"
	case rate > anomalyCacheHitRateDegradedThreshold:
		c.Status = "ok"
	default:
		c.Status = "degraded"
		c.Note = "hit rate below 50% — cache thrashing or aggressive invalidation"
	}
	return c
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
	botHandler := tgbot.NewBotHandler(notifier.Bot(), webhookSecret, &telegramManagerAdapter{m: kcManager}, app.logger, kcManager.KiteClientFactory())
	// Mirror the MCP tool gating: /buy, /sell, /quick are disabled when
	// ENABLE_TRADING is false so the Telegram surface stays consistent
	// with the registered MCP tool set (Path 2 compliance).
	botHandler.SetTradingEnabled(app.Config.EnableTrading)
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

// createStreamableHTTPServer creates and configures a streamable HTTP server.
//
// We register a custom SessionIdManagerResolver so that each newly generated
// MCP session carries a ClientHint derived from the incoming request's
// User-Agent. The resolver wraps the existing SessionRegistry — all other
// behavior (validation, termination, persistence, cleanup hooks) is
// unchanged. See kc/client_hint_resolver.go for the detailed design.
func (app *App) createStreamableHTTPServer(mcpServer *server.MCPServer, kcManager *kc.Manager) *server.StreamableHTTPServer {
	resolver := newClientHintedResolver(kcManager.SessionManager())
	return server.NewStreamableHTTPServer(mcpServer,
		server.WithSessionIdManagerResolver(resolver),
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
		// Chain: IP rate limit → RequireAuth → per-user rate limit → handler.
		// Both IP and user limits must pass; user scope defends against a single
		// authenticated identity abusing the endpoint across rotating source IPs.
		mux.Handle("/sse", rateLimit(app.rateLimiters.mcp)(app.oauthHandler.RequireAuth(rateLimitUser(app.rateLimiters.mcpUser)(http.HandlerFunc(sseHandler)))))
		mux.Handle("/message", rateLimit(app.rateLimiters.mcp)(app.oauthHandler.RequireAuth(rateLimitUser(app.rateLimiters.mcpUser)(http.HandlerFunc(sseHandler)))))
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

// configureAndStartServer sets up server handler and starts it.
//
// Middleware order (outermost first):
//  1. recoverPanic — outermost so it catches panics in any inner
//     middleware or handler; logs the stack with the request ID and
//     returns a structured 500 rather than a bare connection close.
//  2. withRequestID — so every downstream handler, middleware, and log
//     line can observe the correlation ID via RequestIDFromCtx.
//  3. securityHeaders — applies standard response hardening headers.
//  4. mux — application routes.
func (app *App) configureAndStartServer(srv *http.Server, mux *http.ServeMux) {
	srv.Handler = recoverPanic(app.logger, withRequestID(securityHeaders(mux)))
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
		// IP rate limit → RequireAuth → per-user rate limit → handler.
		mux.Handle("/mcp", rateLimit(app.rateLimiters.mcp)(app.oauthHandler.RequireAuth(rateLimitUser(app.rateLimiters.mcpUser)(http.HandlerFunc(mcpHandler)))))
	} else {
		mux.Handle("/mcp", rateLimitFunc(app.rateLimiters.mcp, mcpHandler))
	}

	app.logger.Info("Hybrid mode enabled with both SSE and MCP endpoints on the same server")
	app.logger.Info("SSE endpoints available", "url", fmt.Sprintf("http://%s/sse and http://%s/message", url, url))
	app.logger.Info("MCP endpoint available", "url", fmt.Sprintf("http://%s/mcp", url))

	// Wire graceful shutdown AFTER setupMux has populated app.rateLimiters;
	// the `go` statement inside setupGracefulShutdown establishes the
	// happens-before edge needed for the shutdown goroutine's later reads.
	app.setupGracefulShutdown(srv, kcManager)

	app.configureAndStartServer(srv, mux)
}

// startStdIOServer starts a server in STDIO mode
func (app *App) startStdIOServer(srv *http.Server, kcManager *kc.Manager, mcpServer *server.MCPServer) {
	app.logger.Info("Starting STDIO MCP server...")
	stdio := server.NewStdioServer(mcpServer)

	// Setup mux with common handlers
	mux := app.setupMux(kcManager)

	// Wire graceful shutdown AFTER setupMux (see startHybridServer).
	app.setupGracefulShutdown(srv, kcManager)

	go app.configureAndStartServer(srv, mux)

	// Cancellable ctx tied to shutdownCh so mcp-go's internal
	// handleNotifications goroutine exits when the app is shut down.
	// Previously used context.Background() which meant the goroutine
	// outlived the test process and tripped goleak sentinels.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if app.shutdownCh != nil {
		go func() {
			select {
			case <-app.shutdownCh:
				cancel()
			case <-ctx.Done():
			}
		}()
	}
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

	// Wire graceful shutdown AFTER setupMux (see startHybridServer).
	app.setupGracefulShutdown(srv, kcManager)

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
		// IP rate limit → RequireAuth → per-user rate limit → handler.
		mux.Handle("/mcp", rateLimit(app.rateLimiters.mcp)(app.oauthHandler.RequireAuth(rateLimitUser(app.rateLimiters.mcpUser)(http.HandlerFunc(mcpHandler)))))
		app.logger.Info("OAuth middleware enabled for /mcp endpoint")
	} else {
		mux.Handle("/mcp", rateLimitFunc(app.rateLimiters.mcp, mcpHandler))
	}

	// Wire graceful shutdown AFTER setupMux (see startHybridServer).
	app.setupGracefulShutdown(srv, kcManager)

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
//
// Both routes render markdown documents (kc/legaldocs/TERMS.md,
// kc/legaldocs/PRIVACY.md) embedded at build time and pre-rendered to HTML
// in app/legal.go. The handler supports two response formats, selected by
// the ?format query parameter:
//
//   - default (no ?format, or anything other than "md"): HTML, wrapped in
//     the shared legal.html template (topbar, dashboard styling, footer).
//   - ?format=md: raw markdown (Content-Type: text/markdown; charset=utf-8),
//     useful for scraping, archival, or clients that prefer the source.
//
// Both responses carry Cache-Control: public, max-age=3600. The pages are
// public and change rarely (policy updates are the only reason); a 1-hour
// cache keeps Fly.io edge load low without making updates painful to roll
// out.
//
// When app.legalTemplate is nil (initStatusPageTemplate not called or
// failed) the routes are skipped entirely so /terms and /privacy return
// 404 via the default mux handler — the same defensive behaviour the
// previous implementation had.
func (app *App) serveLegalPages(mux *http.ServeMux) {
	if app.legalTemplate == nil {
		return
	}

	serve := func(title string, htmlContent template.HTML, markdown []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Shared cache header — applied to both response formats so
			// CDNs treat them consistently.
			w.Header().Set("Cache-Control", "public, max-age=3600")

			if r.URL.Query().Get("format") == "md" {
				w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
				_, _ = w.Write(markdown)
				return
			}

			var buf bytes.Buffer
			if err := app.legalTemplate.ExecuteTemplate(&buf, "legal", legalPageData{
				Title:   title,
				Content: htmlContent,
			}); err != nil {
				app.logger.Error("Failed to execute legal template", "page", title, "error", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = buf.WriteTo(w)
		}
	}

	mux.HandleFunc("/terms", serve("Terms of Service", termsHTML, termsMarkdown))
	mux.HandleFunc("/privacy", serve("Privacy Policy", privacyHTML, privacyMarkdown))
	app.logger.Info("Legal pages registered at /terms and /privacy")
}

// serveErrorPage renders a styled HTML error page with the given status code, title, and message.
func serveErrorPage(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>%s · Kite MCP</title><link rel="stylesheet" href="/static/dashboard-base.css"></head><body><div style="display:flex;justify-content:center;align-items:center;min-height:100vh"><div style="text-align:center;max-width:400px"><h2 style="color:var(--text-0)">%s</h2><p style="color:var(--text-1);margin:16px 0">%s</p><a href="/" style="color:var(--accent)">← Home</a></div></div></body></html>`, title, title, message)
}

// serveStatusPage configures the HTTP mux to serve status page using templates.
// If OAuth is enabled and the user has a valid cookie, redirects to /dashboard.
// Otherwise shows the status page with login links.
func (app *App) serveStatusPage(mux *http.ServeMux) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Only serve status page at root path
		if path != "/" {
			serveErrorPage(w, 404, "Page Not Found", "The page you're looking for doesn't exist.")
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
