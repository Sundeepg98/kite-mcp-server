package dashboard

import (
	"log/slog"
	"net/http"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/templates"
	"github.com/zerodha/kite-mcp-server/kc/ticker"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// Handler serves the live P&L dashboard.
type Handler struct {
	manager      *kc.Manager
	oauthHandler *oauth.Handler
	logger       *slog.Logger
}

// New creates a new dashboard Handler.
func New(manager *kc.Manager, oauthHandler *oauth.Handler, logger *slog.Logger) *Handler {
	return &Handler{
		manager:      manager,
		oauthHandler: oauthHandler,
		logger:       logger,
	}
}

// RegisterRoutes registers all dashboard routes on the mux.
// All routes are protected by browser-based OAuth (cookie JWT).
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	if h.oauthHandler == nil {
		h.logger.Info("Dashboard disabled (OAuth not configured)")
		return
	}

	// Dashboard login initiation (redirects to Google OAuth)
	mux.HandleFunc("/dashboard/login", h.handleLogin)

	// Dashboard login callback (sets cookie, redirects to dashboard)
	mux.HandleFunc("/dashboard/callback", h.handleCallback)

	// Protected routes
	auth := h.oauthHandler.RequireAuthBrowser

	mux.Handle("/dashboard", auth(http.HandlerFunc(h.serveDashboard)))
	mux.Handle("/api/dashboard/data", auth(http.HandlerFunc(h.serveData)))
	mux.Handle("/api/dashboard/stream", auth(http.HandlerFunc(h.serveStream)))

	h.logger.Info("Dashboard routes registered at /dashboard")
}

// handleLogin redirects to Google OAuth for browser-based auth.
func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/dashboard"
	}

	// Use the same Google OAuth flow — store redirect target in state
	oauthURL := h.oauthHandler.GetGoogleAuthURL("dashboard:" + redirect)
	http.Redirect(w, r, oauthURL, http.StatusFound)
}

// handleCallback handles the Google OAuth callback for dashboard login.
func (h *Handler) handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	// Exchange code for Google user info
	email, err := h.oauthHandler.ExchangeCodeForEmail(r.Context(), code)
	if err != nil {
		h.logger.Error("Dashboard OAuth callback failed", "error", err)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	// Set JWT cookie for browser auth
	if err := h.oauthHandler.SetAuthCookie(w, email); err != nil {
		h.logger.Error("Failed to set auth cookie", "error", err)
		http.Error(w, "Failed to set auth cookie", http.StatusInternalServerError)
		return
	}

	// Extract redirect target from state
	redirect := "/dashboard"
	if len(state) > len("dashboard:") {
		redirect = state[len("dashboard:"):]
	}

	h.logger.Info("Dashboard login successful", "email", email)
	http.Redirect(w, r, redirect, http.StatusFound)
}

// serveDashboard serves the dashboard HTML page.
func (h *Handler) serveDashboard(w http.ResponseWriter, r *http.Request) {
	data, err := templates.FS.ReadFile("dashboard.html")
	if err != nil {
		h.logger.Error("Failed to read dashboard template", "error", err)
		http.Error(w, "Dashboard template not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

// subscribeUserTicker ensures the user's ticker is running and subscribes to their holdings.
// This is a helper used by both data and stream endpoints.
func (h *Handler) ensureTickerForUser(email string) {
	if h.manager.TickerService().IsRunning(email) {
		return
	}

	apiKey := h.manager.GetAPIKeyForEmail(email)
	accessToken := h.manager.GetAccessTokenForEmail(email)
	if accessToken == "" {
		return
	}

	if err := h.manager.TickerService().Start(email, apiKey, accessToken); err != nil {
		h.logger.Warn("Failed to auto-start ticker for dashboard", "email", email, "error", err)
		return
	}

	// Auto-subscribe to user's holdings instrument tokens
	entry, ok := h.manager.TokenStore().Get(email)
	if !ok || entry.AccessToken == "" {
		return
	}

	kd := kc.NewKiteConnect(apiKey)
	kd.Client.SetAccessToken(entry.AccessToken)

	holdings, err := kd.Client.GetHoldings()
	if err != nil {
		h.logger.Warn("Failed to fetch holdings for auto-subscribe", "email", email, "error", err)
		return
	}

	var tokens []uint32
	for _, h := range holdings {
		if h.InstrumentToken != 0 {
			tokens = append(tokens, h.InstrumentToken)
		}
	}

	if len(tokens) > 0 {
		if err := h.manager.TickerService().Subscribe(email, tokens, ticker.ModeQuote); err != nil {
			h.logger.Warn("Failed to auto-subscribe holdings", "email", email, "error", err)
		} else {
			h.logger.Info("Auto-subscribed holdings for dashboard", "email", email, "count", len(tokens))
		}
	}
}
