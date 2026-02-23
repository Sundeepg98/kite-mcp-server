package dashboard

import (
	"html/template"
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

	// Dashboard login initiation (shows email form or redirects to Kite)
	mux.HandleFunc("/dashboard/login", h.handleLogin)

	// Protected routes
	auth := h.oauthHandler.RequireAuthBrowser

	mux.Handle("/dashboard", auth(http.HandlerFunc(h.serveDashboard)))
	mux.Handle("/api/dashboard/data", auth(http.HandlerFunc(h.serveData)))
	mux.Handle("/api/dashboard/stream", auth(http.HandlerFunc(h.serveStream)))

	h.logger.Info("Dashboard routes registered at /dashboard")
}

// handleLogin shows a login form or redirects to Kite login.
// If email query param is provided, looks up stored credentials and redirects to Kite.
// Otherwise, serves a login form where the user enters their email.
func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/dashboard"
	}
	email := r.URL.Query().Get("email")
	if r.Method == http.MethodPost {
		r.ParseForm()
		email = r.FormValue("email")
	}

	if email == "" {
		h.serveLoginForm(w, redirect, "")
		return
	}

	apiKey := h.manager.GetAPIKeyForEmail(email)
	if apiKey == "" {
		h.serveLoginForm(w, redirect, "No credentials found for this email. Please authenticate via your MCP client first.")
		return
	}

	kiteURL := h.oauthHandler.GenerateDashboardLoginURL(apiKey, redirect)
	http.Redirect(w, r, kiteURL, http.StatusFound)
}

// serveLoginForm renders the dashboard login form template.
func (h *Handler) serveLoginForm(w http.ResponseWriter, redirect string, errorMsg string) {
	tmpl, err := template.ParseFS(templates.FS, "base.html", "dashboard_login.html")
	if err != nil {
		h.logger.Error("Failed to parse dashboard login template", "error", err)
		http.Error(w, "Failed to load login page", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := struct {
		Title    string
		Redirect string
		Error    string
	}{
		Title:    "Dashboard Login",
		Redirect: redirect,
		Error:    errorMsg,
	}
	if err := tmpl.ExecuteTemplate(w, "base", data); err != nil {
		h.logger.Error("Failed to render dashboard login template", "error", err)
	}
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
