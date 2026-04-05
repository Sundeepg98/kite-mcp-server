package ops

import (
	"encoding/json"
	"fmt"
	htmltemplate "html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/zerodha/kite-mcp-server/app/metrics"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/registry"
	"github.com/zerodha/kite-mcp-server/kc/templates"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// Handler serves the ops dashboard pages and API endpoints.
type Handler struct {
	manager       *kc.Manager
	metrics       *metrics.Manager
	logBuffer     *LogBuffer
	logger        *slog.Logger
	startTime     time.Time
	version       string
	userStore     *users.Store
	auditStore    *audit.Store
	registryStore *registry.Store
	overviewTmpl  *htmltemplate.Template
	adminTmpl     *htmltemplate.Template
	opsTmpl       *htmltemplate.Template
}

// New creates a new ops Handler.
func New(manager *kc.Manager, metrics *metrics.Manager, logBuffer *LogBuffer, logger *slog.Logger, version string, startTime time.Time, userStore *users.Store, auditStore *audit.Store) *Handler {
	h := &Handler{
		manager:       manager,
		metrics:       metrics,
		logBuffer:     logBuffer,
		logger:        logger,
		startTime:     startTime,
		version:       version,
		userStore:     userStore,
		auditStore:    auditStore,
		registryStore: manager.RegistryStoreConcrete(),
	}
	tmpl, err := overviewFragmentTemplates()
	if err != nil {
		logger.Error("Failed to parse overview templates", "error", err)
	} else {
		h.overviewTmpl = tmpl
	}

	adminTmpl, err := adminFragmentTemplates()
	if err != nil {
		logger.Error("Failed to parse admin fragment templates", "error", err)
	} else {
		h.adminTmpl = adminTmpl
	}

	opsTmpl, err := htmltemplate.ParseFS(templates.FS,
		"ops.html",
		"overview_stats.html", "overview_tools.html",
		"admin_sessions.html", "admin_tickers.html", "admin_alerts.html",
		"admin_users.html", "admin_metrics.html",
	)
	if err != nil {
		logger.Error("Failed to parse ops template", "error", err)
	} else {
		h.opsTmpl = opsTmpl
	}

	return h
}

// isAdmin returns true if the given email belongs to an active admin user.
func (h *Handler) isAdmin(email string) bool {
	if h.userStore == nil {
		return false
	}
	return h.userStore.IsAdmin(email)
}

// RegisterRoutes mounts all ops routes under /admin/ops, protected by the provided auth middleware.
func (h *Handler) RegisterRoutes(mux *http.ServeMux, auth func(http.Handler) http.Handler) {
	wrap := func(f http.HandlerFunc) http.Handler { return auth(f) }
	mux.Handle("/admin/ops", wrap(h.servePage))
	mux.Handle("/admin/ops/api/overview", wrap(h.overview))
	mux.Handle("/admin/ops/api/sessions", wrap(h.sessions))
	mux.Handle("/admin/ops/api/tickers", wrap(h.tickers))
	mux.Handle("/admin/ops/api/alerts", wrap(h.alerts))
	mux.Handle("/admin/ops/api/logs", wrap(h.logStream))
	mux.Handle("/admin/ops/api/credentials", wrap(h.credentials))
	mux.Handle("/admin/ops/api/force-reauth", wrap(h.forceReauth))
	mux.Handle("/admin/ops/api/verify-chain", wrap(h.verifyChain))
	// User management (admin only)
	mux.Handle("/admin/ops/api/users", wrap(h.listUsers))
	mux.Handle("/admin/ops/api/users/suspend", wrap(h.suspendUser))
	mux.Handle("/admin/ops/api/users/activate", wrap(h.activateUser))
	mux.Handle("/admin/ops/api/users/offboard", wrap(h.offboardUser))
	mux.Handle("/admin/ops/api/users/role", wrap(h.changeRole))
	// Risk management (admin only)
	mux.Handle("/admin/ops/api/risk/freeze", wrap(h.freezeTrading))
	mux.Handle("/admin/ops/api/risk/unfreeze", wrap(h.unfreezeTrading))
	// Key registry (admin only)
	mux.Handle("/admin/ops/api/registry", wrap(h.registryHandler))
	mux.Handle("/admin/ops/api/registry/", wrap(h.registryItemHandler))
	// Metrics (admin only)
	mux.Handle("/admin/ops/api/metrics", wrap(h.metricsAPI))
	mux.Handle("/admin/ops/api/metrics-fragment", wrap(h.metricsFragment))
	// Overview SSE stream (admin only)
	mux.Handle("/admin/ops/api/overview-stream", wrap(h.overviewStream))
}

// OpsPageData is the template data for the ops.html admin page.
type OpsPageData struct {
	Email    string
	IsAdmin  string
	Overview OverviewTemplateData
	Sessions SessionsTemplateData
	Tickers  TickersTemplateData
	Alerts   AlertsTemplateData
	Users    UsersTemplateData
	Metrics  MetricsTemplateData
}

// servePage serves the embedded ops.html dashboard page via Go template execution,
// injecting user context and pre-rendered overview data.
func (h *Handler) servePage(w http.ResponseWriter, r *http.Request) {
	if h.opsTmpl == nil {
		http.Error(w, "failed to load ops page", http.StatusInternalServerError)
		return
	}

	email := oauth.EmailFromContext(r.Context())
	admin := h.isAdmin(email)

	adminVal := "false"
	if admin {
		adminVal = "true"
	}

	overview := h.buildOverview()

	// Build users list (admin-only, empty for non-admins).
	var usersData UsersTemplateData
	if admin && h.userStore != nil {
		usersData = usersToTemplateData(h.userStore.List(), email)
	}

	// Build initial metrics data (default 1h period).
	var metricsData MetricsTemplateData
	if h.auditStore != nil {
		since := time.Now().Add(-1 * time.Hour)
		stats, _ := h.auditStore.GetGlobalStats(since)
		toolMetrics, _ := h.auditStore.GetToolMetrics(since)
		metricsData = metricsToTemplateData(stats, toolMetrics, int(time.Since(h.startTime).Seconds()))
	}

	data := OpsPageData{
		Email:    email,
		IsAdmin:  adminVal,
		Overview: overviewToTemplateData(overview),
		Sessions: sessionsToTemplateData(h.buildSessions()),
		Tickers:  tickersToTemplateData(h.buildTickers()),
		Alerts:   alertsToTemplateData(h.buildAlerts()),
		Users:    usersData,
		Metrics:  metricsData,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.opsTmpl.Execute(w, data); err != nil {
		h.logger.Error("Failed to render ops page", "error", err)
	}
}

// writeJSON encodes data as JSON and writes it to the response writer.
// Logs an error if encoding fails rather than silently discarding the error.
func (h *Handler) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// writeJSONError writes a JSON error response with the given HTTP status code.
func (h *Handler) writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": msg}); err != nil {
		h.logger.Error("Failed to encode JSON error response", "error", err)
	}
}

// overview returns the combined overview JSON.
// Admin sees global counts; non-admin sees only their own data.
func (h *Handler) overview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if h.isAdmin(email) {
		h.writeJSON(w, h.buildOverview())
	} else {
		h.writeJSON(w, h.buildOverviewForUser(email))
	}
}

// sessions returns the sessions JSON.
// Admin sees all sessions; non-admin sees only their own.
func (h *Handler) sessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if h.isAdmin(email) {
		h.writeJSON(w, h.buildSessions())
	} else {
		h.writeJSON(w, h.buildSessionsForUser(email))
	}
}

// tickers returns the tickers JSON.
// Admin sees all tickers; non-admin sees only their own.
func (h *Handler) tickers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if h.isAdmin(email) {
		h.writeJSON(w, h.buildTickers())
	} else {
		h.writeJSON(w, h.buildTickersForUser(email))
	}
}

// alerts returns the alerts JSON.
// Admin sees all alerts; non-admin sees only their own.
func (h *Handler) alerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if h.isAdmin(email) {
		h.writeJSON(w, h.buildAlerts())
	} else {
		h.writeJSON(w, h.buildAlertsForUser(email))
	}
}

// credentials handles GET (list own), POST (create own), DELETE (remove own) for per-user Kite credentials.
// Operations are scoped to the authenticated user's email to prevent IDOR.
func (h *Handler) credentials(w http.ResponseWriter, r *http.Request) {
	jsonError := func(status int, msg string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(map[string]string{"error": msg}); err != nil {
			h.logger.Error("Failed to encode JSON error response", "error", err)
		}
	}

	// Get the authenticated user's email from context
	authEmail := oauth.EmailFromContext(r.Context())
	if authEmail == "" {
		jsonError(http.StatusUnauthorized, "not authenticated")
		return
	}

	switch r.Method {
	case http.MethodGet:
		// Only return the authenticated user's own credentials
		entry, ok := h.manager.CredentialStore().Get(authEmail)
		if ok {
			secretHint := ""
			if len(entry.APISecret) > 7 {
				secretHint = entry.APISecret[:4] + "****" + entry.APISecret[len(entry.APISecret)-3:]
			} else if entry.APISecret != "" {
				secretHint = "****"
			}
			h.writeJSON(w, []map[string]any{{
				"email":           authEmail,
				"api_key":         entry.APIKey,
				"api_secret_hint": secretHint,
				"stored_at":       entry.StoredAt,
			}})
		} else {
			h.writeJSON(w, []map[string]any{})
		}

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // 64 KB limit
		var req struct {
			APIKey    string `json:"api_key"`
			APISecret string `json:"api_secret"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(http.StatusBadRequest, "invalid JSON")
			return
		}
		if req.APIKey == "" || req.APISecret == "" {
			jsonError(http.StatusBadRequest, "api_key and api_secret are required")
			return
		}
		h.manager.CredentialStore().Set(authEmail, &kc.KiteCredentialEntry{
			APIKey:    req.APIKey,
			APISecret: req.APISecret,
		})
		// Clear cached token — old token was generated with different credentials
		h.manager.TokenStore().Delete(authEmail)

		// Auto-register in registry if not already present
		if h.registryStore != nil {
			if _, found := h.registryStore.GetByAPIKeyAnyStatus(req.APIKey); !found {
				regID := fmt.Sprintf("self-%s-%s", authEmail, truncKey(req.APIKey, 8))
				if err := h.registryStore.Register(&registry.AppRegistration{
					ID:           regID,
					APIKey:       req.APIKey,
					APISecret:    req.APISecret,
					AssignedTo:   authEmail,
					Label:        "Self-provisioned (dashboard)",
					Status:       registry.StatusActive,
					Source:       registry.SourceSelfProvisioned,
					RegisteredBy: authEmail,
				}); err != nil {
					h.logger.Warn("Failed to auto-register credentials in registry", "email", authEmail, "error", err)
				}
			}
		}

		h.logger.Info("Stored Kite credentials", "email", authEmail)
		h.writeJSON(w, map[string]string{"status": "ok"})

	case http.MethodDelete:
		targetEmail := authEmail
		if h.isAdmin(authEmail) {
			if qEmail := r.URL.Query().Get("email"); qEmail != "" {
				targetEmail = strings.ToLower(qEmail)
			}
		}
		h.manager.CredentialStore().Delete(targetEmail)
		h.manager.TokenStore().Delete(targetEmail)
		h.logger.Info("Deleted Kite credentials", "email", targetEmail, "by", authEmail)
		h.writeJSON(w, map[string]string{"status": "ok"})

	default:
		jsonError(http.StatusMethodNotAllowed, "method not allowed")
	}
}

// forceReauth deletes a user's cached Kite token so their next MCP call triggers re-authentication.
// Only admin users can invoke this endpoint.
func (h *Handler) forceReauth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adminEmail := oauth.EmailFromContext(r.Context())
	if !h.isAdmin(adminEmail) {
		http.Error(w, "admin access required", http.StatusForbidden)
		return
	}

	targetEmail := r.URL.Query().Get("email")
	if targetEmail == "" {
		h.writeJSONError(w, http.StatusBadRequest, "email parameter required")
		return
	}

	// Delete the cached Kite token — next MCP call will trigger 401 + re-auth
	h.manager.TokenStore().Delete(targetEmail)
	h.logger.Info("Admin forced re-auth", "admin", adminEmail, "target", targetEmail)
	h.writeJSON(w, map[string]string{"status": "ok", "message": "Token deleted, user will re-authenticate on next MCP call"})
}

// verifyChain runs the HMAC-SHA256 hash chain verification over the entire
// audit trail. Only admin users can invoke this endpoint.
func (h *Handler) verifyChain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if !h.isAdmin(email) {
		http.Error(w, "admin access required", http.StatusForbidden)
		return
	}
	if h.auditStore == nil {
		h.writeJSONError(w, http.StatusServiceUnavailable, "audit trail not enabled")
		return
	}
	result, err := h.auditStore.VerifyChain()
	if err != nil {
		h.logger.Error("Chain verification failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.writeJSON(w, result)
}

// --- User management endpoints (admin only) ---

// listUsers returns all registered users. Admin only.
func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if !h.isAdmin(email) {
		http.Error(w, "admin access required", http.StatusForbidden)
		return
	}
	if h.userStore == nil {
		h.writeJSON(w, []interface{}{})
		return
	}
	h.writeJSON(w, h.userStore.List())
}

// suspendUser sets a user's status to suspended. Admin only.
// Expects query param: email
func (h *Handler) suspendUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adminEmail := oauth.EmailFromContext(r.Context())
	if !h.isAdmin(adminEmail) {
		http.Error(w, "admin access required", http.StatusForbidden)
		return
	}
	targetEmail := r.URL.Query().Get("email")
	if targetEmail == "" {
		h.writeJSONError(w, http.StatusBadRequest, "email parameter required")
		return
	}
	if strings.EqualFold(targetEmail, adminEmail) {
		h.writeJSONError(w, http.StatusBadRequest, "Cannot perform this action on yourself")
		return
	}
	if h.userStore == nil {
		h.writeJSONError(w, http.StatusServiceUnavailable, "user store not initialized")
		return
	}
	if err := h.userStore.UpdateStatus(targetEmail, users.StatusSuspended); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.logger.Info("Admin suspended user", "admin", adminEmail, "target", targetEmail)
	h.logAdminAction(adminEmail, "suspend_user", targetEmail)
	h.writeJSON(w, map[string]string{"status": "ok", "message": "User suspended"})
}

// activateUser sets a user's status to active. Admin only.
// Expects query param: email
func (h *Handler) activateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adminEmail := oauth.EmailFromContext(r.Context())
	if !h.isAdmin(adminEmail) {
		http.Error(w, "admin access required", http.StatusForbidden)
		return
	}
	targetEmail := r.URL.Query().Get("email")
	if targetEmail == "" {
		h.writeJSONError(w, http.StatusBadRequest, "email parameter required")
		return
	}
	if strings.EqualFold(targetEmail, adminEmail) {
		h.writeJSONError(w, http.StatusBadRequest, "Cannot perform this action on yourself")
		return
	}
	if h.userStore == nil {
		h.writeJSONError(w, http.StatusServiceUnavailable, "user store not initialized")
		return
	}
	if err := h.userStore.UpdateStatus(targetEmail, users.StatusActive); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.logger.Info("Admin activated user", "admin", adminEmail, "target", targetEmail)
	h.logAdminAction(adminEmail, "activate_user", targetEmail)
	h.writeJSON(w, map[string]string{"status": "ok", "message": "User activated"})
}

// offboardUser removes all user data (credentials, tokens, sessions) and sets status to offboarded. Admin only.
// Expects query param: email
func (h *Handler) offboardUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adminEmail := oauth.EmailFromContext(r.Context())
	if !h.isAdmin(adminEmail) {
		http.Error(w, "admin access required", http.StatusForbidden)
		return
	}
	targetEmail := r.URL.Query().Get("email")
	if targetEmail == "" {
		h.writeJSONError(w, http.StatusBadRequest, "email parameter required")
		return
	}
	if strings.EqualFold(targetEmail, adminEmail) {
		h.writeJSONError(w, http.StatusBadRequest, "Cannot perform this action on yourself")
		return
	}

	// Parse request body for confirmation
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var confirmBody struct {
		Confirm bool `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&confirmBody); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "invalid_request",
			"message": "Invalid JSON body.",
		})
		return
	}
	if !confirmBody.Confirm {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "confirmation_required",
			"message": "This is a destructive action. Set confirm: true to proceed.",
		})
		return
	}

	if h.userStore == nil {
		h.writeJSONError(w, http.StatusServiceUnavailable, "user store not initialized")
		return
	}

	// Delete credentials, tokens, and sessions
	h.manager.CredentialStore().Delete(targetEmail)
	h.manager.TokenStore().Delete(targetEmail)
	h.manager.SessionManager().TerminateByEmail(targetEmail)

	if err := h.userStore.UpdateStatus(targetEmail, users.StatusOffboarded); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.logger.Info("Admin offboarded user", "admin", adminEmail, "target", targetEmail)
	h.logAdminAction(adminEmail, "offboard_user", targetEmail)
	h.writeJSON(w, map[string]string{"status": "ok", "message": "User offboarded, all data removed"})
}

// changeRole changes a user's role. Admin only.
// Expects query param: email, JSON body: {"role": "viewer"}
func (h *Handler) changeRole(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adminEmail := oauth.EmailFromContext(r.Context())
	if !h.isAdmin(adminEmail) {
		http.Error(w, "admin access required", http.StatusForbidden)
		return
	}
	targetEmail := r.URL.Query().Get("email")
	if targetEmail == "" {
		h.writeJSONError(w, http.StatusBadRequest, "email parameter required")
		return
	}
	if h.userStore == nil {
		h.writeJSONError(w, http.StatusServiceUnavailable, "user store not initialized")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var req struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Last-admin guard: prevent demoting the only active admin
	target, ok := h.userStore.Get(targetEmail)
	if ok && target.Role == "admin" && req.Role != "admin" {
		admins := 0
		for _, u := range h.userStore.List() {
			if u.Role == "admin" && u.Status == "active" {
				admins++
			}
		}
		if admins <= 1 {
			h.writeJSONError(w, http.StatusConflict, "Cannot demote the last admin")
			return
		}
	}

	if err := h.userStore.UpdateRole(targetEmail, req.Role); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.logger.Info("Admin changed user role", "admin", adminEmail, "target", targetEmail, "role", req.Role)
	h.logAdminAction(adminEmail, "change_role", targetEmail+" -> "+req.Role)
	h.writeJSON(w, map[string]string{"status": "ok", "message": "Role updated to " + req.Role})
}

// freezeTrading freezes trading for a user. Admin only.
func (h *Handler) freezeTrading(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adminEmail := oauth.EmailFromContext(r.Context())
	if !h.isAdmin(adminEmail) {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	var body struct {
		Email   string `json:"email"`
		Reason  string `json:"reason"`
		Confirm bool   `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		http.Error(w, "email required", http.StatusBadRequest)
		return
	}
	if strings.EqualFold(body.Email, adminEmail) {
		h.writeJSONError(w, http.StatusBadRequest, "Cannot perform this action on yourself")
		return
	}
	if !body.Confirm {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "confirmation_required",
			"message": "This is a destructive action. Set confirm: true to proceed.",
		})
		return
	}
	guard := h.manager.RiskGuard()
	if guard == nil {
		http.Error(w, "riskguard not enabled", http.StatusServiceUnavailable)
		return
	}
	guard.Freeze(body.Email, adminEmail, body.Reason)
	h.logger.Info("Admin froze trading", "admin", adminEmail, "target", body.Email, "reason", body.Reason)
	h.logAdminAction(adminEmail, "freeze_trading", body.Email)
	h.writeJSON(w, map[string]string{"status": "ok", "message": "Trading frozen for " + body.Email})
}

// unfreezeTrading unfreezes trading for a user. Admin only.
func (h *Handler) unfreezeTrading(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adminEmail := oauth.EmailFromContext(r.Context())
	if !h.isAdmin(adminEmail) {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		http.Error(w, "email required", http.StatusBadRequest)
		return
	}
	if strings.EqualFold(body.Email, adminEmail) {
		h.writeJSONError(w, http.StatusBadRequest, "Cannot perform this action on yourself")
		return
	}
	guard := h.manager.RiskGuard()
	if guard == nil {
		http.Error(w, "riskguard not enabled", http.StatusServiceUnavailable)
		return
	}
	guard.Unfreeze(body.Email)
	h.logger.Info("Admin unfroze trading", "admin", adminEmail, "target", body.Email)
	h.logAdminAction(adminEmail, "unfreeze_trading", body.Email)
	h.writeJSON(w, map[string]string{"status": "ok", "message": "Trading unfrozen for " + body.Email})
}

// logAdminAction records an admin action in the audit trail.
func (h *Handler) logAdminAction(adminEmail, action, target string) {
	if h.auditStore == nil {
		return
	}
	now := time.Now()
	entry := &audit.ToolCall{
		CallID:        fmt.Sprintf("admin-%d", now.UnixNano()),
		Email:         adminEmail,
		ToolName:      action,
		ToolCategory:  "admin",
		InputSummary:  target,
		OutputSummary: "ok",
		StartedAt:     now,
		CompletedAt:   now,
	}
	if err := h.auditStore.Record(entry); err != nil {
		h.logger.Error("Failed to record admin action", "action", action, "error", err)
	}
}

// logStream serves an SSE stream of structured log entries.
// Only admin users can access the log stream.
func (h *Handler) logStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if !h.isAdmin(email) {
		http.Error(w, "admin access required", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	listenerID := fmt.Sprintf("ops-%d", time.Now().UnixNano())
	ch := h.logBuffer.AddListener(listenerID)
	defer h.logBuffer.RemoveListener(listenerID)

	// Backfill recent entries.
	for _, entry := range h.logBuffer.Recent(50) {
		if data, err := json.Marshal(entry); err == nil {
			fmt.Fprintf(w, "data: %s\n\n", data)
		}
	}
	flusher.Flush()

	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case entry := <-ch:
			if data, err := json.Marshal(entry); err == nil {
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
			}
		case <-keepalive.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

// --- Key Registry endpoints (admin only) ---
//
// API contract for the "API Key Registry" tab in ops.html:
//
//   GET  /admin/ops/api/registry
//     Response: []registry.AppRegistrationSummary (JSON array)
//       Fields: id, api_key (masked), api_secret_hint (masked), assigned_to,
//               label, status, registered_by, source, last_used_at, created_at, updated_at
//
//   POST /admin/ops/api/registry
//     Request:  {"id": string, "api_key": string, "api_secret": string, "assigned_to": string, "label": string}
//       Required: id, api_key, api_secret
//     Response: {"status": "ok", "id": "<id>"} (201) | {"error": "..."} (400/409)
//
//   PUT  /admin/ops/api/registry/{id}
//     Request:  {"assigned_to": string, "label": string, "status": string}
//       Status values: "active", "disabled", "invalid", "replaced"
//     Response: {"status": "ok"} (200) | {"error": "..."} (404)
//
//   DELETE /admin/ops/api/registry/{id}
//     Response: {"status": "ok"} (200) | {"error": "..."} (404)

// registryHandler handles GET (list) and POST (create) for /admin/ops/api/registry.
func (h *Handler) registryHandler(w http.ResponseWriter, r *http.Request) {
	email := oauth.EmailFromContext(r.Context())
	if !h.isAdmin(email) {
		http.Error(w, "admin access required", http.StatusForbidden)
		return
	}
	if h.registryStore == nil {
		h.writeJSONError(w, http.StatusServiceUnavailable, "registry not initialized")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.writeJSON(w, h.registryStore.List())

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
		var req struct {
			ID         string `json:"id"`
			APIKey     string `json:"api_key"`
			APISecret  string `json:"api_secret"`
			AssignedTo string `json:"assigned_to"`
			Label      string `json:"label"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			h.writeJSON(w, map[string]string{"error": "invalid JSON"})
			return
		}
		if req.ID == "" || req.APIKey == "" || req.APISecret == "" {
			w.WriteHeader(http.StatusBadRequest)
			h.writeJSON(w, map[string]string{"error": "id, api_key, and api_secret are required"})
			return
		}
		reg := &registry.AppRegistration{
			ID:           req.ID,
			APIKey:       req.APIKey,
			APISecret:    req.APISecret,
			AssignedTo:   req.AssignedTo,
			Label:        req.Label,
			RegisteredBy: email,
			Source:       registry.SourceAdmin,
		}
		if err := h.registryStore.Register(reg); err != nil {
			w.WriteHeader(http.StatusConflict)
			h.writeJSON(w, map[string]string{"error": err.Error()})
			return
		}
		h.logger.Info("Admin registered app in key registry", "admin", email, "id", req.ID, "api_key", req.APIKey[:8]+"...")
		h.logAdminAction(email, "register_app", req.ID+" ("+req.Label+")")
		w.WriteHeader(http.StatusCreated)
		h.writeJSON(w, map[string]string{"status": "ok", "id": req.ID})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// registryItemHandler handles PUT (update) and DELETE (remove) for /admin/ops/api/registry/{id}.
func (h *Handler) registryItemHandler(w http.ResponseWriter, r *http.Request) {
	email := oauth.EmailFromContext(r.Context())
	if !h.isAdmin(email) {
		http.Error(w, "admin access required", http.StatusForbidden)
		return
	}
	if h.registryStore == nil {
		h.writeJSONError(w, http.StatusServiceUnavailable, "registry not initialized")
		return
	}

	// Extract ID from URL: /admin/ops/api/registry/{id}
	id := strings.TrimPrefix(r.URL.Path, "/admin/ops/api/registry/")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		h.writeJSON(w, map[string]string{"error": "id is required in URL path"})
		return
	}

	switch r.Method {
	case http.MethodPut:
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
		var req struct {
			AssignedTo string `json:"assigned_to"`
			Label      string `json:"label"`
			Status     string `json:"status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			h.writeJSON(w, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := h.registryStore.Update(id, req.AssignedTo, req.Label, req.Status); err != nil {
			w.WriteHeader(http.StatusNotFound)
			h.writeJSON(w, map[string]string{"error": err.Error()})
			return
		}
		h.logger.Info("Admin updated registry entry", "admin", email, "id", id)
		h.logAdminAction(email, "update_registry", id)
		h.writeJSON(w, map[string]string{"status": "ok"})

	case http.MethodDelete:
		if err := h.registryStore.Delete(id); err != nil {
			w.WriteHeader(http.StatusNotFound)
			h.writeJSON(w, map[string]string{"error": err.Error()})
			return
		}
		h.logger.Info("Admin deleted registry entry", "admin", email, "id", id)
		h.logAdminAction(email, "delete_registry", id)
		h.writeJSON(w, map[string]string{"status": "ok"})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// metricsAPI returns global audit trail metrics for the ops dashboard.
// Requires admin access. Accepts ?period=1h|24h|7d|30d (default 24h).
func (h *Handler) metricsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if !h.isAdmin(email) {
		http.Error(w, "admin access required", http.StatusForbidden)
		return
	}
	if h.auditStore == nil {
		h.writeJSONError(w, http.StatusServiceUnavailable, "audit trail not enabled")
		return
	}

	// Parse period parameter
	period := r.URL.Query().Get("period")
	var since time.Time
	switch period {
	case "1h":
		since = time.Now().Add(-1 * time.Hour)
	case "7d":
		since = time.Now().AddDate(0, 0, -7)
	case "30d":
		since = time.Now().AddDate(0, 0, -30)
	default:
		since = time.Now().Add(-24 * time.Hour)
	}

	stats, err := h.auditStore.GetGlobalStats(since)
	if err != nil {
		h.logger.Error("Failed to get global stats", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	toolMetrics, err := h.auditStore.GetToolMetrics(since)
	if err != nil {
		h.logger.Error("Failed to get tool metrics", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	uptime := time.Since(h.startTime)
	h.writeJSON(w, map[string]any{
		"uptime_seconds": int(uptime.Seconds()),
		"stats":          stats,
		"tool_metrics":   toolMetrics,
	})
}

// metricsFragment returns server-rendered HTML for the metrics cards and table.
// Used by htmx period buttons to swap the metrics content without full JS rendering.
func (h *Handler) metricsFragment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if !h.isAdmin(email) {
		http.Error(w, "admin access required", http.StatusForbidden)
		return
	}
	if h.auditStore == nil {
		http.Error(w, "audit trail not enabled", http.StatusServiceUnavailable)
		return
	}
	if h.adminTmpl == nil {
		http.Error(w, "templates not loaded", http.StatusInternalServerError)
		return
	}

	period := r.URL.Query().Get("period")
	var since time.Time
	switch period {
	case "1h":
		since = time.Now().Add(-1 * time.Hour)
	case "7d":
		since = time.Now().AddDate(0, 0, -7)
	case "30d":
		since = time.Now().AddDate(0, 0, -30)
	default:
		since = time.Now().Add(-24 * time.Hour)
	}

	stats, err := h.auditStore.GetGlobalStats(since)
	if err != nil {
		h.logger.Error("Failed to get global stats for fragment", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	toolMetrics, err := h.auditStore.GetToolMetrics(since)
	if err != nil {
		h.logger.Error("Failed to get tool metrics for fragment", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data := metricsToTemplateData(stats, toolMetrics, int(time.Since(h.startTime).Seconds()))

	cardsHTML, err := renderFragment(h.adminTmpl, "admin_metrics_cards", data)
	if err != nil {
		h.logger.Error("Failed to render metrics cards fragment", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	tableHTML, err := renderFragment(h.adminTmpl, "admin_metrics_table", data)
	if err != nil {
		h.logger.Error("Failed to render metrics table fragment", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<div class="stats-grid">%s</div><div class="section-header">Tool Details</div><div class="tbl-wrap"><table><thead><tr><th>Tool</th><th>Calls</th><th>Avg (ms)</th><th>Max (ms)</th><th>Errors</th><th>Error %%</th></tr></thead><tbody>%s</tbody></table></div>`, cardsHTML, tableHTML)
}

// truncKey safely returns the first n characters of a string, or the whole string if shorter.
func truncKey(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
