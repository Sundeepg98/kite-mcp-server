package ops

import (
	"encoding/json"
	"fmt"
	htmltemplate "html/template"
	"log/slog"
	"net/http"
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
//
// Route handlers are grouped by concern across sibling files:
//   - handler.go              core wiring (New, RegisterRoutes, servePage, JSON helpers)
//   - handler_telemetry.go    overview / sessions / tickers / alerts (read-only JSON)
//   - handler_credentials.go  credentials / forceReauth / verifyChain
//   - handler_users.go        listUsers / suspendUser / activateUser / offboardUser / changeRole
//   - handler_risk.go         freezeTrading / unfreezeTrading / *Global
//   - handler_registry.go     registryHandler / registryItemHandler
//   - handler_metrics.go      metricsAPI / metricsFragment
//   - handler_logs.go         logStream (SSE)
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

	// alertDBPath holds the SQLite DB path so metrics endpoints can stat
	// the file for size reporting without reading os.Getenv at request
	// time. Lives on the struct so tests can set it via SetAlertDBPath
	// instead of t.Setenv("ALERT_DB_PATH", ...) — letting them run with
	// t.Parallel(). Production wires app.Config.AlertDBPath through the
	// setter at startup; empty path means "no DB size reported".
	alertDBPath string
}

// SetAlertDBPath wires the SQLite DB path used by the metrics endpoint
// for the db-size calculation branch. Lives outside New() so existing
// callers don't need to change the constructor signature; production
// calls this once at startup, tests call it once per fixture.
//
// Empty path means "no DB size reported" — same behaviour as the
// pre-refactor os.Getenv("ALERT_DB_PATH") returning empty.
func (h *Handler) SetAlertDBPath(path string) {
	h.alertDBPath = path
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
	mux.Handle("/admin/ops/api/risk/freeze-global", wrap(h.freezeTradingGlobal))
	mux.Handle("/admin/ops/api/risk/unfreeze-global", wrap(h.unfreezeTradingGlobal))
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
func (h *Handler) writeJSON(w http.ResponseWriter, data any) {
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

// truncKey safely returns the first n characters of a string, or the whole string if shorter.
func truncKey(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// logAdminAction records an admin action in the audit trail. Used by handlers
// in handler_admin.go that mutate user / risk / registry state.
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
