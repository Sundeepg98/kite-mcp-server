package ops

import (
	"encoding/json"
	"fmt"
	htmltemplate "html/template"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/billing"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
	"github.com/zerodha/kite-mcp-server/kc/templates"
)

// DashboardHandler is the composition root for the per-user trading dashboard.
//
// It owns the shared state (manager, logger, audit store, admin check, parsed
// templates) and delegates route handling to focused sub-handlers that each
// cover one concern (activity, portfolio, orders, alerts, paper, safety).
// Sub-handlers hold a `core *DashboardHandler` back-reference so they can
// reach the shared state and helpers (writeJSON, userContext, ...).
//
// Wave D Phase 3 Package 7c-2 (Logger sweep): loggerPort field carries
// the kc/logger.Logger port. The deprecated slog-typed logger field
// stays populated from the same source so the ~80 consumer sites
// across api_*.go, handler_*.go, and dashboard_*.go keep compiling
// against the legacy slog-shape `d.logger.X(...)` idiom. After
// consumer sites migrate to ctx-aware port surface (future cleanup
// commit), the slog logger field is removed.
type DashboardHandler struct {
	manager      *kc.Manager
	logger       *slog.Logger // Deprecated: use loggerPort
	loggerPort   logport.Logger
	auditStore   *audit.Store
	adminCheck   func(string) bool // returns true if email is admin
	billingStore billingStoreIface // optional: billing tier lookup

	// Parsed Go templates for server-side rendering of user dashboard pages.
	portfolioTmpl *htmltemplate.Template
	activityTmpl  *htmltemplate.Template
	ordersTmpl    *htmltemplate.Template
	alertsTmpl    *htmltemplate.Template
	paperTmpl     *htmltemplate.Template
	safetyTmpl    *htmltemplate.Template
	fragmentTmpl  *htmltemplate.Template // partials for htmx fragment responses

	// Focused sub-handlers (composition root pattern).
	activity  *ActivityHandler
	orders    *OrdersHandler
	portfolio *PortfolioHandler
	alerts    *AlertsHandler
	paper     *PaperHandler
	safety    *SafetyHandler
	tax       *TaxHandler
	account   *AccountHandler
}

// billingStoreIface is the subset of billing.Store used by the dashboard.
type billingStoreIface interface {
	GetSubscription(email string) *billing.Subscription
}

// NewDashboardHandler creates a new DashboardHandler. The auditStore parameter
// can be nil if the audit trail feature is not enabled.
//
// Public signature retains *slog.Logger for backward-compat with
// app/wire.go's call site; the value is wrapped via logport.NewSlog
// so the typed-port loggerPort field is also populated. New code
// paths should consume d.loggerPort with ctx threading; existing
// d.logger.X(slog-shape) call sites stay green.
func NewDashboardHandler(manager *kc.Manager, logger *slog.Logger, auditStore *audit.Store) *DashboardHandler {
	d := &DashboardHandler{
		manager:    manager,
		logger:     logger,
		loggerPort: logport.NewSlog(logger),
		auditStore: auditStore,
	}
	d.InitTemplates()
	d.activity = newActivityHandler(d)
	d.orders = newOrdersHandler(d)
	d.portfolio = newPortfolioHandler(d)
	d.alerts = newAlertsHandler(d)
	d.paper = newPaperHandler(d)
	d.safety = newSafetyHandler(d)
	d.tax = newTaxHandler(d)
	d.account = newAccountHandler(d)
	return d
}

// SetAdminCheck registers a callback to check if an email belongs to an admin.
func (d *DashboardHandler) SetAdminCheck(fn func(string) bool) {
	d.adminCheck = fn
}

// SetBillingStore sets the billing store for the billing page.
func (d *DashboardHandler) SetBillingStore(store billingStoreIface) {
	d.billingStore = store
}

// RegisterRoutes mounts all dashboard routes, protected by the provided auth middleware.
func (d *DashboardHandler) RegisterRoutes(mux *http.ServeMux, auth func(http.Handler) http.Handler) {
	wrap := func(f http.HandlerFunc) http.Handler { return auth(f) }
	mux.Handle("/dashboard", wrap(d.portfolio.servePortfolioPage))
	mux.Handle("/dashboard/activity", wrap(d.activity.serveActivityPageSSR))
	mux.Handle("/dashboard/api/activity", wrap(d.activity.activityAPI))
	mux.Handle("/dashboard/api/activity/stream", wrap(d.activity.activityStreamSSE))
	mux.Handle("/dashboard/api/activity/export", wrap(d.activity.activityExport))
	mux.Handle("/dashboard/orders", wrap(d.orders.serveOrdersPageSSR))
	mux.Handle("/dashboard/alerts", wrap(d.alerts.serveAlertsPageSSR))
	mux.Handle("/dashboard/api/orders", wrap(d.orders.ordersAPI))
	mux.Handle("/dashboard/api/portfolio", wrap(d.portfolio.portfolio))
	mux.Handle("/dashboard/api/alerts", wrap(d.alerts.alerts))
	mux.Handle("/dashboard/api/alerts-enriched", wrap(d.alerts.alertsEnrichedAPI))
	mux.Handle("/dashboard/api/pnl-chart", wrap(d.alerts.pnlChartAPI))
	mux.Handle("/dashboard/api/order-attribution", wrap(d.orders.orderAttributionAPI))
	mux.Handle("/dashboard/api/status", wrap(d.status))
	mux.Handle("/dashboard/api/connections", wrap(d.connections))
	mux.Handle("/dashboard/api/market-indices", wrap(d.portfolio.marketIndices))
	mux.Handle("/dashboard/safety", wrap(d.safety.serveSafetyPageSSR))
	mux.Handle("/dashboard/api/safety/status", wrap(d.safety.safetyStatus))
	mux.Handle("/dashboard/paper", wrap(d.paper.servePaperPageSSR))
	mux.Handle("/dashboard/api/paper/status", wrap(d.paper.paperStatus))
	// Fragment endpoints for htmx auto-refresh
	mux.Handle("/dashboard/api/portfolio-fragment", wrap(d.portfolio.servePortfolioFragment))
	mux.Handle("/dashboard/api/safety-fragment", wrap(d.safety.serveSafetyFragment))
	mux.Handle("/dashboard/api/paper-fragment", wrap(d.paper.servePaperFragment))
	mux.Handle("/dashboard/api/paper/holdings", wrap(d.paper.paperHoldings))
	mux.Handle("/dashboard/api/paper/positions", wrap(d.paper.paperPositions))
	mux.Handle("/dashboard/api/paper/orders", wrap(d.paper.paperOrders))
	mux.Handle("/dashboard/api/paper/reset", wrap(d.paper.paperReset))
	mux.Handle("/dashboard/api/sector-exposure", wrap(d.portfolio.sectorExposureAPI))
	mux.Handle("/dashboard/api/tax-analysis", wrap(d.tax.taxAnalysisAPI))
	mux.Handle("/dashboard/api/account/delete", wrap(d.account.selfDeleteAccount))
	mux.Handle("/dashboard/api/account/credentials", wrap(d.account.selfManageCredentials))
	// Only register billing page if billing store is available
	if d.billingStore != nil {
		mux.Handle("/dashboard/billing", wrap(d.serveBillingPage))
	} else {
		// Show a friendly "Free plan" page when billing is not configured
		mux.HandleFunc("/dashboard/billing", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Billing · Kite MCP</title><link rel="stylesheet" href="/static/dashboard-base.css"></head><body><div style="display:flex;justify-content:center;align-items:center;min-height:100vh"><div style="text-align:center;max-width:400px"><h2 style="color:var(--text-0)">Free Plan</h2><p style="color:var(--text-1);margin:16px 0">All tools are currently available for free.</p><a href="/dashboard" style="color:var(--accent)">← Back to Dashboard</a></div></div></body></html>`)
		})
	}

	// Static CSS — no auth required, publicly cacheable.
	mux.HandleFunc("/static/dashboard-base.css", func(w http.ResponseWriter, r *http.Request) {
		data, err := templates.FS.ReadFile("dashboard-base.css")
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(data)
	})

	// htmx core + SSE extension — no auth required, long cache.
	for _, sf := range []struct{ path, file, ct string }{
		{"/static/htmx.min.js", "static/htmx.min.js", "application/javascript; charset=utf-8"},
		{"/static/htmx-sse.js", "static/htmx-sse.js", "application/javascript; charset=utf-8"},
	} {
		file, ct := sf.file, sf.ct
		mux.HandleFunc(sf.path, func(w http.ResponseWriter, r *http.Request) {
			data, err := templates.FS.ReadFile(file)
			if err != nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", ct)
			w.Header().Set("Cache-Control", "public, max-age=604800")
			_, _ = w.Write(data)
		})
	}
}

// writeJSON encodes data as JSON and writes it to the response writer.
func (d *DashboardHandler) writeJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		d.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// writeJSONError writes a JSON error response with the given status code.
func (d *DashboardHandler) writeJSONError(w http.ResponseWriter, status int, errorCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"error":   errorCode,
		"message": message,
	}); err != nil {
		d.logger.Error("Failed to encode JSON error response", "error", err)
	}
}

// intParam parses an integer query parameter, returning defaultVal if missing, invalid, or negative.
func intParam(r *http.Request, key string, defaultVal int) int {
	s := r.URL.Query().Get(key)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 {
		return defaultVal
	}
	return v
}
