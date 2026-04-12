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
	"github.com/zerodha/kite-mcp-server/kc/templates"
)

// DashboardHandler serves the per-user trading dashboard and its API endpoints.
type DashboardHandler struct {
	manager      *kc.Manager
	logger       *slog.Logger
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
}

// billingStoreIface is the subset of billing.Store used by the dashboard.
type billingStoreIface interface {
	GetSubscription(email string) *billing.Subscription
}

// NewDashboardHandler creates a new DashboardHandler. The auditStore parameter
// can be nil if the audit trail feature is not enabled.
func NewDashboardHandler(manager *kc.Manager, logger *slog.Logger, auditStore *audit.Store) *DashboardHandler {
	d := &DashboardHandler{
		manager:    manager,
		logger:     logger,
		auditStore: auditStore,
	}
	d.InitTemplates()
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
	mux.Handle("/dashboard", wrap(d.servePortfolioPage))
	mux.Handle("/dashboard/activity", wrap(d.serveActivityPageSSR))
	mux.Handle("/dashboard/api/activity", wrap(d.activityAPI))
	mux.Handle("/dashboard/api/activity/stream", wrap(d.activityStreamSSE))
	mux.Handle("/dashboard/api/activity/export", wrap(d.activityExport))
	mux.Handle("/dashboard/orders", wrap(d.serveOrdersPageSSR))
	mux.Handle("/dashboard/alerts", wrap(d.serveAlertsPageSSR))
	mux.Handle("/dashboard/api/orders", wrap(d.ordersAPI))
	mux.Handle("/dashboard/api/portfolio", wrap(d.portfolio))
	mux.Handle("/dashboard/api/alerts", wrap(d.alerts))
	mux.Handle("/dashboard/api/alerts-enriched", wrap(d.alertsEnrichedAPI))
	mux.Handle("/dashboard/api/pnl-chart", wrap(d.pnlChartAPI))
	mux.Handle("/dashboard/api/order-attribution", wrap(d.orderAttributionAPI))
	mux.Handle("/dashboard/api/status", wrap(d.status))
	mux.Handle("/dashboard/api/market-indices", wrap(d.marketIndices))
	mux.Handle("/dashboard/safety", wrap(d.serveSafetyPageSSR))
	mux.Handle("/dashboard/api/safety/status", wrap(d.safetyStatus))
	mux.Handle("/dashboard/paper", wrap(d.servePaperPageSSR))
	mux.Handle("/dashboard/api/paper/status", wrap(d.paperStatus))
	// Fragment endpoints for htmx auto-refresh
	mux.Handle("/dashboard/api/portfolio-fragment", wrap(d.servePortfolioFragment))
	mux.Handle("/dashboard/api/safety-fragment", wrap(d.serveSafetyFragment))
	mux.Handle("/dashboard/api/paper-fragment", wrap(d.servePaperFragment))
	mux.Handle("/dashboard/api/paper/holdings", wrap(d.paperHoldings))
	mux.Handle("/dashboard/api/paper/positions", wrap(d.paperPositions))
	mux.Handle("/dashboard/api/paper/orders", wrap(d.paperOrders))
	mux.Handle("/dashboard/api/paper/reset", wrap(d.paperReset))
	mux.Handle("/dashboard/api/sector-exposure", wrap(d.sectorExposureAPI))
	mux.Handle("/dashboard/api/tax-analysis", wrap(d.taxAnalysisAPI))
	mux.Handle("/dashboard/api/account/delete", wrap(d.selfDeleteAccount))
	mux.Handle("/dashboard/api/account/credentials", wrap(d.selfManageCredentials))
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
func (d *DashboardHandler) writeJSON(w http.ResponseWriter, data interface{}) {
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
