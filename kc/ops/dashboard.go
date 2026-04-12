package ops

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	htmltemplate "html/template"
	"log/slog"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/templates"
	"github.com/zerodha/kite-mcp-server/oauth"
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

// serveBillingPage shows a proper account/billing page with tier info,
// feature list, family membership details, and Stripe portal link.
func (d *DashboardHandler) serveBillingPage(w http.ResponseWriter, r *http.Request) {
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		http.Redirect(w, r, "/auth/login", http.StatusFound)
		return
	}

	tier := "Free"
	status := ""
	maxUsers := 1
	memberCount := 0
	adminEmail := ""
	isAdmin := false
	hasStripe := false

	if d.adminCheck != nil {
		isAdmin = d.adminCheck(email)
	}

	if d.billingStore != nil {
		if sub := d.billingStore.GetSubscription(email); sub != nil {
			tier = tierDisplayName(sub.Tier)
			status = sub.Status
			maxUsers = sub.MaxUsers
			hasStripe = sub.StripeCustomerID != ""
		}
	}

	// Check if family member (inherited tier from admin).
	if d.manager != nil {
		if uStore := d.manager.UserStore(); uStore != nil {
			if u, ok := uStore.Get(email); ok && u.AdminEmail != "" {
				adminEmail = u.AdminEmail
				// Get admin's tier if user has no direct subscription.
				if tier == "Free" && d.billingStore != nil {
					if adminSub := d.billingStore.GetSubscription(u.AdminEmail); adminSub != nil {
						tier = tierDisplayName(adminSub.Tier)
						status = adminSub.Status
					}
				}
			}
			// Count family members if admin.
			if isAdmin {
				memberCount = len(uStore.ListByAdminEmail(email))
			}
		}
	}

	// Build feature list per tier.
	type feature struct {
		Name    string
		Enabled bool
	}
	features := []feature{
		{"Read-only market data", true},
		{"Paper trading", true},
		{"Watchlists", true},
		{"Basic portfolio view", true},
		{"Live order execution", tier == "Pro" || tier == "Premium"},
		{"GTT orders", tier == "Pro" || tier == "Premium"},
		{"Price alerts + Telegram", tier == "Pro" || tier == "Premium"},
		{"Trailing stops", tier == "Pro" || tier == "Premium"},
		{"Advanced analytics", tier == "Pro" || tier == "Premium"},
		{"Backtesting", tier == "Premium"},
		{"Options strategies", tier == "Premium"},
		{"Technical indicators", tier == "Premium"},
		{"Tax harvesting", tier == "Premium"},
		{"SEBI compliance", tier == "Premium"},
	}

	// Status badge color.
	statusColor := "#64748b" // gray for unknown/empty
	statusLabel := "—"
	switch status {
	case "active", "trialing":
		statusColor = "#34d399" // green
		statusLabel = strings.ToUpper(status[:1]) + status[1:]
	case "past_due":
		statusColor = "#fbbf24" // amber
		statusLabel = "Past Due"
	case "canceled":
		statusColor = "#f87171" // red
		statusLabel = "Canceled"
	default:
		if tier == "Free" {
			statusLabel = "Active"
			statusColor = "#34d399"
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Account &amp; Billing - Kite MCP</title>
<link rel="stylesheet" href="/static/dashboard-base.css">
<style>
.billing-wrap{max-width:640px;margin:0 auto;padding:40px 20px}
.billing-header{margin-bottom:32px}
.billing-header h1{font-size:1.5rem;font-weight:700;color:var(--text-0,#e2e8f0);margin-bottom:4px}
.billing-header p{color:var(--text-1,#94a3b8);font-size:0.9rem}
.tier-card{border:1px solid var(--border,#1e293b);border-radius:12px;padding:28px 24px;margin-bottom:24px;background:var(--card-bg,rgba(30,41,59,0.3))}
.tier-row{display:flex;align-items:center;gap:12px;margin-bottom:16px}
.tier-name{font-size:1.6rem;font-weight:700;color:var(--text-0,#e2e8f0)}
.tier-badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:0.75rem;font-weight:600;letter-spacing:0.03em}
.tier-meta{color:var(--text-1,#94a3b8);font-size:0.85rem;line-height:1.5}
.features-card{border:1px solid var(--border,#1e293b);border-radius:12px;padding:24px;margin-bottom:24px;background:var(--card-bg,rgba(30,41,59,0.3))}
.features-card h3{font-size:1rem;font-weight:600;color:var(--text-0,#e2e8f0);margin-bottom:16px}
.feature-list{list-style:none;padding:0;margin:0;columns:2;column-gap:24px}
.feature-list li{padding:6px 0;font-size:0.85rem;break-inside:avoid}
.feature-list li.on{color:var(--text-1,#94a3b8)}
.feature-list li.on::before{content:"\2713 ";color:#34d399;font-weight:700}
.feature-list li.off{color:var(--text-2,#475569)}
.feature-list li.off::before{content:"\2717 ";color:#475569;font-weight:700}
.family-card{border:1px solid var(--border,#1e293b);border-radius:12px;padding:24px;margin-bottom:24px;background:var(--card-bg,rgba(30,41,59,0.3))}
.family-card h3{font-size:1rem;font-weight:600;color:var(--text-0,#e2e8f0);margin-bottom:12px}
.family-card p{color:var(--text-1,#94a3b8);font-size:0.85rem;line-height:1.5}
.actions{display:flex;gap:12px;flex-wrap:wrap}
.btn{display:inline-block;padding:10px 20px;border-radius:6px;font-weight:600;font-size:0.85rem;text-decoration:none;text-align:center;cursor:pointer;border:none}
.btn-primary{background:#22d3ee;color:#0a0c10}
.btn-primary:hover{opacity:0.9}
.btn-secondary{background:transparent;color:#94a3b8;border:1px solid #1e293b}
.btn-secondary:hover{border-color:#334155;color:#e2e8f0}
.back-link{display:inline-block;margin-top:24px;color:var(--accent,#22d3ee);font-size:0.85rem;text-decoration:none}
.back-link:hover{text-decoration:underline}
</style>
</head>
<body>
<div class="billing-wrap">
<div class="billing-header">
<h1>Account &amp; Billing</h1>
<p>%s</p>
</div>
`, htmltemplate.HTMLEscapeString(email))

	// Tier card.
	fmt.Fprintf(w, `<div class="tier-card">
<div class="tier-row">
<span class="tier-name">%s</span>
<span class="tier-badge" style="background:%s22;color:%s">%s</span>
</div>
`, htmltemplate.HTMLEscapeString(tier), statusColor, statusColor, htmltemplate.HTMLEscapeString(statusLabel))

	if adminEmail != "" {
		fmt.Fprintf(w, `<div class="tier-meta">Inherited from admin: <strong>%s</strong></div>
`, htmltemplate.HTMLEscapeString(adminEmail))
	}
	if tier != "Free" && maxUsers > 1 {
		fmt.Fprintf(w, `<div class="tier-meta">Plan includes up to %d family members</div>
`, maxUsers)
	}
	fmt.Fprint(w, `</div>
`)

	// Feature list.
	fmt.Fprint(w, `<div class="features-card">
<h3>Features</h3>
<ul class="feature-list">
`)
	for _, f := range features {
		cls := "off"
		if f.Enabled {
			cls = "on"
		}
		fmt.Fprintf(w, `<li class="%s">%s</li>
`, cls, htmltemplate.HTMLEscapeString(f.Name))
	}
	fmt.Fprint(w, `</ul>
</div>
`)

	// Family section (only if admin or family member).
	if isAdmin || adminEmail != "" {
		fmt.Fprint(w, `<div class="family-card">
<h3>Family Plan</h3>
`)
		if isAdmin {
			fmt.Fprintf(w, `<p><strong>%d</strong> of <strong>%d</strong> family member seats used.</p>
<p style="margin-top:8px;font-size:0.8rem;color:var(--text-2,#475569)">Use the <code>admin_list_family</code> MCP tool to see all members, or <code>admin_invite_family_member</code> to invite new ones.</p>
`, memberCount, maxUsers)
		} else {
			fmt.Fprintf(w, `<p>You are a family member. Your plan is inherited from <strong>%s</strong>.</p>
`, htmltemplate.HTMLEscapeString(adminEmail))
		}
		fmt.Fprint(w, `</div>
`)
	}

	// Action buttons.
	fmt.Fprint(w, `<div class="actions">
`)
	if tier == "Free" {
		fmt.Fprint(w, `<a href="/pricing" class="btn btn-primary">Upgrade Plan</a>
`)
	} else {
		fmt.Fprint(w, `<a href="/pricing" class="btn btn-secondary">Change Plan</a>
`)
	}
	if hasStripe {
		fmt.Fprint(w, `<a href="/stripe-portal" class="btn btn-secondary">Manage in Stripe</a>
<p style="font-size:12px;color:var(--text-2);margin-top:8px;">View billing history, invoices, and update payment methods in the Stripe portal.</p>
`)
	}
	fmt.Fprint(w, `</div>
`)

	fmt.Fprint(w, `<a href="/dashboard" class="back-link">&larr; Back to Dashboard</a>
</div>
</body>
</html>`)
}

// tierDisplayName returns a title-cased display name for a billing tier.
func tierDisplayName(t billing.Tier) string {
	switch t {
	case billing.TierPro:
		return "Pro"
	case billing.TierPremium:
		return "Premium"
	default:
		return "Free"
	}
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

// NOTE: servePage and serveActivityPage have been replaced by SSR handlers
// in dashboard_templates.go (servePortfolioPage and serveActivityPageSSR).

// activityAPI returns paginated, filterable audit trail entries for the authenticated user.
func (d *DashboardHandler) activityAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	if d.auditStore == nil {
		d.writeJSONError(w, http.StatusServiceUnavailable, "not_available", "Audit trail not enabled")
		return
	}

	// Parse query params
	opts := audit.ListOptions{
		Limit:      intParam(r, "limit", 50),
		Offset:     intParam(r, "offset", 0),
		Category:   r.URL.Query().Get("category"),
		OnlyErrors: r.URL.Query().Get("errors") == "true",
	}
	if since := r.URL.Query().Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			opts.Since = t
		}
	}
	if until := r.URL.Query().Get("until"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			opts.Until = t
		}
	}

	results, total, err := d.auditStore.List(email, opts)
	if err != nil {
		d.logger.Error("Failed to list audit entries", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Compute aggregate stats from the DB (not just the current page).
	// Pass category and errorsOnly so stats reflect the user's active filters.
	var stats *audit.Stats
	stats, err = d.auditStore.GetStats(email, opts.Since, opts.Category, opts.OnlyErrors)
	if err != nil {
		d.logger.Error("Failed to get audit stats", "error", err)
		// Non-fatal: return entries without stats.
	}

	// Get tool usage counts for the bar chart (scoped to active filters).
	toolCounts, tcErr := d.auditStore.GetToolCounts(email, opts.Since, opts.Category, opts.OnlyErrors)
	if tcErr != nil {
		d.logger.Error("Failed to get tool counts", "error", tcErr)
	}

	d.writeJSON(w, map[string]any{
		"entries":     results,
		"total":       total,
		"limit":       opts.Limit,
		"offset":      opts.Offset,
		"stats":       stats,
		"tool_counts": toolCounts,
	})
}

// activityExport streams audit trail entries as CSV or JSON for download.
func (d *DashboardHandler) activityExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if email == "" || d.auditStore == nil {
		http.Error(w, "not available", http.StatusBadRequest)
		return
	}

	// Parse format (csv or json)
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}

	// Parse time range and filters
	opts := audit.ListOptions{Limit: 10000} // cap at 10K rows per export
	if since := r.URL.Query().Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			opts.Since = t
		}
	}
	if until := r.URL.Query().Get("until"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			opts.Until = t
		}
	}
	opts.Category = r.URL.Query().Get("category")
	opts.OnlyErrors = r.URL.Query().Get("errors") == "true"

	results, _, err := d.auditStore.List(email, opts)
	if err != nil {
		d.logger.Error("Failed to export activity", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if format == "json" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=activity.json")
		if err := json.NewEncoder(w).Encode(results); err != nil {
			d.logger.Error("Failed to encode JSON export", "error", err)
		}
		return
	}

	// CSV export
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=activity.csv")
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"Time", "Tool", "Category", "Input", "Output", "Duration (ms)", "Error", "Error Message"})
	for _, e := range results {
		isErr := "false"
		if e.IsError {
			isErr = "true"
		}
		_ = cw.Write([]string{
			e.StartedAt.Format(time.RFC3339),
			e.ToolName,
			e.ToolCategory,
			e.InputSummary,
			e.OutputSummary,
			fmt.Sprintf("%d", e.DurationMs),
			isErr,
			e.ErrorMessage,
		})
	}
	cw.Flush()
}

// activityStreamSSE serves an SSE stream of new audit trail entries for the authenticated user.
func (d *DashboardHandler) activityStreamSSE(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	if d.auditStore == nil {
		http.Error(w, "audit trail not enabled", http.StatusNotFound)
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

	listenerID := fmt.Sprintf("activity-%s-%d", email, time.Now().UnixNano())
	ch := d.auditStore.AddActivityListener(listenerID)
	defer d.auditStore.RemoveActivityListener(listenerID)

	// Send initial keepalive
	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case entry := <-ch:
			// Only send entries belonging to this user.
			// The entry email may be hashed; compare using the store's hmac method.
			// Since the listener receives all entries, we filter by email here.
			if entry.Email != email {
				continue
			}
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

// --- Portfolio types ---

type holdingItem struct {
	Tradingsymbol      string  `json:"tradingsymbol"`
	Exchange           string  `json:"exchange"`
	Quantity           int     `json:"quantity"`
	AveragePrice       float64 `json:"average_price"`
	LastPrice          float64 `json:"last_price"`
	PnL                float64 `json:"pnl"`
	DayChangePercent   float64 `json:"day_change_percentage"`
	Product            string  `json:"product"`
}

type positionItem struct {
	Tradingsymbol string  `json:"tradingsymbol"`
	Exchange      string  `json:"exchange"`
	Quantity      int     `json:"quantity"`
	AveragePrice  float64 `json:"average_price"`
	LastPrice     float64 `json:"last_price"`
	PnL           float64 `json:"pnl"`
	Product       string  `json:"product"`
}

type portfolioSummary struct {
	HoldingsCount  int     `json:"holdings_count"`
	TotalInvested  float64 `json:"total_invested"`
	TotalCurrent   float64 `json:"total_current"`
	TotalPnL       float64 `json:"total_pnl"`
	PositionsCount int     `json:"positions_count"`
	PositionsPnL   float64 `json:"positions_pnl"`
}

type portfolioResponse struct {
	Holdings []holdingItem    `json:"holdings"`
	Positions []positionItem  `json:"positions"`
	Summary  portfolioSummary `json:"summary"`
}

// --- Alerts types ---

type alertsResponse struct {
	Active         interface{} `json:"active"`
	Triggered      interface{} `json:"triggered"`
	ActiveCount    int         `json:"active_count"`
	TriggeredCount int         `json:"triggered_count"`
}

// --- Status types ---

type tokenStatus struct {
	Valid    bool   `json:"valid"`
	StoredAt string `json:"stored_at,omitempty"`
}

type credentialStatus struct {
	Stored bool   `json:"stored"`
	APIKey string `json:"api_key,omitempty"`
}

type tickerStatus struct {
	Running       bool `json:"running"`
	Subscriptions int  `json:"subscriptions"`
}

type statusResponse struct {
	Email       string           `json:"email"`
	Role        string           `json:"role,omitempty"`
	IsAdmin     bool             `json:"is_admin"`
	DevMode     bool             `json:"dev_mode,omitempty"`
	KiteToken   tokenStatus      `json:"kite_token"`
	Credentials credentialStatus `json:"credentials"`
	Ticker      tickerStatus     `json:"ticker"`
}

// --- Handlers ---

// marketIndices returns OHLC data for NIFTY 50, BANK NIFTY, and SENSEX.
func (d *DashboardHandler) marketIndices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	credEntry, hasCreds := d.manager.CredentialStore().Get(email)
	if !hasCreds {
		d.writeJSONError(w, http.StatusUnauthorized, "no_credentials",
			"Kite credentials not found. Please register your API credentials via your MCP client.")
		return
	}
	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	if !hasToken {
		d.writeJSONError(w, http.StatusUnauthorized, "no_session",
			"Kite token expired or not found. Please re-authenticate via your MCP client.")
		return
	}

	client := d.manager.KiteClientFactory().NewClientWithToken(credEntry.APIKey, tokenEntry.AccessToken)

	ohlcData, err := client.GetOHLC("NSE:NIFTY 50", "NSE:NIFTY BANK", "BSE:SENSEX")
	if err != nil {
		d.writeJSONError(w, http.StatusBadGateway, "kite_error",
			"Failed to fetch market indices from Kite: "+err.Error())
		return
	}

	result := make(map[string]any, len(ohlcData))
	for k, v := range ohlcData {
		change := v.LastPrice - v.OHLC.Close
		changePct := 0.0
		if v.OHLC.Close > 0 {
			changePct = (change / v.OHLC.Close) * 100
		}
		result[k] = map[string]any{
			"last_price": v.LastPrice,
			"close":      v.OHLC.Close,
			"open":       v.OHLC.Open,
			"high":       v.OHLC.High,
			"low":        v.OHLC.Low,
			"change":     math.Round(change*100) / 100,
			"change_pct": math.Round(changePct*100) / 100,
		}
	}
	d.writeJSON(w, result)
}

// portfolio fetches holdings and positions from the Kite API for the authenticated user.
func (d *DashboardHandler) portfolio(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	// Get credentials
	credEntry, hasCreds := d.manager.CredentialStore().Get(email)
	if !hasCreds {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated",
			"Kite credentials not found. Please register your API credentials via your MCP client.")
		return
	}

	// Get token
	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	if !hasToken {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated",
			"Kite token expired or not found. Please re-authenticate via your MCP client.")
		return
	}

	// Create kiteconnect client
	client := d.manager.KiteClientFactory().NewClientWithToken(credEntry.APIKey, tokenEntry.AccessToken)

	// Fetch holdings
	holdings, holdingsErr := client.GetHoldings()
	if holdingsErr != nil {
		d.logger.Error("Failed to fetch holdings", "email", email, "error", holdingsErr)
		d.writeJSONError(w, http.StatusBadGateway, "kite_error",
			"Failed to fetch holdings from Kite: "+holdingsErr.Error())
		return
	}

	// Fetch positions
	positions, positionsErr := client.GetPositions()
	if positionsErr != nil {
		d.logger.Error("Failed to fetch positions", "email", email, "error", positionsErr)
		d.writeJSONError(w, http.StatusBadGateway, "kite_error",
			"Failed to fetch positions from Kite: "+positionsErr.Error())
		return
	}

	// Build response
	resp := d.buildPortfolioResponse(holdings, positions)
	d.writeJSON(w, resp)
}

// buildPortfolioResponse maps gokiteconnect holdings/positions to the dashboard response format.
func (d *DashboardHandler) buildPortfolioResponse(holdings kiteconnect.Holdings, positions kiteconnect.Positions) portfolioResponse {
	// Map holdings
	holdingItems := make([]holdingItem, 0, len(holdings))
	var totalInvested, totalCurrent, totalPnL float64
	for _, h := range holdings {
		holdingItems = append(holdingItems, holdingItem{
			Tradingsymbol:    h.Tradingsymbol,
			Exchange:         h.Exchange,
			Quantity:         h.Quantity,
			AveragePrice:     h.AveragePrice,
			LastPrice:        h.LastPrice,
			PnL:              h.PnL,
			DayChangePercent: h.DayChangePercentage,
			Product:          h.Product,
		})
		totalInvested += h.AveragePrice * float64(h.Quantity)
		totalCurrent += h.LastPrice * float64(h.Quantity)
		totalPnL += h.PnL
	}

	// Map positions (use Net positions for the dashboard view)
	positionItems := make([]positionItem, 0, len(positions.Net))
	var positionsPnL float64
	for _, p := range positions.Net {
		positionItems = append(positionItems, positionItem{
			Tradingsymbol: p.Tradingsymbol,
			Exchange:      p.Exchange,
			Quantity:      p.Quantity,
			AveragePrice:  p.AveragePrice,
			LastPrice:     p.LastPrice,
			PnL:           p.PnL,
			Product:       p.Product,
		})
		positionsPnL += p.PnL
	}

	return portfolioResponse{
		Holdings:  holdingItems,
		Positions: positionItems,
		Summary: portfolioSummary{
			HoldingsCount:  len(holdings),
			TotalInvested:  totalInvested,
			TotalCurrent:   totalCurrent,
			TotalPnL:       totalPnL,
			PositionsCount: len(positions.Net),
			PositionsPnL:   positionsPnL,
		},
	}
}

// alerts returns the authenticated user's price alerts, separated into active and triggered.
func (d *DashboardHandler) alerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	allAlerts := d.manager.AlertStore().List(email)

	activeAlerts := make([]interface{}, 0)
	triggeredAlerts := make([]interface{}, 0)
	for _, a := range allAlerts {
		if a.Triggered {
			triggeredAlerts = append(triggeredAlerts, a)
		} else {
			activeAlerts = append(activeAlerts, a)
		}
	}

	d.writeJSON(w, alertsResponse{
		Active:         activeAlerts,
		Triggered:      triggeredAlerts,
		ActiveCount:    len(activeAlerts),
		TriggeredCount: len(triggeredAlerts),
	})
}

// status returns the connection and auth health check for the authenticated user.
func (d *DashboardHandler) status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	resp := statusResponse{
		Email:   email,
		DevMode: d.manager.DevMode(),
	}

	// Determine role and admin status
	if d.adminCheck != nil && d.adminCheck(email) {
		resp.Role = "admin"
		resp.IsAdmin = true
	} else {
		resp.Role = "trader"
	}

	// Check token
	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	if hasToken {
		expired := kc.IsKiteTokenExpired(tokenEntry.StoredAt)
		resp.KiteToken = tokenStatus{
			Valid:    !expired,
			StoredAt: tokenEntry.StoredAt.Format("2006-01-02T15:04:05Z07:00"),
		}
	} else {
		resp.KiteToken = tokenStatus{Valid: false}
	}

	// Check credentials
	credEntry, hasCreds := d.manager.CredentialStore().Get(email)
	if hasCreds {
		resp.Credentials = credentialStatus{
			Stored: true,
			APIKey: credEntry.APIKey,
		}
	} else {
		resp.Credentials = credentialStatus{Stored: false}
	}

	// Check ticker
	tickerSt, err := d.manager.TickerService().GetStatus(email)
	if err != nil {
		d.logger.Error("Failed to get ticker status", "email", email, "error", err)
		resp.Ticker = tickerStatus{Running: false, Subscriptions: 0}
	} else {
		resp.Ticker = tickerStatus{
			Running:       tickerSt.Running,
			Subscriptions: len(tickerSt.Subscriptions),
		}
	}

	d.writeJSON(w, resp)
}

// --- Orders P&L types ---

type orderLifecycleStep struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	Message   string `json:"message,omitempty"`
}

type orderEntry struct {
	OrderID      string                `json:"order_id"`
	Symbol       string                `json:"symbol"`
	Exchange     string                `json:"exchange"`
	Side         string                `json:"side"`
	Quantity     float64               `json:"quantity"`
	OrderType    string                `json:"order_type"`
	PlacedAt     string                `json:"placed_at"`
	Status       string                `json:"status"`
	FillPrice    *float64              `json:"fill_price"`
	CurrentPrice *float64              `json:"current_price"`
	PnL          *float64              `json:"pnl"`
	PnLPct       *float64              `json:"pnl_pct"`
	Error        string                `json:"error,omitempty"`
	Lifecycle    []orderLifecycleStep  `json:"lifecycle,omitempty"`
}

type ordersSummary struct {
	TotalOrders   int      `json:"total_orders"`
	Completed     int      `json:"completed"`
	TotalPnL      *float64 `json:"total_pnl"`
	WinningTrades int      `json:"winning_trades"`
	LosingTrades  int      `json:"losing_trades"`
}

type ordersResponse struct {
	Orders  []orderEntry  `json:"orders"`
	Summary ordersSummary `json:"summary"`
}

// NOTE: serveOrdersPage has been replaced by serveOrdersPageSSR in dashboard_templates.go.

// ordersAPI returns order entries with P&L enrichment from the Kite API.
func (d *DashboardHandler) ordersAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}
	if d.auditStore == nil {
		d.writeJSONError(w, http.StatusServiceUnavailable, "not_available", "Audit trail not enabled")
		return
	}

	// Parse since param (default: 7 days ago)
	since := time.Now().AddDate(0, 0, -7)
	if s := r.URL.Query().Get("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			since = t
		}
	}

	toolCalls, err := d.auditStore.ListOrders(email, since)
	if err != nil {
		d.logger.Error("Failed to list orders", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Build base order entries from audit trail
	entries := make([]orderEntry, 0, len(toolCalls))
	for _, tc := range toolCalls {
		oe := orderEntry{
			OrderID:  tc.OrderID,
			PlacedAt: tc.StartedAt.Format(time.RFC3339),
		}

		// Parse symbol/exchange/side/order_type from input_params JSON
		if tc.InputParams != "" {
			var params map[string]interface{}
			if jsonErr := json.Unmarshal([]byte(tc.InputParams), &params); jsonErr == nil {
				if v, ok := params["tradingsymbol"].(string); ok {
					oe.Symbol = v
				}
				if v, ok := params["exchange"].(string); ok {
					oe.Exchange = v
				}
				if v, ok := params["transaction_type"].(string); ok {
					oe.Side = v
				}
				if v, ok := params["order_type"].(string); ok {
					oe.OrderType = v
				}
				if v, ok := params["quantity"].(float64); ok {
					oe.Quantity = v
				}
			}
		}

		entries = append(entries, oe)
	}

	// Try to enrich with Kite API data
	var client *kiteconnect.Client
	credEntry, hasCreds := d.manager.CredentialStore().Get(email)
	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	if hasCreds && hasToken {
		client = d.manager.KiteClientFactory().NewClientWithToken(credEntry.APIKey, tokenEntry.AccessToken)
	}

	if client != nil {
		// Enrich each order with fill details from order history
		// Collect symbols for batched LTP lookup
		type ltpKey struct {
			exchange string
			symbol   string
		}
		ltpKeys := make(map[string]ltpKey) // "exchange:symbol" -> ltpKey
		for i := range entries {
			oe := &entries[i]
			history, histErr := client.GetOrderHistory(oe.OrderID)
			if histErr != nil {
				oe.Error = "order history: " + histErr.Error()
				continue
			}

			// Capture all lifecycle steps and find the latest status
			if len(history) > 0 {
				latest := history[len(history)-1]
				oe.Status = latest.Status

				// Build lifecycle array from all status transitions
				lifecycle := make([]orderLifecycleStep, 0, len(history))
				for _, h := range history {
					step := orderLifecycleStep{
						Status:    h.Status,
						Timestamp: h.OrderTimestamp.Time.Format(time.RFC3339),
						Message:   h.StatusMessage,
					}
					lifecycle = append(lifecycle, step)
				}
				oe.Lifecycle = lifecycle

				// Use symbol/exchange from order history if not set from params
				if oe.Symbol == "" {
					oe.Symbol = latest.TradingSymbol
				}
				if oe.Exchange == "" {
					oe.Exchange = latest.Exchange
				}
				if oe.Side == "" {
					oe.Side = latest.TransactionType
				}
				if oe.OrderType == "" {
					oe.OrderType = latest.OrderType
				}
				if oe.Quantity == 0 {
					oe.Quantity = latest.Quantity
				}

				// Only set fill price for completed orders
				if latest.Status == "COMPLETE" && latest.AveragePrice > 0 {
					fp := latest.AveragePrice
					oe.FillPrice = &fp
					if latest.FilledQuantity > 0 {
						oe.Quantity = latest.FilledQuantity
					}

					// Queue for LTP lookup
					if oe.Exchange != "" && oe.Symbol != "" {
						key := oe.Exchange + ":" + oe.Symbol
						ltpKeys[key] = ltpKey{exchange: oe.Exchange, symbol: oe.Symbol}
					}
				}
			}
		}

		// Batch LTP lookup for all completed orders
		if len(ltpKeys) > 0 {
			instruments := make([]string, 0, len(ltpKeys))
			for k := range ltpKeys {
				instruments = append(instruments, k)
			}
			ltpMap, ltpErr := client.GetLTP(instruments...)
			if ltpErr != nil {
				d.logger.Error("Failed to get LTP for orders", "email", email, "error", ltpErr)
			} else {
				// Apply current prices and compute P&L
				for i := range entries {
					oe := &entries[i]
					if oe.FillPrice == nil || oe.Exchange == "" || oe.Symbol == "" {
						continue
					}
					key := oe.Exchange + ":" + oe.Symbol
					if quote, ok := ltpMap[key]; ok && quote.LastPrice > 0 {
						cp := quote.LastPrice
						oe.CurrentPrice = &cp

						// Direction: BUY = +1, SELL = -1
						dir := 1.0
						if oe.Side == "SELL" {
							dir = -1.0
						}
						pnl := (cp - *oe.FillPrice) * oe.Quantity * dir
						pnl = math.Round(pnl*100) / 100
						oe.PnL = &pnl

						if *oe.FillPrice > 0 {
							pnlPct := ((cp - *oe.FillPrice) / *oe.FillPrice) * 100 * dir
							pnlPct = math.Round(pnlPct*100) / 100
							oe.PnLPct = &pnlPct
						}
					}
				}
			}
		}
	}

	// Compute summary
	summary := ordersSummary{TotalOrders: len(entries)}
	var totalPnL float64
	hasPnL := false
	for _, oe := range entries {
		if oe.Status == "COMPLETE" {
			summary.Completed++
		}
		if oe.PnL != nil {
			hasPnL = true
			totalPnL += *oe.PnL
			if *oe.PnL > 0 {
				summary.WinningTrades++
			} else if *oe.PnL < 0 {
				summary.LosingTrades++
			}
		}
	}
	if hasPnL {
		rounded := math.Round(totalPnL*100) / 100
		summary.TotalPnL = &rounded
	}

	d.writeJSON(w, ordersResponse{
		Orders:  entries,
		Summary: summary,
	})
}

// --- Alerts enriched types ---

type enrichedActiveAlert struct {
	ID              string  `json:"id"`
	Tradingsymbol   string  `json:"tradingsymbol"`
	Exchange        string  `json:"exchange"`
	Direction       string  `json:"direction"`
	TargetPrice     float64 `json:"target_price"`
	ReferencePrice  float64 `json:"reference_price,omitempty"`
	CurrentPrice    float64  `json:"current_price,omitempty"`
	DistancePct     *float64 `json:"distance_pct,omitempty"`
	CreatedAt       string  `json:"created_at"`
}

type enrichedTriggeredAlert struct {
	ID                string  `json:"id"`
	Tradingsymbol     string  `json:"tradingsymbol"`
	Exchange          string  `json:"exchange"`
	Direction         string  `json:"direction"`
	TargetPrice       float64 `json:"target_price"`
	ReferencePrice    float64 `json:"reference_price,omitempty"`
	TriggeredPrice    float64 `json:"triggered_price,omitempty"`
	TriggerDeltaPct   float64 `json:"trigger_delta_pct,omitempty"`
	CreatedAt         string  `json:"created_at"`
	TriggeredAt       string  `json:"triggered_at,omitempty"`
	TimeToTrigger     string  `json:"time_to_trigger,omitempty"`
	NotificationSentAt string `json:"notification_sent_at,omitempty"`
	NotificationDelay string  `json:"notification_delay,omitempty"`
}

type alertsSummary struct {
	ActiveCount      int    `json:"active_count"`
	TriggeredCount   int    `json:"triggered_count"`
	AvgTimeToTrigger string `json:"avg_time_to_trigger"`
}

type enrichedAlertsResponse struct {
	Active    []enrichedActiveAlert    `json:"active"`
	Triggered []enrichedTriggeredAlert `json:"triggered"`
	Summary   alertsSummary            `json:"summary"`
}

// formatDuration formats a time.Duration into a human-readable string like "5d 1h 32m".
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm", minutes)
	}
	secs := int(d.Seconds())
	if secs > 0 {
		return fmt.Sprintf("%ds", secs)
	}
	return "0s"
}

// NOTE: serveAlertsPage has been replaced by serveAlertsPageSSR in dashboard_templates.go.

// alertsEnrichedAPI returns enriched alert data with lifecycle metrics and current prices.
// It also supports DELETE method to remove an active alert by ID.
func (d *DashboardHandler) alertsEnrichedAPI(w http.ResponseWriter, r *http.Request) {
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	if r.Method == http.MethodDelete {
		alertID := r.URL.Query().Get("alert_id")
		if alertID == "" {
			http.Error(w, "alert_id required", http.StatusBadRequest)
			return
		}
		if err := d.manager.AlertStore().Delete(email, alertID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		d.writeJSON(w, map[string]string{"status": "ok"})
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	allAlerts := d.manager.AlertStore().List(email)

	// Separate active and triggered
	var activeAlerts, triggeredAlerts []*alertCopy
	for _, a := range allAlerts {
		ac := &alertCopy{
			ID:                 a.ID,
			Tradingsymbol:      a.Tradingsymbol,
			Exchange:           a.Exchange,
			Direction:          string(a.Direction),
			TargetPrice:        a.TargetPrice,
			ReferencePrice:     a.ReferencePrice,
			Triggered:          a.Triggered,
			CreatedAt:          a.CreatedAt,
			TriggeredAt:        a.TriggeredAt,
			TriggeredPrice:     a.TriggeredPrice,
			NotificationSentAt: a.NotificationSentAt,
		}
		if a.Triggered {
			triggeredAlerts = append(triggeredAlerts, ac)
		} else {
			activeAlerts = append(activeAlerts, ac)
		}
	}

	// Try to get a Kite client for LTP enrichment
	var client *kiteconnect.Client
	credEntry, hasCreds := d.manager.CredentialStore().Get(email)
	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	if hasCreds && hasToken && !kc.IsKiteTokenExpired(tokenEntry.StoredAt) {
		client = d.manager.KiteClientFactory().NewClientWithToken(credEntry.APIKey, tokenEntry.AccessToken)
	}

	// Batch LTP lookup for active alerts
	ltpMap := make(map[string]float64) // "exchange:symbol" -> last price
	if client != nil && len(activeAlerts) > 0 {
		instruments := make(map[string]bool)
		for _, a := range activeAlerts {
			key := a.Exchange + ":" + a.Tradingsymbol
			instruments[key] = true
		}
		instList := make([]string, 0, len(instruments))
		for k := range instruments {
			instList = append(instList, k)
		}
		ltpData, err := client.GetLTP(instList...)
		if err != nil {
			d.logger.Error("Failed to get LTP for alerts", "email", email, "error", err)
		} else {
			for k, v := range ltpData {
				if v.LastPrice > 0 {
					ltpMap[k] = v.LastPrice
				}
			}
		}
	}

	// Build enriched active alerts
	enrichedActive := make([]enrichedActiveAlert, 0, len(activeAlerts))
	for _, a := range activeAlerts {
		ea := enrichedActiveAlert{
			ID:             a.ID,
			Tradingsymbol:  a.Tradingsymbol,
			Exchange:       a.Exchange,
			Direction:      a.Direction,
			TargetPrice:    a.TargetPrice,
			ReferencePrice: a.ReferencePrice,
			CreatedAt:      a.CreatedAt.Format(time.RFC3339),
		}
		key := a.Exchange + ":" + a.Tradingsymbol
		if cp, ok := ltpMap[key]; ok {
			ea.CurrentPrice = cp
			if cp > 0 {
				d := math.Round(math.Abs(cp-a.TargetPrice)/cp*10000) / 100
				ea.DistancePct = &d
			}
		}
		enrichedActive = append(enrichedActive, ea)
	}

	// Build enriched triggered alerts
	enrichedTriggered := make([]enrichedTriggeredAlert, 0, len(triggeredAlerts))
	var totalTriggerDuration time.Duration
	triggerDurationCount := 0
	for _, a := range triggeredAlerts {
		et := enrichedTriggeredAlert{
			ID:             a.ID,
			Tradingsymbol:  a.Tradingsymbol,
			Exchange:       a.Exchange,
			Direction:      a.Direction,
			TargetPrice:    a.TargetPrice,
			ReferencePrice: a.ReferencePrice,
			TriggeredPrice: a.TriggeredPrice,
			CreatedAt:      a.CreatedAt.Format(time.RFC3339),
		}
		// Trigger delta percentage
		if a.TriggeredPrice > 0 && a.TargetPrice > 0 {
			et.TriggerDeltaPct = math.Round(math.Abs(a.TriggeredPrice-a.TargetPrice)/a.TargetPrice*10000) / 100
		}
		// Time to trigger
		if !a.TriggeredAt.IsZero() {
			et.TriggeredAt = a.TriggeredAt.Format(time.RFC3339)
			ttd := a.TriggeredAt.Sub(a.CreatedAt)
			et.TimeToTrigger = formatDuration(ttd)
			totalTriggerDuration += ttd
			triggerDurationCount++
		}
		// Notification delay
		if !a.NotificationSentAt.IsZero() {
			et.NotificationSentAt = a.NotificationSentAt.Format(time.RFC3339)
			if !a.TriggeredAt.IsZero() {
				nd := a.NotificationSentAt.Sub(a.TriggeredAt)
				et.NotificationDelay = formatDuration(nd)
			}
		}
		enrichedTriggered = append(enrichedTriggered, et)
	}

	// Compute summary
	summary := alertsSummary{
		ActiveCount:    len(enrichedActive),
		TriggeredCount: len(enrichedTriggered),
	}
	if triggerDurationCount > 0 {
		avg := totalTriggerDuration / time.Duration(triggerDurationCount)
		summary.AvgTimeToTrigger = formatDuration(avg)
	}

	d.writeJSON(w, enrichedAlertsResponse{
		Active:    enrichedActive,
		Triggered: enrichedTriggered,
		Summary:   summary,
	})
}

// --- P&L Chart API ---

type pnlChartPoint struct {
	Date       string  `json:"date"`
	NetPnL     float64 `json:"net_pnl"`
	Cumulative float64 `json:"cumulative"`
}

type pnlChartResponse struct {
	Points []pnlChartPoint `json:"points"`
	Period int             `json:"period"`
}

// pnlChartAPI returns daily P&L data for charting on the portfolio page.
// Query params: period (days, default 30)
func (d *DashboardHandler) pnlChartAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	alertDB := d.manager.AlertDB()
	if alertDB == nil {
		d.writeJSON(w, pnlChartResponse{Points: []pnlChartPoint{}, Period: 0})
		return
	}

	period := intParam(r, "period", 90)
	if period < 1 {
		period = 90
	}
	if period > 365 {
		period = 365
	}

	toDate := time.Now().Format("2006-01-02")
	fromDate := time.Now().AddDate(0, 0, -period).Format("2006-01-02")

	entries, err := alertDB.LoadDailyPnL(email, fromDate, toDate)
	if err != nil {
		d.logger.Error("Failed to load daily P&L for chart", "email", email, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	points := make([]pnlChartPoint, 0, len(entries))
	var cumulative float64
	for _, e := range entries {
		cumulative += e.NetPnL
		points = append(points, pnlChartPoint{
			Date:       e.Date,
			NetPnL:     math.Round(e.NetPnL*100) / 100,
			Cumulative: math.Round(cumulative*100) / 100,
		})
	}

	d.writeJSON(w, pnlChartResponse{
		Points: points,
		Period: period,
	})
}

// --- Order Attribution API ---

type attributionStep struct {
	Time         string `json:"time"`
	ToolName     string `json:"tool_name"`
	ToolCategory string `json:"tool_category"`
	InputSummary string `json:"input_summary"`
	OutputSummary string `json:"output_summary"`
	DurationMs   int64  `json:"duration_ms"`
	IsError      bool   `json:"is_error"`
	IsOrder      bool   `json:"is_order"`
}

type attributionResponse struct {
	OrderID string            `json:"order_id"`
	Steps   []attributionStep `json:"steps"`
}

// orderAttributionAPI returns the tool call sequence that led to a specific order.
// Query params: order_id (required)
func (d *DashboardHandler) orderAttributionAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	orderID := r.URL.Query().Get("order_id")
	if orderID == "" {
		d.writeJSONError(w, http.StatusBadRequest, "bad_request", "order_id parameter is required.")
		return
	}

	if d.auditStore == nil {
		d.writeJSON(w, attributionResponse{OrderID: orderID, Steps: []attributionStep{}})
		return
	}

	toolCalls, err := d.auditStore.GetOrderAttribution(email, orderID)
	if err != nil {
		d.logger.Error("Failed to get order attribution", "email", email, "order_id", orderID, "error", err)
		d.writeJSON(w, attributionResponse{OrderID: orderID, Steps: []attributionStep{}})
		return
	}

	steps := make([]attributionStep, 0, len(toolCalls))
	for _, tc := range toolCalls {
		steps = append(steps, attributionStep{
			Time:          tc.StartedAt.Format("15:04:05"),
			ToolName:      tc.ToolName,
			ToolCategory:  tc.ToolCategory,
			InputSummary:  tc.InputSummary,
			OutputSummary: tc.OutputSummary,
			DurationMs:    tc.DurationMs,
			IsError:       tc.IsError,
			IsOrder:       tc.OrderID != "",
		})
	}

	d.writeJSON(w, attributionResponse{
		OrderID: orderID,
		Steps:   steps,
	})
}

// alertCopy is an internal struct for processing alerts without importing the alerts package directly.
type alertCopy struct {
	ID                 string
	Tradingsymbol      string
	Exchange           string
	Direction          string
	TargetPrice        float64
	ReferencePrice     float64
	Triggered          bool
	CreatedAt          time.Time
	TriggeredAt        time.Time
	TriggeredPrice     float64
	NotificationSentAt time.Time
}

// --- Paper Trading Dashboard Handlers ---

// NOTE: servePaperPage has been replaced by servePaperPageSSR in dashboard_templates.go.

// paperStatus returns the paper trading account status for the authenticated user.
func (d *DashboardHandler) paperStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}
	engine := d.manager.PaperEngine()
	if engine == nil {
		d.writeJSONError(w, http.StatusNotFound, "not_configured", "Paper trading engine is not configured.")
		return
	}
	status, err := engine.Status(email)
	if err != nil {
		d.logger.Error("Failed to get paper status", "email", email, "error", err)
		d.writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to get paper trading status.")
		return
	}
	d.writeJSON(w, status)
}

// paperHoldings returns paper trading holdings for the authenticated user.
func (d *DashboardHandler) paperHoldings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}
	engine := d.manager.PaperEngine()
	if engine == nil {
		d.writeJSONError(w, http.StatusNotFound, "not_configured", "Paper trading engine is not configured.")
		return
	}
	holdings, err := engine.GetHoldings(email)
	if err != nil {
		d.logger.Error("Failed to get paper holdings", "email", email, "error", err)
		d.writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to get paper holdings.")
		return
	}
	d.writeJSON(w, holdings)
}

// paperPositions returns paper trading positions for the authenticated user.
func (d *DashboardHandler) paperPositions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}
	engine := d.manager.PaperEngine()
	if engine == nil {
		d.writeJSONError(w, http.StatusNotFound, "not_configured", "Paper trading engine is not configured.")
		return
	}
	positions, err := engine.GetPositions(email)
	if err != nil {
		d.logger.Error("Failed to get paper positions", "email", email, "error", err)
		d.writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to get paper positions.")
		return
	}
	d.writeJSON(w, positions)
}

// paperOrders returns paper trading orders for the authenticated user.
func (d *DashboardHandler) paperOrders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}
	engine := d.manager.PaperEngine()
	if engine == nil {
		d.writeJSONError(w, http.StatusNotFound, "not_configured", "Paper trading engine is not configured.")
		return
	}
	orders, err := engine.GetOrders(email)
	if err != nil {
		d.logger.Error("Failed to get paper orders", "email", email, "error", err)
		d.writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to get paper orders.")
		return
	}
	d.writeJSON(w, orders)
}

// paperReset resets the paper trading account for the authenticated user.
func (d *DashboardHandler) paperReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}
	engine := d.manager.PaperEngine()
	if engine == nil {
		d.writeJSONError(w, http.StatusNotFound, "not_configured", "Paper trading engine is not configured.")
		return
	}
	if err := engine.Reset(email); err != nil {
		d.logger.Error("Failed to reset paper account", "email", email, "error", err)
		d.writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to reset paper trading account.")
		return
	}
	d.writeJSON(w, map[string]string{"status": "ok", "message": "Paper trading account reset successfully."})
}

// NOTE: serveSafetyPage has been replaced by serveSafetyPageSSR in dashboard_templates.go.

// safetyStatus returns riskguard status and effective limits for the authenticated user.
func (d *DashboardHandler) safetyStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	guard := d.manager.RiskGuard()
	if guard == nil {
		d.writeJSON(w, map[string]any{
			"enabled": false,
			"message": "RiskGuard is not enabled on this server.",
		})
		return
	}

	status := guard.GetUserStatus(email)
	limits := guard.GetEffectiveLimits(email)

	// Check session and credential status for SEBI compliance summary
	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	sessionActive := hasToken && !kc.IsKiteTokenExpired(tokenEntry.StoredAt)
	_, hasCreds := d.manager.CredentialStore().Get(email)

	d.writeJSON(w, map[string]any{
		"enabled": true,
		"status":  status,
		"limits": map[string]any{
			"max_single_order_inr":   limits.MaxSingleOrderINR,
			"max_orders_per_day":     limits.MaxOrdersPerDay,
			"max_orders_per_minute":  limits.MaxOrdersPerMinute,
			"duplicate_window_secs":  limits.DuplicateWindowSecs,
			"max_daily_value_inr":    limits.MaxDailyValueINR,
			"auto_freeze_on_limit":   limits.AutoFreezeOnLimitHit,
		},
		"sebi": map[string]any{
			"static_egress_ip":  true,
			"session_active":    sessionActive,
			"credentials_set":   hasCreds,
			"order_tagging":     true,
			"audit_trail":       d.auditStore != nil,
		},
	})
}

// --- Sector Exposure API ---

type dashboardSectorAllocation struct {
	Sector      string  `json:"sector"`
	Value       float64 `json:"value"`
	Pct         float64 `json:"pct"`
	Holdings    int     `json:"holdings"`
	OverExposed bool    `json:"over_exposed,omitempty"`
}

type sectorExposureAPIResponse struct {
	TotalValue    float64                     `json:"total_value"`
	HoldingsCount int                         `json:"holdings_count"`
	MappedCount   int                         `json:"mapped_count"`
	UnmappedCount int                         `json:"unmapped_count"`
	Sectors       []dashboardSectorAllocation `json:"sectors"`
	Warnings      []string                    `json:"warnings,omitempty"`
}

// sectorExposureAPI returns sector allocation data for the authenticated user's holdings.
func (d *DashboardHandler) sectorExposureAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	credEntry, hasCreds := d.manager.CredentialStore().Get(email)
	if !hasCreds {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated",
			"Kite credentials not found.")
		return
	}
	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	if !hasToken {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated",
			"Kite token expired or not found.")
		return
	}

	client := d.manager.KiteClientFactory().NewClientWithToken(credEntry.APIKey, tokenEntry.AccessToken)

	holdings, err := client.GetHoldings()
	if err != nil {
		d.logger.Error("Failed to fetch holdings for sector exposure", "email", email, "error", err)
		d.writeJSONError(w, http.StatusBadGateway, "kite_error",
			"Failed to fetch holdings: "+err.Error())
		return
	}

	if len(holdings) == 0 {
		d.writeJSON(w, sectorExposureAPIResponse{
			Sectors: []dashboardSectorAllocation{},
		})
		return
	}

	resp := d.computeDashboardSectorExposure(holdings)
	d.writeJSON(w, resp)
}

// computeDashboardSectorExposure maps holdings to sectors and computes allocation percentages.
func (d *DashboardHandler) computeDashboardSectorExposure(holdings kiteconnect.Holdings) sectorExposureAPIResponse {
	const overExposureThresh = 30.0

	var totalValue float64
	for _, h := range holdings {
		totalValue += h.LastPrice * float64(h.Quantity)
	}

	if totalValue == 0 {
		return sectorExposureAPIResponse{
			HoldingsCount: len(holdings),
			Sectors:       []dashboardSectorAllocation{},
		}
	}

	type sectorAccum struct {
		value    float64
		holdings int
	}
	sectorMap := make(map[string]*sectorAccum)
	mappedCount := 0
	unmappedCount := 0

	for _, h := range holdings {
		val := h.LastPrice * float64(h.Quantity)
		symbol := dashboardNormalizeSymbol(h.Tradingsymbol)
		sector, ok := dashboardStockSectors[symbol]
		if !ok {
			unmappedCount++
			sector = "Other"
		} else {
			mappedCount++
		}

		acc, exists := sectorMap[sector]
		if !exists {
			acc = &sectorAccum{}
			sectorMap[sector] = acc
		}
		acc.value += val
		acc.holdings++
	}

	sectors := make([]dashboardSectorAllocation, 0, len(sectorMap))
	var warnings []string
	for name, acc := range sectorMap {
		pct := math.Round(acc.value/totalValue*10000) / 100
		overExposed := pct > overExposureThresh
		sectors = append(sectors, dashboardSectorAllocation{
			Sector:      name,
			Value:       math.Round(acc.value*100) / 100,
			Pct:         pct,
			Holdings:    acc.holdings,
			OverExposed: overExposed,
		})
		if overExposed {
			warnings = append(warnings, fmt.Sprintf("%s is over-exposed at %.1f%% of portfolio (threshold: 30%%)", name, pct))
		}
	}

	// Sort by allocation descending.
	sort.Slice(sectors, func(i, j int) bool {
		return sectors[i].Pct > sectors[j].Pct
	})

	return sectorExposureAPIResponse{
		TotalValue:    math.Round(totalValue*100) / 100,
		HoldingsCount: len(holdings),
		MappedCount:   mappedCount,
		UnmappedCount: unmappedCount,
		Sectors:       sectors,
		Warnings:      warnings,
	}
}

// dashboardNormalizeSymbol strips common suffixes for sector lookup.
func dashboardNormalizeSymbol(ts string) string {
	s := strings.ToUpper(strings.TrimSpace(ts))
	for _, suffix := range []string{"-BE", "-EQ", "-BZ", "-BL"} {
		s = strings.TrimSuffix(s, suffix)
	}
	return s
}

// --- Tax Analysis API ---

type taxHoldingEntry struct {
	Symbol         string  `json:"symbol"`
	Exchange       string  `json:"exchange"`
	Quantity       int     `json:"quantity"`
	AveragePrice   float64 `json:"average_price"`
	LastPrice      float64 `json:"last_price"`
	InvestedValue  float64 `json:"invested_value"`
	CurrentValue   float64 `json:"current_value"`
	UnrealizedPnL  float64 `json:"unrealized_pnl"`
	Classification string  `json:"classification"` // "LTCG" or "STCG"
	TaxRate        float64 `json:"tax_rate"`        // percentage
	TaxIfSold      float64 `json:"tax_if_sold"`
	Harvestable    bool    `json:"harvestable"`
}

type taxSummary struct {
	TotalLTCGGains     float64 `json:"total_ltcg_gains"`
	TotalSTCGGains     float64 `json:"total_stcg_gains"`
	TotalLTCGLosses    float64 `json:"total_ltcg_losses"`
	TotalSTCGLosses    float64 `json:"total_stcg_losses"`
	HarvestableLoss    float64 `json:"harvestable_loss"`
	PotentialTaxSaving float64 `json:"potential_tax_saving"`
	HoldingsAnalyzed   int     `json:"holdings_analyzed"`
}

type taxAnalysisResponse struct {
	Holdings []taxHoldingEntry `json:"holdings"`
	Summary  taxSummary        `json:"summary"`
}

// taxAnalysisAPI returns tax classification and harvesting opportunities for holdings.
func (d *DashboardHandler) taxAnalysisAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	credEntry, hasCreds := d.manager.CredentialStore().Get(email)
	if !hasCreds {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated",
			"Kite credentials not found.")
		return
	}
	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	if !hasToken {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated",
			"Kite token expired or not found.")
		return
	}

	client := d.manager.KiteClientFactory().NewClientWithToken(credEntry.APIKey, tokenEntry.AccessToken)

	holdings, err := client.GetHoldings()
	if err != nil {
		d.logger.Error("Failed to fetch holdings for tax analysis", "email", email, "error", err)
		d.writeJSONError(w, http.StatusBadGateway, "kite_error",
			"Failed to fetch holdings: "+err.Error())
		return
	}

	if len(holdings) == 0 {
		d.writeJSON(w, taxAnalysisResponse{
			Holdings: []taxHoldingEntry{},
		})
		return
	}

	resp := d.computeTaxAnalysis(holdings)
	d.writeJSON(w, resp)
}

// computeTaxAnalysis classifies holdings and computes tax harvesting opportunities.
// Since Kite API does not expose purchase dates, we use a simplified heuristic:
// equity delivery holdings are classified as STCG by default (conservative).
// Indian tax rates (FY 2025-26): STCG on equity = 20%, LTCG on equity = 12.5% (above 1.25L exemption).
func (d *DashboardHandler) computeTaxAnalysis(holdings kiteconnect.Holdings) taxAnalysisResponse {
	const (
		stcgRate = 20.0 // STCG tax rate for equity
		ltcgRate = 12.5 // LTCG tax rate for equity
	)
	// Suppress unused variable warning for ltcgRate — reserved for future LTCG classification.
	_ = ltcgRate

	entries := make([]taxHoldingEntry, 0, len(holdings))
	var summary taxSummary
	summary.HoldingsAnalyzed = len(holdings)

	for _, h := range holdings {
		invested := h.AveragePrice * float64(h.Quantity)
		current := h.LastPrice * float64(h.Quantity)
		unrealizedPnL := current - invested

		// Simplified classification: use STCG by default since Kite doesn't
		// expose purchase dates. Users should verify actual holding period.
		classification := "STCG"
		taxRate := stcgRate

		taxIfSold := 0.0
		if unrealizedPnL > 0 {
			taxIfSold = math.Round(unrealizedPnL*taxRate) / 100
		}

		harvestable := unrealizedPnL < 0

		entry := taxHoldingEntry{
			Symbol:         h.Tradingsymbol,
			Exchange:       h.Exchange,
			Quantity:       h.Quantity,
			AveragePrice:   h.AveragePrice,
			LastPrice:      h.LastPrice,
			InvestedValue:  math.Round(invested*100) / 100,
			CurrentValue:   math.Round(current*100) / 100,
			UnrealizedPnL:  math.Round(unrealizedPnL*100) / 100,
			Classification: classification,
			TaxRate:        taxRate,
			TaxIfSold:      math.Round(taxIfSold*100) / 100,
			Harvestable:    harvestable,
		}
		entries = append(entries, entry)

		// Aggregate summary
		if unrealizedPnL > 0 {
			if classification == "LTCG" {
				summary.TotalLTCGGains += unrealizedPnL
			} else {
				summary.TotalSTCGGains += unrealizedPnL
			}
		} else if unrealizedPnL < 0 {
			if classification == "LTCG" {
				summary.TotalLTCGLosses += unrealizedPnL
			} else {
				summary.TotalSTCGLosses += unrealizedPnL
			}
			summary.HarvestableLoss += unrealizedPnL
		}
	}

	// Round summary values
	summary.TotalLTCGGains = math.Round(summary.TotalLTCGGains*100) / 100
	summary.TotalSTCGGains = math.Round(summary.TotalSTCGGains*100) / 100
	summary.TotalLTCGLosses = math.Round(summary.TotalLTCGLosses*100) / 100
	summary.TotalSTCGLosses = math.Round(summary.TotalSTCGLosses*100) / 100
	summary.HarvestableLoss = math.Round(summary.HarvestableLoss*100) / 100

	// Potential tax saving = harvestable loss * blended rate (use STCG rate as conservative estimate)
	if summary.HarvestableLoss < 0 {
		summary.PotentialTaxSaving = math.Round(math.Abs(summary.HarvestableLoss)*stcgRate) / 100
	}

	// Sort: harvestable (losses) first, then by unrealized P&L ascending
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Harvestable != entries[j].Harvestable {
			return entries[i].Harvestable
		}
		return entries[i].UnrealizedPnL < entries[j].UnrealizedPnL
	})

	return taxAnalysisResponse{
		Holdings: entries,
		Summary:  summary,
	}
}

// dashboardStockSectors maps NSE/BSE trading symbols to their primary sector.
// Duplicated from mcp/sector_tool.go to avoid cross-package import.
var dashboardStockSectors = map[string]string{
	// Banking
	"HDFCBANK": "Banking", "ICICIBANK": "Banking", "SBIN": "Banking",
	"KOTAKBANK": "Banking", "AXISBANK": "Banking", "INDUSINDBK": "Banking",
	"BANKBARODA": "Banking", "PNB": "Banking", "IDFCFIRSTB": "Banking",
	"FEDERALBNK": "Banking", "AUBANK": "Banking", "BANDHANBNK": "Banking",
	"CANBK": "Banking", "UNIONBANK": "Banking", "YESBANK": "Banking",
	// IT
	"TCS": "IT", "INFY": "IT", "HCLTECH": "IT", "WIPRO": "IT",
	"TECHM": "IT", "LTIM": "IT", "MPHASIS": "IT", "COFORGE": "IT",
	"PERSISTENT": "IT", "LTTS": "IT", "TATAELXSI": "IT",
	// FMCG
	"HINDUNILVR": "FMCG", "ITC": "FMCG", "NESTLEIND": "FMCG",
	"BRITANNIA": "FMCG", "DABUR": "FMCG", "TATACONSUM": "FMCG",
	"MARICO": "FMCG", "GODREJCP": "FMCG", "COLPAL": "FMCG",
	// Pharma / Healthcare
	"SUNPHARMA": "Pharma", "DRREDDY": "Pharma", "CIPLA": "Pharma",
	"DIVISLAB": "Pharma", "LUPIN": "Pharma", "AUROPHARMA": "Pharma",
	"BIOCON": "Pharma", "APOLLOHOSP": "Healthcare", "MAXHEALTH": "Healthcare",
	"FORTIS": "Healthcare",
	// Auto
	"MARUTI": "Auto", "TATAMOTORS": "Auto", "M&M": "Auto",
	"HEROMOTOCO": "Auto", "EICHERMOT": "Auto", "BAJAJ-AUTO": "Auto",
	"ASHOKLEY": "Auto", "TVSMOTOR": "Auto", "MOTHERSON": "Auto",
	// Energy
	"RELIANCE": "Energy", "NTPC": "Energy", "POWERGRID": "Energy",
	"ONGC": "Energy", "COALINDIA": "Energy", "BPCL": "Energy",
	"IOC": "Energy", "GAIL": "Energy", "TATAPOWER": "Energy",
	"ADANIGREEN": "Energy", "NHPC": "Energy",
	// Metals
	"TATASTEEL": "Metals", "JSWSTEEL": "Metals", "HINDALCO": "Metals",
	"VEDL": "Metals", "JINDALSTEL": "Metals", "NMDC": "Metals", "SAIL": "Metals",
	// Infra
	"LT": "Infra", "ADANIPORTS": "Infra", "SIEMENS": "Infra",
	"ABB": "Infra", "HAVELLS": "Infra", "POLYCAB": "Infra",
	"BEL": "Infra", "BHEL": "Infra",
	// Cement
	"ULTRACEMCO": "Cement", "GRASIM": "Cement", "SHREECEM": "Cement",
	"AMBUJACEM": "Cement", "ACC": "Cement",
	// NBFC / Insurance
	"BAJFINANCE": "NBFC", "BAJAJFINSV": "NBFC", "SBILIFE": "Insurance",
	"HDFCLIFE": "Insurance", "ICICIGI": "Insurance", "MUTHOOTFIN": "NBFC",
	"SHRIRAMFIN": "NBFC", "CHOLAFIN": "NBFC", "PFC": "NBFC", "RECLTD": "NBFC",
	// Telecom
	"BHARTIARTL": "Telecom", "IDEA": "Telecom",
	// Consumer
	"TITAN": "Consumer", "ASIANPAINT": "Consumer", "PIDILITIND": "Consumer",
	"TRENT": "Consumer", "DMART": "Consumer",
	// Tech / New Economy
	"ZOMATO": "Tech", "PAYTM": "Tech", "NYKAA": "Tech",
	"POLICYBZR": "Tech", "INFOEDGE": "Tech",
	// Defence
	"HAL": "Defence", "BDL": "Defence", "MAZAGON": "Defence",
	// Conglomerate
	"ADANIENT": "Conglomerate",
	// Real Estate
	"DLF": "Real Estate", "GODREJPROP": "Real Estate", "OBEROIRLTY": "Real Estate",
	// Chemicals
	"PIIND": "Chemicals", "SRF": "Chemicals", "DEEPAKNTR": "Chemicals",
	// Services
	"IRCTC": "Services", "INDIGO": "Aviation",
}

// selfDeleteAccount handles POST /dashboard/api/account/delete.
// Permanently deletes all data for the authenticated user.
func (d *DashboardHandler) selfDeleteAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	var body struct {
		Confirm bool `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !body.Confirm {
		d.writeJSONError(w, http.StatusBadRequest, "confirmation_required",
			"This permanently deletes all your data. Send {\"confirm\": true} to proceed.")
		return
	}

	// Delete all user data across stores
	d.manager.CredentialStore().Delete(email)
	d.manager.TokenStore().Delete(email)

	if sm := d.manager.SessionManager(); sm != nil {
		sm.TerminateByEmail(email)
	}

	d.manager.AlertStore().DeleteByEmail(email)

	if ws := d.manager.WatchlistStore(); ws != nil {
		ws.DeleteByEmail(email)
	}

	if tsm := d.manager.TrailingStopManager(); tsm != nil {
		tsm.CancelByEmail(email)
	}

	if pe := d.manager.PaperEngine(); pe != nil {
		if err := pe.Reset(email); err != nil {
			d.logger.Error("Failed to reset paper trading during self-delete", "email", email, "error", err)
		}
		if err := pe.Disable(email); err != nil {
			d.logger.Error("Failed to disable paper trading during self-delete", "email", email, "error", err)
		}
	}

	if us := d.manager.UserStore(); us != nil {
		if err := us.UpdateStatus(email, "offboarded"); err != nil {
			d.logger.Error("Failed to update user status during self-delete", "email", email, "error", err)
		}
	}

	// Clear auth cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "kite_jwt",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	d.logger.Info("User self-deleted account", "email", email)
	d.writeJSON(w, map[string]string{"status": "ok", "message": "Account deleted. All data has been removed."})
}

// maskKey returns a masked version of an API key (first 4 + **** + last 4).
func maskKey(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}

// selfManageCredentials handles GET/PUT/DELETE /dashboard/api/account/credentials.
func (d *DashboardHandler) selfManageCredentials(w http.ResponseWriter, r *http.Request) {
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	switch r.Method {
	case http.MethodGet:
		entry, ok := d.manager.CredentialStore().Get(email)
		if !ok {
			d.writeJSON(w, map[string]interface{}{
				"has_credentials": false,
			})
			return
		}
		d.writeJSON(w, map[string]interface{}{
			"has_credentials": true,
			"api_key":         maskKey(entry.APIKey),
			"has_secret":      entry.APISecret != "",
			"stored_at":       entry.StoredAt,
		})

	case http.MethodPut:
		var body struct {
			APIKey    string `json:"api_key"`
			APISecret string `json:"api_secret"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			d.writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid JSON body.")
			return
		}
		body.APIKey = strings.TrimSpace(body.APIKey)
		body.APISecret = strings.TrimSpace(body.APISecret)
		if body.APIKey == "" || body.APISecret == "" {
			d.writeJSONError(w, http.StatusBadRequest, "missing_fields", "Both api_key and api_secret are required.")
			return
		}

		d.manager.CredentialStore().Set(email, &kc.KiteCredentialEntry{
			APIKey:    body.APIKey,
			APISecret: body.APISecret,
		})
		// Always clear cached token — credentials changed, old token is invalid
		d.manager.TokenStore().Delete(email)
		d.logger.Info("User updated credentials via dashboard", "email", email)
		d.writeJSON(w, map[string]string{
			"status":  "ok",
			"message": "Credentials updated. Your cached Kite token has been cleared; please re-authenticate.",
		})

	case http.MethodDelete:
		d.manager.CredentialStore().Delete(email)
		d.manager.TokenStore().Delete(email)
		d.logger.Info("User deleted credentials via dashboard", "email", email)
		d.writeJSON(w, map[string]string{
			"status":  "ok",
			"message": "Credentials removed. You will need to re-register to use the service.",
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
