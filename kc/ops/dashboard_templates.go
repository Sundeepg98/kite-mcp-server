package ops

import (
	htmltemplate "html/template"
	"net/http"
	"time"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/templates"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// Page data types and shared helpers for the user dashboard SSR pages.
//
// The individual handlers live in sibling files grouped by page:
//   - dashboard_portfolio.go  portfolio page + fragment, buildUserStatus, market bar
//   - dashboard_activity.go   activity timeline page
//   - dashboard_orders.go     orders page, Kite enrichment, summary, param parsing
//   - dashboard_alerts.go     alerts page (active + triggered)
//   - dashboard_paper.go      paper trading page + fragment + conversion helpers
//   - dashboard_safety.go     safety page + fragment + riskguard data builder

// ============================================================================
// Page data types for server-side template rendering
// ============================================================================

// PortfolioPageData is the top-level data for the dashboard (portfolio) page template.
type PortfolioPageData struct {
	Email              string
	Role               string
	TokenValid         bool
	UpdatedAt          string
	Stats              PortfolioStatsData
	Market             MarketBarData
	Holdings           PortfolioHoldingsData
	Positions          PortfolioPositionsData
	AlertCount         int
	Credentials        credentialStatus
	Expired            bool // true when kite token is expired
	HasKiteCredentials bool // true when user has stored Kite API credentials
	DevMode            bool // true when server is running with mock broker
}

// ActivityPageData is the top-level data for the activity page template.
type ActivityPageData struct {
	Email      string
	Role       string
	TokenValid bool
	UpdatedAt  string
	Stats      ActivityStatsData
	Timeline   ActivityTimelineData
}

// OrdersPageData is the top-level data for the orders page template.
type OrdersPageData struct {
	Email      string
	Role       string
	TokenValid bool
	UpdatedAt  string
	Stats      OrdersStatsData
	Orders     OrdersTableData
}

// AlertsPageData is the top-level data for the alerts page template.
type AlertsPageData struct {
	Email      string
	Role       string
	TokenValid bool
	UpdatedAt  string
	Stats      AlertsStatsData
	Active     AlertsActiveData
	Triggered  AlertsTriggeredData
}

// PaperPageData is the top-level data for the paper trading page template.
type PaperPageData struct {
	Email      string
	Role       string
	TokenValid bool
	UpdatedAt  string
	Banner     PaperBannerData
	Stats      PaperStatsData
	Tables     PaperTablesData
	Enabled    bool
}

// SafetyPageData is the top-level data for the safety page template.
type SafetyPageData struct {
	Email      string
	Role       string
	TokenValid bool
	UpdatedAt  string
	Freeze     SafetyFreezeData
	Limits     SafetyLimitsData
	SEBI       SafetySEBIData
}

// ============================================================================
// Template initialization
// ============================================================================

// InitTemplates parses all user dashboard page templates with their partials.
// Call this during DashboardHandler setup.
func (d *DashboardHandler) InitTemplates() {
	partials := []string{
		"user_portfolio_stats.html",
		"user_portfolio_holdings.html",
		"user_portfolio_positions.html",
		"user_market_bar.html",
		"user_activity_stats.html",
		"user_activity_timeline.html",
		"user_orders_stats.html",
		"user_orders_table.html",
		"user_alerts_stats.html",
		"user_alerts_active.html",
		"user_alerts_triggered.html",
		"user_paper_stats.html",
		"user_paper_banner.html",
		"user_paper_tables.html",
		"user_safety_freeze.html",
		"user_safety_limits.html",
		"user_safety_sebi.html",
	}

	parsePage := func(page string) *htmltemplate.Template {
		files := append([]string{page}, partials...)
		tmpl, err := htmltemplate.ParseFS(templates.FS, files...)
		if err != nil {
			d.logger.Error("Failed to parse user dashboard template", "page", page, "error", err)
			return nil
		}
		return tmpl
	}

	d.portfolioTmpl = parsePage("dashboard.html")
	d.activityTmpl = parsePage("activity.html")
	d.ordersTmpl = parsePage("orders.html")
	d.alertsTmpl = parsePage("alerts.html")
	d.paperTmpl = parsePage("paper.html")
	d.safetyTmpl = parsePage("safety.html")

	fragTmpl, err := userDashboardFragmentTemplates()
	if err != nil {
		d.logger.Error("Failed to parse user fragment templates", "error", err)
	} else {
		d.fragmentTmpl = fragTmpl
	}
}

// ============================================================================
// Common helpers for page handlers
// ============================================================================

// userContext extracts email, role, and token validity from the request.
func (d *DashboardHandler) userContext(r *http.Request) (email, role string, tokenValid bool) {
	email = oauth.EmailFromContext(r.Context())
	if email == "" {
		return "", "", false
	}
	role = "trader"
	if d.adminCheck != nil && d.adminCheck(email) {
		role = "admin"
	}
	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	tokenValid = hasToken && !kc.IsKiteTokenExpired(tokenEntry.StoredAt)
	return
}

// nowTimestamp returns the current time formatted for the "Updated" display.
func nowTimestamp() string {
	return time.Now().Format("Updated 15:04:05")
}

// servePageFallback writes a raw template file when the parsed template is missing.
func (d *DashboardHandler) servePageFallback(w http.ResponseWriter, filename string) {
	data, err := templates.FS.ReadFile(filename)
	if err != nil {
		http.Error(w, "failed to load page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}
