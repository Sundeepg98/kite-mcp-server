package ops

import (
	"bytes"
	"fmt"
	"html/template"
	"math"
	"strings"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/templates"
)

// ============================================================================
// Common template helpers
// ============================================================================

// UserStatCard represents a single stat card in any user dashboard page.
type UserStatCard struct {
	Label string
	Value string
	Class string // CSS class: "green", "red", "amber", ""
	Sub   string // optional subtitle text
	Hero  bool   // if true, renders as a wider hero card
	ID    string // optional HTML id for JS updates
}

// fmtINR formats a float64 as Indian Rupee string with grouping (e.g. "₹1,23,456.78").
func fmtINR(v float64) string {
	neg := v < 0
	abs := math.Abs(v)
	parts := strings.SplitN(fmt.Sprintf("%.2f", abs), ".", 2)
	intPart := parts[0]
	decPart := parts[1]

	if len(intPart) > 3 {
		last3 := intPart[len(intPart)-3:]
		rest := intPart[:len(intPart)-3]
		var groups []string
		for len(rest) > 2 {
			groups = append([]string{rest[len(rest)-2:]}, groups...)
			rest = rest[:len(rest)-2]
		}
		if len(rest) > 0 {
			groups = append([]string{rest}, groups...)
		}
		intPart = strings.Join(groups, ",") + "," + last3
	}

	prefix := ""
	if neg {
		prefix = "-"
	}
	return prefix + "\u20B9" + intPart + "." + decPart
}

// fmtINRShort formats large values as short strings (e.g. "₹5.0L", "₹1.2K").
func fmtINRShort(v float64) string {
	abs := math.Abs(v)
	if abs >= 100000 {
		return fmt.Sprintf("\u20B9%.1fL", v/100000)
	}
	if abs >= 1000 {
		return fmt.Sprintf("\u20B9%.1fK", v/1000)
	}
	return fmt.Sprintf("\u20B9%.0f", v)
}

// fmtPrice formats a float64 as a price string with 2 decimals.
func fmtPrice(v float64) string {
	if v == 0 {
		return "--"
	}
	return fmt.Sprintf("%.2f", v)
}

// fmtPct formats a float64 as a percentage string (e.g. "+1.25%").
func fmtPct(v float64) string {
	prefix := ""
	if v > 0 {
		prefix = "+"
	}
	return prefix + fmt.Sprintf("%.2f%%", v)
}

// pnlClass returns CSS class "green", "red", or "" based on P&L value.
func pnlClass(v float64) string {
	if v > 0 {
		return "green"
	}
	if v < 0 {
		return "red"
	}
	return ""
}

// fmtTimeDDMon formats a time.Time as "02 Jan 15:04".
func fmtTimeDDMon(t time.Time) string {
	if t.IsZero() {
		return "--"
	}
	return t.Format("02 Jan 15:04")
}

// fmtTimeHMS formats a time.Time as "15:04:05".
func fmtTimeHMS(t time.Time) string {
	if t.IsZero() {
		return "--:--:--"
	}
	return t.Format("15:04:05")
}

// fmtDurationMs formats milliseconds as a human-readable string.
func fmtDurationMs(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%.1fs", float64(ms)/1000)
}

// ============================================================================
// Template parsing and rendering
// ============================================================================

// userDashboardTemplateFiles lists all user dashboard partial template filenames.
var userDashboardTemplateFiles = []string{
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

// userDashboardFragmentTemplates parses and returns all user dashboard partial templates.
func userDashboardFragmentTemplates() (*template.Template, error) {
	return template.ParseFS(templates.FS, userDashboardTemplateFiles...)
}

// renderUserFragment executes a named user dashboard template into a string.
func renderUserFragment(t *template.Template, name string, data any) (string, error) {
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, name, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
