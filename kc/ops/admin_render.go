package ops

import (
	"fmt"
	"html/template"
	"sort"
	"strconv"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/templates"
	"github.com/zerodha/kite-mcp-server/kc/users"
)

// fmtTimeStr formats a time.Time as "HH:MM:SS DD Mon" matching the JS fmtTime function.
// Returns "--" for zero times.
func fmtTimeStr(t time.Time) string {
	if t.IsZero() {
		return "--"
	}
	return t.Format("15:04:05 02 Jan")
}

// --- Sessions ---

// SessionRow is a template-ready row for the sessions table.
type SessionRow struct {
	IDShort   string
	Email     string
	CreatedAt string
	ExpiresAt string
}

// SessionsTemplateData is passed to the sessions_table template.
type SessionsTemplateData struct {
	Sessions []SessionRow
}

// sessionsToTemplateData converts a slice of SessionInfo into template-ready data.
func sessionsToTemplateData(sessions []SessionInfo) SessionsTemplateData {
	rows := make([]SessionRow, len(sessions))
	for i, s := range sessions {
		idShort := s.ID
		if len(idShort) > 12 {
			idShort = idShort[:12] + "\u2026"
		}
		email := s.Email
		if email == "" {
			email = "\u2014"
		}
		rows[i] = SessionRow{
			IDShort:   idShort,
			Email:     email,
			CreatedAt: fmtTimeStr(s.CreatedAt),
			ExpiresAt: fmtTimeStr(s.ExpiresAt),
		}
	}
	return SessionsTemplateData{Sessions: rows}
}

// --- Tickers ---

// TickerRow is a template-ready row for the tickers table.
type TickerRow struct {
	Email         string
	StatusLabel   string
	StatusClass   string
	StartedAt     string
	Subscriptions string
}

// TickersTemplateData is passed to the tickers_table template.
type TickersTemplateData struct {
	Tickers []TickerRow
}

// tickersToTemplateData converts TickerData into template-ready data.
func tickersToTemplateData(d TickerData) TickersTemplateData {
	rows := make([]TickerRow, len(d.Tickers))
	for i, t := range d.Tickers {
		statusLabel := "disconnected"
		statusClass := "red"
		if t.Connected {
			statusLabel = "connected"
			statusClass = "green"
		}
		rows[i] = TickerRow{
			Email:         t.Email,
			StatusLabel:   statusLabel,
			StatusClass:   statusClass,
			StartedAt:     fmtTimeStr(t.StartedAt),
			Subscriptions: strconv.Itoa(t.Subscriptions),
		}
	}
	return TickersTemplateData{Tickers: rows}
}

// --- Alerts ---

// AlertRow is a template-ready row for the alerts table.
type AlertRow struct {
	ID          string
	Email       string
	Symbol      string
	TargetPrice string
	Direction   string
	StatusLabel string
	StatusClass string
	CreatedAt   string
}

// TelegramMapping is a template-ready row for the telegram mappings table.
type TelegramMapping struct {
	Email  string
	ChatID string
}

// AlertsTemplateData is passed to the alerts_panel template.
type AlertsTemplateData struct {
	Alerts           []AlertRow
	TelegramMappings []TelegramMapping
}

// alertsToTemplateData converts AlertData into template-ready data.
func alertsToTemplateData(d AlertData) AlertsTemplateData {
	var rows []AlertRow
	// Collect all alerts from the map and flatten into a single list.
	for _, list := range d.Alerts {
		for _, a := range list {
			statusLabel := "active"
			statusClass := "green"
			if a.Triggered {
				statusLabel = "triggered"
				statusClass = "amber"
			}
			rows = append(rows, AlertRow{
				ID:          a.ID,
				Email:       a.Email,
				Symbol:      a.Tradingsymbol + ":" + a.Exchange,
				TargetPrice: formatFloat(a.TargetPrice),
				Direction:   string(a.Direction),
				StatusLabel: statusLabel,
				StatusClass: statusClass,
				CreatedAt:   fmtTimeStr(a.CreatedAt),
			})
		}
	}

	// Sort by email then ID for consistent ordering.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Email != rows[j].Email {
			return rows[i].Email < rows[j].Email
		}
		return rows[i].ID < rows[j].ID
	})

	var tgMappings []TelegramMapping
	// Sort telegram keys for consistent ordering.
	tgKeys := make([]string, 0, len(d.Telegram))
	for email := range d.Telegram {
		tgKeys = append(tgKeys, email)
	}
	sort.Strings(tgKeys)
	for _, email := range tgKeys {
		tgMappings = append(tgMappings, TelegramMapping{
			Email:  email,
			ChatID: fmt.Sprintf("%d", d.Telegram[email]),
		})
	}

	return AlertsTemplateData{
		Alerts:           rows,
		TelegramMappings: tgMappings,
	}
}

// --- Users ---

// UserRow is a template-ready row for the users table.
type UserRow struct {
	Email       string
	Role        string
	RoleClass   string
	Status      string
	StatusClass string
	LastLogin   string
	CreatedAt   string
	IsSelf      bool
}

// UsersTemplateData is passed to the users_table template.
type UsersTemplateData struct {
	Users []UserRow
}

// usersToTemplateData converts a slice of users.User into template-ready data.
// currentEmail is the authenticated user's email, used to mark "self" rows.
func usersToTemplateData(list []*users.User, currentEmail string) UsersTemplateData {
	rows := make([]UserRow, len(list))
	for i, u := range list {
		roleClass := "green"
		if u.Role == "admin" {
			roleClass = "purple"
		}
		statusClass := "green"
		switch u.Status {
		case "suspended":
			statusClass = "red"
		case "offboarded":
			statusClass = "amber"
		}
		rows[i] = UserRow{
			Email:       u.Email,
			Role:        u.Role,
			RoleClass:   roleClass,
			Status:      u.Status,
			StatusClass: statusClass,
			LastLogin:   fmtTimeStr(u.LastLogin),
			CreatedAt:   fmtTimeStr(u.CreatedAt),
			IsSelf:      u.Email == currentEmail,
		}
	}
	return UsersTemplateData{Users: rows}
}

// --- Metrics ---

// MetricsToolRow is a template-ready row for the metrics tool details table.
type MetricsToolRow struct {
	ToolName   string
	CallCount  string
	AvgMs      string
	MaxMs      string
	ErrorCount string
	ErrorPct   string
	HasErrors  bool
}

// MetricsTemplateData is passed to the metrics_panel template.
type MetricsTemplateData struct {
	Cards       []StatCard
	ToolMetrics []MetricsToolRow
}

// metricsToTemplateData converts the metrics API response into template-ready data.
func metricsToTemplateData(stats *audit.Stats, toolMetrics []audit.ToolMetric, uptimeSeconds int) MetricsTemplateData {
	// Uptime formatting (matches the JS)
	days := uptimeSeconds / 86400
	hours := (uptimeSeconds % 86400) / 3600
	mins := (uptimeSeconds % 3600) / 60
	uptimeStr := ""
	if days > 0 {
		uptimeStr += strconv.Itoa(days) + "d "
	}
	if hours > 0 {
		uptimeStr += strconv.Itoa(hours) + "h "
	}
	uptimeStr += strconv.Itoa(mins) + "m"

	totalCalls := 0
	errorCount := 0
	avgLatency := 0.0
	topTool := "--"
	if stats != nil {
		totalCalls = stats.TotalCalls
		errorCount = stats.ErrorCount
		avgLatency = stats.AvgLatencyMs
		if stats.TopTool != "" {
			topTool = stats.TopTool + " (" + strconv.Itoa(stats.TopToolCount) + ")"
		}
	}

	var errorRate float64
	if totalCalls > 0 {
		errorRate = float64(errorCount) / float64(totalCalls) * 100
	}
	errorRateStr := fmt.Sprintf("%.1f%%", errorRate)

	errorRateClass := "green"
	if errorRate > 5 {
		errorRateClass = "red"
	} else if errorRate > 1 {
		errorRateClass = "amber"
	}

	cards := []StatCard{
		{Label: "Uptime", Value: uptimeStr},
		{Label: "Total Calls", Value: formatInt(totalCalls), Class: boolClass(totalCalls > 0, "green")},
		{Label: "Error Rate", Value: errorRateStr, Class: errorRateClass},
		{Label: "Avg Latency", Value: fmt.Sprintf("%.0fms", avgLatency)},
		{Label: "Top Tool", Value: topTool},
	}

	rows := make([]MetricsToolRow, len(toolMetrics))
	for i, t := range toolMetrics {
		var errPct float64
		if t.CallCount > 0 {
			errPct = float64(t.ErrorCount) / float64(t.CallCount) * 100
		}
		rows[i] = MetricsToolRow{
			ToolName:   t.ToolName,
			CallCount:  formatInt(t.CallCount),
			AvgMs:      fmt.Sprintf("%.0f", t.AvgMs),
			MaxMs:      fmt.Sprintf("%d", t.MaxMs),
			ErrorCount: strconv.Itoa(t.ErrorCount),
			ErrorPct:   fmt.Sprintf("%.1f%%", errPct),
			HasErrors:  t.ErrorCount > 0,
		}
	}

	return MetricsTemplateData{Cards: cards, ToolMetrics: rows}
}

// --- Template parsing ---

// adminFragmentTemplates parses and returns all admin tab partial templates.
func adminFragmentTemplates() (*template.Template, error) {
	return template.ParseFS(templates.FS,
		"admin_sessions.html",
		"admin_tickers.html",
		"admin_alerts.html",
		"admin_users.html",
		"admin_metrics.html",
	)
}

// --- Helpers ---

// formatFloat formats a float64 with two decimal places.
func formatFloat(f float64) string {
	return fmt.Sprintf("%.2f", f)
}

// formatInt formats an integer with comma separators (simple implementation).
func formatInt(n int) string {
	s := strconv.Itoa(n)
	if n < 1000 {
		return s
	}
	// Insert commas from the right.
	result := make([]byte, 0, len(s)+(len(s)-1)/3)
	for i := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, s[i])
	}
	return string(result)
}

// Ensure alerts import is used (the type is referenced via AlertData).
var _ alerts.Direction
