package ops

import (
	"bytes"
	"fmt"
	"html/template"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/audit"
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
// Portfolio page
// ============================================================================

// PortfolioStatsData is the template data for user_portfolio_stats.
type PortfolioStatsData struct {
	Cards []UserStatCard
}

// HoldingRow is a single row in the holdings table template.
type HoldingRow struct {
	Tradingsymbol string
	Exchange      string
	Quantity      int
	AvgPriceFmt   string
	LastPriceFmt  string
	PnLFmt        string
	PnLClass      string
	DayChangeFmt  string
	DayChangeClass string
}

// PortfolioHoldingsData is the template data for user_portfolio_holdings.
type PortfolioHoldingsData struct {
	Holdings []HoldingRow
}

// PositionRow is a single row in the positions table template.
type PositionRow struct {
	Tradingsymbol string
	Exchange      string
	Product       string
	Quantity      int
	AvgPriceFmt   string
	LastPriceFmt  string
	PnLFmt        string
	PnLClass      string
}

// PortfolioPositionsData is the template data for user_portfolio_positions.
type PortfolioPositionsData struct {
	Positions []PositionRow
}

// MarketIndex represents one entry in the market bar.
type MarketIndex struct {
	Label       string
	PriceFmt    string
	ChangeFmt   string
	ChangeClass string // "up" or "down"
}

// MarketBarData is the template data for user_market_bar.
type MarketBarData struct {
	Indices []MarketIndex
}

// portfolioToStatsData converts status + portfolio API data into stat cards.
func portfolioToStatsData(status statusResponse, portfolio portfolioResponse, alertCount int) PortfolioStatsData {
	tokenVal := "Expired"
	tokenCls := "red"
	if status.KiteToken.Valid {
		tokenVal = "Active"
		tokenCls = "green"
	}

	tickerVal := "Off"
	tickerCls := ""
	if status.Ticker.Running {
		tickerVal = fmt.Sprintf("%d feeds", status.Ticker.Subscriptions)
		tickerCls = "green"
	}

	todayPnl := portfolio.Summary.TotalPnL + portfolio.Summary.PositionsPnL
	pnlSub := ""
	if portfolio.Summary.TotalCurrent > 0 {
		pnlPct := (todayPnl / portfolio.Summary.TotalCurrent) * 100
		pnlSub = fmtPct(pnlPct)
	}

	return PortfolioStatsData{
		Cards: []UserStatCard{
			{Label: "Kite Token", Value: tokenVal, Class: tokenCls},
			{Label: "Holdings", Value: strconv.Itoa(portfolio.Summary.HoldingsCount)},
			{Label: "Today's P&L", Value: fmtINR(todayPnl), Class: pnlClass(todayPnl), Sub: pnlSub, Hero: true},
			{Label: "Active Alerts", Value: strconv.Itoa(alertCount)},
			{Label: "Ticker", Value: tickerVal, Class: tickerCls},
		},
	}
}

// portfolioToHoldingsData converts API holdings into template rows.
func portfolioToHoldingsData(holdings []holdingItem) PortfolioHoldingsData {
	rows := make([]HoldingRow, 0, len(holdings))
	for _, h := range holdings {
		rows = append(rows, HoldingRow{
			Tradingsymbol:  h.Tradingsymbol,
			Exchange:       h.Exchange,
			Quantity:       h.Quantity,
			AvgPriceFmt:    fmtPrice(h.AveragePrice),
			LastPriceFmt:   fmtPrice(h.LastPrice),
			PnLFmt:         fmtINR(h.PnL),
			PnLClass:       pnlClass(h.PnL),
			DayChangeFmt:   fmtPct(h.DayChangePercent),
			DayChangeClass: pnlClass(h.DayChangePercent),
		})
	}
	return PortfolioHoldingsData{Holdings: rows}
}

// portfolioToPositionsData converts API positions into template rows.
func portfolioToPositionsData(positions []positionItem) PortfolioPositionsData {
	rows := make([]PositionRow, 0, len(positions))
	for _, p := range positions {
		rows = append(rows, PositionRow{
			Tradingsymbol: p.Tradingsymbol,
			Exchange:      p.Exchange,
			Product:       p.Product,
			Quantity:      p.Quantity,
			AvgPriceFmt:   fmtPrice(p.AveragePrice),
			LastPriceFmt:  fmtPrice(p.LastPrice),
			PnLFmt:        fmtINR(p.PnL),
			PnLClass:      pnlClass(p.PnL),
		})
	}
	return PortfolioPositionsData{Positions: rows}
}

// marketIndicesToBarData converts the market indices API map into template data.
func marketIndicesToBarData(indices map[string]any) MarketBarData {
	order := []struct {
		key   string
		label string
	}{
		{"NSE:NIFTY 50", "NIFTY 50"},
		{"NSE:NIFTY BANK", "BANK NIFTY"},
		{"BSE:SENSEX", "SENSEX"},
	}

	items := make([]MarketIndex, 0, len(order))
	for _, o := range order {
		idx, ok := indices[o.key]
		if !ok {
			items = append(items, MarketIndex{Label: o.label, PriceFmt: "--", ChangeFmt: "--"})
			continue
		}
		m, ok := idx.(map[string]any)
		if !ok {
			items = append(items, MarketIndex{Label: o.label, PriceFmt: "--", ChangeFmt: "--"})
			continue
		}

		lastPrice, _ := m["last_price"].(float64)
		change, _ := m["change"].(float64)
		changePct, _ := m["change_pct"].(float64)

		cls := "down"
		prefix := ""
		if change >= 0 {
			cls = "up"
			prefix = "+"
		}

		items = append(items, MarketIndex{
			Label:       o.label,
			PriceFmt:    fmt.Sprintf("%.0f", lastPrice),
			ChangeFmt:   fmt.Sprintf("%s%.0f (%.2f%%)", prefix, change, changePct),
			ChangeClass: cls,
		})
	}
	return MarketBarData{Indices: items}
}

// ============================================================================
// Activity page
// ============================================================================

// ActivityStatsData is the template data for user_activity_stats.
type ActivityStatsData struct {
	Cards []UserStatCard
}

// ActivityEntry is a single entry in the activity timeline template.
type ActivityEntry struct {
	TimeFmt       string
	ToolName      string
	CatBg         string
	CatFg         string
	CatLabel      string
	InputSummary  string
	OutputSummary string
	DurationFmt   string
	StatusClass   string // "success" or "fail"
	StatusLabel   string
	IsError       bool
	ErrorMessage  string
}

// ActivityTimelineData is the template data for user_activity_timeline.
type ActivityTimelineData struct {
	Entries []ActivityEntry
}

// Category color config matching the JS catColors map.
var catColors = map[string]struct{ bg, fg string }{
	"order":        {"var(--accent-dim)", "var(--accent)"},
	"query":        {"rgba(148,163,184,0.12)", "var(--text-1)"},
	"market_data":  {"var(--green-dim)", "var(--green)"},
	"alert":        {"var(--amber-dim)", "var(--amber)"},
	"notification": {"var(--amber-dim)", "var(--amber)"},
	"ticker":       {"var(--purple-dim)", "var(--purple)"},
	"setup":        {"rgba(100,116,139,0.12)", "var(--text-2)"},
}

var catLabels = map[string]string{
	"order":        "ORDER",
	"query":        "QUERY",
	"market_data":  "MARKET",
	"alert":        "ALERT",
	"notification": "NOTIF",
	"ticker":       "TICKER",
	"setup":        "SETUP",
}

func getCatColor(cat string) (string, string) {
	if c, ok := catColors[cat]; ok {
		return c.bg, c.fg
	}
	return catColors["setup"].bg, catColors["setup"].fg
}

func getCatLabel(cat string) string {
	if l, ok := catLabels[cat]; ok {
		return l
	}
	if cat != "" {
		return strings.ToUpper(cat)
	}
	return "OTHER"
}

// activityToStatsData converts audit.Stats into stat cards.
func activityToStatsData(stats *audit.Stats) ActivityStatsData {
	if stats == nil {
		return ActivityStatsData{Cards: []UserStatCard{
			{Label: "Total Calls", Value: "--"},
			{Label: "Errors", Value: "--"},
			{Label: "Avg Latency", Value: "--"},
			{Label: "Top Tool", Value: "--"},
		}}
	}
	errCls := ""
	if stats.ErrorCount > 0 {
		errCls = "red"
	}
	latency := fmt.Sprintf("%.0fms", stats.AvgLatencyMs)
	topTool := stats.TopTool
	topSub := ""
	if topTool != "" && stats.TopToolCount > 0 {
		topSub = fmt.Sprintf("%d calls", stats.TopToolCount)
	}
	if topTool == "" {
		topTool = "--"
	}
	return ActivityStatsData{Cards: []UserStatCard{
		{Label: "Total Calls", Value: strconv.Itoa(stats.TotalCalls)},
		{Label: "Errors", Value: strconv.Itoa(stats.ErrorCount), Class: errCls},
		{Label: "Avg Latency", Value: latency},
		{Label: "Top Tool", Value: topTool, Sub: topSub},
	}}
}

// activityToTimelineData converts audit entries into template rows.
func activityToTimelineData(entries []audit.ToolCall) ActivityTimelineData {
	rows := make([]ActivityEntry, 0, len(entries))
	for _, e := range entries {
		bg, fg := getCatColor(e.ToolCategory)
		statusCls := "success"
		statusLabel := "OK"
		if e.IsError {
			statusCls = "fail"
			statusLabel = "ERR"
		}
		rows = append(rows, ActivityEntry{
			TimeFmt:       fmtTimeHMS(e.StartedAt),
			ToolName:      e.ToolName,
			CatBg:         bg,
			CatFg:         fg,
			CatLabel:      getCatLabel(e.ToolCategory),
			InputSummary:  e.InputSummary,
			OutputSummary: e.OutputSummary,
			DurationFmt:   fmtDurationMs(e.DurationMs),
			StatusClass:   statusCls,
			StatusLabel:   statusLabel,
			IsError:       e.IsError,
			ErrorMessage:  e.ErrorMessage,
		})
	}
	return ActivityTimelineData{Entries: rows}
}

// ============================================================================
// Orders page
// ============================================================================

// OrdersStatsData is the template data for user_orders_stats.
type OrdersStatsData struct {
	Cards []UserStatCard
}

// OrderRow is a single row in the orders table template.
type OrderRow struct {
	Symbol          string
	Side            string
	SideClass       string // "side-buy" or "side-sell"
	QuantityFmt     string
	FillPriceFmt    string
	CurrentPriceFmt string
	PnLFmt          string
	PnLClass        string // "pnl-pos", "pnl-neg", "pnl-zero"
	PnLPctFmt       string
	PnLPctClass     string
	Status          string
	StatusBadge     string // CSS class for the status badge
	TimeFmt         string
}

// OrdersTableData is the template data for user_orders_table.
type OrdersTableData struct {
	Orders []OrderRow
}

func statusBadgeClass(status string) string {
	switch strings.ToUpper(status) {
	case "COMPLETE":
		return "status-complete"
	case "CANCELLED":
		return "status-cancelled"
	case "REJECTED":
		return "status-rejected"
	case "OPEN", "TRIGGER PENDING":
		return "status-open"
	default:
		return "status-pending"
	}
}

func pnlDisplayClass(v *float64) string {
	if v == nil {
		return "pnl-zero"
	}
	if *v > 0 {
		return "pnl-pos"
	}
	if *v < 0 {
		return "pnl-neg"
	}
	return "pnl-zero"
}

// ordersToStatsData converts ordersSummary into stat cards.
func ordersToStatsData(s ordersSummary) OrdersStatsData {
	pnlVal := "--"
	pnlCls := ""
	if s.TotalPnL != nil {
		pnlVal = fmtINR(*s.TotalPnL)
		pnlCls = pnlClass(*s.TotalPnL)
	}

	winRate := "--"
	winSub := ""
	total := s.WinningTrades + s.LosingTrades
	if total > 0 {
		pct := float64(s.WinningTrades) / float64(total) * 100
		winRate = fmt.Sprintf("%.0f%%", pct)
		winSub = fmt.Sprintf("%dW / %dL", s.WinningTrades, s.LosingTrades)
	}

	return OrdersStatsData{Cards: []UserStatCard{
		{Label: "Total Orders", Value: strconv.Itoa(s.TotalOrders)},
		{Label: "Completed", Value: strconv.Itoa(s.Completed)},
		{Label: "Total P&L", Value: pnlVal, Class: pnlCls},
		{Label: "Win Rate", Value: winRate, Sub: winSub},
	}}
}

// ordersToTableData converts order entries into template rows.
func ordersToTableData(entries []orderEntry) OrdersTableData {
	rows := make([]OrderRow, 0, len(entries))
	for _, oe := range entries {
		sideCls := "side-buy"
		if oe.Side == "SELL" {
			sideCls = "side-sell"
		}

		fillFmt := "--"
		if oe.FillPrice != nil {
			fillFmt = fmtPrice(*oe.FillPrice)
		}
		currFmt := "--"
		if oe.CurrentPrice != nil {
			currFmt = fmtPrice(*oe.CurrentPrice)
		}
		pnlFmt := "--"
		if oe.PnL != nil {
			pnlFmt = fmtINR(*oe.PnL)
		}
		pnlPctFmt := "--"
		if oe.PnLPct != nil {
			pnlPctFmt = fmtPct(*oe.PnLPct)
		}

		t, _ := time.Parse(time.RFC3339, oe.PlacedAt)

		rows = append(rows, OrderRow{
			Symbol:          oe.Symbol,
			Side:            oe.Side,
			SideClass:       sideCls,
			QuantityFmt:     fmt.Sprintf("%.0f", oe.Quantity),
			FillPriceFmt:    fillFmt,
			CurrentPriceFmt: currFmt,
			PnLFmt:          pnlFmt,
			PnLClass:        pnlDisplayClass(oe.PnL),
			PnLPctFmt:       pnlPctFmt,
			PnLPctClass:     pnlDisplayClass(oe.PnLPct),
			Status:          oe.Status,
			StatusBadge:     statusBadgeClass(oe.Status),
			TimeFmt:         fmtTimeDDMon(t),
		})
	}
	return OrdersTableData{Orders: rows}
}

// ============================================================================
// Alerts page
// ============================================================================

// AlertsStatsData is the template data for user_alerts_stats.
type AlertsStatsData struct {
	Cards []UserStatCard
}

// ActiveAlertRow is a single row in the active alerts table.
type ActiveAlertRow struct {
	ID            string
	Tradingsymbol string
	Direction     string
	DirBadge      string // "green", "red", "amber"
	TargetFmt     string
	CurrentFmt    string
	DistFmt       string
	DistClass     string // "dist-green", "dist-amber", "dist-red"
	CreatedFmt    string
}

// AlertsActiveData is the template data for user_alerts_active.
type AlertsActiveData struct {
	Alerts []ActiveAlertRow
}

// TriggeredAlertRow is a single row in the triggered alerts timeline.
type TriggeredAlertRow struct {
	Tradingsymbol     string
	Direction         string
	DirBadge          string
	TargetFmt         string
	CreatedFmt        string
	TriggeredFmt      string
	TimeToTrigger     string
	NotificationFmt   string
	NotificationDelay string
}

// AlertsTriggeredData is the template data for user_alerts_triggered.
type AlertsTriggeredData struct {
	Alerts []TriggeredAlertRow
}

func dirBadge(dir string) string {
	switch dir {
	case "above", "rise_pct":
		return "green"
	case "below", "drop_pct":
		return "red"
	default:
		return "amber"
	}
}

func distanceClass(pct float64) string {
	if pct < 2 {
		return "dist-green"
	}
	if pct < 5 {
		return "dist-amber"
	}
	return "dist-red"
}

// alertsToStatsData converts enriched alerts summary into stat cards.
func alertsToStatsData(summary alertsSummary, nearest *enrichedActiveAlert) AlertsStatsData {
	nearestVal := "--"
	nearestSub := ""
	if nearest != nil {
		nearestVal = nearest.Tradingsymbol
		if nearest.DistancePct != nil {
			nearestSub = fmt.Sprintf("%.1f%% away", *nearest.DistancePct)
		}
	}

	avgTime := summary.AvgTimeToTrigger
	if avgTime == "" {
		avgTime = "--"
	}

	return AlertsStatsData{Cards: []UserStatCard{
		{Label: "Active Alerts", Value: strconv.Itoa(summary.ActiveCount)},
		{Label: "Triggered", Value: strconv.Itoa(summary.TriggeredCount)},
		{Label: "Avg Time to Trigger", Value: avgTime},
		{Label: "Nearest Alert", Value: nearestVal, Sub: nearestSub},
	}}
}

// alertsToActiveData converts enriched active alerts into template rows.
func alertsToActiveData(active []enrichedActiveAlert) AlertsActiveData {
	rows := make([]ActiveAlertRow, 0, len(active))
	for _, a := range active {
		distFmt := "--"
		distCls := ""
		if a.DistancePct != nil {
			distFmt = fmt.Sprintf("%.1f%%", *a.DistancePct)
			distCls = distanceClass(*a.DistancePct)
		}
		t, _ := time.Parse(time.RFC3339, a.CreatedAt)
		rows = append(rows, ActiveAlertRow{
			ID:            a.ID,
			Tradingsymbol: a.Tradingsymbol,
			Direction:     a.Direction,
			DirBadge:      dirBadge(a.Direction),
			TargetFmt:     fmtPrice(a.TargetPrice),
			CurrentFmt:    fmtPrice(a.CurrentPrice),
			DistFmt:       distFmt,
			DistClass:     distCls,
			CreatedFmt:    fmtTimeDDMon(t),
		})
	}
	return AlertsActiveData{Alerts: rows}
}

// alertsToTriggeredData converts enriched triggered alerts into template rows.
func alertsToTriggeredData(triggered []enrichedTriggeredAlert) AlertsTriggeredData {
	rows := make([]TriggeredAlertRow, 0, len(triggered))
	for _, a := range triggered {
		ct, _ := time.Parse(time.RFC3339, a.CreatedAt)
		tt, _ := time.Parse(time.RFC3339, a.TriggeredAt)
		notifFmt := ""
		if a.NotificationSentAt != "" {
			nt, _ := time.Parse(time.RFC3339, a.NotificationSentAt)
			if !nt.IsZero() {
				notifFmt = fmtTimeDDMon(nt)
			}
		}
		rows = append(rows, TriggeredAlertRow{
			Tradingsymbol:     a.Tradingsymbol,
			Direction:         a.Direction,
			DirBadge:          dirBadge(a.Direction),
			TargetFmt:         fmtPrice(a.TargetPrice),
			CreatedFmt:        fmtTimeDDMon(ct),
			TriggeredFmt:      fmtTimeDDMon(tt),
			TimeToTrigger:     a.TimeToTrigger,
			NotificationFmt:   notifFmt,
			NotificationDelay: a.NotificationDelay,
		})
	}
	return AlertsTriggeredData{Alerts: rows}
}

// ============================================================================
// Paper trading page
// ============================================================================

// PaperStatsData is the template data for user_paper_stats.
type PaperStatsData struct {
	Cards []UserStatCard
}

// PaperBannerData is the template data for user_paper_banner.
type PaperBannerData struct {
	Enabled        bool
	InitialCashFmt string
	CreatedFmt     string
}

// PaperHoldingRow is a row in the paper holdings table.
type PaperHoldingRow struct {
	Tradingsymbol string
	Exchange      string
	Quantity      int
	AvgPriceFmt   string
	LastPriceFmt  string
	PnLFmt        string
	PnLClass      string
}

// PaperPositionRow is a row in the paper positions table.
type PaperPositionRow struct {
	Tradingsymbol string
	Product       string
	Quantity      int
	AvgPriceFmt   string
	LastPriceFmt  string
	PnLFmt        string
	PnLClass      string
}

// PaperOrderRow is a row in the paper orders table.
type PaperOrderRow struct {
	OrderIDShort    string
	Tradingsymbol   string
	TransactionType string
	SideBadge       string // "badge-green" or "badge-red"
	OrderType       string
	Quantity        int
	PriceFmt        string
	Status          string
	StatusBadge     string // "badge-green", "badge-red", "badge-amber"
	TimeFmt         string
}

// PaperTablesData is the template data for user_paper_tables.
type PaperTablesData struct {
	Holdings  []PaperHoldingRow
	Positions []PaperPositionRow
	Orders    []PaperOrderRow
}

// ============================================================================
// Safety page
// ============================================================================

// SafetyFreezeData is the template data for user_safety_freeze.
type SafetyFreezeData struct {
	Enabled      bool
	Message      string
	IsFrozen     bool
	FrozenReason string
	FrozenBy     string
	FrozenAtFmt  string
}

// SafetyLimitItem represents one limit utilization bar.
type SafetyLimitItem struct {
	Name     string
	ValueFmt string
	Pct      int    // 0-100
	BarClass string // "safe", "warn", "danger"
	Static   bool   // if true, no bar is rendered
}

// SafetyLimitsData is the template data for user_safety_limits.
type SafetyLimitsData struct {
	Enabled bool
	Limits  []SafetyLimitItem
}

// SafetyCheck represents one SEBI compliance check.
type SafetyCheck struct {
	Label    string
	DotClass string // "ok", "warn", "off"
}

// SafetySEBIData is the template data for user_safety_sebi.
type SafetySEBIData struct {
	Enabled bool
	Checks  []SafetyCheck
}

func barClass(pct int) string {
	if pct >= 90 {
		return "danger"
	}
	if pct >= 70 {
		return "warn"
	}
	return "safe"
}

// safetyToFreezeData converts the safety API response into freeze banner data.
func safetyToFreezeData(data map[string]any) SafetyFreezeData {
	enabled, _ := data["enabled"].(bool)
	if !enabled {
		msg, _ := data["message"].(string)
		if msg == "" {
			msg = "Not enabled on this server."
		}
		return SafetyFreezeData{Enabled: false, Message: msg}
	}

	status, _ := data["status"].(map[string]any)
	if status == nil {
		return SafetyFreezeData{Enabled: true}
	}

	isFrozen, _ := status["is_frozen"].(bool)
	frozenReason, _ := status["frozen_reason"].(string)
	frozenBy, _ := status["frozen_by"].(string)
	frozenAtStr, _ := status["frozen_at"].(string)
	frozenAtFmt := ""
	if frozenAtStr != "" && frozenAtStr != "0001-01-01T00:00:00Z" {
		if t, err := time.Parse(time.RFC3339, frozenAtStr); err == nil {
			frozenAtFmt = fmtTimeDDMon(t)
		}
	}

	return SafetyFreezeData{
		Enabled:      true,
		IsFrozen:     isFrozen,
		FrozenReason: frozenReason,
		FrozenBy:     frozenBy,
		FrozenAtFmt:  frozenAtFmt,
	}
}

// safetyToLimitsData converts the safety API response into limit utilization bars.
func safetyToLimitsData(data map[string]any) SafetyLimitsData {
	enabled, _ := data["enabled"].(bool)
	if !enabled {
		return SafetyLimitsData{Enabled: false}
	}

	status, _ := data["status"].(map[string]any)
	limits, _ := data["limits"].(map[string]any)
	if status == nil || limits == nil {
		return SafetyLimitsData{Enabled: true}
	}

	dailyCount, _ := status["daily_order_count"].(float64)
	dailyValue, _ := status["daily_placed_value"].(float64)
	maxOrders, _ := limits["max_orders_per_day"].(float64)
	maxDailyVal, _ := limits["max_daily_value_inr"].(float64)
	maxSingle, _ := limits["max_single_order_inr"].(float64)
	maxPerMin, _ := limits["max_orders_per_minute"].(float64)
	dupWindow, _ := limits["duplicate_window_secs"].(float64)

	pctOrders := 0
	if maxOrders > 0 {
		pctOrders = int(math.Min(100, dailyCount/maxOrders*100))
	}
	pctValue := 0
	if maxDailyVal > 0 {
		pctValue = int(math.Min(100, dailyValue/maxDailyVal*100))
	}

	items := []SafetyLimitItem{
		{
			Name:     "Daily Orders",
			ValueFmt: fmt.Sprintf("%.0f / %.0f", dailyCount, maxOrders),
			Pct:      pctOrders,
			BarClass: barClass(pctOrders),
		},
		{
			Name:     "Daily Value",
			ValueFmt: fmtINRShort(dailyValue) + " / " + fmtINRShort(maxDailyVal),
			Pct:      pctValue,
			BarClass: barClass(pctValue),
		},
		{
			Name:     "Single Order Cap",
			ValueFmt: "Limit: " + fmtINRShort(maxSingle),
			Static:   true,
		},
		{
			Name:     "Rate Limit",
			ValueFmt: fmt.Sprintf("Limit: %.0f/min", maxPerMin),
			Static:   true,
		},
		{
			Name:     "Duplicate Window",
			ValueFmt: fmt.Sprintf("Limit: %.0fs", dupWindow),
			Static:   true,
		},
	}

	return SafetyLimitsData{Enabled: true, Limits: items}
}

// safetyToSEBIData converts the safety API response into SEBI compliance cards.
func safetyToSEBIData(data map[string]any) SafetySEBIData {
	enabled, _ := data["enabled"].(bool)
	if !enabled {
		return SafetySEBIData{Enabled: false}
	}

	sebi, _ := data["sebi"].(map[string]any)
	if sebi == nil {
		return SafetySEBIData{Enabled: true}
	}

	boolDot := func(key string) string {
		v, _ := sebi[key].(bool)
		if v {
			return "ok"
		}
		return "off"
	}

	return SafetySEBIData{
		Enabled: true,
		Checks: []SafetyCheck{
			{Label: "Static Egress IP", DotClass: boolDot("static_egress_ip")},
			{Label: "Session Active", DotClass: boolDot("session_active")},
			{Label: "Credentials Set", DotClass: boolDot("credentials_set")},
			{Label: "Order Tagging", DotClass: boolDot("order_tagging")},
			{Label: "Audit Trail", DotClass: boolDot("audit_trail")},
		},
	}
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
