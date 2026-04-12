package ops

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/zerodha/kite-mcp-server/kc/audit"
)

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
	"order":         {"var(--accent-dim)", "var(--accent)"},
	"query":         {"rgba(148,163,184,0.12)", "var(--text-1)"},
	"market_data":   {"var(--green-dim)", "var(--green)"},
	"alert":         {"var(--amber-dim)", "var(--amber)"},
	"notification":  {"var(--amber-dim)", "var(--amber)"},
	"ticker":        {"var(--purple-dim)", "var(--purple)"},
	"setup":         {"rgba(100,116,139,0.12)", "var(--text-2)"},
	"mf_order":      {"var(--accent-dim)", "var(--accent)"},
	"trailing_stop": {"var(--amber-dim)", "var(--amber)"},
	"watchlist":     {"rgba(148,163,184,0.12)", "var(--text-1)"},
	"analytics":     {"var(--purple-dim)", "var(--purple)"},
}

var catLabels = map[string]string{
	"order":         "ORDER",
	"query":         "QUERY",
	"market_data":   "MARKET",
	"alert":         "ALERT",
	"notification":  "NOTIF",
	"ticker":        "TICKER",
	"setup":         "SETUP",
	"mf_order":      "MF ORDER",
	"trailing_stop": "TRAILING",
	"watchlist":     "WATCHLIST",
	"analytics":     "ANALYTICS",
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
			{Label: "Total Calls", Value: "--", ID: "statTotal"},
			{Label: "Errors", Value: "--", ID: "statErrors"},
			{Label: "Avg Latency", Value: "--", ID: "statLatency"},
			{Label: "Top Tool", Value: "--", ID: "statTopTool"},
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
		{Label: "Total Calls", Value: strconv.Itoa(stats.TotalCalls), ID: "statTotal"},
		{Label: "Errors", Value: strconv.Itoa(stats.ErrorCount), Class: errCls, ID: "statErrors"},
		{Label: "Avg Latency", Value: latency, Sub: "across all calls", ID: "statLatency"},
		{Label: "Top Tool", Value: topTool, Sub: topSub, ID: "statTopTool"},
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
