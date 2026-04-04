package ops

import (
	"bytes"
	"fmt"
	"html/template"
	"sort"
	"strconv"

	"github.com/zerodha/kite-mcp-server/kc/templates"
)

// StatCard represents a single card in the Overview stats grid.
type StatCard struct {
	Label string
	Value string
	Class string
}

// ToolUsageRow represents a row in the tool usage table.
type ToolUsageRow struct {
	Name  string
	Count string
}

// OverviewTemplateData is passed to the overview template partials.
type OverviewTemplateData struct {
	Cards []StatCard
	Tools []ToolUsageRow
}

// overviewToTemplateData converts OverviewData into template-ready data.
func overviewToTemplateData(d OverviewData) OverviewTemplateData {
	cards := []StatCard{
		{Label: "Version", Value: d.Version},
		{Label: "Sessions", Value: strconv.Itoa(d.ActiveSessions), Class: boolClass(d.ActiveSessions > 0, "green")},
		{Label: "Ticker Feeds", Value: strconv.Itoa(d.ActiveTickers), Class: boolClass(d.ActiveTickers > 0, "green")},
		{Label: "Active Alerts", Value: strconv.Itoa(d.ActiveAlerts) + " / " + strconv.Itoa(d.TotalAlerts)},
		{Label: "Cached Tokens", Value: strconv.Itoa(d.CachedTokens)},
		{Label: "API Keys", Value: strconv.Itoa(d.PerUserCredentials)},
		{Label: "Users Today", Value: strconv.FormatInt(d.DailyUsers, 10), Class: boolClass(d.DailyUsers > 0, "amber")},
	}

	type kv struct {
		k string
		v int64
	}
	sorted := make([]kv, 0, len(d.ToolUsage))
	for k, v := range d.ToolUsage {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].v > sorted[j].v })

	tools := make([]ToolUsageRow, len(sorted))
	for i, s := range sorted {
		tools[i] = ToolUsageRow{Name: s.k, Count: fmt.Sprintf("%d", s.v)}
	}

	return OverviewTemplateData{Cards: cards, Tools: tools}
}

func boolClass(cond bool, cls string) string {
	if cond {
		return cls
	}
	return ""
}

// overviewFragmentTemplates parses and returns the overview partial templates.
func overviewFragmentTemplates() (*template.Template, error) {
	return template.ParseFS(templates.FS, "overview_stats.html", "overview_tools.html")
}

// renderFragment executes a named template into a string.
func renderFragment(t *template.Template, name string, data any) (string, error) {
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, name, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
