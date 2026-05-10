package shared

import (
	"bytes"
	"fmt"
	"html/template"
	"sort"
	"strconv"

	"github.com/algo2go/kite-mcp-templates"
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
	Cards        []StatCard
	Tools        []ToolUsageRow
	GlobalFrozen bool
}

// OverviewToTemplateData converts OverviewData into template-ready data.
//
// Anchor 3 PR 3.1: was unexported `overviewToTemplateData` in kc/ops.
// Capitalised on extraction so kc/ops/ callers can invoke
// shared.OverviewToTemplateData(...). Go does not allow function-level
// type aliases, so the 4 in-tree callers (kc/ops/handler.go,
// kc/ops/overview_sse.go, plus tests) were updated in the same PR.
func OverviewToTemplateData(d OverviewData) OverviewTemplateData {
	cards := []StatCard{
		{Label: "Version", Value: d.Version},
		{Label: "Sessions", Value: strconv.Itoa(d.ActiveSessions), Class: BoolClass(d.ActiveSessions > 0, "green")},
		{Label: "Ticker Feeds", Value: strconv.Itoa(d.ActiveTickers), Class: BoolClass(d.ActiveTickers > 0, "green")},
		{Label: "Active Alerts", Value: strconv.Itoa(d.ActiveAlerts) + " / " + strconv.Itoa(d.TotalAlerts)},
		{Label: "Cached Tokens", Value: strconv.Itoa(d.CachedTokens)},
		{Label: "API Keys", Value: strconv.Itoa(d.PerUserCredentials)},
		{Label: "Users Today", Value: strconv.FormatInt(d.DailyUsers, 10), Class: BoolClass(d.DailyUsers > 0, "amber")},
		{Label: "Heap (MB)", Value: fmt.Sprintf("%.1f", d.HeapAllocMB)},
		{Label: "Goroutines", Value: strconv.Itoa(d.Goroutines), Class: BoolClass(d.Goroutines > 100, "amber")},
		{Label: "GC Pause (ms)", Value: fmt.Sprintf("%.2f", d.GCPauseMs)},
		{Label: "DB Size (MB)", Value: fmt.Sprintf("%.2f", d.DBSizeMB)},
	}
	// Show a red "Global Freeze" card when trading is globally suspended.
	if d.GlobalFrozen {
		cards = append([]StatCard{{Label: "Global Freeze", Value: "ACTIVE", Class: "red"}}, cards...)
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

	return OverviewTemplateData{Cards: cards, Tools: tools, GlobalFrozen: d.GlobalFrozen}
}

// BoolClass returns cls when cond is true, empty string otherwise.
//
// Anchor 3 PR 3.1: was unexported `boolClass`.
func BoolClass(cond bool, cls string) string {
	if cond {
		return cls
	}
	return ""
}

// OverviewFragmentTemplates parses and returns the overview partial templates.
//
// Anchor 3 PR 3.1: was unexported `overviewFragmentTemplates`.
func OverviewFragmentTemplates() (*template.Template, error) {
	return template.ParseFS(templates.FS, "overview_stats.html", "overview_tools.html")
}

// RenderFragment executes a named template into a string.
//
// Anchor 3 PR 3.1: was unexported `renderFragment`.
func RenderFragment(t *template.Template, name string, data any) (string, error) {
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, name, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
