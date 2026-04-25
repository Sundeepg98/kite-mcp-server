package ops

import (
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/zerodha/kite-mcp-server/oauth"
)

// metricsAPI returns global audit trail metrics for the ops dashboard.
// Requires admin access. Accepts ?period=1h|24h|7d|30d (default 24h).
func (h *Handler) metricsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if !h.isAdmin(email) {
		http.Error(w, "admin access required", http.StatusForbidden)
		return
	}
	if h.auditStore == nil {
		h.writeJSONError(w, http.StatusServiceUnavailable, "audit trail not enabled")
		return
	}

	since := metricsSince(r.URL.Query().Get("period"))

	stats, err := h.auditStore.GetGlobalStats(since)
	if err != nil {
		h.logger.Error("Failed to get global stats", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	toolMetrics, err := h.auditStore.GetToolMetrics(since)
	if err != nil {
		h.logger.Error("Failed to get tool metrics", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Runtime metrics.
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	var gcPauseMs float64
	if memStats.NumGC > 0 {
		gcPauseMs = float64(memStats.PauseNs[(memStats.NumGC+255)%256]) / 1e6
	}
	var dbSizeMB float64
	if h.alertDBPath != "" {
		if info, err := os.Stat(h.alertDBPath); err == nil { // #nosec G703 — server-side config, not user input
			dbSizeMB = float64(info.Size()) / 1024 / 1024
		}
	}

	topErrorUsers, _ := h.auditStore.GetTopErrorUsers(since, 5)

	uptime := time.Since(h.startTime)
	h.writeJSON(w, map[string]any{
		"uptime_seconds":  int(uptime.Seconds()),
		"stats":           stats,
		"tool_metrics":    toolMetrics,
		"heap_alloc_mb":   float64(memStats.HeapAlloc) / 1024 / 1024,
		"goroutines":      runtime.NumGoroutine(),
		"gc_pause_ms":     gcPauseMs,
		"db_size_mb":      dbSizeMB,
		"top_error_users": topErrorUsers,
	})
}

// metricsFragment returns server-rendered HTML for the metrics cards and table.
// Used by htmx period buttons to swap the metrics content without full JS rendering.
func (h *Handler) metricsFragment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if !h.isAdmin(email) {
		http.Error(w, "admin access required", http.StatusForbidden)
		return
	}
	if h.auditStore == nil {
		http.Error(w, "audit trail not enabled", http.StatusServiceUnavailable)
		return
	}
	if h.adminTmpl == nil {
		http.Error(w, "templates not loaded", http.StatusInternalServerError)
		return
	}

	since := metricsSince(r.URL.Query().Get("period"))

	stats, err := h.auditStore.GetGlobalStats(since)
	if err != nil {
		h.logger.Error("Failed to get global stats for fragment", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	toolMetrics, err := h.auditStore.GetToolMetrics(since)
	if err != nil {
		h.logger.Error("Failed to get tool metrics for fragment", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data := metricsToTemplateData(stats, toolMetrics, int(time.Since(h.startTime).Seconds()))

	cardsHTML, err := renderFragment(h.adminTmpl, "admin_metrics_cards", data)
	if err != nil {
		h.logger.Error("Failed to render metrics cards fragment", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	tableHTML, err := renderFragment(h.adminTmpl, "admin_metrics_table", data)
	if err != nil {
		h.logger.Error("Failed to render metrics table fragment", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<div class="stats-grid">%s</div><div class="section-header">Tool Details</div><div class="tbl-wrap"><table><thead><tr><th>Tool</th><th>Calls</th><th>Avg (ms)</th><th>Max (ms)</th><th>Errors</th><th>Error %%</th></tr></thead><tbody>%s</tbody></table></div>`, cardsHTML, tableHTML)
}

// metricsSince maps a period string to a start time. Defaults to 24h.
func metricsSince(period string) time.Time {
	switch period {
	case "1h":
		return time.Now().Add(-1 * time.Hour)
	case "7d":
		return time.Now().AddDate(0, 0, -7)
	case "30d":
		return time.Now().AddDate(0, 0, -30)
	default:
		return time.Now().Add(-24 * time.Hour)
	}
}
