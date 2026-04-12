package ops

import (
	"net/http"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/audit"
)

// serveActivityPageSSR renders the user activity timeline page.
func (h *ActivityHandler) serveActivityPageSSR(w http.ResponseWriter, r *http.Request) {
	d := h.core
	if d.activityTmpl == nil {
		d.servePageFallback(w, "activity.html")
		return
	}

	email, role, tokenValid := d.userContext(r)
	data := ActivityPageData{
		Email:      email,
		Role:       role,
		TokenValid: tokenValid,
		UpdatedAt:  nowTimestamp(),
	}

	if d.auditStore != nil && email != "" {
		today := time.Now().Truncate(24 * time.Hour)
		opts := audit.ListOptions{
			Limit: 50,
			Since: today,
		}
		ptrEntries, _, _ := d.auditStore.List(email, opts)
		stats, _ := d.auditStore.GetStats(email, today, "", false)

		entries := make([]audit.ToolCall, 0, len(ptrEntries))
		for _, e := range ptrEntries {
			if e != nil {
				entries = append(entries, *e)
			}
		}

		data.Stats = activityToStatsData(stats)
		data.Timeline = activityToTimelineData(entries)
	} else {
		data.Stats = activityToStatsData(nil)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := d.activityTmpl.Execute(w, data); err != nil {
		d.logger.Error("Failed to render activity page", "error", err)
	}
}
