package ops

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// ActivityHandler serves activity-timeline JSON, CSV export, and the SSE stream.
// It holds a back-reference to the dashboard core for shared state (audit store,
// logger, JSON helpers).
type ActivityHandler struct {
	core *DashboardHandler
}

func newActivityHandler(core *DashboardHandler) *ActivityHandler {
	return &ActivityHandler{core: core}
}

func (h *ActivityHandler) activityAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	if h.core.auditStore == nil {
		h.core.writeJSONError(w, http.StatusServiceUnavailable, "not_available", "Audit trail not enabled")
		return
	}

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

	results, total, err := h.core.auditStore.List(email, opts)
	if err != nil {
		h.core.loggerPort.Error(r.Context(), "Failed to list audit entries", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var stats *audit.Stats
	stats, err = h.core.auditStore.GetStats(email, opts.Since, opts.Category, opts.OnlyErrors)
	if err != nil {
		h.core.loggerPort.Error(r.Context(), "Failed to get audit stats", err)
	}

	toolCounts, tcErr := h.core.auditStore.GetToolCounts(email, opts.Since, opts.Category, opts.OnlyErrors)
	if tcErr != nil {
		h.core.loggerPort.Error(r.Context(), "Failed to get tool counts", tcErr)
	}

	h.core.writeJSON(w, map[string]any{
		"entries":     results,
		"total":       total,
		"limit":       opts.Limit,
		"offset":      opts.Offset,
		"stats":       stats,
		"tool_counts": toolCounts,
	})
}

// activityExport streams audit trail entries as CSV or JSON for download.
func (h *ActivityHandler) activityExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if email == "" || h.core.auditStore == nil {
		http.Error(w, "not available", http.StatusBadRequest)
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}

	opts := audit.ListOptions{Limit: 10000}
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

	results, _, err := h.core.auditStore.List(email, opts)
	if err != nil {
		h.core.loggerPort.Error(r.Context(), "Failed to export activity", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if format == "json" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=activity.json")
		if err := json.NewEncoder(w).Encode(results); err != nil {
			h.core.loggerPort.Error(r.Context(), "Failed to encode JSON export", err)
		}
		return
	}

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
func (h *ActivityHandler) activityStreamSSE(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	if h.core.auditStore == nil {
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
	ch := h.core.auditStore.AddActivityListener(listenerID)
	defer h.core.auditStore.RemoveActivityListener(listenerID)

	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case entry := <-ch:
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
