package ops

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// overviewStream sends Server-Sent Events with pre-rendered HTML fragments
// for the Overview tab. Pushes updates every 10 seconds until the client
// disconnects.
func (h *Handler) overviewStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher.Flush()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Send initial event immediately.
	h.sendOverviewEvents(w, flusher)

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			h.sendOverviewEvents(w, flusher)
		}
	}
}

// sendOverviewEvents renders and sends the overview fragments as named SSE events.
func (h *Handler) sendOverviewEvents(w http.ResponseWriter, flusher http.Flusher) {
	if h.overviewTmpl == nil {
		return
	}

	overview := h.buildOverview()
	data := overviewToTemplateData(overview)

	statsHTML, err := renderFragment(h.overviewTmpl, "overview_stats", data)
	if err != nil {
		h.logger.Error("Failed to render overview stats fragment", "error", err)
		return
	}

	toolsHTML, err := renderFragment(h.overviewTmpl, "overview_tools", data)
	if err != nil {
		h.logger.Error("Failed to render overview tools fragment", "error", err)
		return
	}

	writeSSEEvent(w, "overview-stats", statsHTML)
	writeSSEEvent(w, "overview-tools", toolsHTML)
	writeSSEEvent(w, "overview-uptime", "up "+overview.Uptime)

	flusher.Flush()
}

// writeSSEEvent writes a named SSE event with multiline data support.
func writeSSEEvent(w http.ResponseWriter, event, payload string) {
	fmt.Fprintf(w, "event: %s\n", event)
	for _, line := range strings.Split(payload, "\n") {
		fmt.Fprintf(w, "data: %s\n", line)
	}
	fmt.Fprint(w, "\n")
}
