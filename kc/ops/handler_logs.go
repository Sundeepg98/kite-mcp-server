package ops

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/zerodha/kite-mcp-server/oauth"
)

// logStream serves an SSE stream of structured log entries.
// Only admin users can access the log stream.
func (h *Handler) logStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if !h.isAdmin(email) {
		http.Error(w, "admin access required", http.StatusForbidden)
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

	listenerID := fmt.Sprintf("ops-%d", time.Now().UnixNano())
	ch := h.logBuffer.AddListener(listenerID)
	defer h.logBuffer.RemoveListener(listenerID)

	// Backfill recent entries.
	for _, entry := range h.logBuffer.Recent(50) {
		if data, err := json.Marshal(entry); err == nil {
			fmt.Fprintf(w, "data: %s\n\n", data)
		}
	}
	flusher.Flush()

	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case entry := <-ch:
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
