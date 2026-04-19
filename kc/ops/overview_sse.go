package ops

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/zerodha/kite-mcp-server/oauth"
)

// overviewStream sends Server-Sent Events with pre-rendered HTML fragments
// for the Overview tab and other admin tabs. Pushes updates every 10 seconds
// until the client disconnects.
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

	email := oauth.EmailFromContext(r.Context())

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Send initial event immediately.
	h.sendAllAdminEvents(w, flusher, email)

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			h.sendAllAdminEvents(w, flusher, email)
		}
	}
}

// sendAllAdminEvents renders and sends fragments for Overview and all other
// SSE-driven admin tabs (sessions, tickers, alerts, users).
// Metrics is excluded (expensive + has user-interactive period selector).
func (h *Handler) sendAllAdminEvents(w http.ResponseWriter, flusher http.Flusher, currentEmail string) {
	// --- Overview ---
	if h.overviewTmpl != nil {
		overview := h.buildOverview()
		data := overviewToTemplateData(overview)

		if html, err := renderFragment(h.overviewTmpl, "overview_stats", data); err == nil {
			writeSSEEvent(w, "overview-stats", html)
		} else {
			h.logger.Error("Failed to render overview stats fragment", "error", err)
		}

		if html, err := renderFragment(h.overviewTmpl, "overview_tools", data); err == nil {
			writeSSEEvent(w, "overview-tools", html)
		} else {
			h.logger.Error("Failed to render overview tools fragment", "error", err)
		}

		writeSSEEvent(w, "overview-uptime", "up "+overview.Uptime)
	}

	// --- Other admin tabs (require adminTmpl) ---
	if h.adminTmpl != nil {
		// Sessions
		sessionsData := sessionsToTemplateData(h.buildSessions())
		if html, err := renderFragment(h.adminTmpl, "admin_sessions", sessionsData); err == nil {
			writeSSEEvent(w, "admin-sessions", html)
		} else {
			h.logger.Error("Failed to render sessions fragment", "error", err)
		}

		// Tickers
		tickersData := tickersToTemplateData(h.buildTickers())
		if html, err := renderFragment(h.adminTmpl, "admin_tickers", tickersData); err == nil {
			writeSSEEvent(w, "admin-tickers", html)
		} else {
			h.logger.Error("Failed to render tickers fragment", "error", err)
		}

		// Alerts
		alertsData := alertsToTemplateData(h.buildAlerts())
		if html, err := renderFragment(h.adminTmpl, "admin_alerts", alertsData); err == nil {
			writeSSEEvent(w, "admin-alerts", html)
		} else {
			h.logger.Error("Failed to render alerts fragment", "error", err)
		}

		// Users (needs currentEmail for IsSelf check)
		if h.userStore != nil {
			usersData := usersToTemplateData(h.userStore.List(), currentEmail)
			if html, err := renderFragment(h.adminTmpl, "admin_users", usersData); err == nil {
				writeSSEEvent(w, "admin-users", html)
			} else {
				h.logger.Error("Failed to render users fragment", "error", err)
			}
		}
	}

	flusher.Flush()
}

// writeSSEEvent writes a named SSE event with multiline data support.
//
// #nosec G705 -- payload is pre-rendered HTML produced by html/template
// (via renderFragment); auto-escaping is applied at template execution.
// The SSE `data:` prefix is a wire-protocol framing context, not an HTML
// rendering context, so the %s interpolation here is re-emitting already-
// escaped bytes verbatim. There is no new injection surface.
func writeSSEEvent(w http.ResponseWriter, event, payload string) {
	fmt.Fprintf(w, "event: %s\n", event)
	for line := range strings.SplitSeq(payload, "\n") {
		fmt.Fprintf(w, "data: %s\n", line)
	}
	fmt.Fprint(w, "\n")
}
