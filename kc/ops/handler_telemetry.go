package ops

import (
	"net/http"

	"github.com/zerodha/kite-mcp-server/oauth"
)

// overview returns the combined overview JSON.
// Admin sees global counts; non-admin sees only their own data.
func (h *Handler) overview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if h.isAdmin(email) {
		h.writeJSON(w, h.buildOverview())
	} else {
		h.writeJSON(w, h.buildOverviewForUser(email))
	}
}

// sessions returns the sessions JSON.
// Admin sees all sessions; non-admin sees only their own.
func (h *Handler) sessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if h.isAdmin(email) {
		h.writeJSON(w, h.buildSessions())
	} else {
		h.writeJSON(w, h.buildSessionsForUser(email))
	}
}

// tickers returns the tickers JSON.
// Admin sees all tickers; non-admin sees only their own.
func (h *Handler) tickers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if h.isAdmin(email) {
		h.writeJSON(w, h.buildTickers())
	} else {
		h.writeJSON(w, h.buildTickersForUser(email))
	}
}

// alerts returns the alerts JSON.
// Admin sees all alerts; non-admin sees only their own.
func (h *Handler) alerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if h.isAdmin(email) {
		h.writeJSON(w, h.buildAlerts())
	} else {
		h.writeJSON(w, h.buildAlertsForUser(email))
	}
}
