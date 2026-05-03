package ops

import (
	"net/http"

	"github.com/zerodha/kite-mcp-server/oauth"
)

// paperStatus returns the paper trading account status for the authenticated user.
func (h *PaperHandler) paperStatus(w http.ResponseWriter, r *http.Request) {
	d := h.core
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}
	engine := d.manager.PaperEngine()
	if engine == nil {
		d.writeJSONError(w, http.StatusNotFound, "not_configured", "Paper trading engine is not configured.")
		return
	}
	status, err := engine.Status(email)
	if err != nil {
		d.loggerPort.Error(r.Context(), "Failed to get paper status", err, "email", email)
		d.writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to get paper trading status.")
		return
	}
	d.writeJSON(w, status)
}

// paperHoldings returns paper trading holdings for the authenticated user.
func (h *PaperHandler) paperHoldings(w http.ResponseWriter, r *http.Request) {
	d := h.core
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}
	engine := d.manager.PaperEngine()
	if engine == nil {
		d.writeJSONError(w, http.StatusNotFound, "not_configured", "Paper trading engine is not configured.")
		return
	}
	holdings, err := engine.GetHoldings(email)
	if err != nil {
		d.loggerPort.Error(r.Context(), "Failed to get paper holdings", err, "email", email)
		d.writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to get paper holdings.")
		return
	}
	d.writeJSON(w, holdings)
}

// paperPositions returns paper trading positions for the authenticated user.
func (h *PaperHandler) paperPositions(w http.ResponseWriter, r *http.Request) {
	d := h.core
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}
	engine := d.manager.PaperEngine()
	if engine == nil {
		d.writeJSONError(w, http.StatusNotFound, "not_configured", "Paper trading engine is not configured.")
		return
	}
	positions, err := engine.GetPositions(email)
	if err != nil {
		d.loggerPort.Error(r.Context(), "Failed to get paper positions", err, "email", email)
		d.writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to get paper positions.")
		return
	}
	d.writeJSON(w, positions)
}

// paperOrders returns paper trading orders for the authenticated user.
func (h *PaperHandler) paperOrders(w http.ResponseWriter, r *http.Request) {
	d := h.core
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}
	engine := d.manager.PaperEngine()
	if engine == nil {
		d.writeJSONError(w, http.StatusNotFound, "not_configured", "Paper trading engine is not configured.")
		return
	}
	orders, err := engine.GetOrders(email)
	if err != nil {
		d.loggerPort.Error(r.Context(), "Failed to get paper orders", err, "email", email)
		d.writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to get paper orders.")
		return
	}
	d.writeJSON(w, orders)
}

// paperReset resets the paper trading account for the authenticated user.
func (h *PaperHandler) paperReset(w http.ResponseWriter, r *http.Request) {
	d := h.core
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}
	engine := d.manager.PaperEngine()
	if engine == nil {
		d.writeJSONError(w, http.StatusNotFound, "not_configured", "Paper trading engine is not configured.")
		return
	}
	if err := engine.Reset(email); err != nil {
		d.loggerPort.Error(r.Context(), "Failed to reset paper account", err, "email", email)
		d.writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to reset paper trading account.")
		return
	}
	d.writeJSON(w, map[string]string{"status": "ok", "message": "Paper trading account reset successfully."})
}
