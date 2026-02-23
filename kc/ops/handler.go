package ops

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/zerodha/kite-mcp-server/app/metrics"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/templates"
)

// Handler serves the ops dashboard pages and API endpoints.
type Handler struct {
	manager   *kc.Manager
	metrics   *metrics.Manager
	logBuffer *LogBuffer
	logger    *slog.Logger
	startTime time.Time
	version   string
}

// New creates a new ops Handler.
func New(manager *kc.Manager, metrics *metrics.Manager, logBuffer *LogBuffer, logger *slog.Logger, version string, startTime time.Time) *Handler {
	return &Handler{
		manager:   manager,
		metrics:   metrics,
		logBuffer: logBuffer,
		logger:    logger,
		startTime: startTime,
		version:   version,
	}
}

// RegisterRoutes mounts all ops routes under /admin/ops, protected by the provided auth middleware.
func (h *Handler) RegisterRoutes(mux *http.ServeMux, auth func(http.Handler) http.Handler) {
	wrap := func(f http.HandlerFunc) http.Handler { return auth(f) }
	mux.Handle("/admin/ops", wrap(h.servePage))
	mux.Handle("/admin/ops/api/overview", wrap(h.overview))
	mux.Handle("/admin/ops/api/sessions", wrap(h.sessions))
	mux.Handle("/admin/ops/api/tickers", wrap(h.tickers))
	mux.Handle("/admin/ops/api/alerts", wrap(h.alerts))
	mux.Handle("/admin/ops/api/logs", wrap(h.logStream))
	mux.Handle("/admin/ops/api/credentials", wrap(h.credentials))
}

// servePage serves the embedded ops.html dashboard page.
func (h *Handler) servePage(w http.ResponseWriter, r *http.Request) {
	data, err := templates.FS.ReadFile("ops.html")
	if err != nil {
		http.Error(w, "failed to load ops page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

// overview returns the combined overview JSON.
func (h *Handler) overview(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.buildOverview())
}

// sessions returns the sessions JSON.
func (h *Handler) sessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.buildSessions())
}

// tickers returns the tickers JSON.
func (h *Handler) tickers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.buildTickers())
}

// alerts returns the alerts JSON.
func (h *Handler) alerts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.buildAlerts())
}

// credentials handles GET (list), POST (create), DELETE (remove) for per-user Kite credentials.
func (h *Handler) credentials(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	jsonError := func(status int, msg string) {
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]string{"error": msg})
	}

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(h.manager.CredentialStore().ListAll())

	case http.MethodPost:
		var req struct {
			Email     string `json:"email"`
			APIKey    string `json:"api_key"`
			APISecret string `json:"api_secret"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(http.StatusBadRequest, "invalid JSON")
			return
		}
		if req.Email == "" || req.APIKey == "" || req.APISecret == "" {
			jsonError(http.StatusBadRequest, "email, api_key, and api_secret are required")
			return
		}
		h.manager.CredentialStore().Set(req.Email, &kc.KiteCredentialEntry{
			APIKey:    req.APIKey,
			APISecret: req.APISecret,
		})
		// Clear cached token — old token was generated with different credentials
		h.manager.TokenStore().Delete(req.Email)
		h.logger.Info("Stored Kite credentials", "email", req.Email)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

	case http.MethodDelete:
		email := r.URL.Query().Get("email")
		if email == "" {
			jsonError(http.StatusBadRequest, "email query parameter required")
			return
		}
		h.manager.CredentialStore().Delete(email)
		h.manager.TokenStore().Delete(email)
		h.logger.Info("Deleted Kite credentials", "email", email)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

	default:
		jsonError(http.StatusMethodNotAllowed, "method not allowed")
	}
}

// logStream serves an SSE stream of structured log entries.
func (h *Handler) logStream(w http.ResponseWriter, r *http.Request) {
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
