package ops

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/registry"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// credentials handles GET (list own), POST (create own), DELETE (remove own) for per-user Kite credentials.
// Operations are scoped to the authenticated user's email to prevent IDOR.
func (h *Handler) credentials(w http.ResponseWriter, r *http.Request) {
	jsonError := func(status int, msg string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(map[string]string{"error": msg}); err != nil {
			h.logger.Error("Failed to encode JSON error response", "error", err)
		}
	}

	authEmail := oauth.EmailFromContext(r.Context())
	if authEmail == "" {
		jsonError(http.StatusUnauthorized, "not authenticated")
		return
	}

	switch r.Method {
	case http.MethodGet:
		entry, ok := h.manager.CredentialStore().Get(authEmail)
		if ok {
			secretHint := ""
			if len(entry.APISecret) > 7 {
				secretHint = entry.APISecret[:4] + "****" + entry.APISecret[len(entry.APISecret)-3:]
			} else if entry.APISecret != "" {
				secretHint = "****"
			}
			h.writeJSON(w, []map[string]any{{
				"email":           authEmail,
				"api_key":         entry.APIKey,
				"api_secret_hint": secretHint,
				"stored_at":       entry.StoredAt,
			}})
		} else {
			h.writeJSON(w, []map[string]any{})
		}

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // 64 KB limit
		var req struct {
			APIKey    string `json:"api_key"`
			APISecret string `json:"api_secret"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(http.StatusBadRequest, "invalid JSON")
			return
		}
		if req.APIKey == "" || req.APISecret == "" {
			jsonError(http.StatusBadRequest, "api_key and api_secret are required")
			return
		}
		h.manager.CredentialStore().Set(authEmail, &kc.KiteCredentialEntry{
			APIKey:    req.APIKey,
			APISecret: req.APISecret,
		})
		h.manager.TokenStore().Delete(authEmail)

		if h.registryStore != nil {
			if _, found := h.registryStore.GetByAPIKeyAnyStatus(req.APIKey); !found {
				regID := fmt.Sprintf("self-%s-%s", authEmail, truncKey(req.APIKey, 8))
				if err := h.registryStore.Register(&registry.AppRegistration{
					ID:           regID,
					APIKey:       req.APIKey,
					APISecret:    req.APISecret,
					AssignedTo:   authEmail,
					Label:        "Self-provisioned (dashboard)",
					Status:       registry.StatusActive,
					Source:       registry.SourceSelfProvisioned,
					RegisteredBy: authEmail,
				}); err != nil {
					h.logger.Warn("Failed to auto-register credentials in registry", "email", authEmail, "error", err)
				}
			}
		}

		h.logger.Info("Stored Kite credentials", "email", authEmail)
		h.writeJSON(w, map[string]string{"status": "ok"})

	case http.MethodDelete:
		targetEmail := authEmail
		if h.isAdmin(authEmail) {
			if qEmail := r.URL.Query().Get("email"); qEmail != "" {
				targetEmail = strings.ToLower(qEmail)
			}
		}
		h.manager.CredentialStore().Delete(targetEmail)
		h.manager.TokenStore().Delete(targetEmail)
		h.logger.Info("Deleted Kite credentials", "email", targetEmail, "by", authEmail)
		h.writeJSON(w, map[string]string{"status": "ok"})

	default:
		jsonError(http.StatusMethodNotAllowed, "method not allowed")
	}
}

// forceReauth deletes a user's cached Kite token so their next MCP call triggers re-authentication.
// Only admin users can invoke this endpoint.
func (h *Handler) forceReauth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adminEmail := oauth.EmailFromContext(r.Context())
	if !h.isAdmin(adminEmail) {
		http.Error(w, "admin access required", http.StatusForbidden)
		return
	}

	targetEmail := r.URL.Query().Get("email")
	if targetEmail == "" {
		h.writeJSONError(w, http.StatusBadRequest, "email parameter required")
		return
	}

	h.manager.TokenStore().Delete(targetEmail)
	h.logger.Info("Admin forced re-auth", "admin", adminEmail, "target", targetEmail)
	h.writeJSON(w, map[string]string{"status": "ok", "message": "Token deleted, user will re-authenticate on next MCP call"})
}

// verifyChain runs the HMAC-SHA256 hash chain verification over the entire
// audit trail. Only admin users can invoke this endpoint.
func (h *Handler) verifyChain(w http.ResponseWriter, r *http.Request) {
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
	result, err := h.auditStore.VerifyChain()
	if err != nil {
		h.logger.Error("Chain verification failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.writeJSON(w, result)
}
