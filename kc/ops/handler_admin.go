package ops

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// --- User management endpoints (admin only) ---

// listUsers returns all registered users. Admin only.
func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if !h.isAdmin(email) {
		http.Error(w, "admin access required", http.StatusForbidden)
		return
	}
	if h.userStore == nil {
		h.writeJSON(w, []any{})
		return
	}
	h.writeJSON(w, h.userStore.List())
}

// suspendUser sets a user's status to suspended. Admin only.
// Expects query param: email
func (h *Handler) suspendUser(w http.ResponseWriter, r *http.Request) {
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
	if strings.EqualFold(targetEmail, adminEmail) {
		h.writeJSONError(w, http.StatusBadRequest, "Cannot perform this action on yourself")
		return
	}
	if h.userStore == nil {
		h.writeJSONError(w, http.StatusServiceUnavailable, "user store not initialized")
		return
	}
	// Route through the CommandBus so the mutation hits LoggingMiddleware
	// uniformly with the rest of the codebase. The handler stays in
	// kc/ops because it owns the HTTP request shape (auth check,
	// self-action guard, JSON shape); the bus owns the persistence.
	if err := h.manager.CommandBus().Dispatch(r.Context(), cqrs.AdminSuspendUserCommand{
		AdminEmail:  adminEmail,
		TargetEmail: targetEmail,
	}); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.loggerPort.Info(r.Context(), "Admin suspended user", "admin", adminEmail, "target", targetEmail)
	h.logAdminAction(adminEmail, "suspend_user", targetEmail)
	h.writeJSON(w, map[string]string{"status": "ok", "message": "User suspended"})
}

// activateUser sets a user's status to active. Admin only.
// Expects query param: email
func (h *Handler) activateUser(w http.ResponseWriter, r *http.Request) {
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
	if strings.EqualFold(targetEmail, adminEmail) {
		h.writeJSONError(w, http.StatusBadRequest, "Cannot perform this action on yourself")
		return
	}
	if h.userStore == nil {
		h.writeJSONError(w, http.StatusServiceUnavailable, "user store not initialized")
		return
	}
	if err := h.manager.CommandBus().Dispatch(r.Context(), cqrs.AdminActivateUserCommand{
		AdminEmail:  adminEmail,
		TargetEmail: targetEmail,
	}); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.loggerPort.Info(r.Context(), "Admin activated user", "admin", adminEmail, "target", targetEmail)
	h.logAdminAction(adminEmail, "activate_user", targetEmail)
	h.writeJSON(w, map[string]string{"status": "ok", "message": "User activated"})
}

// offboardUser removes all user data (credentials, tokens, sessions) and sets status to offboarded. Admin only.
// Expects query param: email
func (h *Handler) offboardUser(w http.ResponseWriter, r *http.Request) {
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
	if strings.EqualFold(targetEmail, adminEmail) {
		h.writeJSONError(w, http.StatusBadRequest, "Cannot perform this action on yourself")
		return
	}

	// Parse request body for confirmation
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var confirmBody struct {
		Confirm bool `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&confirmBody); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "invalid_request",
			"message": "Invalid JSON body.",
		})
		return
	}
	if !confirmBody.Confirm {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "confirmation_required",
			"message": "This is a destructive action. Set confirm: true to proceed.",
		})
		return
	}

	if h.userStore == nil {
		h.writeJSONError(w, http.StatusServiceUnavailable, "user store not initialized")
		return
	}

	// Phase B-Audit #25: admin offboard = full account teardown, which
	// is DeleteMyAccountUseCase's exact contract — credentials, tokens,
	// sessions, alerts, watchlists, trailing stops, paper-trading reset,
	// and the UserStore "offboarded" status write. One dispatch replaces
	// four manual operations and gains the bus's audit/observability
	// layer. The use case already calls UpdateStatus(email, "offboarded")
	// internally, so we drop the now-redundant inline UpdateStatus call.
	if _, err := h.manager.CommandBus().DispatchWithResult(r.Context(), cqrs.DeleteMyAccountCommand{
		Email: targetEmail,
	}); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.loggerPort.Info(r.Context(), "Admin offboarded user", "admin", adminEmail, "target", targetEmail)
	h.logAdminAction(adminEmail, "offboard_user", targetEmail)
	h.writeJSON(w, map[string]string{"status": "ok", "message": "User offboarded, all data removed"})
}

// changeRole changes a user's role. Admin only.
// Expects query param: email, JSON body: {"role": "viewer"}
func (h *Handler) changeRole(w http.ResponseWriter, r *http.Request) {
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
	if h.userStore == nil {
		h.writeJSONError(w, http.StatusServiceUnavailable, "user store not initialized")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var req struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Last-admin guard: prevent demoting the only active admin
	target, ok := h.userStore.Get(targetEmail)
	if ok && target.Role == "admin" && req.Role != "admin" {
		admins := 0
		for _, u := range h.userStore.List() {
			if u.Role == "admin" && u.Status == "active" {
				admins++
			}
		}
		if admins <= 1 {
			h.writeJSONError(w, http.StatusConflict, "Cannot demote the last admin")
			return
		}
	}

	if err := h.manager.CommandBus().Dispatch(r.Context(), cqrs.AdminChangeRoleCommand{
		AdminEmail:  adminEmail,
		TargetEmail: targetEmail,
		NewRole:     req.Role,
	}); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.loggerPort.Info(r.Context(), "Admin changed user role", "admin", adminEmail, "target", targetEmail, "role", req.Role)
	h.logAdminAction(adminEmail, "change_role", targetEmail+" -> "+req.Role)
	h.writeJSON(w, map[string]string{"status": "ok", "message": "Role updated to " + req.Role})
}

// freezeTrading freezes trading for a user. Admin only.
func (h *Handler) freezeTrading(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adminEmail := oauth.EmailFromContext(r.Context())
	if !h.isAdmin(adminEmail) {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	var body struct {
		Email   string `json:"email"`
		Reason  string `json:"reason"`
		Confirm bool   `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		http.Error(w, "email required", http.StatusBadRequest)
		return
	}
	if strings.EqualFold(body.Email, adminEmail) {
		h.writeJSONError(w, http.StatusBadRequest, "Cannot perform this action on yourself")
		return
	}
	if !body.Confirm {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "confirmation_required",
			"message": "This is a destructive action. Set confirm: true to proceed.",
		})
		return
	}
	guard := h.manager.RiskGuard()
	if guard == nil {
		http.Error(w, "riskguard not enabled", http.StatusServiceUnavailable)
		return
	}
	guard.Freeze(body.Email, adminEmail, body.Reason)
	h.loggerPort.Info(r.Context(), "Admin froze trading", "admin", adminEmail, "target", body.Email, "reason", body.Reason)
	h.logAdminAction(adminEmail, "freeze_trading", body.Email)
	h.writeJSON(w, map[string]string{"status": "ok", "message": "Trading frozen for " + body.Email})
}

// unfreezeTrading unfreezes trading for a user. Admin only.
func (h *Handler) unfreezeTrading(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adminEmail := oauth.EmailFromContext(r.Context())
	if !h.isAdmin(adminEmail) {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		http.Error(w, "email required", http.StatusBadRequest)
		return
	}
	if strings.EqualFold(body.Email, adminEmail) {
		h.writeJSONError(w, http.StatusBadRequest, "Cannot perform this action on yourself")
		return
	}
	guard := h.manager.RiskGuard()
	if guard == nil {
		http.Error(w, "riskguard not enabled", http.StatusServiceUnavailable)
		return
	}
	guard.Unfreeze(body.Email)
	h.loggerPort.Info(r.Context(), "Admin unfroze trading", "admin", adminEmail, "target", body.Email)
	h.logAdminAction(adminEmail, "unfreeze_trading", body.Email)
	h.writeJSON(w, map[string]string{"status": "ok", "message": "Trading unfrozen for " + body.Email})
}

// freezeTradingGlobal activates a server-wide trading freeze. Admin only.
func (h *Handler) freezeTradingGlobal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adminEmail := oauth.EmailFromContext(r.Context())
	if !h.isAdmin(adminEmail) {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	var body struct {
		Reason  string `json:"reason"`
		Confirm bool   `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if !body.Confirm {
		h.writeJSONError(w, http.StatusBadRequest, "This is a destructive action. Set confirm: true to proceed.")
		return
	}
	guard := h.manager.RiskGuard()
	if guard == nil {
		http.Error(w, "riskguard not enabled", http.StatusServiceUnavailable)
		return
	}
	reason := body.Reason
	if reason == "" {
		reason = "Admin emergency freeze"
	}
	guard.FreezeGlobal(adminEmail, reason)
	h.loggerPort.Warn(r.Context(), "Admin activated GLOBAL trading freeze", "admin", adminEmail, "reason", reason)
	h.logAdminAction(adminEmail, "freeze_global", reason)
	h.writeJSON(w, map[string]string{"status": "ok", "message": "Global trading freeze activated"})
}

// unfreezeTradingGlobal lifts the server-wide trading freeze. Admin only.
func (h *Handler) unfreezeTradingGlobal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adminEmail := oauth.EmailFromContext(r.Context())
	if !h.isAdmin(adminEmail) {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	guard := h.manager.RiskGuard()
	if guard == nil {
		http.Error(w, "riskguard not enabled", http.StatusServiceUnavailable)
		return
	}
	guard.UnfreezeGlobal()
	h.loggerPort.Info(r.Context(), "Admin lifted global trading freeze", "admin", adminEmail)
	h.logAdminAction(adminEmail, "unfreeze_global", "")
	h.writeJSON(w, map[string]string{"status": "ok", "message": "Global trading freeze lifted"})
}

// --- Key Registry endpoints (admin only) ---

// registryHandler handles GET (list) and POST (create) for /admin/ops/api/registry.
func (h *Handler) registryHandler(w http.ResponseWriter, r *http.Request) {
	email := oauth.EmailFromContext(r.Context())
	if !h.isAdmin(email) {
		http.Error(w, "admin access required", http.StatusForbidden)
		return
	}
	if h.registryStore == nil {
		h.writeJSONError(w, http.StatusServiceUnavailable, "registry not initialized")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.writeJSON(w, h.registryStore.List())

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
		var req struct {
			ID         string `json:"id"`
			APIKey     string `json:"api_key"`
			APISecret  string `json:"api_secret"`
			AssignedTo string `json:"assigned_to"`
			Label      string `json:"label"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			h.writeJSON(w, map[string]string{"error": "invalid JSON"})
			return
		}
		if req.ID == "" || req.APIKey == "" || req.APISecret == "" {
			w.WriteHeader(http.StatusBadRequest)
			h.writeJSON(w, map[string]string{"error": "id, api_key, and api_secret are required"})
			return
		}
		if err := h.manager.CommandBus().Dispatch(r.Context(), cqrs.AdminRegisterAppCommand{
			ID:           req.ID,
			APIKey:       req.APIKey,
			APISecret:    req.APISecret,
			AssignedTo:   req.AssignedTo,
			Label:        req.Label,
			RegisteredBy: email,
		}); err != nil {
			w.WriteHeader(http.StatusConflict)
			h.writeJSON(w, map[string]string{"error": err.Error()})
			return
		}
		h.loggerPort.Info(r.Context(), "Admin registered app in key registry", "admin", email, "id", req.ID, "api_key", req.APIKey[:8]+"...")
		h.logAdminAction(email, "register_app", req.ID+" ("+req.Label+")")
		w.WriteHeader(http.StatusCreated)
		h.writeJSON(w, map[string]string{"status": "ok", "id": req.ID})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// registryItemHandler handles PUT (update) and DELETE (remove) for /admin/ops/api/registry/{id}.
func (h *Handler) registryItemHandler(w http.ResponseWriter, r *http.Request) {
	email := oauth.EmailFromContext(r.Context())
	if !h.isAdmin(email) {
		http.Error(w, "admin access required", http.StatusForbidden)
		return
	}
	if h.registryStore == nil {
		h.writeJSONError(w, http.StatusServiceUnavailable, "registry not initialized")
		return
	}

	// Extract ID from URL: /admin/ops/api/registry/{id}
	id := strings.TrimPrefix(r.URL.Path, "/admin/ops/api/registry/")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		h.writeJSON(w, map[string]string{"error": "id is required in URL path"})
		return
	}

	switch r.Method {
	case http.MethodPut:
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
		var req struct {
			AssignedTo string `json:"assigned_to"`
			Label      string `json:"label"`
			Status     string `json:"status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			h.writeJSON(w, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := h.manager.CommandBus().Dispatch(r.Context(), cqrs.AdminUpdateRegistryCommand{
			ID:         id,
			AssignedTo: req.AssignedTo,
			Label:      req.Label,
			Status:     req.Status,
		}); err != nil {
			w.WriteHeader(http.StatusNotFound)
			h.writeJSON(w, map[string]string{"error": err.Error()})
			return
		}
		h.loggerPort.Info(r.Context(), "Admin updated registry entry", "admin", email, "id", id)
		h.logAdminAction(email, "update_registry", id)
		h.writeJSON(w, map[string]string{"status": "ok"})

	case http.MethodDelete:
		if err := h.manager.CommandBus().Dispatch(r.Context(), cqrs.AdminDeleteRegistryCommand{ID: id}); err != nil {
			w.WriteHeader(http.StatusNotFound)
			h.writeJSON(w, map[string]string{"error": err.Error()})
			return
		}
		h.loggerPort.Info(r.Context(), "Admin deleted registry entry", "admin", email, "id", id)
		h.logAdminAction(email, "delete_registry", id)
		h.writeJSON(w, map[string]string{"status": "ok"})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
