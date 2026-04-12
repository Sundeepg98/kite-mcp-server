package ops

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// --- Status types ---

type tokenStatus struct {
	Valid    bool   `json:"valid"`
	StoredAt string `json:"stored_at,omitempty"`
}

type credentialStatus struct {
	Stored bool   `json:"stored"`
	APIKey string `json:"api_key,omitempty"`
}

type tickerStatus struct {
	Running       bool `json:"running"`
	Subscriptions int  `json:"subscriptions"`
}

type statusResponse struct {
	Email       string           `json:"email"`
	Role        string           `json:"role,omitempty"`
	IsAdmin     bool             `json:"is_admin"`
	DevMode     bool             `json:"dev_mode,omitempty"`
	KiteToken   tokenStatus      `json:"kite_token"`
	Credentials credentialStatus `json:"credentials"`
	Ticker      tickerStatus     `json:"ticker"`
}

// status returns the connection and auth health check for the authenticated user.
func (d *DashboardHandler) status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	resp := statusResponse{
		Email:   email,
		DevMode: d.manager.DevMode(),
	}

	if d.adminCheck != nil && d.adminCheck(email) {
		resp.Role = "admin"
		resp.IsAdmin = true
	} else {
		resp.Role = "trader"
	}

	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	if hasToken {
		expired := kc.IsKiteTokenExpired(tokenEntry.StoredAt)
		resp.KiteToken = tokenStatus{
			Valid:    !expired,
			StoredAt: tokenEntry.StoredAt.Format("2006-01-02T15:04:05Z07:00"),
		}
	} else {
		resp.KiteToken = tokenStatus{Valid: false}
	}

	credEntry, hasCreds := d.manager.CredentialStore().Get(email)
	if hasCreds {
		resp.Credentials = credentialStatus{
			Stored: true,
			APIKey: credEntry.APIKey,
		}
	} else {
		resp.Credentials = credentialStatus{Stored: false}
	}

	tickerSt, err := d.manager.TickerService().GetStatus(email)
	if err != nil {
		d.logger.Error("Failed to get ticker status", "email", email, "error", err)
		resp.Ticker = tickerStatus{Running: false, Subscriptions: 0}
	} else {
		resp.Ticker = tickerStatus{
			Running:       tickerSt.Running,
			Subscriptions: len(tickerSt.Subscriptions),
		}
	}

	d.writeJSON(w, resp)
}

// safetyStatus returns riskguard status and effective limits for the authenticated user.
func (d *DashboardHandler) safetyStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	guard := d.manager.RiskGuard()
	if guard == nil {
		d.writeJSON(w, map[string]any{
			"enabled": false,
			"message": "RiskGuard is not enabled on this server.",
		})
		return
	}

	status := guard.GetUserStatus(email)
	limits := guard.GetEffectiveLimits(email)

	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	sessionActive := hasToken && !kc.IsKiteTokenExpired(tokenEntry.StoredAt)
	_, hasCreds := d.manager.CredentialStore().Get(email)

	d.writeJSON(w, map[string]any{
		"enabled": true,
		"status":  status,
		"limits": map[string]any{
			"max_single_order_inr":  limits.MaxSingleOrderINR,
			"max_orders_per_day":    limits.MaxOrdersPerDay,
			"max_orders_per_minute": limits.MaxOrdersPerMinute,
			"duplicate_window_secs": limits.DuplicateWindowSecs,
			"max_daily_value_inr":   limits.MaxDailyValueINR,
			"auto_freeze_on_limit":  limits.AutoFreezeOnLimitHit,
		},
		"sebi": map[string]any{
			"static_egress_ip": true,
			"session_active":   sessionActive,
			"credentials_set":  hasCreds,
			"order_tagging":    true,
			"audit_trail":      d.auditStore != nil,
		},
	})
}

// selfDeleteAccount handles POST /dashboard/api/account/delete.
// Permanently deletes all data for the authenticated user.
func (d *DashboardHandler) selfDeleteAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	var body struct {
		Confirm bool `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !body.Confirm {
		d.writeJSONError(w, http.StatusBadRequest, "confirmation_required",
			"This permanently deletes all your data. Send {\"confirm\": true} to proceed.")
		return
	}

	d.manager.CredentialStore().Delete(email)
	d.manager.TokenStore().Delete(email)

	if sm := d.manager.SessionManager(); sm != nil {
		sm.TerminateByEmail(email)
	}

	d.manager.AlertStore().DeleteByEmail(email)

	if ws := d.manager.WatchlistStore(); ws != nil {
		ws.DeleteByEmail(email)
	}

	if tsm := d.manager.AlertSvc().TrailingStopManager(); tsm != nil {
		tsm.CancelByEmail(email)
	}

	if pe := d.manager.PaperEngine(); pe != nil {
		if err := pe.Reset(email); err != nil {
			d.logger.Error("Failed to reset paper trading during self-delete", "email", email, "error", err)
		}
		if err := pe.Disable(email); err != nil {
			d.logger.Error("Failed to disable paper trading during self-delete", "email", email, "error", err)
		}
	}

	if us := d.manager.UserStore(); us != nil {
		if err := us.UpdateStatus(email, "offboarded"); err != nil {
			d.logger.Error("Failed to update user status during self-delete", "email", email, "error", err)
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "kite_jwt",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	d.logger.Info("User self-deleted account", "email", email)
	d.writeJSON(w, map[string]string{"status": "ok", "message": "Account deleted. All data has been removed."})
}

// maskKey returns a masked version of an API key (first 4 + **** + last 4).
func maskKey(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}

// selfManageCredentials handles GET/PUT/DELETE /dashboard/api/account/credentials.
func (d *DashboardHandler) selfManageCredentials(w http.ResponseWriter, r *http.Request) {
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	switch r.Method {
	case http.MethodGet:
		entry, ok := d.manager.CredentialStore().Get(email)
		if !ok {
			d.writeJSON(w, map[string]interface{}{
				"has_credentials": false,
			})
			return
		}
		d.writeJSON(w, map[string]interface{}{
			"has_credentials": true,
			"api_key":         maskKey(entry.APIKey),
			"has_secret":      entry.APISecret != "",
			"stored_at":       entry.StoredAt,
		})

	case http.MethodPut:
		var body struct {
			APIKey    string `json:"api_key"`
			APISecret string `json:"api_secret"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			d.writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid JSON body.")
			return
		}
		body.APIKey = strings.TrimSpace(body.APIKey)
		body.APISecret = strings.TrimSpace(body.APISecret)
		if body.APIKey == "" || body.APISecret == "" {
			d.writeJSONError(w, http.StatusBadRequest, "missing_fields", "Both api_key and api_secret are required.")
			return
		}

		d.manager.CredentialStore().Set(email, &kc.KiteCredentialEntry{
			APIKey:    body.APIKey,
			APISecret: body.APISecret,
		})
		d.manager.TokenStore().Delete(email)
		d.logger.Info("User updated credentials via dashboard", "email", email)
		d.writeJSON(w, map[string]string{
			"status":  "ok",
			"message": "Credentials updated. Your cached Kite token has been cleared; please re-authenticate.",
		})

	case http.MethodDelete:
		d.manager.CredentialStore().Delete(email)
		d.manager.TokenStore().Delete(email)
		d.logger.Info("User deleted credentials via dashboard", "email", email)
		d.writeJSON(w, map[string]string{
			"status":  "ok",
			"message": "Credentials removed. You will need to re-register to use the service.",
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
