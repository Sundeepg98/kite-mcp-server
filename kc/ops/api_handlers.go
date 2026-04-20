package ops

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
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
		expired := kc.ToDomainSession(email, tokenEntry).IsExpired()
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
func (h *SafetyHandler) safetyStatus(w http.ResponseWriter, r *http.Request) {
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
	sessionActive := hasToken && !kc.ToDomainSession(email, tokenEntry).IsExpired()
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
func (h *AccountHandler) selfDeleteAccount(w http.ResponseWriter, r *http.Request) {
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

	var body struct {
		Confirm bool `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !body.Confirm {
		d.writeJSONError(w, http.StatusBadRequest, "confirmation_required",
			"This permanently deletes all your data. Send {\"confirm\": true} to proceed.")
		return
	}

	// Phase B-Audit (residual): self-delete routes through the CommandBus
	// as a single DeleteMyAccountCommand dispatch. The use case
	// (kc/usecases/account_usecases.go) owns the full teardown:
	// credentials, tokens, sessions, alerts, watchlists, trailing stops,
	// paper trading reset+disable, and offboarded user-status write.
	// Replaces ~30 lines of manual orchestration while gaining the bus's
	// audit/observability layer.
	if _, err := d.manager.CommandBus().DispatchWithResult(r.Context(), cqrs.DeleteMyAccountCommand{
		Email: email,
	}); err != nil {
		d.writeJSONError(w, http.StatusBadRequest, "delete_failed", err.Error())
		return
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
func (h *AccountHandler) selfManageCredentials(w http.ResponseWriter, r *http.Request) {
	d := h.core
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	switch r.Method {
	case http.MethodGet:
		entry, ok := d.manager.CredentialStore().Get(email)
		if !ok {
			d.writeJSON(w, map[string]any{
				"has_credentials": false,
			})
			return
		}
		d.writeJSON(w, map[string]any{
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

		// Phase B-Audit #25: dashboard credential PUT routes through the
		// CommandBus — UpdateMyCredentialsUseCase owns both store writes.
		if _, err := d.manager.CommandBus().DispatchWithResult(r.Context(), cqrs.UpdateMyCredentialsCommand{
			Email:     email,
			APIKey:    body.APIKey,
			APISecret: body.APISecret,
		}); err != nil {
			d.writeJSONError(w, http.StatusBadRequest, "update_failed", err.Error())
			return
		}
		d.logger.Info("User updated credentials via dashboard", "email", email)
		d.writeJSON(w, map[string]string{
			"status":  "ok",
			"message": "Credentials updated. Your cached Kite token has been cleared; please re-authenticate.",
		})

	case http.MethodDelete:
		// Phase B-Audit #25: dashboard credential DELETE routes through
		// the narrow RevokeCredentialsCommand — credentials + cached
		// token only. Account-scope teardown (alerts/watchlists/etc.)
		// lives on /dashboard/api/account/delete, not here.
		if _, err := d.manager.CommandBus().DispatchWithResult(r.Context(), cqrs.RevokeCredentialsCommand{
			Email:  email,
			Reason: "user_self",
		}); err != nil {
			d.writeJSONError(w, http.StatusBadRequest, "revoke_failed", err.Error())
			return
		}
		d.logger.Info("User deleted credentials via dashboard", "email", email)
		d.writeJSON(w, map[string]string{
			"status":  "ok",
			"message": "Credentials removed. You will need to re-register to use the service.",
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// --- Connections (active MCP sessions) ---
//
// The dashboard Connections card answers "who is connected to my account right
// now?" — a feature absent from Linear/Sentry/etc. We merge two data sources:
//
//  1. SessionRegistry.ListActiveSessions() — authoritative for in-memory MCP
//     sessions. Populated when a session record gains a KiteSessionData (first
//     tool call that touches the Kite client), so fresh OAuth-only clients may
//     be absent here until they make a real tool call.
//  2. Audit log — recent tool calls grouped by session_id. Surfaces activity
//     for sessions that are not yet in the registry (the "lazy population"
//     case) and enriches registered sessions with `tool_calls_today` and
//     `last_tool_called`.
//
// If the registry has zero entries but the audit log has today's activity,
// the response still lists those sessions as "recent activity" rows so the
// user sees something meaningful.

// connectionEntry is the per-session payload returned by /dashboard/api/connections.
type connectionEntry struct {
	SessionIDShort       string `json:"session_id_short"`
	ClientHint           string `json:"client_hint"`
	CreatedAt            string `json:"created_at,omitempty"`
	LastActivityAt       string `json:"last_activity_at,omitempty"`
	LastActivityRelative string `json:"last_activity_relative,omitempty"`
	ToolCallsToday       int    `json:"tool_calls_today"`
	LastToolCalled       string `json:"last_tool_called,omitempty"`
}

type connectionsResponse struct {
	Connections []connectionEntry `json:"connections"`
	Total       int               `json:"total"`
	Message     string            `json:"message,omitempty"`
}

// connectionsIDHead/Tail control the shortened session ID display:
// `kitemcp-abc1…d4f2` — same convention used by list_mcp_sessions.
const (
	connectionsIDHead = 12
	connectionsIDTail = 4
)

// truncateConnectionID renders a session ID as `<first-12>…<last-4>`.
// Short IDs are returned unchanged.
func truncateConnectionID(id string) string {
	if len(id) <= connectionsIDHead+connectionsIDTail {
		return id
	}
	return id[:connectionsIDHead] + "…" + id[len(id)-connectionsIDTail:]
}

// relativeTime formats a duration since t as a short "3 min ago"-style string.
// Returns "" for zero time.
func relativeTime(t, now time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := now.Sub(t)
	d = max(d, 0)
	switch {
	case d < time.Minute:
		secs := int(d.Seconds())
		if secs <= 1 {
			return "just now"
		}
		return fmt.Sprintf("%d sec ago", secs)
	case d < time.Hour:
		mins := int(d.Minutes())
		if mins == 1 {
			return "1 min ago"
		}
		return fmt.Sprintf("%d min ago", mins)
	case d < 24*time.Hour:
		hrs := int(d.Hours())
		if hrs == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hrs)
	default:
		days := int(d / (24 * time.Hour))
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	}
}

// connections returns the authenticated user's active MCP sessions, merged
// with recent audit activity. This powers the "Connections" card on the
// dashboard — the integration-feel feature that answers "what's connected
// to my account right now?".
func (d *DashboardHandler) connections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}
	emailLower := strings.ToLower(email)

	now := time.Now()
	todayStart := now.Truncate(24 * time.Hour)

	// --- Data source 1: active in-memory sessions for this user. ---
	type sessionAgg struct {
		sessionID  string
		clientHint string
		createdAt  time.Time
		fromReg    bool
	}
	agg := map[string]*sessionAgg{}

	if reg := d.manager.SessionManager(); reg != nil {
		for _, s := range reg.ListActiveSessions() {
			if s == nil {
				continue
			}
			kd, ok := s.Data.(*kc.KiteSessionData)
			if !ok || kd == nil {
				continue
			}
			if !strings.EqualFold(kd.Email, emailLower) {
				continue
			}
			hint := s.ClientHint
			if hint == "" {
				hint = "Unknown"
			}
			agg[s.ID] = &sessionAgg{
				sessionID:  s.ID,
				clientHint: hint,
				createdAt:  s.CreatedAt,
				fromReg:    true,
			}
		}
	}

	// --- Data source 2: today's audit entries grouped by session_id. ---
	// Per-session totals, last-activity timestamp and last-called tool are
	// computed from the audit log since it already has the data we need and
	// avoids hitting the DB per session.
	type sessionStats struct {
		count      int
		lastAt     time.Time
		lastTool   string
		earliestAt time.Time
	}
	stats := map[string]*sessionStats{}

	if d.auditStore != nil {
		// A reasonable cap; most users have at most a few sessions. 500 is
		// enough to cover a high-volume day without dragging the dashboard.
		opts := audit.ListOptions{
			Limit: 500,
			Since: todayStart,
		}
		calls, _, err := d.auditStore.List(email, opts)
		if err != nil {
			d.logger.Warn("connections: audit list failed", "email", email, "error", err)
		}
		for _, c := range calls {
			if c == nil || c.SessionID == "" {
				continue
			}
			st, ok := stats[c.SessionID]
			if !ok {
				st = &sessionStats{}
				stats[c.SessionID] = st
			}
			st.count++
			if c.StartedAt.After(st.lastAt) {
				st.lastAt = c.StartedAt
				st.lastTool = c.ToolName
			}
			if st.earliestAt.IsZero() || c.StartedAt.Before(st.earliestAt) {
				st.earliestAt = c.StartedAt
			}
		}
	}

	// --- Merge audit-only sessions (registry missed them). ---
	// SessionRegistry only populates on first tool call that creates the
	// Kite client. If the audit log has today's activity for a session that
	// isn't in the registry, surface it as an "audit-only" row so the user
	// still sees the connection.
	for sid := range stats {
		if _, ok := agg[sid]; ok {
			continue
		}
		agg[sid] = &sessionAgg{
			sessionID:  sid,
			clientHint: "Unknown",
			createdAt:  stats[sid].earliestAt, // best-effort: first seen today
			fromReg:    false,
		}
	}

	// --- Build the response payload. ---
	entries := make([]connectionEntry, 0, len(agg))
	for _, s := range agg {
		e := connectionEntry{
			SessionIDShort: truncateConnectionID(s.sessionID),
			ClientHint:     s.clientHint,
		}
		if !s.createdAt.IsZero() {
			e.CreatedAt = s.createdAt.UTC().Format(time.RFC3339)
		}
		if !s.fromReg {
			// Audit-only: session registry didn't have this one. Make it
			// obvious to the UI so it can show a subtle badge.
			e.SessionIDShort = "recent activity"
		}
		if st, ok := stats[s.sessionID]; ok {
			e.ToolCallsToday = st.count
			e.LastToolCalled = st.lastTool
			if !st.lastAt.IsZero() {
				e.LastActivityAt = st.lastAt.UTC().Format(time.RFC3339)
				e.LastActivityRelative = relativeTime(st.lastAt, now)
			}
		}
		entries = append(entries, e)
	}

	// Sort most-recent-activity first; fall back to created_at.
	sort.Slice(entries, func(i, j int) bool {
		li, _ := time.Parse(time.RFC3339, entries[i].LastActivityAt)
		lj, _ := time.Parse(time.RFC3339, entries[j].LastActivityAt)
		if !li.Equal(lj) {
			return li.After(lj)
		}
		ci, _ := time.Parse(time.RFC3339, entries[i].CreatedAt)
		cj, _ := time.Parse(time.RFC3339, entries[j].CreatedAt)
		return ci.After(cj)
	})

	resp := connectionsResponse{
		Connections: entries,
		Total:       len(entries),
	}
	if len(entries) == 0 {
		resp.Connections = []connectionEntry{}
		resp.Message = "No active MCP connections — pair a client at /"
	}

	d.writeJSON(w, resp)
}
