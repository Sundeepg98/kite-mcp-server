package ops

import (
	"strings"
	"time"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/ticker"
)

type OverviewData struct {
	Version         string           `json:"version"`
	Uptime          string           `json:"uptime"`
	ActiveSessions  int              `json:"active_sessions"`
	ActiveTickers   int              `json:"active_tickers"`
	TotalAlerts     int              `json:"total_alerts"`
	ActiveAlerts    int              `json:"active_alerts"`
	CachedTokens       int              `json:"cached_tokens"`
	PerUserCredentials int              `json:"per_user_credentials"`
	ToolUsage          map[string]int64 `json:"tool_usage"`
	DailyUsers         int64            `json:"daily_users"`
}

type SessionInfo struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type TickerData struct {
	Tickers []ticker.UserTickerInfo `json:"tickers"`
}

type AlertData struct {
	Alerts   map[string][]*alerts.Alert `json:"alerts"`
	Telegram map[string]int64           `json:"telegram"`
}

func (h *Handler) buildOverview() OverviewData {
	allAlerts := h.manager.AlertStore().ListAll()
	var total, active int
	for _, list := range allAlerts {
		for _, a := range list {
			total++
			if !a.Triggered {
				active++
			}
		}
	}
	toolUsage := map[string]int64{}
	var dailyUsers int64
	if h.metrics != nil {
		toolUsage = h.metrics.GetAllCounters()
		dailyUsers = h.metrics.GetTodayUserCount()
	}
	return OverviewData{
		Version:         h.version,
		Uptime:          time.Since(h.startTime).Truncate(time.Second).String(),
		ActiveSessions:  len(h.buildSessions()),
		ActiveTickers:   len(h.manager.TickerService().ListAll()),
		TotalAlerts:     total,
		ActiveAlerts:    active,
		CachedTokens:       len(h.manager.TokenStore().ListAll()),
		PerUserCredentials: h.manager.CredentialStore().Count(),
		ToolUsage:          toolUsage,
		DailyUsers:         dailyUsers,
	}
}

// buildSessions returns a snapshot of active sessions.
// All fields are copied by value to prevent callers from mutating internal session state.
func (h *Handler) buildSessions() []SessionInfo {
	sessions := h.manager.SessionManager().ListActiveSessions()
	out := make([]SessionInfo, 0, len(sessions))
	for _, s := range sessions {
		// Copy scalar fields from the session to avoid holding pointers to internal state.
		id := s.ID
		createdAt := s.CreatedAt
		expiresAt := s.ExpiresAt

		kd, ok := s.Data.(*kc.KiteSessionData)
		email := ""
		if ok && kd != nil {
			email = kd.Email
		}
		// Skip orphan sessions from transport handshakes (no email = not authenticated)
		if email == "" {
			continue
		}
		out = append(out, SessionInfo{ID: id, Email: email, CreatedAt: createdAt, ExpiresAt: expiresAt})
	}
	return out
}

func (h *Handler) buildTickers() TickerData {
	return TickerData{Tickers: h.manager.TickerService().ListAll()}
}

func (h *Handler) buildAlerts() AlertData {
	return AlertData{Alerts: h.manager.AlertStore().ListAll(), Telegram: h.manager.AlertStore().ListAllTelegram()}
}

// --- Per-user filtered data builders (for non-admin users) ---

// buildOverviewForUser returns overview data scoped to a single user's email.
func (h *Handler) buildOverviewForUser(email string) OverviewData {
	emailLower := strings.ToLower(email)

	userAlerts := h.manager.AlertStore().List(emailLower)
	var total, active int
	for _, a := range userAlerts {
		total++
		if !a.Triggered {
			active++
		}
	}

	userSessions := h.buildSessionsForUser(email)
	userTickers := h.buildTickersForUser(email)

	// Check if user has a cached token
	cachedTokens := 0
	if _, ok := h.manager.TokenStore().Get(emailLower); ok {
		cachedTokens = 1
	}

	// Check if user has stored credentials
	perUserCreds := 0
	if _, ok := h.manager.CredentialStore().Get(emailLower); ok {
		perUserCreds = 1
	}

	return OverviewData{
		Version:            h.version,
		Uptime:             time.Since(h.startTime).Truncate(time.Second).String(),
		ActiveSessions:     len(userSessions),
		ActiveTickers:      len(userTickers.Tickers),
		TotalAlerts:        total,
		ActiveAlerts:       active,
		CachedTokens:       cachedTokens,
		PerUserCredentials: perUserCreds,
		ToolUsage:          nil, // tool usage is global, not per-user
		DailyUsers:         0,   // not applicable for per-user view
	}
}

// buildSessionsForUser returns sessions filtered to the given email.
func (h *Handler) buildSessionsForUser(email string) []SessionInfo {
	all := h.buildSessions()
	emailLower := strings.ToLower(email)
	out := make([]SessionInfo, 0)
	for _, s := range all {
		if strings.ToLower(s.Email) == emailLower {
			out = append(out, s)
		}
	}
	return out
}

// buildTickersForUser returns tickers filtered to the given email.
func (h *Handler) buildTickersForUser(email string) TickerData {
	all := h.manager.TickerService().ListAll()
	emailLower := strings.ToLower(email)
	out := make([]ticker.UserTickerInfo, 0)
	for _, t := range all {
		if strings.ToLower(t.Email) == emailLower {
			out = append(out, t)
		}
	}
	return TickerData{Tickers: out}
}

// buildAlertsForUser returns alerts and telegram data for a single user.
func (h *Handler) buildAlertsForUser(email string) AlertData {
	emailLower := strings.ToLower(email)
	userAlerts := h.manager.AlertStore().List(emailLower)
	alertMap := map[string][]*alerts.Alert{}
	if len(userAlerts) > 0 {
		alertMap[emailLower] = userAlerts
	}
	telegramMap := map[string]int64{}
	if chatID, ok := h.manager.AlertStore().GetTelegramChatID(emailLower); ok {
		telegramMap[emailLower] = chatID
	}
	return AlertData{Alerts: alertMap, Telegram: telegramMap}
}
