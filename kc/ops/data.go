package ops

import (
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
	CachedTokens    int              `json:"cached_tokens"`
	UserCredentials int              `json:"user_credentials"`
	ToolUsage       map[string]int64 `json:"tool_usage"`
	DailyUsers      int64            `json:"daily_users"`
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
		ActiveSessions:  len(h.manager.SessionManager().ListActiveSessions()),
		ActiveTickers:   len(h.manager.TickerService().ListAll()),
		TotalAlerts:     total,
		ActiveAlerts:    active,
		CachedTokens:    len(h.manager.TokenStore().ListAll()),
		UserCredentials: len(h.manager.CredentialStore().ListAll()),
		ToolUsage:       toolUsage,
		DailyUsers:      dailyUsers,
	}
}

func (h *Handler) buildSessions() []SessionInfo {
	sessions := h.manager.SessionManager().ListActiveSessions()
	out := make([]SessionInfo, len(sessions))
	for i, s := range sessions {
		kd, ok := s.Data.(*kc.KiteSessionData)
		email := ""
		if ok && kd != nil {
			email = kd.Email
		}
		out[i] = SessionInfo{ID: s.ID, Email: email, CreatedAt: s.CreatedAt, ExpiresAt: s.ExpiresAt}
	}
	return out
}

func (h *Handler) buildTickers() TickerData {
	return TickerData{Tickers: h.manager.TickerService().ListAll()}
}

func (h *Handler) buildAlerts() AlertData {
	return AlertData{Alerts: h.manager.AlertStore().ListAll(), Telegram: h.manager.AlertStore().ListAllTelegram()}
}
