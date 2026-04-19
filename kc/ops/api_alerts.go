package ops

import (
	"math"
	"net/http"
	"time"

	"github.com/zerodha/kite-mcp-server/broker/zerodha"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// --- Alerts types ---

type alertsResponse struct {
	Active         any `json:"active"`
	Triggered      any `json:"triggered"`
	ActiveCount    int         `json:"active_count"`
	TriggeredCount int         `json:"triggered_count"`
}

type enrichedActiveAlert struct {
	ID             string   `json:"id"`
	Tradingsymbol  string   `json:"tradingsymbol"`
	Exchange       string   `json:"exchange"`
	Direction      string   `json:"direction"`
	TargetPrice    float64  `json:"target_price"`
	ReferencePrice float64  `json:"reference_price,omitempty"`
	CurrentPrice   float64  `json:"current_price,omitempty"`
	DistancePct    *float64 `json:"distance_pct,omitempty"`
	CreatedAt      string   `json:"created_at"`
}

type enrichedTriggeredAlert struct {
	ID                 string  `json:"id"`
	Tradingsymbol      string  `json:"tradingsymbol"`
	Exchange           string  `json:"exchange"`
	Direction          string  `json:"direction"`
	TargetPrice        float64 `json:"target_price"`
	ReferencePrice     float64 `json:"reference_price,omitempty"`
	TriggeredPrice     float64 `json:"triggered_price,omitempty"`
	TriggerDeltaPct    float64 `json:"trigger_delta_pct,omitempty"`
	CreatedAt          string  `json:"created_at"`
	TriggeredAt        string  `json:"triggered_at,omitempty"`
	TimeToTrigger      string  `json:"time_to_trigger,omitempty"`
	NotificationSentAt string  `json:"notification_sent_at,omitempty"`
	NotificationDelay  string  `json:"notification_delay,omitempty"`
}

type alertsSummary struct {
	ActiveCount      int    `json:"active_count"`
	TriggeredCount   int    `json:"triggered_count"`
	AvgTimeToTrigger string `json:"avg_time_to_trigger"`
}

type enrichedAlertsResponse struct {
	Active    []enrichedActiveAlert    `json:"active"`
	Triggered []enrichedTriggeredAlert `json:"triggered"`
	Summary   alertsSummary            `json:"summary"`
}

// alertCopy is an internal struct for processing alerts without importing the alerts package directly.
type alertCopy struct {
	ID                 string
	Tradingsymbol      string
	Exchange           string
	Direction          string
	TargetPrice        float64
	ReferencePrice     float64
	Triggered          bool
	CreatedAt          time.Time
	TriggeredAt        time.Time
	TriggeredPrice     float64
	NotificationSentAt time.Time
}

// --- P&L Chart types ---

type pnlChartPoint struct {
	Date       string  `json:"date"`
	NetPnL     float64 `json:"net_pnl"`
	Cumulative float64 `json:"cumulative"`
}

type pnlChartResponse struct {
	Points []pnlChartPoint `json:"points"`
	Period int             `json:"period"`
}

// alerts returns the authenticated user's price alerts, separated into active and triggered.
func (h *AlertsHandler) alerts(w http.ResponseWriter, r *http.Request) {
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

	allAlerts := d.manager.AlertStore().List(email)

	activeAlerts := make([]any, 0)
	triggeredAlerts := make([]any, 0)
	for _, a := range allAlerts {
		if a.Triggered {
			triggeredAlerts = append(triggeredAlerts, a)
		} else {
			activeAlerts = append(activeAlerts, a)
		}
	}

	d.writeJSON(w, alertsResponse{
		Active:         activeAlerts,
		Triggered:      triggeredAlerts,
		ActiveCount:    len(activeAlerts),
		TriggeredCount: len(triggeredAlerts),
	})
}

// alertsEnrichedAPI returns enriched alert data with lifecycle metrics and current prices.
// It also supports DELETE method to remove an active alert by ID.
func (h *AlertsHandler) alertsEnrichedAPI(w http.ResponseWriter, r *http.Request) {
	d := h.core
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	if r.Method == http.MethodDelete {
		alertID := r.URL.Query().Get("alert_id")
		if alertID == "" {
			http.Error(w, "alert_id required", http.StatusBadRequest)
			return
		}
		if err := d.manager.AlertStore().Delete(email, alertID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		d.writeJSON(w, map[string]string{"status": "ok"})
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	allAlerts := d.manager.AlertStore().List(email)

	var activeAlerts, triggeredAlerts []*alertCopy
	for _, a := range allAlerts {
		ac := &alertCopy{
			ID:                 a.ID,
			Tradingsymbol:      a.Tradingsymbol,
			Exchange:           a.Exchange,
			Direction:          string(a.Direction),
			TargetPrice:        a.TargetPrice,
			ReferencePrice:     a.ReferencePrice,
			Triggered:          a.Triggered,
			CreatedAt:          a.CreatedAt,
			TriggeredAt:        a.TriggeredAt,
			TriggeredPrice:     a.TriggeredPrice,
			NotificationSentAt: a.NotificationSentAt,
		}
		if a.Triggered {
			triggeredAlerts = append(triggeredAlerts, ac)
		} else {
			activeAlerts = append(activeAlerts, ac)
		}
	}

	var client *kiteconnect.Client
	credEntry, hasCreds := d.manager.CredentialStore().Get(email)
	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	if hasCreds && hasToken && !kc.IsKiteTokenExpired(tokenEntry.StoredAt) {
		client = d.manager.KiteClientFactory().NewClientWithToken(credEntry.APIKey, tokenEntry.AccessToken)
	}

	ltpMap := make(map[string]float64)
	if client != nil && len(activeAlerts) > 0 {
		instruments := make(map[string]bool)
		for _, a := range activeAlerts {
			key := a.Exchange + ":" + a.Tradingsymbol
			instruments[key] = true
		}
		instList := make([]string, 0, len(instruments))
		for k := range instruments {
			instList = append(instList, k)
		}
		ltpData, err := client.GetLTP(instList...)
		if err != nil {
			d.logger.Error("Failed to get LTP for alerts", "email", email, "error", err)
		} else {
			for k, v := range ltpData {
				if v.LastPrice > 0 {
					ltpMap[k] = v.LastPrice
				}
			}
		}
	}

	enrichedActive := make([]enrichedActiveAlert, 0, len(activeAlerts))
	for _, a := range activeAlerts {
		ea := enrichedActiveAlert{
			ID:             a.ID,
			Tradingsymbol:  a.Tradingsymbol,
			Exchange:       a.Exchange,
			Direction:      a.Direction,
			TargetPrice:    a.TargetPrice,
			ReferencePrice: a.ReferencePrice,
			CreatedAt:      a.CreatedAt.Format(time.RFC3339),
		}
		key := a.Exchange + ":" + a.Tradingsymbol
		if cp, ok := ltpMap[key]; ok {
			ea.CurrentPrice = cp
			if cp > 0 {
				dist := math.Round(math.Abs(cp-a.TargetPrice)/cp*10000) / 100
				ea.DistancePct = &dist
			}
		}
		enrichedActive = append(enrichedActive, ea)
	}

	enrichedTriggered := make([]enrichedTriggeredAlert, 0, len(triggeredAlerts))
	var totalTriggerDuration time.Duration
	triggerDurationCount := 0
	for _, a := range triggeredAlerts {
		et := enrichedTriggeredAlert{
			ID:             a.ID,
			Tradingsymbol:  a.Tradingsymbol,
			Exchange:       a.Exchange,
			Direction:      a.Direction,
			TargetPrice:    a.TargetPrice,
			ReferencePrice: a.ReferencePrice,
			TriggeredPrice: a.TriggeredPrice,
			CreatedAt:      a.CreatedAt.Format(time.RFC3339),
		}
		if a.TriggeredPrice > 0 && a.TargetPrice > 0 {
			et.TriggerDeltaPct = math.Round(math.Abs(a.TriggeredPrice-a.TargetPrice)/a.TargetPrice*10000) / 100
		}
		if !a.TriggeredAt.IsZero() {
			et.TriggeredAt = a.TriggeredAt.Format(time.RFC3339)
			ttd := a.TriggeredAt.Sub(a.CreatedAt)
			et.TimeToTrigger = formatDuration(ttd)
			totalTriggerDuration += ttd
			triggerDurationCount++
		}
		if !a.NotificationSentAt.IsZero() {
			et.NotificationSentAt = a.NotificationSentAt.Format(time.RFC3339)
			if !a.TriggeredAt.IsZero() {
				nd := a.NotificationSentAt.Sub(a.TriggeredAt)
				et.NotificationDelay = formatDuration(nd)
			}
		}
		enrichedTriggered = append(enrichedTriggered, et)
	}

	summary := alertsSummary{
		ActiveCount:    len(enrichedActive),
		TriggeredCount: len(enrichedTriggered),
	}
	if triggerDurationCount > 0 {
		avg := totalTriggerDuration / time.Duration(triggerDurationCount)
		summary.AvgTimeToTrigger = formatDuration(avg)
	}

	d.writeJSON(w, enrichedAlertsResponse{
		Active:    enrichedActive,
		Triggered: enrichedTriggered,
		Summary:   summary,
	})
}

// pnlChartAPI returns daily P&L data for charting on the portfolio page.
// Query params: period (days, default 30)
func (h *AlertsHandler) pnlChartAPI(w http.ResponseWriter, r *http.Request) {
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

	alertDB := d.manager.AlertDB()
	if alertDB == nil {
		d.writeJSON(w, pnlChartResponse{Points: []pnlChartPoint{}, Period: 0})
		return
	}

	period := intParam(r, "period", 90)
	if period < 1 {
		period = 90
	}
	if period > 365 {
		period = 365
	}

	toDate := time.Now().Format("2006-01-02")
	fromDate := time.Now().AddDate(0, 0, -period).Format("2006-01-02")

	entries, err := alertDB.LoadDailyPnL(email, fromDate, toDate)
	if err != nil {
		d.logger.Error("Failed to load daily P&L for chart", "email", email, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	points := make([]pnlChartPoint, 0, len(entries))
	var cumulative float64
	for _, e := range entries {
		cumulative += e.NetPnL
		points = append(points, pnlChartPoint{
			Date:       e.Date,
			NetPnL:     math.Round(e.NetPnL*100) / 100,
			Cumulative: math.Round(cumulative*100) / 100,
		})
	}

	d.writeJSON(w, pnlChartResponse{
		Points: points,
		Period: period,
	})
}
