package ops

import (
	"math"
	"net/http"
	"time"
)

// serveAlertsPageSSR renders the user alerts page with active / triggered tabs.
func (h *AlertsHandler) serveAlertsPageSSR(w http.ResponseWriter, r *http.Request) {
	d := h.core
	if d.alertsTmpl == nil {
		d.servePageFallback(w, "alerts.html")
		return
	}

	email, role, tokenValid := d.userContext(r)
	data := AlertsPageData{
		Email:      email,
		Role:       role,
		TokenValid: tokenValid,
		UpdatedAt:  nowTimestamp(),
	}

	if email != "" {
		allAlerts := d.manager.AlertStore().List(email)
		var activeAlerts, triggeredAlerts []*alertCopy
		for _, a := range allAlerts {
			ac := &alertCopy{
				ID: a.ID, Tradingsymbol: a.Tradingsymbol, Exchange: a.Exchange,
				Direction: string(a.Direction), TargetPrice: a.TargetPrice,
				ReferencePrice: a.ReferencePrice, Triggered: a.Triggered,
				CreatedAt: a.CreatedAt, TriggeredAt: a.TriggeredAt,
				TriggeredPrice: a.TriggeredPrice, NotificationSentAt: a.NotificationSentAt,
			}
			if a.Triggered {
				triggeredAlerts = append(triggeredAlerts, ac)
			} else {
				activeAlerts = append(activeAlerts, ac)
			}
		}

		ltpMap := make(map[string]float64)
		if tokenValid {
			credEntry, hasCreds := d.manager.CredentialStore().Get(email)
			tokenEntry, hasToken := d.manager.TokenStore().Get(email)
			if hasCreds && hasToken {
				client := d.manager.KiteClientFactory().NewClientWithToken(credEntry.APIKey, tokenEntry.AccessToken)
				instruments := make(map[string]bool)
				for _, a := range activeAlerts {
					key := a.Exchange + ":" + a.Tradingsymbol
					instruments[key] = true
				}
				if len(instruments) > 0 {
					instList := make([]string, 0, len(instruments))
					for k := range instruments {
						instList = append(instList, k)
					}
					ltpData, err := client.GetLTP(instList...)
					if err == nil {
						for k, v := range ltpData {
							if v.LastPrice > 0 {
								ltpMap[k] = v.LastPrice
							}
						}
					}
				}
			}
		}

		enrichedActive := make([]enrichedActiveAlert, 0, len(activeAlerts))
		for _, a := range activeAlerts {
			ea := enrichedActiveAlert{
				ID: a.ID, Tradingsymbol: a.Tradingsymbol, Exchange: a.Exchange,
				Direction: a.Direction, TargetPrice: a.TargetPrice,
				ReferencePrice: a.ReferencePrice, CreatedAt: a.CreatedAt.Format(time.RFC3339),
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
				ID: a.ID, Tradingsymbol: a.Tradingsymbol, Exchange: a.Exchange,
				Direction: a.Direction, TargetPrice: a.TargetPrice,
				ReferencePrice: a.ReferencePrice, TriggeredPrice: a.TriggeredPrice,
				CreatedAt: a.CreatedAt.Format(time.RFC3339),
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
					et.NotificationDelay = formatDuration(a.NotificationSentAt.Sub(a.TriggeredAt))
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

		var nearest *enrichedActiveAlert
		for i := range enrichedActive {
			if enrichedActive[i].DistancePct != nil {
				if nearest == nil || *enrichedActive[i].DistancePct < *nearest.DistancePct {
					nearest = &enrichedActive[i]
				}
			}
		}

		data.Stats = alertsToStatsData(summary, nearest)
		data.Active = alertsToActiveData(enrichedActive)
		data.Triggered = alertsToTriggeredData(enrichedTriggered)
	} else {
		data.Stats = alertsToStatsData(alertsSummary{}, nil)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := d.alertsTmpl.Execute(w, data); err != nil {
		d.loggerPort.Error(r.Context(), "Failed to render alerts page", err)
	}
}
