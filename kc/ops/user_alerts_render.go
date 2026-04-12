package ops

import (
	"fmt"
	"strconv"
	"time"
)

// ============================================================================
// Alerts page
// ============================================================================

// AlertsStatsData is the template data for user_alerts_stats.
type AlertsStatsData struct {
	Cards []UserStatCard
}

// ActiveAlertRow is a single row in the active alerts table.
type ActiveAlertRow struct {
	ID            string
	Tradingsymbol string
	Direction     string
	DirBadge      string // "green", "red", "amber"
	TargetFmt     string
	CurrentFmt    string
	DistFmt       string
	DistClass     string // "dist-green", "dist-amber", "dist-red"
	CreatedFmt    string
}

// AlertsActiveData is the template data for user_alerts_active.
type AlertsActiveData struct {
	Alerts []ActiveAlertRow
}

// TriggeredAlertRow is a single row in the triggered alerts timeline.
type TriggeredAlertRow struct {
	Tradingsymbol     string
	Direction         string
	DirBadge          string
	TargetFmt         string
	CreatedFmt        string
	TriggeredFmt      string
	TimeToTrigger     string
	NotificationFmt   string
	NotificationDelay string
}

// AlertsTriggeredData is the template data for user_alerts_triggered.
type AlertsTriggeredData struct {
	Alerts []TriggeredAlertRow
}

func dirBadge(dir string) string {
	switch dir {
	case "above", "rise_pct":
		return "green"
	case "below", "drop_pct":
		return "red"
	default:
		return "amber"
	}
}

func distanceClass(pct float64) string {
	if pct < 2 {
		return "dist-green"
	}
	if pct < 5 {
		return "dist-amber"
	}
	return "dist-red"
}

// alertsToStatsData converts enriched alerts summary into stat cards.
func alertsToStatsData(summary alertsSummary, nearest *enrichedActiveAlert) AlertsStatsData {
	nearestVal := "--"
	nearestSub := ""
	if nearest != nil {
		nearestVal = nearest.Tradingsymbol
		if nearest.DistancePct != nil {
			nearestSub = fmt.Sprintf("%.1f%% away", *nearest.DistancePct)
		}
	}

	avgTime := summary.AvgTimeToTrigger
	if avgTime == "" {
		avgTime = "--"
	}

	return AlertsStatsData{Cards: []UserStatCard{
		{Label: "Active Alerts", Value: strconv.Itoa(summary.ActiveCount)},
		{Label: "Triggered", Value: strconv.Itoa(summary.TriggeredCount)},
		{Label: "Avg Time to Trigger", Value: avgTime},
		{Label: "Nearest Alert", Value: nearestVal, Sub: nearestSub},
	}}
}

// alertsToActiveData converts enriched active alerts into template rows.
func alertsToActiveData(active []enrichedActiveAlert) AlertsActiveData {
	rows := make([]ActiveAlertRow, 0, len(active))
	for _, a := range active {
		distFmt := "--"
		distCls := ""
		if a.DistancePct != nil {
			distFmt = fmt.Sprintf("%.1f%%", *a.DistancePct)
			distCls = distanceClass(*a.DistancePct)
		}
		t, _ := time.Parse(time.RFC3339, a.CreatedAt)
		rows = append(rows, ActiveAlertRow{
			ID:            a.ID,
			Tradingsymbol: a.Tradingsymbol,
			Direction:     a.Direction,
			DirBadge:      dirBadge(a.Direction),
			TargetFmt:     fmtPrice(a.TargetPrice),
			CurrentFmt:    fmtPrice(a.CurrentPrice),
			DistFmt:       distFmt,
			DistClass:     distCls,
			CreatedFmt:    fmtTimeDDMon(t),
		})
	}
	return AlertsActiveData{Alerts: rows}
}

// alertsToTriggeredData converts enriched triggered alerts into template rows.
func alertsToTriggeredData(triggered []enrichedTriggeredAlert) AlertsTriggeredData {
	rows := make([]TriggeredAlertRow, 0, len(triggered))
	for _, a := range triggered {
		ct, _ := time.Parse(time.RFC3339, a.CreatedAt)
		tt, _ := time.Parse(time.RFC3339, a.TriggeredAt)
		notifFmt := ""
		if a.NotificationSentAt != "" {
			nt, _ := time.Parse(time.RFC3339, a.NotificationSentAt)
			if !nt.IsZero() {
				notifFmt = fmtTimeDDMon(nt)
			}
		}
		rows = append(rows, TriggeredAlertRow{
			Tradingsymbol:     a.Tradingsymbol,
			Direction:         a.Direction,
			DirBadge:          dirBadge(a.Direction),
			TargetFmt:         fmtPrice(a.TargetPrice),
			CreatedFmt:        fmtTimeDDMon(ct),
			TriggeredFmt:      fmtTimeDDMon(tt),
			TimeToTrigger:     a.TimeToTrigger,
			NotificationFmt:   notifFmt,
			NotificationDelay: a.NotificationDelay,
		})
	}
	return AlertsTriggeredData{Alerts: rows}
}
