package ops

import (
	"fmt"
	"math"
	"time"
)

// ============================================================================
// Safety page
// ============================================================================

// SafetyFreezeData is the template data for user_safety_freeze.
type SafetyFreezeData struct {
	Enabled      bool
	Message      string
	IsFrozen     bool
	FrozenReason string
	FrozenBy     string
	FrozenAtFmt  string
}

// SafetyLimitItem represents one limit utilization bar.
type SafetyLimitItem struct {
	Name     string
	ValueFmt string
	Pct      int    // 0-100
	BarClass string // "safe", "warn", "danger"
	Static   bool   // if true, no bar is rendered
}

// SafetyLimitsData is the template data for user_safety_limits.
type SafetyLimitsData struct {
	Enabled bool
	Limits  []SafetyLimitItem
}

// SafetyCheck represents one SEBI compliance check.
type SafetyCheck struct {
	Label    string
	DotClass string // "ok", "warn", "off"
}

// SafetySEBIData is the template data for user_safety_sebi.
type SafetySEBIData struct {
	Enabled bool
	Checks  []SafetyCheck
}

func barClass(pct int) string {
	if pct >= 90 {
		return "danger"
	}
	if pct >= 70 {
		return "warn"
	}
	return "safe"
}

// safetyToFreezeData converts the safety API response into freeze banner data.
func safetyToFreezeData(data map[string]any) SafetyFreezeData {
	enabled, _ := data["enabled"].(bool)
	if !enabled {
		msg, _ := data["message"].(string)
		if msg == "" {
			msg = "Not enabled on this server."
		}
		return SafetyFreezeData{Enabled: false, Message: msg}
	}

	status, _ := data["status"].(map[string]any)
	if status == nil {
		return SafetyFreezeData{Enabled: true}
	}

	isFrozen, _ := status["is_frozen"].(bool)
	frozenReason, _ := status["frozen_reason"].(string)
	frozenBy, _ := status["frozen_by"].(string)
	frozenAtStr, _ := status["frozen_at"].(string)
	frozenAtFmt := ""
	if frozenAtStr != "" && frozenAtStr != "0001-01-01T00:00:00Z" {
		if t, err := time.Parse(time.RFC3339, frozenAtStr); err == nil {
			frozenAtFmt = fmtTimeDDMon(t)
		}
	}

	return SafetyFreezeData{
		Enabled:      true,
		IsFrozen:     isFrozen,
		FrozenReason: frozenReason,
		FrozenBy:     frozenBy,
		FrozenAtFmt:  frozenAtFmt,
	}
}

// safetyToLimitsData converts the safety API response into limit utilization bars.
func safetyToLimitsData(data map[string]any) SafetyLimitsData {
	enabled, _ := data["enabled"].(bool)
	if !enabled {
		return SafetyLimitsData{Enabled: false}
	}

	status, _ := data["status"].(map[string]any)
	limits, _ := data["limits"].(map[string]any)
	if status == nil || limits == nil {
		return SafetyLimitsData{Enabled: true}
	}

	dailyCount, _ := status["daily_order_count"].(float64)
	dailyValue, _ := status["daily_placed_value"].(float64)
	maxOrders, _ := limits["max_orders_per_day"].(float64)
	maxDailyVal, _ := limits["max_daily_value_inr"].(float64)
	maxSingle, _ := limits["max_single_order_inr"].(float64)
	maxPerMin, _ := limits["max_orders_per_minute"].(float64)
	dupWindow, _ := limits["duplicate_window_secs"].(float64)

	pctOrders := 0
	if maxOrders > 0 {
		pctOrders = int(math.Min(100, dailyCount/maxOrders*100))
	}
	pctValue := 0
	if maxDailyVal > 0 {
		pctValue = int(math.Min(100, dailyValue/maxDailyVal*100))
	}

	items := []SafetyLimitItem{
		{
			Name:     "Daily Orders",
			ValueFmt: fmt.Sprintf("%.0f / %.0f", dailyCount, maxOrders),
			Pct:      pctOrders,
			BarClass: barClass(pctOrders),
		},
		{
			Name:     "Daily Value",
			ValueFmt: fmtINRShort(dailyValue) + " / " + fmtINRShort(maxDailyVal),
			Pct:      pctValue,
			BarClass: barClass(pctValue),
		},
		{
			Name:     "Single Order Cap",
			ValueFmt: "Limit: " + fmtINRShort(maxSingle),
			Static:   true,
		},
		{
			Name:     "Rate Limit",
			ValueFmt: fmt.Sprintf("Limit: %.0f/min", maxPerMin),
			Static:   true,
		},
		{
			Name:     "Duplicate Window",
			ValueFmt: fmt.Sprintf("Limit: %.0fs", dupWindow),
			Static:   true,
		},
	}

	return SafetyLimitsData{Enabled: true, Limits: items}
}

// safetyToSEBIData converts the safety API response into SEBI compliance cards.
func safetyToSEBIData(data map[string]any) SafetySEBIData {
	enabled, _ := data["enabled"].(bool)
	if !enabled {
		return SafetySEBIData{Enabled: false}
	}

	sebi, _ := data["sebi"].(map[string]any)
	if sebi == nil {
		return SafetySEBIData{Enabled: true}
	}

	boolDot := func(key string) string {
		v, _ := sebi[key].(bool)
		if v {
			return "ok"
		}
		return "off"
	}

	return SafetySEBIData{
		Enabled: true,
		Checks: []SafetyCheck{
			{Label: "Static Egress IP", DotClass: boolDot("static_egress_ip")},
			{Label: "Session Active", DotClass: boolDot("session_active")},
			{Label: "Credentials Set", DotClass: boolDot("credentials_set")},
			{Label: "Order Tagging", DotClass: boolDot("order_tagging")},
			{Label: "Audit Trail", DotClass: boolDot("audit_trail")},
		},
	}
}
