package ops

import (
	"fmt"
	"net/http"

	"github.com/zerodha/kite-mcp-server/kc"
)

// serveSafetyPageSSR renders the user safety / risk limits page.
func (h *SafetyHandler) serveSafetyPageSSR(w http.ResponseWriter, r *http.Request) {
	d := h.core
	if d.safetyTmpl == nil {
		d.servePageFallback(w, "safety.html")
		return
	}

	email, role, tokenValid := d.userContext(r)
	data := SafetyPageData{
		Email:      email,
		Role:       role,
		TokenValid: tokenValid,
		UpdatedAt:  nowTimestamp(),
	}

	safetyData := h.buildSafetyData(email)
	data.Freeze = safetyToFreezeData(safetyData)
	data.Limits = safetyToLimitsData(safetyData)
	data.SEBI = safetyToSEBIData(safetyData)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := d.safetyTmpl.Execute(w, data); err != nil {
		d.logger.Error("Failed to render safety page", "error", err)
	}
}

// serveSafetyFragment renders safety partials for htmx refresh.
func (h *SafetyHandler) serveSafetyFragment(w http.ResponseWriter, r *http.Request) {
	d := h.core
	if d.fragmentTmpl == nil {
		http.Error(w, "templates not initialized", http.StatusInternalServerError)
		return
	}

	email, _, _ := d.userContext(r)
	safetyData := h.buildSafetyData(email)

	freeze := safetyToFreezeData(safetyData)
	limitsData := safetyToLimitsData(safetyData)
	sebiData := safetyToSEBIData(safetyData)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if html, err := renderUserFragment(d.fragmentTmpl, "user_safety_freeze", freeze); err == nil {
		fmt.Fprint(w, html)
	}
	fmt.Fprint(w, `<div class="section-header">Limit Utilization</div>`)
	if html, err := renderUserFragment(d.fragmentTmpl, "user_safety_limits", limitsData); err == nil {
		fmt.Fprint(w, html)
	}
	fmt.Fprint(w, `<div class="section-header">SEBI Compliance</div>`)
	if html, err := renderUserFragment(d.fragmentTmpl, "user_safety_sebi", sebiData); err == nil {
		fmt.Fprint(w, html)
	}
}

// buildSafetyData assembles the safety map used by both the safety page and
// its htmx fragment — riskguard status, effective limits, and SEBI compliance.
func (h *SafetyHandler) buildSafetyData(email string) map[string]any {
	d := h.core
	guard := d.manager.RiskGuard()
	if guard == nil {
		return map[string]any{
			"enabled": false,
			"message": "RiskGuard is not enabled on this server.",
		}
	}
	if email == "" {
		return map[string]any{"enabled": true}
	}

	status := guard.GetUserStatus(email)
	limits := guard.GetEffectiveLimits(email)

	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	sessionActive := hasToken && !kc.ToDomainSession(email, tokenEntry).IsExpired()
	_, hasCreds := d.manager.CredentialStore().Get(email)

	return map[string]any{
		"enabled": true,
		"status":  status,
		"limits": map[string]any{
			"max_single_order_inr":  limits.MaxSingleOrderINR,
			"max_orders_per_day":    limits.MaxOrdersPerDay,
			"max_orders_per_minute": limits.MaxOrdersPerMinute,
			"duplicate_window_secs": limits.DuplicateWindowSecs,
			"max_daily_value_inr":   limits.MaxDailyValueINR,
		},
		"sebi": map[string]any{
			"static_egress_ip": true,
			"session_active":   sessionActive,
			"credentials_set":  hasCreds,
			"order_tagging":    true,
			"audit_trail":      d.auditStore != nil,
		},
	}
}
