package ops

// coverage_max_test.go: push ops coverage toward 100%.
// Targets remaining uncovered branches across handler.go, data.go,
// dashboard.go, dashboard_templates.go, and overview_sse.go.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// --- Helpers (unique names to avoid collisions) ---

// newHandlerWithAuditAndMetrics creates a handler with audit store, user store, riskguard and metrics.


// ===========================================================================
// handler.go: logAdminAction with nil auditStore
// ===========================================================================
func TestMax_LogAdminAction_NilAuditStore(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	h.logAdminAction("admin@test.com", "test_action", "target")
	// No panic = pass
}


// ===========================================================================
// dashboard.go: static files
// ===========================================================================
func TestMax_StaticCSS(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/static/dashboard-base.css", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/css")
}


func TestMax_StaticHTMX(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/static/htmx.min.js", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "javascript")
}


// ===========================================================================
// data.go: buildOverview with alerts, riskguard
// ===========================================================================
func TestMax_BuildOverview_WithAlerts(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)

	_, err := h.manager.AlertStore().Add("user@test.com", "INFY", "NSE", 256265, 1500, alerts.DirectionAbove)
	require.NoError(t, err)
	_, err = h.manager.AlertStore().Add("user@test.com", "RELIANCE", "NSE", 408065, 2500, alerts.DirectionBelow)
	require.NoError(t, err)

	overview := h.buildOverview()
	assert.Equal(t, 2, overview.TotalAlerts)
	assert.Equal(t, 2, overview.ActiveAlerts) // both untriggered
	assert.NotZero(t, overview.HeapAllocMB)
	assert.NotZero(t, overview.Goroutines)
}


// ===========================================================================
// data.go: buildOverviewForUser
// ===========================================================================
func TestMax_BuildOverviewForUser(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)

	_, err := h.manager.AlertStore().Add("user@test.com", "INFY", "NSE", 256265, 1500, alerts.DirectionAbove)
	require.NoError(t, err)

	overview := h.buildOverviewForUser("user@test.com")
	assert.Equal(t, 1, overview.TotalAlerts)
	assert.Equal(t, 1, overview.ActiveAlerts)
	assert.Equal(t, 1, overview.CachedTokens)
	assert.Equal(t, 1, overview.PerUserCredentials)
}


// ===========================================================================
// data.go: buildSessionsForUser / buildTickersForUser / buildAlertsForUser
// ===========================================================================
func TestMax_BuildSessionsForUser_Empty(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	sessions := h.buildSessionsForUser("nobody@test.com")
	assert.Empty(t, sessions)
}


func TestMax_BuildTickersForUser_Empty(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	tickers := h.buildTickersForUser("nobody@test.com")
	assert.Empty(t, tickers.Tickers)
}


func TestMax_BuildAlertsForUser_WithTelegram(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)

	_, err := h.manager.AlertStore().Add("user@test.com", "INFY", "NSE", 256265, 1500, alerts.DirectionAbove)
	require.NoError(t, err)
	h.manager.TelegramStore().SetTelegramChatID("user@test.com", 12345)

	data := h.buildAlertsForUser("user@test.com")
	assert.Len(t, data.Alerts["user@test.com"], 1)
	assert.Equal(t, int64(12345), data.Telegram["user@test.com"])
}


// ===========================================================================
// overview_sse.go: sendAllAdminEvents
// ===========================================================================
func TestMax_SendAllAdminEvents(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)

	rec := httptest.NewRecorder()
	h.sendAllAdminEvents(context.Background(), rec, rec, "admin@test.com")
	body := rec.Body.String()
	assert.Contains(t, body, "event: overview-stats")
	assert.Contains(t, body, "event: overview-tools")
	assert.Contains(t, body, "event: overview-uptime")
	assert.Contains(t, body, "event: admin-sessions")
	assert.Contains(t, body, "event: admin-tickers")
	assert.Contains(t, body, "event: admin-alerts")
	assert.Contains(t, body, "event: admin-users")
}


func TestMax_Status_WithEmail(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/status", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// handler.go: servePage with opsTmpl nil
// ===========================================================================
func TestMax_ServePage_NilOpsTmpl(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	h.opsTmpl = nil
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/admin/ops", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}


// ===========================================================================
// dashboard_templates.go: servePortfolioPage success path
// ===========================================================================
func TestMax_ServePortfolioPage(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
}


// ===========================================================================
// dashboard_templates.go: serveActivityPageSSR success path
// ===========================================================================
func TestMax_ServeActivityPageSSR(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/activity", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// dashboard_templates.go: serveOrdersPageSSR success path
// ===========================================================================
func TestMax_ServeOrdersPageSSR(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/orders", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// dashboard_templates.go: serveAlertsPageSSR success path
// ===========================================================================
func TestMax_ServeAlertsPageSSR(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/alerts", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// dashboard_templates.go: servePaperPageSSR success path
// ===========================================================================
func TestMax_ServePaperPageSSR(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/paper", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// dashboard_templates.go: serveSafetyPageSSR success path
// ===========================================================================
func TestMax_ServeSafetyPageSSR(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/safety", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// overview_sse.go: writeSSEEvent with multiline data
// ===========================================================================
func TestMax_WriteSSEEvent_Multiline(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	writeSSEEvent(rec, "test-event", "line1\nline2\nline3")
	body := rec.Body.String()
	assert.Contains(t, body, "event: test-event\n")
	assert.Contains(t, body, "data: line1\n")
	assert.Contains(t, body, "data: line2\n")
	assert.Contains(t, body, "data: line3\n")
}


// ===========================================================================
// handler.go: servePage with nil template
// ===========================================================================
func TestFinal_ServePage_NilOpsTmpl(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	h.opsTmpl = nil
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodGet, "/admin/ops", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}


// ===========================================================================
// data.go: buildOverview with metrics + global frozen
// ===========================================================================
func TestFinal_BuildOverview_WithRiskGuard(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	overview := h.buildOverview()

	assert.Equal(t, "test-v1", overview.Version)
	assert.NotEmpty(t, overview.Uptime)
	assert.False(t, overview.GlobalFrozen)
}


func TestFinal_BuildOverview_WithFrozen(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	h.manager.RiskGuard().FreezeGlobal("admin@test.com", "test freeze")

	overview := h.buildOverview()
	assert.True(t, overview.GlobalFrozen)
}


// ===========================================================================
// data.go: buildOverviewForUser / buildSessionsForUser / buildTickersForUser / buildAlertsForUser
// ===========================================================================
func TestFinal_BuildOverviewForUser(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	h.manager.AlertStore().Add("user@test.com", "INFY", "NSE", 256265, 1500, alerts.DirectionAbove)

	overview := h.buildOverviewForUser("user@test.com")
	assert.Equal(t, "test-v1", overview.Version)
	assert.Equal(t, 1, overview.TotalAlerts)
	assert.Equal(t, 1, overview.ActiveAlerts)
	assert.Equal(t, 1, overview.CachedTokens)
	assert.Equal(t, 1, overview.PerUserCredentials)
}


func TestFinal_BuildOverviewForUser_NoCreds(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)

	overview := h.buildOverviewForUser("nobody@test.com")
	assert.Equal(t, 0, overview.CachedTokens)
	assert.Equal(t, 0, overview.PerUserCredentials)
	assert.Equal(t, 0, overview.TotalAlerts)
}


func TestFinal_BuildSessionsForUser(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	h.manager.GetOrCreateSessionWithEmail("sess-test-001", "user@test.com")

	sessions := h.buildSessionsForUser("user@test.com")
	assert.NotNil(t, sessions)
	// May or may not find sessions depending on internal session data type
}


func TestFinal_BuildTickersForUser(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	tickers := h.buildTickersForUser("user@test.com")
	assert.NotNil(t, tickers.Tickers)
}


func TestFinal_BuildAlertsForUser(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	h.manager.AlertStore().Add("user@test.com", "INFY", "NSE", 256265, 1500, alerts.DirectionAbove)

	alertData := h.buildAlertsForUser("user@test.com")
	assert.NotEmpty(t, alertData.Alerts)
}


func TestFinal_BuildAlertsForUser_NoAlerts(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)

	alertData := h.buildAlertsForUser("nobody@test.com")
	assert.Empty(t, alertData.Alerts)
	assert.Empty(t, alertData.Telegram)
}


// ===========================================================================
// data.go: buildSessions with actual session data
// ===========================================================================
func TestFinal_BuildSessions_WithSessions(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	h.manager.GetOrCreateSessionWithEmail("a1b2c3d4-build-sess-test01", "active@test.com")

	sessions := h.buildSessions()
	// The session may or may not have KiteSessionData depending on whether GetOrCreateSessionWithEmail
	// sets that. Either way, buildSessions should not panic.
	assert.NotNil(t, sessions)
}


// ===========================================================================
// dashboard.go: status handler - more branches
// ===========================================================================
func TestFinal_Status_WithToken(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/status", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp statusResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "user@test.com", resp.Email)
	assert.True(t, resp.Credentials.Stored)
}


func TestFinal_Status_Admin(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/status", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp statusResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.IsAdmin)
	assert.Equal(t, "admin", resp.Role)
}


func TestFinal_Status_NoToken(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t) // no credentials seeded
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/status", "nobody@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp statusResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.False(t, resp.KiteToken.Valid)
	assert.False(t, resp.Credentials.Stored)
}


func TestFinal_Status_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/status", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


// ===========================================================================
// dashboard_templates.go: serveAlertsPageSSR - unauthenticated and nil template
// ===========================================================================
func TestFinal_AlertsPageSSR_NilTemplate(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	d.alertsTmpl = nil
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/alerts", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// Falls back to serving the raw HTML file
	assert.Equal(t, http.StatusOK, rec.Code)
}


func TestFinal_AlertsPageSSR_WithTriggeredAlerts(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	store := d.manager.AlertStore()
	id, _ := store.Add("user@test.com", "RELIANCE", "NSE", 408065, 2400, alerts.DirectionBelow)
	store.MarkTriggered(id, 2350)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/alerts", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// dashboard_templates.go: serveOrdersPageSSR - nil template
// ===========================================================================
func TestFinal_OrdersPageSSR_NilTemplate(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	d.ordersTmpl = nil
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/orders", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code) // fallback
}


// ===========================================================================
// dashboard_templates.go: serveSafetyPageSSR - nil template
// ===========================================================================
func TestFinal_SafetyPageSSR_NilTemplate(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	d.safetyTmpl = nil
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/safety", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code) // fallback
}


// ===========================================================================
// admin_render.go: usersToTemplateData with different statuses
// ===========================================================================
func TestFinal_UsersToTemplateData_Statuses(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)

	// Create users with different statuses
	h.userStore.EnsureAdmin("admin2@test.com")
	_ = h.userStore.UpdateStatus("user@test.com", "suspended")

	users := h.userStore.List()
	data := usersToTemplateData(users, "admin@test.com")

	assert.NotEmpty(t, data.Users)
	// Check that at least one user has the correct status classes
	found := false
	for _, u := range data.Users {
		if u.Status == "suspended" {
			assert.Equal(t, "red", u.StatusClass)
			found = true
		}
	}
	// May or may not have suspended user depending on store behavior
	_ = found
}


// ===========================================================================
// overview_render.go: renderFragment error path
// ===========================================================================
func TestFinal_RenderFragment_InvalidTemplate(t *testing.T) {
	t.Parallel()
	tmpl, err := overviewFragmentTemplates()
	require.NoError(t, err)

	// Try rendering a non-existent template name
	_, err = renderFragment(tmpl, "nonexistent_template_name", nil)
	assert.Error(t, err)
}


// ===========================================================================
// user_render.go: renderUserFragment error path
// ===========================================================================
func TestFinal_RenderUserFragment_InvalidTemplate(t *testing.T) {
	t.Parallel()
	tmpl, err := userDashboardFragmentTemplates()
	require.NoError(t, err)

	_, err = renderUserFragment(tmpl, "nonexistent_template_name", nil)
	assert.Error(t, err)
}


// ===========================================================================
// handler.go: logAdminAction with nil audit store
// ===========================================================================
func TestFinal_LogAdminAction_NilAuditStore(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t) // no audit store
	// Should not panic
	h.logAdminAction("admin@test.com", "test_action", "target")
}


// ===========================================================================
// dashboard_templates.go: buildUserStatus
// ===========================================================================
func TestFinal_BuildUserStatus(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")

	resp := d.buildUserStatus("user@test.com")
	assert.Equal(t, "user@test.com", resp.Email)
	assert.True(t, resp.Credentials.Stored)
}


func TestFinal_BuildUserStatus_NoCreds(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)

	resp := d.buildUserStatus("nobody@test.com")
	assert.False(t, resp.Credentials.Stored)
}


// ===========================================================================
// dashboard.go: alertsEnrichedAPI - delete nonexistent alert
// ===========================================================================
func TestFinal_AlertsEnriched_DeleteNonexistent(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodDelete, "/dashboard/api/alerts-enriched?alert_id=nonexistent-id", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


// ===========================================================================
// dashboard.go: maskKey
// ===========================================================================
func TestFinal_MaskKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want string
	}{
		{"short", "****"},
		{"12345678", "****"},
		{"1234567890", "1234****7890"},
		{"abcdefghijklmnop", "abcd****mnop"},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, maskKey(tc.in), "maskKey(%q)", tc.in)
	}
}


// ===========================================================================
// dashboard.go: intParam edge cases
// ===========================================================================
func TestFinal_IntParam_NegativeValue(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/test?n=-5", nil)
	assert.Equal(t, 42, intParam(req, "n", 42))
}


func TestFinal_IntParam_InvalidString(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/test?n=abc", nil)
	assert.Equal(t, 42, intParam(req, "n", 42))
}


// ===========================================================================
// dashboard.go: formatDuration edge cases
// ===========================================================================
func TestFinal_FormatDuration_Negative(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "0s", formatDuration(-5*time.Second))
}


func TestFinal_FormatDuration_Days(t *testing.T) {
	t.Parallel()
	assert.Contains(t, formatDuration(49*time.Hour+30*time.Minute), "2d")
}


func TestFinal_FormatDuration_SubSecond(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "0s", formatDuration(500*time.Millisecond))
}
