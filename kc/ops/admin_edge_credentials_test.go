package ops

// coverage_max_test.go: push ops coverage toward 100%.
// Targets remaining uncovered branches across handler.go, data.go,
// dashboard.go, dashboard_templates.go, and overview_sse.go.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// --- Helpers (unique names to avoid collisions) ---

// newHandlerWithAuditAndMetrics creates a handler with audit store, user store, riskguard and metrics.


// ===========================================================================
// handler.go: credentials POST auto-register in registry
// ===========================================================================
func TestMax_Credentials_Post_AutoRegister(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/credentials", "user@test.com",
		strings.NewReader(`{"api_key":"new_key_12345678","api_secret":"new_secret_12345678"}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// handler.go: credentials GET with short secret (<= 7 chars)
// ===========================================================================
func TestMax_Credentials_Get_ShortSecret(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	h.manager.CredentialStore().Set("user@test.com", &kc.KiteCredentialEntry{
		APIKey: "test_key", APISecret: "shorty", StoredAt: time.Now(),
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/admin/ops/api/credentials", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "****")
}


// ===========================================================================
// handler.go: credentials DELETE as admin with email param
// ===========================================================================
func TestMax_Credentials_Delete_AdminWithEmail(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodDelete, "/admin/ops/api/credentials?email=user@test.com", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// dashboard.go: selfDeleteAccount - no confirm
// ===========================================================================
func TestMax_SelfDeleteAccount_NoConfirm(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/dashboard/api/account/delete", "user@test.com",
		strReaderPtr(`{"confirm": false}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


// ===========================================================================
// dashboard.go: selfManageCredentials
// ===========================================================================
func TestMax_SelfManageCredentials_GET(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/account/credentials", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// handler.go: credentials - all method branches
// ===========================================================================
func TestFinal_Credentials_POST(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := `{"api_key":"new_key_123456","api_secret":"new_secret_12345"}`
	req := userReq(http.MethodPost, "/admin/ops/api/credentials", body)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "ok")
}


func TestFinal_Credentials_POST_MissingFields(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := `{"api_key":"key_only"}`
	req := userReq(http.MethodPost, "/admin/ops/api/credentials", body)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestFinal_Credentials_POST_InvalidJSON(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := userReq(http.MethodPost, "/admin/ops/api/credentials", "invalid json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestFinal_Credentials_DELETE_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := userReq(http.MethodDelete, "/admin/ops/api/credentials", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}


func TestFinal_Credentials_DELETE_Admin_WithEmail(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodDelete, "/admin/ops/api/credentials?email=user@test.com", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}


func TestFinal_Credentials_GET_WithShortSecret(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	// Set a short secret
	h.manager.CredentialStore().Set("short@test.com", &kc.KiteCredentialEntry{
		APIKey: "key123", APISecret: "short", StoredAt: time.Now(),
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/admin/ops/api/credentials", nil)
	ctx := oauth.ContextWithEmail(req.Context(), "short@test.com")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "****")
}


func TestFinal_Credentials_GET_NoCredentials(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/admin/ops/api/credentials", nil)
	ctx := oauth.ContextWithEmail(req.Context(), "nobody@test.com")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "[]")
}


func TestFinal_Credentials_Unauthenticated(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/admin/ops/api/credentials", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


func TestFinal_Credentials_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := userReq(http.MethodPut, "/admin/ops/api/credentials", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


// ===========================================================================
// handler.go: forceReauth
// ===========================================================================
func TestFinal_ForceReauth_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodGet, "/admin/ops/api/force-reauth?email=user@test.com", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestFinal_ForceReauth_MissingEmail(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/force-reauth", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


// ===========================================================================
// dashboard.go: selfDeleteAccount additional paths
// ===========================================================================
func TestFinal_SelfDeleteAccount_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/account/delete", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestFinal_SelfDeleteAccount_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/account/delete", strings.NewReader(`{"confirm":true}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


func TestFinal_SelfDeleteAccount_NoConfirm(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"confirm":false}`)
	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/account/delete", body)
	req.Header.Set("Content-Type", "application/json")
	ctx := oauth.ContextWithEmail(req.Context(), "user@test.com")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


// ===========================================================================
// dashboard.go: selfManageCredentials PUT and DELETE
// ===========================================================================
func TestFinal_SelfManageCredentials_PUT(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"api_key":"new_key_12345678","api_secret":"new_secret_12345678"}`)
	req := httptest.NewRequest(http.MethodPut, "/dashboard/api/account/credentials", body)
	req.Header.Set("Content-Type", "application/json")
	ctx := oauth.ContextWithEmail(req.Context(), "user@test.com")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}


func TestFinal_SelfManageCredentials_DELETE(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodDelete, "/dashboard/api/account/credentials", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}


func TestFinal_SelfManageCredentials_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/account/credentials", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
