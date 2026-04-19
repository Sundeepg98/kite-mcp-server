package ops

// coverage_max_test.go: push ops coverage toward 100%.
// Targets remaining uncovered branches across handler.go, data.go,
// dashboard.go, dashboard_templates.go, and overview_sse.go.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zerodha/kite-mcp-server/kc/registry"
)

// --- Helpers (unique names to avoid collisions) ---

// newHandlerWithAuditAndMetrics creates a handler with audit store, user store, riskguard and metrics.


// ===========================================================================
// handler.go: registryHandler/registryItemHandler nil registryStore
// ===========================================================================
func TestMax_Registry_NilStore(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	h.registryStore = nil
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/admin/ops/api/registry", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}


func TestMax_RegistryItem_NilStore(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	h.registryStore = nil
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPut, "/admin/ops/api/registry/some-id", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}


// ===========================================================================
// handler.go: registryHandler - POST and error paths
// ===========================================================================
func TestFinal_Registry_POST_Success(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := `{"id":"test-app-1","api_key":"apikey123456","api_secret":"secret123456","assigned_to":"user@test.com","label":"Test App"}`
	req := adminReq(http.MethodPost, "/admin/ops/api/registry", body)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
}


func TestFinal_Registry_POST_Conflict(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)

	// Register first
	h.registryStore.Register(&registry.AppRegistration{
		ID: "dup-id", APIKey: "key1234567890", APISecret: "sec1234567890",
		RegisteredBy: "admin@test.com", Source: registry.SourceAdmin,
	})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := `{"id":"dup-id","api_key":"key2222222222","api_secret":"sec2222222222"}`
	req := adminReq(http.MethodPost, "/admin/ops/api/registry", body)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)
}


func TestFinal_Registry_POST_MissingFields(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := `{"id":"only-id"}`
	req := adminReq(http.MethodPost, "/admin/ops/api/registry", body)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestFinal_Registry_POST_InvalidJSON(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/registry", "notjson")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestFinal_Registry_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodDelete, "/admin/ops/api/registry", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestFinal_Registry_Forbidden(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := userReq(http.MethodGet, "/admin/ops/api/registry", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}


// ===========================================================================
// handler.go: registryItemHandler PUT/DELETE
// ===========================================================================
func TestFinal_RegistryItem_PUT_Success(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	h.registryStore.Register(&registry.AppRegistration{
		ID: "upd-id", APIKey: "key1234567890", APISecret: "sec1234567890",
		RegisteredBy: "admin@test.com", Source: registry.SourceAdmin,
	})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := `{"assigned_to":"user@test.com","label":"Updated Label","status":"active"}`
	req := adminReq(http.MethodPut, "/admin/ops/api/registry/upd-id", body)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}


func TestFinal_RegistryItem_PUT_NotFound(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := `{"label":"X"}`
	req := adminReq(http.MethodPut, "/admin/ops/api/registry/nonexistent", body)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}


func TestFinal_RegistryItem_PUT_InvalidJSON(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPut, "/admin/ops/api/registry/some-id", "notjson")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestFinal_RegistryItem_DELETE_Success(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	h.registryStore.Register(&registry.AppRegistration{
		ID: "del-id", APIKey: "key1234567890", APISecret: "sec1234567890",
		RegisteredBy: "admin@test.com", Source: registry.SourceAdmin,
	})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodDelete, "/admin/ops/api/registry/del-id", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}


func TestFinal_RegistryItem_DELETE_NotFound(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodDelete, "/admin/ops/api/registry/nonexistent", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}


func TestFinal_RegistryItem_EmptyID(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	// Path /admin/ops/api/registry/ with no ID after the slash
	req := adminReq(http.MethodPut, "/admin/ops/api/registry/", `{"label":"X"}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestFinal_RegistryItem_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/registry/some-id", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestFinal_RegistryItem_Forbidden(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := userReq(http.MethodDelete, "/admin/ops/api/registry/some-id", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}
