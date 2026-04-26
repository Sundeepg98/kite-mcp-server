package ops

// coverage_max_test.go: push ops coverage toward 100%.
// Targets remaining uncovered branches across handler.go, data.go,
// dashboard.go, dashboard_templates.go, and overview_sse.go.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

)

// --- Helpers (unique names to avoid collisions) ---

// newHandlerWithAuditAndMetrics creates a handler with audit store, user store, riskguard and metrics.


// ===========================================================================
// handler.go: suspendUser/activateUser self-action guard and UpdateStatus error
// ===========================================================================
func TestMax_SuspendUser_SelfGuard(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/admin/ops/api/users/suspend?email=admin@test.com", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestMax_SuspendUser_UpdateStatusError(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/admin/ops/api/users/suspend?email=nonexistent@test.com", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestMax_ActivateUser_SelfGuard(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/admin/ops/api/users/activate?email=admin@test.com", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestMax_ActivateUser_UpdateStatusError(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/admin/ops/api/users/activate?email=nonexistent@test.com", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


// ===========================================================================
// handler.go: offboardUser - nil userStore and updateStatus error
// ===========================================================================

// Coverage note: The nil-userStore guard in offboardUser (handler.go:545) is unreachable
// because isAdmin() returns false when userStore is nil, causing a 403 before the guard.
// This is a defensive pattern; the guard exists but cannot be triggered via HTTP.
//
// Behaviour note (Phase B-Audit #25): the offboard handler dispatches
// DeleteMyAccountCommand which uses DeleteMyAccountUseCase. That use case treats
// the teardown as best-effort — credential/token/session/alert/watchlist deletes
// run unconditionally, then UpdateStatus is attempted and any error is LOGGED
// (kc/usecases/account_usecases.go:109-111), not surfaced. Rationale: the
// security-critical deletes have already succeeded by the time UpdateStatus
// runs; failing the response would imply rollback semantics that the use case
// does not provide. So an offboard request for a nonexistent user returns
// 200 OK — the no-op deletes succeed and the status-update miss is logged.
// This test pins the post-#25 contract: 200 OK, not 400.
func TestMax_OffboardUser_UpdateStatusError(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/users/offboard?email=nonexistent@test.com", `{"confirm": true}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// handler.go: changeRole - nil userStore, last-admin guard, UpdateRole error
// ===========================================================================

// Coverage note: The nil-userStore guard in changeRole (handler.go:581) is unreachable
// because isAdmin() returns false when userStore is nil, causing a 403 before the guard.
// Same defensive pattern as offboardUser/suspendUser/activateUser.
func TestMax_ChangeRole_LastAdminGuard(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/users/role?email=admin@test.com", `{"role": "viewer"}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusConflict, rec.Code)
}


func TestMax_ChangeRole_UpdateRoleError(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/users/role?email=nonexistent@test.com", `{"role": "viewer"}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


// ===========================================================================
// handler.go: listUsers with userStore (admin)
// ===========================================================================
func TestMax_ListUsers_Admin(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/admin/ops/api/users", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// handler.go: listUsers null user store
// ===========================================================================
func TestFinal_ListUsers_NullUserStore(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	// Override user store to nil but make isAdmin return true
	h.userStore = nil
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	// Without a user store, isAdmin returns false so we get 403
	req := adminReq(http.MethodGet, "/admin/ops/api/users", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}


func TestFinal_ListUsers_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/users", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


// ===========================================================================
// handler.go: suspendUser / activateUser / offboardUser self-action prevention
// ===========================================================================
func TestFinal_SuspendUser_SelfAction(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/users/suspend?email=admin@test.com", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "yourself")
}


func TestFinal_SuspendUser_MissingEmail(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/users/suspend", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestFinal_SuspendUser_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodGet, "/admin/ops/api/users/suspend?email=user@test.com", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestFinal_ActivateUser_SelfAction(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/users/activate?email=admin@test.com", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestFinal_ActivateUser_MissingEmail(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/users/activate", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestFinal_ActivateUser_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodGet, "/admin/ops/api/users/activate?email=user@test.com", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestFinal_OffboardUser_SelfAction(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/users/offboard?email=admin@test.com", `{"confirm":true}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestFinal_OffboardUser_NoConfirm(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/users/offboard?email=user@test.com", `{"confirm":false}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "confirmation_required")
}


func TestFinal_OffboardUser_InvalidJSON(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/users/offboard?email=user@test.com", "not json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestFinal_OffboardUser_MissingEmail(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/users/offboard", `{"confirm":true}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestFinal_OffboardUser_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodGet, "/admin/ops/api/users/offboard?email=user@test.com", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestFinal_OffboardUser_Forbidden(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := userReq(http.MethodPost, "/admin/ops/api/users/offboard?email=other@test.com", `{"confirm":true}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}


// ===========================================================================
// handler.go: changeRole - last admin guard and null user store
// ===========================================================================
func TestFinal_ChangeRole_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodGet, "/admin/ops/api/users/role?email=user@test.com", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestFinal_ChangeRole_Forbidden(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := userReq(http.MethodPost, "/admin/ops/api/users/role?email=admin@test.com", `{"role":"viewer"}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}


func TestFinal_ChangeRole_MissingEmail(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/users/role", `{"role":"viewer"}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestFinal_ChangeRole_InvalidJSON(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/users/role?email=user@test.com", "notjson")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestFinal_ChangeRole_LastAdminGuard(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	// Demote the only admin
	req := adminReq(http.MethodPost, "/admin/ops/api/users/role?email=admin@test.com", `{"role":"viewer"}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Contains(t, rec.Body.String(), "last admin")
}


func TestFinal_ChangeRole_Success(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	// Register a second user we can change
	h.userStore.EnsureAdmin("second@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/users/role?email=second@test.com", `{"role":"viewer"}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// handler.go: freezeTrading / unfreezeTrading branches
// ===========================================================================
func TestFinal_FreezeTrading_SelfAction(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/risk/freeze", `{"email":"admin@test.com","confirm":true}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestFinal_FreezeTrading_NoConfirm(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/risk/freeze", `{"email":"user@test.com","confirm":false}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestFinal_FreezeTrading_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodGet, "/admin/ops/api/risk/freeze", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestFinal_FreezeTrading_Forbidden(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := userReq(http.MethodPost, "/admin/ops/api/risk/freeze", `{"email":"other@test.com"}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}


func TestFinal_FreezeTrading_MissingEmail(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/risk/freeze", `{"email":"","confirm":true}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestFinal_UnfreezeTrading_SelfAction(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/risk/unfreeze", `{"email":"admin@test.com"}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestFinal_UnfreezeTrading_MissingEmail(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/risk/unfreeze", `{"email":""}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestFinal_UnfreezeTrading_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodGet, "/admin/ops/api/risk/unfreeze", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestFinal_UnfreezeTrading_Forbidden(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := userReq(http.MethodPost, "/admin/ops/api/risk/unfreeze", `{"email":"other@test.com"}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}


func TestFinal_UnfreezeTrading_NoRiskGuard(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)
	// No riskguard set
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/risk/unfreeze", `{"email":"user@test.com"}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}


// ===========================================================================
// handler.go: freezeTradingGlobal / unfreezeTradingGlobal
// ===========================================================================
func TestFinal_FreezeTradingGlobal_NoConfirm(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/risk/freeze-global", `{"confirm":false}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestFinal_FreezeTradingGlobal_InvalidJSON(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/risk/freeze-global", "notjson")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestFinal_FreezeTradingGlobal_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodGet, "/admin/ops/api/risk/freeze-global", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestFinal_FreezeTradingGlobal_Forbidden(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := userReq(http.MethodPost, "/admin/ops/api/risk/freeze-global", `{"confirm":true}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}


func TestFinal_FreezeTradingGlobal_NoRiskGuard(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/risk/freeze-global", `{"confirm":true}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}


func TestFinal_FreezeTradingGlobal_EmptyReason(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/risk/freeze-global", `{"confirm":true}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}


func TestFinal_UnfreezeTradingGlobal_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodGet, "/admin/ops/api/risk/unfreeze-global", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestFinal_UnfreezeTradingGlobal_Forbidden(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := userReq(http.MethodPost, "/admin/ops/api/risk/unfreeze-global", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}


func TestFinal_UnfreezeTradingGlobal_NoRiskGuard(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/risk/unfreeze-global", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}


// ===========================================================================
// dashboard_templates.go: userContext - no email
// ===========================================================================
func TestFinal_UserContext_NoEmail(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	email, role, tokenValid := d.userContext(req)

	assert.Equal(t, "", email)
	assert.Equal(t, "", role)
	assert.False(t, tokenValid)
}


// ===========================================================================
// handler.go: suspendUser/activateUser success + forbidden
// ===========================================================================
func TestFinal_SuspendUser_Forbidden(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := userReq(http.MethodPost, "/admin/ops/api/users/suspend?email=other@test.com", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}


func TestFinal_ActivateUser_Forbidden(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := userReq(http.MethodPost, "/admin/ops/api/users/activate?email=other@test.com", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}


// ===========================================================================
// handler.go: FreezeTrading success path
// ===========================================================================
func TestFinal_FreezeTrading_Success(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/risk/freeze", `{"email":"user@test.com","reason":"test","confirm":true}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}


func TestFinal_UnfreezeTrading_Success(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	h.manager.RiskGuard().Freeze("user@test.com", "admin@test.com", "test")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/risk/unfreeze", `{"email":"user@test.com"}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}


func TestFinal_UnfreezeTradingGlobal_Success(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	h.manager.RiskGuard().FreezeGlobal("admin@test.com", "test")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/risk/unfreeze-global", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}
