package ops

import (
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/registry"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// newTestAdminOpsHandler creates an ops Handler with a user store, audit store,
// and an admin user pre-registered so isAdmin() returns true for "admin@test.com".
func newTestAdminOpsHandler(t *testing.T) *Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelError}))

	instrMgr, err := instruments.New(instruments.Config{
		Logger:   logger,
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)

	mgr, err := kc.New(kc.Config{
		APIKey:             "test_api_key",
		APISecret:          "test_api_secret",
		Logger:             logger,
		DevMode:            true,
		InstrumentsManager: instrMgr,
		AlertDBPath:        ":memory:",
	})
	require.NoError(t, err)
	t.Cleanup(func() { mgr.Shutdown() })

	// Set up user store with admin user
	userStore := mgr.UserStoreConcrete()
	if userStore != nil {
		userStore.EnsureAdmin("admin@test.com")
	}

	auditStore := audit.New(mgr.AlertDB())
	auditStore.SetLogger(logger)
	_ = auditStore.InitTable()

	lb := NewLogBuffer(100)
	h := New(mgr, nil, lb, logger, "test-v1", time.Now(), userStore, auditStore)
	return h
}

func adminCtx(email string) context.Context {
	return oauth.ContextWithEmail(context.Background(), email)
}

// ===========================================================================
// TeeHandler — full coverage
// ===========================================================================

func TestTeeHandler_Handle(t *testing.T) {
	t.Parallel()

	buf := NewLogBuffer(10)
	inner := slog.NewTextHandler(devNull{}, nil)
	tee := NewTeeHandler(inner, buf)

	logger := slog.New(tee)
	logger.Info("test message", "key", "value")

	entries := buf.Recent(10)
	if len(entries) != 1 {
		t.Fatalf("Expected 1 log entry, got %d", len(entries))
	}
	if entries[0].Message != "test message" {
		t.Errorf("Message = %q, want 'test message'", entries[0].Message)
	}
	if !strings.Contains(entries[0].Attrs, "key=value") {
		t.Errorf("Attrs = %q, want to contain 'key=value'", entries[0].Attrs)
	}
}

func TestTeeHandler_Enabled(t *testing.T) {
	t.Parallel()

	buf := NewLogBuffer(10)
	inner := slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelError})
	tee := NewTeeHandler(inner, buf)

	if tee.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("Info should not be enabled when inner is Error level")
	}
	if !tee.Enabled(context.Background(), slog.LevelError) {
		t.Error("Error should be enabled")
	}
}

func TestTeeHandler_WithAttrs(t *testing.T) {
	t.Parallel()

	buf := NewLogBuffer(10)
	inner := slog.NewTextHandler(devNull{}, nil)
	tee := NewTeeHandler(inner, buf)

	derived := tee.WithAttrs([]slog.Attr{slog.String("extra", "attr")})
	if derived == nil {
		t.Fatal("WithAttrs should return non-nil")
	}
	if _, ok := derived.(*TeeHandler); !ok {
		t.Error("WithAttrs should return a *TeeHandler")
	}
}

func TestTeeHandler_WithGroup(t *testing.T) {
	t.Parallel()

	buf := NewLogBuffer(10)
	inner := slog.NewTextHandler(devNull{}, nil)
	tee := NewTeeHandler(inner, buf)

	derived := tee.WithGroup("mygroup")
	if derived == nil {
		t.Fatal("WithGroup should return non-nil")
	}
	if _, ok := derived.(*TeeHandler); !ok {
		t.Error("WithGroup should return a *TeeHandler")
	}
}

// ===========================================================================
// Admin Ops Handler — listUsers
// ===========================================================================

func TestOpsHandler_ListUsers_Admin(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/users", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestOpsHandler_ListUsers_Forbidden(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	// non-admin user
	req := requestWithEmail(http.MethodGet, "/admin/ops/api/users", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ===========================================================================
// Admin Ops Handler — suspendUser
// ===========================================================================

func TestOpsHandler_SuspendUser_Success(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	// Ensure target user exists
	h.userStore.EnsureUser("target@test.com", "", "", "admin@test.com")

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/suspend?email=target@test.com", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestOpsHandler_SuspendUser_SelfAction(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/suspend?email=admin@test.com", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestOpsHandler_SuspendUser_MissingEmail(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/suspend", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestOpsHandler_SuspendUser_WrongMethod_Final(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/users/suspend?email=target@test.com", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ===========================================================================
// Admin Ops Handler — activateUser
// ===========================================================================

func TestOpsHandler_ActivateUser_Success(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	h.userStore.EnsureUser("target@test.com", "", "", "admin@test.com")
	_ = h.userStore.UpdateStatus("target@test.com", "suspended")

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/activate?email=target@test.com", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestOpsHandler_ActivateUser_SelfAction(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/activate?email=admin@test.com", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ===========================================================================
// Admin Ops Handler — offboardUser
// ===========================================================================

func TestOpsHandler_OffboardUser_Success(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	h.userStore.EnsureUser("target@test.com", "", "", "admin@test.com")

	body := strings.NewReader(`{"email":"target@test.com","confirm":true}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/offboard", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestOpsHandler_OffboardUser_NoConfirm(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"email":"target@test.com","confirm":false}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/offboard", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestOpsHandler_OffboardUser_SelfAction(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"email":"admin@test.com","confirm":true}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/offboard", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ===========================================================================
// Admin Ops Handler — changeRole
// ===========================================================================

func TestOpsHandler_ChangeRole_Success(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	h.userStore.EnsureUser("target@test.com", "", "", "admin@test.com")

	body := strings.NewReader(`{"email":"target@test.com","role":"admin"}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/role", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// Admin Ops Handler — freezeTrading
// ===========================================================================

func TestOpsHandler_FreezeTrading_NoRiskGuard(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"email":"target@test.com","reason":"test","confirm":true}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/risk/freeze", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestOpsHandler_FreezeTrading_WithRiskGuard(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	guard := riskguard.NewGuard(nil)
	h.manager.SetRiskGuard(guard)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"email":"target@test.com","reason":"suspicious activity","confirm":true}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/risk/freeze", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestOpsHandler_FreezeTrading_NoConfirm(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	guard := riskguard.NewGuard(nil)
	h.manager.SetRiskGuard(guard)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"email":"target@test.com","reason":"test"}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/risk/freeze", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestOpsHandler_FreezeTrading_SelfAction(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"email":"admin@test.com","reason":"test","confirm":true}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/risk/freeze", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ===========================================================================
// Admin Ops Handler — unfreezeTrading
// ===========================================================================

func TestOpsHandler_UnfreezeTrading_WithRiskGuard(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	guard := riskguard.NewGuard(nil)
	h.manager.SetRiskGuard(guard)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"email":"target@test.com"}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/risk/unfreeze", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestOpsHandler_UnfreezeTrading_SelfAction(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	guard := riskguard.NewGuard(nil)
	h.manager.SetRiskGuard(guard)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"email":"admin@test.com"}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/risk/unfreeze", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ===========================================================================
// Admin Ops Handler — freezeTradingGlobal + unfreezeTradingGlobal
// ===========================================================================

func TestOpsHandler_FreezeTradingGlobal_WithRiskGuard(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	guard := riskguard.NewGuard(nil)
	h.manager.SetRiskGuard(guard)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"reason":"emergency","confirm":true}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/risk/freeze-global", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestOpsHandler_FreezeTradingGlobal_NoConfirm(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	guard := riskguard.NewGuard(nil)
	h.manager.SetRiskGuard(guard)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"reason":"emergency"}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/risk/freeze-global", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestOpsHandler_UnfreezeTradingGlobal_WithRiskGuard(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	guard := riskguard.NewGuard(nil)
	h.manager.SetRiskGuard(guard)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/risk/unfreeze-global", "admin@test.com", nil)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// Admin Ops Handler — verifyChain
// ===========================================================================

func TestOpsHandler_VerifyChain_Admin(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/verify-chain", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestOpsHandler_VerifyChain_WrongMethod_Final(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/verify-chain", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ===========================================================================
// Admin Ops Handler — registry CRUD
// ===========================================================================

func TestOpsHandler_Registry_GET(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/registry", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestOpsHandler_Registry_POST_Success(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"id":"test-app","api_key":"test-key-12345678","api_secret":"test-secret-12345678","assigned_to":"user@test.com","label":"Test App"}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/registry", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestOpsHandler_Registry_POST_MissingFields(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"id":"","api_key":"","api_secret":""}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/registry", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestOpsHandler_Registry_POST_InvalidJSON(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`not json`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/registry", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ===========================================================================
// Admin Ops Handler — registryItemHandler PUT/DELETE
// ===========================================================================

func TestOpsHandler_RegistryItem_PUT(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	// Pre-register an entry
	_ = h.registryStore.Register(&registry.AppRegistration{
		ID:           "test-entry",
		APIKey:       "key-12345678",
		APISecret:    "secret",
		Status:       registry.StatusActive,
		Source:       registry.SourceAdmin,
		RegisteredBy: "admin@test.com",
	})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"assigned_to":"newuser@test.com","label":"Updated","status":"active"}`)
	req := requestWithEmail(http.MethodPut, "/admin/ops/api/registry/test-entry", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestOpsHandler_RegistryItem_DELETE(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	_ = h.registryStore.Register(&registry.AppRegistration{
		ID:           "del-entry",
		APIKey:       "key-12345678",
		APISecret:    "secret",
		Status:       registry.StatusActive,
		Source:       registry.SourceAdmin,
		RegisteredBy: "admin@test.com",
	})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodDelete, "/admin/ops/api/registry/del-entry", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestOpsHandler_RegistryItem_DELETE_NotFound(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodDelete, "/admin/ops/api/registry/nonexistent", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestOpsHandler_RegistryItem_EmptyID(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPut, "/admin/ops/api/registry/", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ===========================================================================
// Admin Ops Handler — metricsAPI
// ===========================================================================

func TestOpsHandler_MetricsAPI_Admin(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/metrics?period=1h", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestOpsHandler_MetricsAPI_AllPeriods(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	for _, period := range []string{"1h", "7d", "30d", "24h"} {
		req := requestWithEmail(http.MethodGet, "/admin/ops/api/metrics?period="+period, "admin@test.com", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "period="+period)
	}
}

// ===========================================================================
// Admin Ops Handler — logAdminAction coverage (auditStore nil path)
// ===========================================================================

func TestOpsHandler_LogAdminAction_NilAuditStore(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t) // uses nil audit store
	// Should not panic
	h.logAdminAction("admin@test.com", "test_action", "target")
}

// ===========================================================================
// Admin Ops Handler — servePage with nil opsTmpl
// ===========================================================================

func TestOpsHandler_ServePage_NilTemplate(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	h.opsTmpl = nil

	req := httptest.NewRequest(http.MethodGet, "/admin/ops", nil)
	rec := httptest.NewRecorder()
	h.servePage(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ===========================================================================
// Dashboard Handler — activityAPI
// ===========================================================================

func TestDashboard_ActivityAPI(t *testing.T) {
	t.Parallel()

	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/activity?limit=10&offset=0", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestDashboard_ActivityAPI_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/activity", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestDashboard_ActivityAPI_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/dashboard/api/activity", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestDashboard_ActivityAPI_WithFilters(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	since := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	until := time.Now().Format(time.RFC3339)
	req := requestWithEmail(http.MethodGet, "/dashboard/api/activity?since="+since+"&until="+until+"&category=test&errors=true", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// Dashboard Handler — activityExport
// ===========================================================================

func TestDashboard_ActivityExport_CSV(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/activity/export?format=csv", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/csv", rec.Header().Get("Content-Type"))
}

func TestDashboard_ActivityExport_JSON(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/activity/export?format=json", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

func TestDashboard_ActivityExport_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/activity/export", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ===========================================================================
// Dashboard Handler — paperStatus, paperHoldings, paperPositions, paperOrders, paperReset
// ===========================================================================

func TestDashboard_PaperStatus_NoPaperEngine(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/paper/status", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestDashboard_PaperHoldings_NoPaperEngine(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/paper/holdings", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestDashboard_PaperPositions_NoPaperEngine(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/paper/positions", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestDashboard_PaperOrders_NoPaperEngine(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/paper/orders", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestDashboard_PaperReset_NoPaperEngine(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/dashboard/api/paper/reset", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestDashboard_PaperStatus_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/paper/status", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestDashboard_PaperReset_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/paper/reset", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ===========================================================================
// Dashboard Handler — safetyStatus
// ===========================================================================

func TestDashboard_SafetyStatus_NoRiskGuard(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/safety/status", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	assert.Equal(t, false, resp["enabled"])
}

func TestDashboard_SafetyStatus_WithRiskGuard(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)

	guard := riskguard.NewGuard(nil)
	d.manager.SetRiskGuard(guard)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/safety/status", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	assert.Equal(t, true, resp["enabled"])
}

func TestDashboard_SafetyStatus_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/safety/status", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ===========================================================================
// Dashboard Handler — selfDeleteAccount
// ===========================================================================

func TestDashboard_SelfDeleteAccount_Success(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"confirm":true}`)
	req := requestWithEmail(http.MethodPost, "/dashboard/api/account/delete", "user@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestDashboard_SelfDeleteAccount_NoConfirm(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"confirm":false}`)
	req := requestWithEmail(http.MethodPost, "/dashboard/api/account/delete", "user@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestDashboard_SelfDeleteAccount_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"confirm":true}`)
	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/account/delete", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestDashboard_SelfDeleteAccount_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/account/delete", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ===========================================================================
// Dashboard Handler — selfManageCredentials
// ===========================================================================

func TestDashboard_SelfManageCredentials_GET_NoCreds(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/account/credentials", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	assert.Equal(t, false, resp["has_credentials"])
}

func TestDashboard_SelfManageCredentials_PUT(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"api_key":"new-key-12345678","api_secret":"new-secret-12345678"}`)
	req := requestWithEmail(http.MethodPut, "/dashboard/api/account/credentials", "user@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestDashboard_SelfManageCredentials_PUT_MissingFields(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"api_key":"","api_secret":""}`)
	req := requestWithEmail(http.MethodPut, "/dashboard/api/account/credentials", "user@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestDashboard_SelfManageCredentials_DELETE(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// First set credentials
	d.manager.CredentialStore().Set("user@test.com", &kc.KiteCredentialEntry{
		APIKey:    "del-key-12345678",
		APISecret: "del-secret-12345678",
	})

	req := requestWithEmail(http.MethodDelete, "/dashboard/api/account/credentials", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestDashboard_SelfManageCredentials_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/account/credentials", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ===========================================================================
// Dashboard Handler — alerts API
// ===========================================================================

func TestDashboard_Alerts(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/alerts", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestDashboard_Alerts_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/alerts", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ===========================================================================
// Dashboard Handler — marketIndices
// ===========================================================================

func TestDashboard_MarketIndices_NoCreds(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/market-indices", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestDashboard_MarketIndices_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/market-indices", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestDashboard_MarketIndices_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/dashboard/api/market-indices", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ===========================================================================
// Dashboard Handler — portfolio + ordersAPI
// ===========================================================================

func TestDashboard_Portfolio_NoCreds(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/portfolio", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestDashboard_OrdersAPI_NoAuditStore(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t) // no audit store
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/orders", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestDashboard_OrdersAPI_WithAuditStore(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/orders", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// Dashboard Handler — writeJSON error path (unmarshalable)
// ===========================================================================

func TestDashboard_WriteJSON_ErrorPath(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)

	rr := httptest.NewRecorder()
	d.writeJSON(rr, map[string]interface{}{
		"bad": math.Inf(1),
	})

	assert.Equal(t, http.StatusOK, rr.Code)
}

// ===========================================================================
// Admin Ops Handler — writeJSON + writeJSONError on handler
// ===========================================================================

func TestOpsHandler_WriteJSONError_Final(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)

	rr := httptest.NewRecorder()
	h.writeJSONError(rr, http.StatusTeapot, "test error")

	assert.Equal(t, http.StatusTeapot, rr.Code)
	var resp map[string]string
	json.NewDecoder(rr.Body).Decode(&resp)
	assert.Equal(t, "test error", resp["error"])
}

// ===========================================================================
// Helper: newTestDashboardWithAudit creates a dashboard handler with audit store
// ===========================================================================

func newTestDashboardWithAudit(t *testing.T) *DashboardHandler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelError}))

	instrMgr, err := instruments.New(instruments.Config{
		Logger:   logger,
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)

	mgr, err := kc.New(kc.Config{
		APIKey:             "test_api_key",
		APISecret:          "test_api_secret",
		Logger:             logger,
		DevMode:            true,
		InstrumentsManager: instrMgr,
		AlertDBPath:        ":memory:",
	})
	require.NoError(t, err)
	t.Cleanup(func() { mgr.Shutdown() })

	auditStore := audit.New(mgr.AlertDB())
	auditStore.SetLogger(logger)
	_ = auditStore.InitTable()

	d := NewDashboardHandler(mgr, logger, auditStore)
	d.SetAdminCheck(func(email string) bool { return email == "admin@test.com" })
	return d
}
