package ops

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
)

// newTestHandler creates an ops Handler backed by a real kc.Manager with minimal config.
// The Manager uses a no-op logger to suppress output during tests.
func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(
		// discard output
		devNull{},
		&slog.HandlerOptions{Level: slog.LevelError},
	))
	// Create an instruments manager with test data to avoid hitting the real Kite API.
	instrMgr, instrErr := instruments.New(instruments.Config{
		Logger:   logger,
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, instrErr)

	mgr, err := kc.NewWithOptions(context.Background(),
		kc.WithLogger(logger),
		kc.WithKiteCredentials("test_api_key", "test_api_secret"),
		kc.WithDevMode(true),
		kc.WithInstrumentsManager(instrMgr),
	)
	require.NoError(t, err)
	t.Cleanup(func() { mgr.Shutdown() })

	lb := NewLogBuffer(100)
	return New(mgr, nil, lb, logger, "test-v1", time.Now(), mgr.UserStoreConcrete(), nil)
}

// --- Overview tests ---

func TestOpsHandler_Overview(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/admin/ops/api/overview", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var overview OverviewData
	err := json.NewDecoder(rec.Body).Decode(&overview)
	require.NoError(t, err)
	assert.Equal(t, "test-v1", overview.Version)
	assert.NotEmpty(t, overview.Uptime)
	assert.GreaterOrEqual(t, overview.ActiveSessions, 0)
	assert.GreaterOrEqual(t, overview.ActiveTickers, 0)
}

func TestOpsHandler_OverviewWrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodPost, "/admin/ops/api/overview", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// --- Credentials tests ---

func TestOpsHandler_Credentials_GET(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/credentials", "test@example.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var result []map[string]string
	err := json.NewDecoder(rec.Body).Decode(&result)
	require.NoError(t, err)
	// No credentials stored yet, expect empty array
	assert.Empty(t, result)
}

func TestOpsHandler_Credentials_GET_Unauthenticated(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	// No email in context
	req := httptest.NewRequest(http.MethodGet, "/admin/ops/api/credentials", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	var errResp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "not authenticated", errResp["error"])
}

func TestOpsHandler_Credentials_POST(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"api_key":"my_key","api_secret":"my_secret"}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/credentials", "test@example.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var result map[string]string
	err := json.NewDecoder(rec.Body).Decode(&result)
	require.NoError(t, err)
	assert.Equal(t, "ok", result["status"])

	// Verify the credential was stored by doing a GET
	getReq := requestWithEmail(http.MethodGet, "/admin/ops/api/credentials", "test@example.com", nil)
	getRec := httptest.NewRecorder()
	mux.ServeHTTP(getRec, getReq)

	var creds []map[string]string
	err = json.NewDecoder(getRec.Body).Decode(&creds)
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "my_key", creds[0]["api_key"])
	assert.Equal(t, "test@example.com", creds[0]["email"])
}

func TestOpsHandler_Credentials_POST_InvalidJSON(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{not valid json}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/credentials", "test@example.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errResp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "invalid JSON", errResp["error"])
}

func TestOpsHandler_Credentials_POST_MissingFields(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"api_key":"only_key"}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/credentials", "test@example.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errResp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Contains(t, errResp["error"], "required")
}

func TestOpsHandler_Credentials_POST_TooLarge(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	// Create a body larger than 64 KB
	largeBody := strings.NewReader(`{"api_key":"` + strings.Repeat("x", 70*1024) + `","api_secret":"s"}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/credentials", "test@example.com", largeBody)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// MaxBytesReader causes json.Decode to fail with an error
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errResp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "invalid JSON", errResp["error"])
}

func TestOpsHandler_Credentials_DELETE(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	// First store a credential
	postBody := strings.NewReader(`{"api_key":"del_key","api_secret":"del_secret"}`)
	postReq := requestWithEmail(http.MethodPost, "/admin/ops/api/credentials", "del@example.com", postBody)
	postReq.Header.Set("Content-Type", "application/json")
	postRec := httptest.NewRecorder()
	mux.ServeHTTP(postRec, postReq)
	require.Equal(t, http.StatusOK, postRec.Code)

	// Delete it
	delReq := requestWithEmail(http.MethodDelete, "/admin/ops/api/credentials", "del@example.com", nil)
	delRec := httptest.NewRecorder()
	mux.ServeHTTP(delRec, delReq)
	assert.Equal(t, http.StatusOK, delRec.Code)

	// Verify gone
	getReq := requestWithEmail(http.MethodGet, "/admin/ops/api/credentials", "del@example.com", nil)
	getRec := httptest.NewRecorder()
	mux.ServeHTTP(getRec, getReq)

	var creds []map[string]string
	err := json.NewDecoder(getRec.Body).Decode(&creds)
	require.NoError(t, err)
	assert.Empty(t, creds)
}

// --- Sessions endpoint ---

func TestOpsHandler_Sessions(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/admin/ops/api/sessions", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var sessions []SessionInfo
	err := json.NewDecoder(rec.Body).Decode(&sessions)
	require.NoError(t, err)
	// Fresh manager has no sessions
	assert.Empty(t, sessions)
}

// --- Tickers endpoint ---

func TestOpsHandler_Tickers(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/admin/ops/api/tickers", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var data TickerData
	err := json.NewDecoder(rec.Body).Decode(&data)
	require.NoError(t, err)
	assert.Empty(t, data.Tickers)
}

// --- Concurrent handler access ---

func TestOpsHandler_ConcurrentOverview(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	// Hit overview from multiple goroutines to check for races
	done := make(chan struct{}, 10)
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			req := httptest.NewRequest(http.MethodGet, "/admin/ops/api/overview", nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
		}()
	}
	for i := 0; i < 10; i++ {
		select {
		case <-done:
		case <-contextTimeout(t, 5*time.Second):
			t.Fatal("timed out waiting for concurrent overview requests")
		}
	}
}

// --- Admin user management tests ---

func TestOpsHandler_ListUsers(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	// Non-admin: forbidden
	req := requestWithEmail(http.MethodGet, "/admin/ops/api/users", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestOpsHandler_ListUsers_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestOpsHandler_SuspendUser_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/suspend?email=victim@test.com", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestOpsHandler_SuspendUser_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/users/suspend", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestOpsHandler_ActivateUser_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/activate?email=target@test.com", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestOpsHandler_OffboardUser_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/offboard?email=target@test.com", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestOpsHandler_ChangeRole_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/role?email=target@test.com&role=admin", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// --- Freeze/unfreeze tests ---

func TestOpsHandler_FreezeTrading_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/risk/freeze?email=target@test.com", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestOpsHandler_UnfreezeTrading_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/risk/unfreeze?email=target@test.com", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestOpsHandler_FreezeGlobal_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/risk/freeze-global", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestOpsHandler_UnfreezeGlobal_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/risk/unfreeze-global", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// --- Force reauth tests ---

func TestOpsHandler_ForceReauth_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/force-reauth?email=target@test.com", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// --- Verify chain tests ---

func TestOpsHandler_VerifyChain_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/verify-chain?email=target@test.com", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// --- Metrics API tests ---

func TestOpsHandler_MetricsAPI_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/metrics", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// --- Alerts endpoint tests ---

func TestOpsHandler_Alerts(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/admin/ops/api/alerts", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestOpsHandler_Alerts_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodPost, "/admin/ops/api/alerts", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// --- Registry handler tests ---

func TestOpsHandler_Registry_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/registry", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// --- Ops page render test ---

func TestOpsHandler_ServePage_NoAuth(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/admin/ops", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
}

// contextTimeout returns a channel that closes after the given duration.
func contextTimeout(t *testing.T, d time.Duration) <-chan struct{} {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	ch := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(ch)
	}()
	return ch
}

// newTestHandlerWithAdmin creates an ops Handler with the given email
// pre-registered as an admin user.
func newTestHandlerWithAdmin(t *testing.T, adminEmail string) *Handler {
	t.Helper()
	h := newTestHandler(t)
	if h.userStore != nil {
		h.userStore.EnsureAdmin(adminEmail)
	}
	return h
}

// --- Sessions endpoint additional tests ---

func TestOpsHandler_Sessions_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodPost, "/admin/ops/api/sessions", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// --- Tickers endpoint additional tests ---

func TestOpsHandler_Tickers_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodPost, "/admin/ops/api/tickers", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// --- Credentials endpoint additional tests ---

func TestOpsHandler_Credentials_UnsupportedMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPut, "/admin/ops/api/credentials", "test@example.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// --- Force reauth additional tests ---

func TestOpsHandler_ForceReauth_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/force-reauth?email=target@test.com", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestOpsHandler_ForceReauth_Admin_MissingEmail(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/force-reauth", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestOpsHandler_ForceReauth_Admin_Success(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/force-reauth?email=target@test.com", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var result map[string]string
	err := json.NewDecoder(rec.Body).Decode(&result)
	require.NoError(t, err)
	assert.Equal(t, "ok", result["status"])
}

// --- Verify chain additional tests ---

func TestOpsHandler_VerifyChain_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/verify-chain", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestOpsHandler_VerifyChain_Admin_NoAuditStore(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	// auditStore is already nil in newTestHandler
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/verify-chain", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// --- List users as admin ---

func TestOpsHandler_ListUsers_Admin_Success(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/users", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

// --- Suspend user as admin ---

func TestOpsHandler_SuspendUser_Admin_MissingEmail(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/suspend", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestOpsHandler_SuspendUser_Admin_SelfSuspend(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/suspend?email=admin@test.com", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestOpsHandler_SuspendUser_Admin_Success(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	// Create a target user to suspend
	h.userStore.EnsureUser("target@test.com", "", "", "self")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/suspend?email=target@test.com", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var result map[string]string
	err := json.NewDecoder(rec.Body).Decode(&result)
	require.NoError(t, err)
	assert.Equal(t, "ok", result["status"])
}

// --- Activate user as admin ---

func TestOpsHandler_ActivateUser_Admin_MissingEmail(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/activate", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestOpsHandler_ActivateUser_Admin_SelfActivate(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/activate?email=admin@test.com", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestOpsHandler_ActivateUser_Admin_Success(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	// Create and suspend a target user
	h.userStore.EnsureUser("target@test.com", "", "", "self")
	_ = h.userStore.UpdateStatus("target@test.com", "suspended")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/activate?email=target@test.com", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// --- Activate user wrong method ---

func TestOpsHandler_ActivateUser_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/users/activate", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// --- Offboard user additional tests ---

func TestOpsHandler_OffboardUser_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/users/offboard?email=target@test.com", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestOpsHandler_OffboardUser_Admin_MissingEmail(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/offboard", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestOpsHandler_OffboardUser_Admin_SelfOffboard(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"confirm": true}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/offboard?email=admin@test.com", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestOpsHandler_OffboardUser_Admin_NoConfirm(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	h.userStore.EnsureUser("target@test.com", "", "", "self")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"confirm": false}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/offboard?email=target@test.com", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestOpsHandler_OffboardUser_Admin_Success(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	h.userStore.EnsureUser("target@test.com", "", "", "self")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"confirm": true}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/offboard?email=target@test.com", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// --- Change role additional tests ---

func TestOpsHandler_ChangeRole_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/users/role?email=target@test.com", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestOpsHandler_ChangeRole_Admin_MissingEmail(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"role":"viewer"}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/role", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestOpsHandler_ChangeRole_Admin_Success(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	h.userStore.EnsureUser("target@test.com", "", "", "self")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"role":"viewer"}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/role?email=target@test.com", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var result map[string]string
	err := json.NewDecoder(rec.Body).Decode(&result)
	require.NoError(t, err)
	assert.Contains(t, result["message"], "viewer")
}

func TestOpsHandler_ChangeRole_Admin_LastAdminGuard(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	// Only one admin exists. Trying to demote them should fail.
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"role":"trader"}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/role?email=admin@test.com", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusConflict, rec.Code)
}

// --- Metrics API additional tests ---

func TestOpsHandler_MetricsAPI_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/metrics", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestOpsHandler_MetricsAPI_Admin_NoAuditStore(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/metrics", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// --- Metrics fragment additional tests ---

func TestOpsHandler_MetricsFragment_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/metrics-fragment", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestOpsHandler_MetricsFragment_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/metrics-fragment", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestOpsHandler_MetricsFragment_Admin_NoAuditStore(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/metrics-fragment", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// --- Log stream tests ---

func TestOpsHandler_LogStream_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/logs", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestOpsHandler_LogStream_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/logs", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// --- Overview stream SSE test ---

func TestOpsHandler_OverviewStream_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	// Non-admin user should not get overview stream
	// Note: the handler is wrapped with adminAuth middleware which the noop bypasses,
	// but the handler internally checks admin status for some endpoints.
	// For overview-stream, it just writes SSE data. Test that it doesn't panic.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	req := httptest.NewRequest(http.MethodGet, "/admin/ops/api/overview-stream", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// The handler should set SSE headers and return some data
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/event-stream")
}

// --- Freeze trading additional tests ---

func TestOpsHandler_FreezeTrading_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/risk/freeze", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestOpsHandler_FreezeTrading_Admin_SelfFreeze(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"email":"admin@test.com","reason":"test","confirm":true}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/risk/freeze", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestOpsHandler_FreezeTrading_Admin_NoConfirm(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"email":"target@test.com","reason":"test","confirm":false}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/risk/freeze", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// --- Unfreeze trading additional tests ---

func TestOpsHandler_UnfreezeTrading_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/risk/unfreeze", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestOpsHandler_UnfreezeTrading_Admin_SelfUnfreeze(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"email":"admin@test.com"}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/risk/unfreeze", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// --- Freeze global additional tests ---

func TestOpsHandler_FreezeGlobal_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/risk/freeze-global", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestOpsHandler_FreezeGlobal_Admin_NoConfirm(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"reason":"market crash","confirm":false}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/risk/freeze-global", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// --- Unfreeze global additional tests ---

func TestOpsHandler_UnfreezeGlobal_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/risk/unfreeze-global", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// --- Registry handler additional tests ---

func TestOpsHandler_Registry_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodDelete, "/admin/ops/api/registry", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestOpsHandler_Registry_Admin_GET(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/registry", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

func TestOpsHandler_Registry_Admin_POST_MissingFields(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"id":"test-1"}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/registry", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestOpsHandler_Registry_Admin_POST_Success(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"id":"test-1","api_key":"testkey123","api_secret":"testsecret","label":"Test App"}`)
	req := requestWithEmail(http.MethodPost, "/admin/ops/api/registry", "admin@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusCreated, rec.Code)

	var result map[string]string
	err := json.NewDecoder(rec.Body).Decode(&result)
	require.NoError(t, err)
	assert.Equal(t, "ok", result["status"])
	assert.Equal(t, "test-1", result["id"])
}

// --- Registry item handler tests ---

func TestOpsHandler_RegistryItem_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPut, "/admin/ops/api/registry/test-1", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestOpsHandler_RegistryItem_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/registry/test-1", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestOpsHandler_RegistryItem_MissingID(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPut, "/admin/ops/api/registry/", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// --- Overview with admin vs non-admin data scoping ---

func TestOpsHandler_Overview_AdminSeesFull(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/overview", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var overview OverviewData
	err := json.NewDecoder(rec.Body).Decode(&overview)
	require.NoError(t, err)
	assert.Equal(t, "test-v1", overview.Version)
}

func TestOpsHandler_Overview_NonAdminSeesScoped(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/overview", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var overview OverviewData
	err := json.NewDecoder(rec.Body).Decode(&overview)
	require.NoError(t, err)
	// Non-admin gets scoped data (version still available)
	assert.Equal(t, "test-v1", overview.Version)
}

// --- Sessions scoping tests ---

func TestOpsHandler_Sessions_NonAdminSeesScoped(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/sessions", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// --- Tickers scoping tests ---

func TestOpsHandler_Tickers_NonAdminSeesScoped(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/tickers", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// --- Alerts scoping tests ---

func TestOpsHandler_Alerts_NonAdminSeesScoped(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/alerts", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// --- writeJSON / writeJSONError (Handler) tests ---

func TestOpsHandler_WriteJSON(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	rec := httptest.NewRecorder()
	h.writeJSON(rec, map[string]string{"key": "value"})

	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	var result map[string]string
	err := json.NewDecoder(rec.Body).Decode(&result)
	require.NoError(t, err)
	assert.Equal(t, "value", result["key"])
}

func TestOpsHandler_WriteJSONError(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	rec := httptest.NewRecorder()
	h.writeJSONError(rec, http.StatusBadRequest, "something went wrong")

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var result map[string]string
	err := json.NewDecoder(rec.Body).Decode(&result)
	require.NoError(t, err)
	assert.Equal(t, "something went wrong", result["error"])
}

// --- isAdmin tests ---

func TestOpsHandler_IsAdmin_NilUserStore(t *testing.T) {
	t.Parallel()
	h := &Handler{userStore: nil}
	assert.False(t, h.isAdmin("admin@test.com"))
}

func TestOpsHandler_IsAdmin_NotAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	assert.False(t, h.isAdmin("user@test.com"))
}

func TestOpsHandler_IsAdmin_Yes(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAdmin(t, "admin@test.com")
	assert.True(t, h.isAdmin("admin@test.com"))
}

// --- logAdminAction tests ---

func TestOpsHandler_LogAdminAction_NoAuditStore(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t) // auditStore is nil
	// Should not panic
	h.logAdminAction("admin@test.com", "test_action", "target@test.com")
}

// --- truncKey (handler.go) tests ---

func TestOpsHandler_TruncKey(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "abcd", truncKey("abcdefgh", 4))
	assert.Equal(t, "ab", truncKey("ab", 4))
	assert.Equal(t, "", truncKey("", 4))
}
