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
	"github.com/zerodha/kite-mcp-server/oauth"
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

	mgr, err := kc.New(kc.Config{
		APIKey:             "test_api_key",
		APISecret:          "test_api_secret",
		Logger:             logger,
		DevMode:            true,
		InstrumentsManager: instrMgr,
	})
	require.NoError(t, err)
	t.Cleanup(func() { mgr.Shutdown() })

	lb := NewLogBuffer(100)
	return New(mgr, nil, lb, logger, "test-v1", time.Now(), mgr.UserStoreConcrete(), nil)
}

// devNull implements io.Writer and discards all bytes.
type devNull struct{}

func (devNull) Write(p []byte) (int, error) { return len(p), nil }

// noopAuth is a pass-through middleware that does NOT enforce authentication.
func noopAuth(next http.Handler) http.Handler { return next }

// requestWithEmail returns a request whose context carries the given email,
// matching what oauth.RequireAuthBrowser would inject in production.
func requestWithEmail(method, target, email string, body *strings.Reader) *http.Request {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, target, body)
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	if email != "" {
		ctx := oauth.ContextWithEmail(req.Context(), email)
		req = req.WithContext(ctx)
	}
	return req
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
