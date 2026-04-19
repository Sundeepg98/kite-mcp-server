package ops

// ops_push100_test.go: push ops coverage from ~89% toward 100%.
// Targets remaining uncovered branches in handler.go, user_render.go,
// dashboard.go, dashboard_templates.go, overview_sse.go, and admin_render.go.

import (
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
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// ---------------------------------------------------------------------------
// Helpers unique to this file
// ---------------------------------------------------------------------------

// newPush100OpsHandler creates a minimal ops handler with nil userStore for nil-path tests.


// ---------------------------------------------------------------------------
// handler.go: credentials POST with auto-register to registry
// ---------------------------------------------------------------------------
func TestPush100_Credentials_Post_AutoRegisterNewKey(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	body := `{"api_key":"brand_new_key_12345","api_secret":"brand_new_secret"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/ops/api/credentials", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(oauth.ContextWithEmail(req.Context(), "newuser@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	// Verify credentials were stored
	_, hasCreds := h.manager.CredentialStore().Get("newuser@test.com")
	assert.True(t, hasCreds)
}


// ---------------------------------------------------------------------------
// handler.go: credentials GET with long secret (>7 chars)
// ---------------------------------------------------------------------------
func TestPush100_Credentials_Get_LongSecret(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	h.manager.CredentialStore().Set("showuser@test.com", &kc.KiteCredentialEntry{
		APIKey: "key123", APISecret: "long_secret_value_here", StoredAt: time.Now(),
	})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/admin/ops/api/credentials", nil)
	req = req.WithContext(oauth.ContextWithEmail(req.Context(), "showuser@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp []map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	require.Len(t, resp, 1)
	hint, _ := resp[0]["api_secret_hint"].(string)
	assert.Contains(t, hint, "****")
	assert.True(t, len(hint) > 4) // Not just "****" — has prefix+suffix
}


// ===========================================================================
// dashboard.go: selfDeleteAccount — method not allowed, no confirm, success
// ===========================================================================
func TestPush100_SelfDeleteAccount_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/account/delete", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestPush100_SelfDeleteAccount_NoEmail(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReqBody(http.MethodPost, "/dashboard/api/account/delete", "", `{"confirm":true}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


func TestPush100_SelfDeleteAccount_NoConfirm(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReqBody(http.MethodPost, "/dashboard/api/account/delete", "user@test.com", `{"confirm":false}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestPush100_SelfDeleteAccount_Success(t *testing.T) {
	t.Parallel()
	d, mgr := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// Seed some data
	mgr.CredentialStore().Set("user@test.com", &kc.KiteCredentialEntry{APIKey: "k", APISecret: "s", StoredAt: time.Now()})
	mgr.TokenStore().Set("user@test.com", &kc.KiteTokenEntry{AccessToken: "t", StoredAt: time.Now()})
	_, _ = mgr.AlertStore().Add("user@test.com", "INFY", "NSE", 256265, 1600, alerts.DirectionAbove)

	req := push100DashReqBody(http.MethodPost, "/dashboard/api/account/delete", "user@test.com", `{"confirm":true}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Account deleted")

	// Verify data was cleaned up
	_, hasCreds := mgr.CredentialStore().Get("user@test.com")
	assert.False(t, hasCreds)
	_, hasToken := mgr.TokenStore().Get("user@test.com")
	assert.False(t, hasToken)
}


func TestPush100_SelfDeleteAccount_WithPaperEngine(t *testing.T) {
	t.Parallel()
	d, mgr := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	paperStore := papertrading.NewStore(mgr.AlertDB(), slog.Default())
	require.NoError(t, paperStore.InitTables())
	pe := papertrading.NewEngine(paperStore, slog.Default())
	mgr.SetPaperEngine(pe)
	_ = pe.Enable("user@test.com", 10000000)

	req := push100DashReqBody(http.MethodPost, "/dashboard/api/account/delete", "user@test.com", `{"confirm":true}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}
