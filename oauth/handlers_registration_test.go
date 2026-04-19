package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// --- Well-Known Metadata ---

func TestResourceMetadata_GET(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rr := httptest.NewRecorder()

	h.ResourceMetadata(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}
	if body["resource"] != "https://test.example.com/mcp" {
		t.Errorf("resource = %v, want %q", body["resource"], "https://test.example.com/mcp")
	}
	servers, ok := body["authorization_servers"].([]any)
	if !ok || len(servers) != 1 || servers[0] != "https://test.example.com" {
		t.Errorf("authorization_servers = %v, want [https://test.example.com]", body["authorization_servers"])
	}
}


func TestResourceMetadata_POST(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodPost, "/.well-known/oauth-protected-resource", nil)
	rr := httptest.NewRecorder()

	h.ResourceMetadata(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %d, want 405", rr.Code)
	}
}


func TestAuthServerMetadata(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rr := httptest.NewRecorder()

	h.AuthServerMetadata(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want 200", rr.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}

	requiredFields := []struct {
		key  string
		want string
	}{
		{"issuer", "https://test.example.com"},
		{"authorization_endpoint", "https://test.example.com/oauth/authorize"},
		{"token_endpoint", "https://test.example.com/oauth/token"},
		{"registration_endpoint", "https://test.example.com/oauth/register"},
	}
	for _, f := range requiredFields {
		if body[f.key] != f.want {
			t.Errorf("%s = %v, want %q", f.key, body[f.key], f.want)
		}
	}

	// Check supported values
	checkStringSlice := func(key string, want []string) {
		t.Helper()
		arr, ok := body[key].([]any)
		if !ok {
			t.Errorf("%s is not an array", key)
			return
		}
		if len(arr) != len(want) {
			t.Errorf("%s length = %d, want %d", key, len(arr), len(want))
			return
		}
		for i, v := range arr {
			if v != want[i] {
				t.Errorf("%s[%d] = %v, want %q", key, i, v, want[i])
			}
		}
	}
	checkStringSlice("response_types_supported", []string{"code"})
	checkStringSlice("grant_types_supported", []string{"authorization_code"})
	checkStringSlice("code_challenge_methods_supported", []string{"S256"})
	checkStringSlice("token_endpoint_auth_methods_supported", []string{"client_secret_post"})
}


// --- Dynamic Client Registration ---
func TestRegister_Valid(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	body := `{"redirect_uris":["https://example.com/callback"],"client_name":"test-app"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.Register(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("Status = %d, want 201. Body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}
	if resp["client_id"] == nil || resp["client_id"] == "" {
		t.Error("client_id should be non-empty")
	}
	if resp["client_secret"] == nil || resp["client_secret"] == "" {
		t.Error("client_secret should be non-empty")
	}
	if resp["client_name"] != "test-app" {
		t.Errorf("client_name = %v, want %q", resp["client_name"], "test-app")
	}
	if resp["token_endpoint_auth_method"] != "client_secret_post" {
		t.Errorf("token_endpoint_auth_method = %v, want %q", resp["token_endpoint_auth_method"], "client_secret_post")
	}
}


func TestRegister_NoRedirectURIs(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	body := `{"redirect_uris":[],"client_name":"test-app"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.Register(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}


func TestRegister_TooManyURIs(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	uris := make([]string, 11)
	for i := range uris {
		uris[i] = fmt.Sprintf("https://example.com/cb%d", i)
	}
	reqBody := struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
	}{RedirectURIs: uris, ClientName: "test-app"}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(string(bodyBytes)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.Register(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}


func TestRegister_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/oauth/register", nil)
	rr := httptest.NewRecorder()

	h.Register(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %d, want 405", rr.Code)
	}
}


// --- Close ---
func TestClose(t *testing.T) {
	t.Parallel()
	h := newTestHandler()

	// Close should not panic
	h.Close()

	// Double close should not panic (protected by sync.Once)
	h.Close()
}


func TestSetUserStore_NilSafe(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Should not panic
	h.SetUserStore(nil)
}


func TestSetGoogleSSO_NilSafe(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Should not panic
	h.SetGoogleSSO(nil)
	if h.GoogleSSOEnabled() {
		t.Error("GoogleSSO should not be enabled after setting nil config")
	}
}


// ===========================================================================
// Handler setters
// ===========================================================================
func TestSetKiteTokenChecker(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Should not panic with nil
	h.SetKiteTokenChecker(nil)
}


func TestSetRegistry(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Should not panic with nil
	h.SetRegistry(nil)
}


// ===========================================================================
// SetHTTPClient coverage
// ===========================================================================
func TestSetHTTPClient_Coverage(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetHTTPClient(nil)
	h.SetHTTPClient(&http.Client{Timeout: 5 * time.Second})
}


// ===========================================================================
// NewHandler — template error paths (already parsed from embedded FS)
// ===========================================================================
func TestNewHandler_SetsAllTemplates(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	if h.loginSuccessTmpl == nil {
		t.Error("loginSuccessTmpl should be non-nil")
	}
	if h.browserLoginTmpl == nil {
		t.Error("browserLoginTmpl should be non-nil")
	}
	if h.adminLoginTmpl == nil {
		t.Error("adminLoginTmpl should be non-nil")
	}
	if h.emailPromptTmpl == nil {
		t.Error("emailPromptTmpl should be non-nil")
	}
	if h.loginChoiceTmpl == nil {
		t.Error("loginChoiceTmpl should be non-nil")
	}
}


// ===========================================================================
// Register endpoint — method not allowed
// ===========================================================================
func TestRegister_MethodNotAllowed_Final(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/oauth/register", nil)
	rr := httptest.NewRecorder()
	h.Register(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %d, want 405", rr.Code)
	}
}


// ---------------------------------------------------------------------------
// handlers.go:403-405 — serveEmailPrompt: template ExecuteTemplate error
// Nil the template after construction so the nil check (line 354) passes
// but execution fails. Actually the nil check returns 500 first, so we
// can't get to ExecuteTemplate with a nil template. We need a template
// that fails on Execute — difficult without breaking the embedded FS.
// This line is effectively unreachable (valid embedded template never fails
// on execution with the struct data types we provide). Documented below.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// google_sso.go:245-247 — fetchGoogleUserInfo: bad URL
// ---------------------------------------------------------------------------
func TestFetchGoogleUserInfo_InvalidURL_Push100(t *testing.T) {
	t.Parallel()

	_, err := fetchGoogleUserInfo(context.Background(), "token", nil, "://invalid-url")
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}


// ---------------------------------------------------------------------------
// google_sso.go:255-257 — fetchGoogleUserInfo: unreachable server
// ---------------------------------------------------------------------------
func TestFetchGoogleUserInfo_ConnectionRefused_Push100(t *testing.T) {
	t.Parallel()

	_, err := fetchGoogleUserInfo(context.Background(), "token", http.DefaultClient,
		"http://127.0.0.1:1/userinfo")
	if err == nil {
		t.Error("Expected error for unreachable server")
	}
}


// ---------------------------------------------------------------------------
// Register — too many redirect URIs (line 228)
// ---------------------------------------------------------------------------
func TestRegister_TooManyRedirectURIs_Gap(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	body := map[string]interface{}{
		"redirect_uris": make([]string, 11), // max is 10
		"client_name":   "test",
	}
	for i := range body["redirect_uris"].([]string) {
		body["redirect_uris"].([]string)[i] = fmt.Sprintf("https://example.com/cb%d", i)
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(string(bodyJSON)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.Register(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400 (too many redirect URIs)", rr.Code)
	}
}


// ---------------------------------------------------------------------------
// Documented unreachable lines
// ---------------------------------------------------------------------------
//
// The following lines are documented as unreachable and NOT tested:
//
// - handlers.go:106-124 — template.ParseFS errors (templates are embedded at build time)
// - handlers.go:823-825 — generateCSRFToken (crypto/rand.Read never fails in Go 1.24+)
// - stores.go:58-60 — randomHex (crypto/rand.Read never fails in Go 1.24+)
// - stores.go:211-213, 215-217 — Register randomHex (same reason)
// - stores.go:349-353 — randomHex (same reason)
// - middleware.go:125-127 — SetAuthCookie (HS256 SignedString never fails)
// - google_sso.go:66-70 — rand.Read (same reason)
// - google_sso.go:217-221 — rand.Read (same reason)
// - google_sso.go:245-247, 255-257 — fetchGoogleUserInfo HTTP/JSON errors (tested via mock servers)

// ===========================================================================
// Merged from stores_coverage_test.go (handler-related test)
// ===========================================================================
func TestNewHandler_Minimal(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		JWTSecret: "test-secret",
		Logger:    testLogger(),
	}
	h := NewHandler(cfg, &mockSigner{}, &mockExchanger{})
	assert.NotNil(t, h)
	h.Close()
}
