package oauth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ===========================================================================
// HandleGoogleLogin
// ===========================================================================



// ===========================================================================
// HandleGoogleCallback — additional error paths not in context_test.go
// ===========================================================================
func TestHandleGoogleCallback_NotConfigured(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/google/callback?code=abc&state=xyz", nil)
	rr := httptest.NewRecorder()

	h.HandleGoogleCallback(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Status = %d, want 404", rr.Code)
	}
}


func TestHandleGoogleCallback_ClearsCookieOnStateMismatch(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()
	h.SetGoogleSSO(&GoogleSSOConfig{
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		RedirectURL:  "https://test.example.com/auth/google/callback",
	})

	// Provide a valid state cookie but mismatched state
	req := httptest.NewRequest(http.MethodGet, "/auth/google/callback?code=abc&state=wrong", nil)
	req.AddCookie(&http.Cookie{Name: googleStateCookieName, Value: "correct|/dashboard"})
	rr := httptest.NewRecorder()

	h.HandleGoogleCallback(rr, req)

	// Cookie should be cleared (MaxAge = -1)
	cookies := rr.Result().Cookies()
	for _, c := range cookies {
		if c.Name == googleStateCookieName {
			if c.MaxAge != -1 {
				t.Errorf("Expected cookie MaxAge=-1 (cleared), got %d", c.MaxAge)
			}
			break
		}
	}
}


func TestHandleGoogleCallback_EmptyStateCookie(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()
	h.SetGoogleSSO(&GoogleSSOConfig{
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		RedirectURL:  "https://test.example.com/auth/google/callback",
	})

	req := httptest.NewRequest(http.MethodGet, "/auth/google/callback?code=abc", nil)
	req.AddCookie(&http.Cookie{Name: googleStateCookieName, Value: ""})
	rr := httptest.NewRecorder()

	h.HandleGoogleCallback(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400 (empty state cookie)", rr.Code)
	}
}



// ===========================================================================
// HandleGoogleCallback — full happy path with mock OAuth + userinfo servers
// ===========================================================================
func TestHandleGoogleCallback_FullHappyPath(t *testing.T) {
	t.Parallel()

	// Mock Google token endpoint: returns an access token
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "mock-access-tok",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenSrv.Close()

	// Mock Google userinfo endpoint
	userinfoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"email":          "admin@test.com",
			"verified_email": true,
		})
	}))
	defer userinfoSrv.Close()

	h := newTestHandler()
	defer h.Close()

	// Configure Google SSO with mock token + userinfo endpoints
	h.SetGoogleSSO(&GoogleSSOConfig{
		ClientID:     "test-google-client-id",
		ClientSecret: "test-google-secret",
		RedirectURL:  "https://test.example.com/auth/google/callback",
		Endpoint:     tokenSrv.URL,
		UserInfoURL:  userinfoSrv.URL,
	})

	h.SetHTTPClient(tokenSrv.Client())

	h.SetUserStore(&mockAdminUserStore{
		roles:    map[string]string{"admin@test.com": "admin"},
		statuses: map[string]string{"admin@test.com": "active"},
	})

	// Build request with valid state cookie
	state := base64.URLEncoding.EncodeToString([]byte("test-state-value"))
	req := httptest.NewRequest(http.MethodGet, "/auth/google/callback?code=test-auth-code&state="+state, nil)
	req.AddCookie(&http.Cookie{
		Name:  googleStateCookieName,
		Value: state + "|/admin/ops",
	})
	rr := httptest.NewRecorder()

	h.HandleGoogleCallback(rr, req)

	// Should redirect (302) after successful login
	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302. Body: %s", rr.Code, rr.Body.String())
	}
}


func TestHandleGoogleCallback_TokenExchangeFails(t *testing.T) {
	t.Parallel()

	// Mock token endpoint that returns an error
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "code expired",
		})
	}))
	defer tokenSrv.Close()

	h := newTestHandler()
	defer h.Close()

	h.SetGoogleSSO(&GoogleSSOConfig{
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		RedirectURL:  "https://test.example.com/auth/google/callback",
		Endpoint:     tokenSrv.URL,
	})
	h.SetHTTPClient(tokenSrv.Client())

	state := base64.URLEncoding.EncodeToString([]byte("test-state"))
	req := httptest.NewRequest(http.MethodGet, "/auth/google/callback?code=expired-code&state="+state, nil)
	req.AddCookie(&http.Cookie{
		Name:  googleStateCookieName,
		Value: state + "|/dashboard",
	})
	rr := httptest.NewRecorder()

	h.HandleGoogleCallback(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500 (token exchange failure). Body: %s", rr.Code, rr.Body.String())
	}
}


func TestHandleGoogleCallback_UserInfoFails(t *testing.T) {
	t.Parallel()

	// Mock token endpoint: succeeds
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "mock-tok",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenSrv.Close()

	// Mock userinfo endpoint: returns 500
	userinfoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer userinfoSrv.Close()

	h := newTestHandler()
	defer h.Close()

	h.SetGoogleSSO(&GoogleSSOConfig{
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		RedirectURL:  "https://test.example.com/auth/google/callback",
		Endpoint:     tokenSrv.URL,
		UserInfoURL:  userinfoSrv.URL,
	})
	h.SetHTTPClient(tokenSrv.Client())

	state := base64.URLEncoding.EncodeToString([]byte("test-state"))
	req := httptest.NewRequest(http.MethodGet, "/auth/google/callback?code=ok-code&state="+state, nil)
	req.AddCookie(&http.Cookie{
		Name:  googleStateCookieName,
		Value: state + "|/dashboard",
	})
	rr := httptest.NewRecorder()

	h.HandleGoogleCallback(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500 (userinfo failure). Body: %s", rr.Code, rr.Body.String())
	}
}


func TestHandleGoogleCallback_EmptyEmail(t *testing.T) {
	t.Parallel()

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenSrv.Close()

	userinfoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"email":          "",
			"verified_email": true,
		})
	}))
	defer userinfoSrv.Close()

	h := newTestHandler()
	defer h.Close()

	h.SetGoogleSSO(&GoogleSSOConfig{
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		RedirectURL:  "https://test.example.com/auth/google/callback",
		Endpoint:     tokenSrv.URL,
		UserInfoURL:  userinfoSrv.URL,
	})
	h.SetHTTPClient(tokenSrv.Client())

	// Must set a userStore so the test reaches the empty-email check
	h.SetUserStore(&mockAdminUserStore{
		roles:    map[string]string{},
		statuses: map[string]string{},
	})

	state := base64.URLEncoding.EncodeToString([]byte("state"))
	req := httptest.NewRequest(http.MethodGet, "/auth/google/callback?code=ok&state="+state, nil)
	req.AddCookie(&http.Cookie{
		Name:  googleStateCookieName,
		Value: state + "|/dashboard",
	})
	rr := httptest.NewRecorder()

	h.HandleGoogleCallback(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400 (empty email). Body: %s", rr.Code, rr.Body.String())
	}
}


func TestHandleGoogleCallback_SuspendedUser(t *testing.T) {
	t.Parallel()

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenSrv.Close()

	userinfoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"email":          "suspended@test.com",
			"verified_email": true,
		})
	}))
	defer userinfoSrv.Close()

	h := newTestHandler()
	defer h.Close()

	h.SetGoogleSSO(&GoogleSSOConfig{
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		RedirectURL:  "https://test.example.com/auth/google/callback",
		Endpoint:     tokenSrv.URL,
		UserInfoURL:  userinfoSrv.URL,
	})
	h.SetHTTPClient(tokenSrv.Client())

	h.SetUserStore(&mockAdminUserStore{
		roles:    map[string]string{"suspended@test.com": "admin"},
		statuses: map[string]string{"suspended@test.com": "suspended"},
	})

	state := base64.URLEncoding.EncodeToString([]byte("state"))
	req := httptest.NewRequest(http.MethodGet, "/auth/google/callback?code=ok&state="+state, nil)
	req.AddCookie(&http.Cookie{
		Name:  googleStateCookieName,
		Value: state + "|/dashboard",
	})
	rr := httptest.NewRecorder()

	h.HandleGoogleCallback(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("Status = %d, want 403 (suspended). Body: %s", rr.Code, rr.Body.String())
	}
}


func TestHandleGoogleCallback_MissingCode_WithValidState(t *testing.T) {
	t.Parallel()

	h := newTestHandler()
	defer h.Close()

	h.SetGoogleSSO(&GoogleSSOConfig{
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		RedirectURL:  "https://test.example.com/auth/google/callback",
	})

	state := "mystate"
	req := httptest.NewRequest(http.MethodGet, "/auth/google/callback?state="+state, nil)
	req.AddCookie(&http.Cookie{
		Name:  googleStateCookieName,
		Value: state + "|/dashboard",
	})
	rr := httptest.NewRecorder()

	h.HandleGoogleCallback(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400 (missing code). Body: %s", rr.Code, rr.Body.String())
	}
}


func TestHandleGoogleCallback_OAuthError_RedirectsToAdminLogin(t *testing.T) {
	t.Parallel()

	h := newTestHandler()
	defer h.Close()

	h.SetGoogleSSO(&GoogleSSOConfig{
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		RedirectURL:  "https://test.example.com/auth/google/callback",
	})

	state := "mystate"
	req := httptest.NewRequest(http.MethodGet, "/auth/google/callback?error=access_denied&state="+state, nil)
	req.AddCookie(&http.Cookie{
		Name:  googleStateCookieName,
		Value: state + "|/admin/ops",
	})
	rr := httptest.NewRecorder()

	h.HandleGoogleCallback(rr, req)

	// Should redirect to admin login page
	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 (redirect on OAuth error). Body: %s", rr.Code, rr.Body.String())
	}
	location := rr.Header().Get("Location")
	if !strings.Contains(location, "/auth/admin-login") {
		t.Errorf("Expected redirect to admin-login, got: %q", location)
	}
}


func TestHandleGoogleCallback_MalformedStateCookie_NoPipe(t *testing.T) {
	t.Parallel()

	h := newTestHandler()
	defer h.Close()

	h.SetGoogleSSO(&GoogleSSOConfig{
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		RedirectURL:  "https://test.example.com/auth/google/callback",
	})

	// Cookie with no pipe separator
	req := httptest.NewRequest(http.MethodGet, "/auth/google/callback?code=abc&state=xyz", nil)
	req.AddCookie(&http.Cookie{
		Name:  googleStateCookieName,
		Value: "no-pipe-separator",
	})
	rr := httptest.NewRecorder()

	h.HandleGoogleCallback(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400 (malformed cookie). Body: %s", rr.Code, rr.Body.String())
	}
}


func TestHandleGoogleCallback_NoUserStore(t *testing.T) {
	t.Parallel()

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenSrv.Close()

	userinfoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"email":          "user@example.com",
			"verified_email": true,
		})
	}))
	defer userinfoSrv.Close()

	h := newTestHandler()
	defer h.Close()

	h.SetGoogleSSO(&GoogleSSOConfig{
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		RedirectURL:  "https://test.example.com/auth/google/callback",
		Endpoint:     tokenSrv.URL,
		UserInfoURL:  userinfoSrv.URL,
	})
	h.SetHTTPClient(tokenSrv.Client())
	// Deliberately do NOT set a userStore

	state := base64.URLEncoding.EncodeToString([]byte("state"))
	req := httptest.NewRequest(http.MethodGet, "/auth/google/callback?code=ok&state="+state, nil)
	req.AddCookie(&http.Cookie{
		Name:  googleStateCookieName,
		Value: state + "|/dashboard",
	})
	rr := httptest.NewRecorder()

	h.HandleGoogleCallback(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500 (no user store). Body: %s", rr.Code, rr.Body.String())
	}
}


func TestHandleGoogleCallback_TraderRedirectToDashboard(t *testing.T) {
	t.Parallel()

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenSrv.Close()

	userinfoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"email":          "trader@test.com",
			"verified_email": true,
		})
	}))
	defer userinfoSrv.Close()

	h := newTestHandler()
	defer h.Close()

	h.SetGoogleSSO(&GoogleSSOConfig{
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		RedirectURL:  "https://test.example.com/auth/google/callback",
		Endpoint:     tokenSrv.URL,
		UserInfoURL:  userinfoSrv.URL,
	})
	h.SetHTTPClient(tokenSrv.Client())

	h.SetUserStore(&mockAdminUserStore{
		roles:    map[string]string{"trader@test.com": "trader"},
		statuses: map[string]string{"trader@test.com": "active"},
	})

	state := base64.URLEncoding.EncodeToString([]byte("state"))
	req := httptest.NewRequest(http.MethodGet, "/auth/google/callback?code=ok&state="+state, nil)
	req.AddCookie(&http.Cookie{
		Name:  googleStateCookieName,
		Value: state + "|/dashboard/activity",
	})
	rr := httptest.NewRecorder()

	h.HandleGoogleCallback(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302. Body: %s", rr.Code, rr.Body.String())
	}
	location := rr.Header().Get("Location")
	if location != "/dashboard/activity" {
		t.Errorf("Location = %q, want /dashboard/activity", location)
	}
}


func TestHandleGoogleCallback_OpenRedirectInCookie(t *testing.T) {
	t.Parallel()

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenSrv.Close()

	userinfoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"email":          "admin@test.com",
			"verified_email": true,
		})
	}))
	defer userinfoSrv.Close()

	h := newTestHandler()
	defer h.Close()

	h.SetGoogleSSO(&GoogleSSOConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		RedirectURL:  "https://test.example.com/auth/google/callback",
		Endpoint:     tokenSrv.URL,
		UserInfoURL:  userinfoSrv.URL,
	})
	h.SetHTTPClient(tokenSrv.Client())
	h.SetUserStore(&mockAdminUserStore{
		roles:    map[string]string{"admin@test.com": "admin"},
		statuses: map[string]string{"admin@test.com": "active"},
	})

	state := base64.URLEncoding.EncodeToString([]byte("mystate"))
	req := httptest.NewRequest(http.MethodGet, "/auth/google/callback?code=c&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: googleStateCookieName, Value: state + "|//evil.com"})
	rr := httptest.NewRecorder()

	h.HandleGoogleCallback(rr, req)

	if rr.Code == http.StatusFound {
		location := rr.Header().Get("Location")
		if strings.Contains(location, "evil.com") {
			t.Errorf("Open redirect should be blocked, got: %q", location)
		}
	}
}
