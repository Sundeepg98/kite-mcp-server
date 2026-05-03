package oauth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

)

// --- Well-Known Metadata ---


// --- HandleLoginChoice ---
func TestHandleLoginChoice_GET_NoCookie(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/login?redirect=/dashboard", nil)
	rr := httptest.NewRecorder()

	h.HandleLoginChoice(rr, req)

	// Should render the login choice page (200).
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Sign In") && !strings.Contains(body, "sign") {
		// Template should render some form content.
		if len(body) == 0 {
			t.Error("Body should not be empty")
		}
	}
}

// TestHandleLoginChoice_LandmarkRoles asserts the /auth/login template
// declares semantic landmark roles for accessibility — `<main role="main">`
// and `role="contentinfo"` on the footer. Pattern matches landing.html
// + dashboard.html. Strict Playwright a11y matrix flagged this as a
// non-blocking finding; this test pins the regression.
func TestHandleLoginChoice_LandmarkRoles(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/login?redirect=/dashboard", nil)
	rr := httptest.NewRecorder()
	h.HandleLoginChoice(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `role="main"`) {
		t.Error("/auth/login must declare a `role=\"main\"` landmark for screen-reader nav")
	}
	if !strings.Contains(body, `role="contentinfo"`) {
		t.Error("/auth/login footer must use `role=\"contentinfo\"` landmark")
	}
}

// TestHandleBrowserLogin_LandmarkRoles asserts /auth/browser-login
// renders the same landmark-role contract as /auth/login.
func TestHandleBrowserLogin_LandmarkRoles(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/browser-login?redirect=/dashboard", nil)
	rr := httptest.NewRecorder()
	h.HandleBrowserLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `role="main"`) {
		t.Error("/auth/browser-login must declare a `role=\"main\"` landmark")
	}
	if !strings.Contains(body, `role="contentinfo"`) {
		t.Error("/auth/browser-login footer must use `role=\"contentinfo\"` landmark")
	}
}


func TestHandleLoginChoice_GET_ValidCookie(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Generate a valid dashboard token
	token, err := h.jwt.GenerateToken("user@test.com", "dashboard")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/login?redirect=/admin/ops", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
	rr := httptest.NewRecorder()

	h.HandleLoginChoice(rr, req)

	// Should redirect since the user already has a valid cookie.
	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 (valid cookie should redirect)", rr.Code)
	}
	location := rr.Header().Get("Location")
	if location != "/admin/ops" {
		t.Errorf("Location = %q, want /admin/ops", location)
	}
}


func TestHandleLoginChoice_GET_InvalidCookie(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/login?redirect=/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: "invalid-jwt"})
	rr := httptest.NewRecorder()

	h.HandleLoginChoice(rr, req)

	// Invalid cookie should render the login page (200).
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (invalid cookie should show login)", rr.Code)
	}
}


func TestHandleLoginChoice_DefaultRedirect_HandlersFile(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Generate a valid dashboard token.
	token, _ := h.jwt.GenerateToken("user@test.com", "dashboard")

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
	rr := httptest.NewRecorder()

	h.HandleLoginChoice(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302", rr.Code)
	}
	location := rr.Header().Get("Location")
	if location != "/dashboard" {
		t.Errorf("Location = %q, want /dashboard (default redirect)", location)
	}
}


// --- HandleAdminLogin ---
func TestHandleAdminLogin_GET(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/admin-login?redirect=/admin/ops", nil)
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	// Should render the admin login form.
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
}


func TestHandleAdminLogin_POST_MissingCSRF(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	form := url.Values{
		"email":    {"admin@test.com"},
		"password": {"secret"},
		"redirect": {"/admin/ops"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	// Should re-render the form (200) due to missing CSRF.
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (CSRF check re-renders form)", rr.Code)
	}
}


func TestHandleAdminLogin_POST_NoUserStore(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Set valid CSRF cookie + form value.
	form := url.Values{
		"email":      {"admin@test.com"},
		"password":   {"secret"},
		"redirect":   {"/admin/ops"},
		"csrf_token": {"test-csrf-value"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: "test-csrf-value"})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	// No user store configured — should re-render form with error.
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (no user store)", rr.Code)
	}
}


func TestHandleAdminLogin_DefaultRedirect(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// GET with no redirect param — should default to /admin/ops.
	req := httptest.NewRequest(http.MethodGet, "/auth/admin-login", nil)
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
}


// ===========================================================================
// HandleLoginChoice
// ===========================================================================
func TestHandleLoginChoice_NoExistingCookie(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/login?redirect=/dashboard", nil)
	rr := httptest.NewRecorder()

	h.HandleLoginChoice(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
}


// ===========================================================================
// serveAdminLoginForm — nil template error path
// ===========================================================================
func TestServeAdminLoginForm_NilTemplate(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.adminLoginTmpl = nil

	rr := httptest.NewRecorder()
	h.serveAdminLoginForm(rr, "/admin/ops", "", "csrf")

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500 (nil template)", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Failed to load admin login page") {
		t.Errorf("Body = %q, want 'Failed to load admin login page'", rr.Body.String())
	}
}


// ===========================================================================
// serveAdminLoginForm — empty CSRF token (no cookie set)
// ===========================================================================
func TestServeAdminLoginForm_EmptyCSRFNoCookie(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	rr := httptest.NewRecorder()
	h.serveAdminLoginForm(rr, "/admin/ops", "Some error", "")

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
	cookies := rr.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "csrf_token_admin" {
			t.Error("Should not set csrf_token_admin cookie when token is empty")
		}
	}
}


// ===========================================================================
// HandleLoginChoice — nil template error path
// ===========================================================================
func TestHandleLoginChoice_NilTemplate(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.loginChoiceTmpl = nil

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	rr := httptest.NewRecorder()

	h.HandleLoginChoice(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500 (nil template)", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Failed to load login page") {
		t.Errorf("Body = %q, want 'Failed to load login page'", rr.Body.String())
	}
}


// ===========================================================================
// HandleLoginChoice — method not allowed
// ===========================================================================
func TestHandleLoginChoice_POST_ServesForm(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// HandleLoginChoice serves the form regardless of method
	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	rr := httptest.NewRecorder()
	h.HandleLoginChoice(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (form served regardless of method)", rr.Code)
	}
}


// ===========================================================================
// HandleLoginChoice — serves page with Google SSO enabled
// ===========================================================================
func TestHandleLoginChoice_WithGoogleSSO(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetGoogleSSO(&GoogleSSOConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		RedirectURL:  "https://test.example.com/cb",
	})

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	rr := httptest.NewRecorder()
	h.HandleLoginChoice(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
}


// HandleLoginChoice — already authenticated via cookie
func TestHandleLoginChoice_AlreadyAuthenticated(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Generate a valid dashboard JWT
	token, err := h.jwt.GenerateToken("user@test.com", "dashboard")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/login?redirect=/custom", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
	rr := httptest.NewRecorder()
	h.HandleLoginChoice(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 redirect", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if loc != "/custom" {
		t.Errorf("Location = %q, want /custom", loc)
	}
}


// HandleLoginChoice — nil loginChoiceTmpl (coverage push)
func TestHandleLoginChoice_NilTemplate_Push(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()
	h.loginChoiceTmpl = nil

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	rr := httptest.NewRecorder()
	h.HandleLoginChoice(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500", rr.Code)
	}
}


// HandleAdminLogin POST — open redirect prevention (with valid credentials)
func TestHandleAdminLogin_POST_OpenRedirectPrevention_Valid(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()
	h.SetUserStore(&mockAdminUserStore{
		roles:     map[string]string{"admin@test.com": "admin"},
		statuses:  map[string]string{"admin@test.com": "active"},
		passwords: map[string]string{"admin@test.com": "correct-password"},
	})

	csrf := "admin-csrf"
	form := url.Values{
		"email":      {"admin@test.com"},
		"password":   {"correct-password"},
		"redirect":   {"//evil.com"},
		"csrf_token": {csrf},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
	rr := httptest.NewRecorder()
	h.HandleAdminLogin(rr, req)

	loc := rr.Header().Get("Location")
	if loc == "//evil.com" {
		t.Errorf("Open redirect not prevented: Location = %q", loc)
	}
}


// ---------------------------------------------------------------------------
// HandleAdminLogin — POST with CSRF mismatch (lines 1142-1146)
// ---------------------------------------------------------------------------
func TestHandleAdminLogin_POST_CSRFMismatch_Gap(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	form := url.Values{
		"email": {"admin@test.com"}, "password": {"pass"}, "csrf_token": {"wrong"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: "correct"})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (CSRF mismatch re-render)", rr.Code)
	}
}


// ---------------------------------------------------------------------------
// HandleAdminLogin — POST without user store (lines 1152-1154)
// ---------------------------------------------------------------------------
func TestHandleAdminLogin_POST_NoUserStore_Gap(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()
	h.userStore = nil

	csrfToken := "valid-csrf"
	form := url.Values{
		"email": {"admin@test.com"}, "password": {"pass"}, "csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
}


// ---------------------------------------------------------------------------
// HandleAdminLogin — POST success (admin login, redirect)
// ---------------------------------------------------------------------------
func TestHandleAdminLogin_POST_Success_Gap(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetUserStore(&mockAdminUserStoreWithPassword{
		roles:    map[string]string{"admin@test.com": "admin"},
		statuses: map[string]string{"admin@test.com": "active"},
		password: "correctpass",
	})

	csrfToken := "valid-csrf"
	form := url.Values{
		"email": {"admin@test.com"}, "password": {"correctpass"}, "csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 (admin login success)", rr.Code)
	}
}


// ---------------------------------------------------------------------------
// HandleAdminLogin — POST with open redirect prevention (line 1133-1134)
// ---------------------------------------------------------------------------
func TestHandleAdminLogin_POST_OpenRedirectPrev_Gap(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetUserStore(&mockAdminUserStoreWithPassword{
		roles:    map[string]string{"admin@test.com": "admin"},
		statuses: map[string]string{"admin@test.com": "active"},
		password: "pass",
	})

	csrfToken := "valid-csrf"
	form := url.Values{
		"email": {"admin@test.com"}, "password": {"pass"}, "csrf_token": {csrfToken},
		"redirect": {"//evil.com"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if loc != "/admin/ops" {
		t.Errorf("Expected redirect to /admin/ops (open redirect prevention), got: %q", loc)
	}
}


// ---------------------------------------------------------------------------
// HandleAdminLogin — POST verify password error (line 1163-1165)
// ---------------------------------------------------------------------------
func TestHandleAdminLogin_POST_VerifyPasswordError(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetUserStore(&mockAdminUserStoreWithVerifyError{
		roles:    map[string]string{"admin@test.com": "admin"},
		statuses: map[string]string{"admin@test.com": "active"},
	})

	csrfToken := "valid-csrf"
	form := url.Values{
		"email": {"admin@test.com"}, "password": {"pass"}, "csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	// Should fail (VerifyPassword returns error), re-render form
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (verify error re-render)", rr.Code)
	}
}


type mockAdminUserStoreWithVerifyError struct {
	roles    map[string]string
	statuses map[string]string
}

func (m *mockAdminUserStoreWithVerifyError) GetRole(email string) string   { return m.roles[email] }
func (m *mockAdminUserStoreWithVerifyError) GetStatus(email string) string { return m.statuses[email] }
func (m *mockAdminUserStoreWithVerifyError) VerifyPassword(email, password string) (bool, error) {
	return false, fmt.Errorf("bcrypt error")
}
func (m *mockAdminUserStoreWithVerifyError) EnsureGoogleUser(email string) {}

// MFA stubs — these existing tests don't exercise MFA; the stubs satisfy
// the AdminUserStore interface contract.
func (m *mockAdminUserStoreWithVerifyError) HasTOTP(email string) bool                          { return false }
func (m *mockAdminUserStoreWithVerifyError) SetTOTPSecret(email, plaintextSecret string) error  { return nil }
func (m *mockAdminUserStoreWithVerifyError) VerifyTOTP(email, code string) (bool, error)        { return false, nil }
func (m *mockAdminUserStoreWithVerifyError) ClearTOTPSecret(email string) error                 { return nil }

// ---------------------------------------------------------------------------
// HandleAdminLogin — GET renders form (line 1192-1198)
// ---------------------------------------------------------------------------
func TestHandleAdminLogin_GET_Gap(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/admin-login", nil)
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
}


// ---------------------------------------------------------------------------
// serveAdminLoginForm — nil template (line 1203-1205)
// ---------------------------------------------------------------------------
func TestServeAdminLoginForm_NilTmpl_Gap(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()
	h.adminLoginTmpl = nil

	rr := httptest.NewRecorder()
	h.serveAdminLoginForm(rr, "/admin/ops", "", "csrf")

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500 (nil template)", rr.Code)
	}
}


// ---------------------------------------------------------------------------
// serveAdminLoginForm — empty CSRF token (no cookie set, line 1209)
// ---------------------------------------------------------------------------
func TestServeAdminLoginForm_EmptyCSRF(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	rr := httptest.NewRecorder()
	h.serveAdminLoginForm(rr, "/admin/ops", "", "")

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (render without CSRF cookie)", rr.Code)
	}
}
