package oauth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// ===========================================================================
// HandleGoogleLogin
// ===========================================================================



// ===========================================================================
// HandleAdminLogin — additional POST paths (beyond context_test.go / handlers_test.go)
// ===========================================================================

// mockAdminUserStore implements AdminUserStore for testing.
type mockAdminUserStore struct {
	roles       map[string]string
	statuses    map[string]string
	passwords   map[string]string
	verifyErr   error
	adminEmails map[string]string
}

func (m *mockAdminUserStore) GetRole(email string) string {
	if m.roles != nil {
		return m.roles[email]
	}
	return ""
}

func (m *mockAdminUserStore) GetStatus(email string) string {
	if m.statuses != nil {
		return m.statuses[email]
	}
	return ""
}

func (m *mockAdminUserStore) VerifyPassword(email, password string) (bool, error) {
	if m.verifyErr != nil {
		return false, m.verifyErr
	}
	if m.passwords != nil {
		return m.passwords[email] == password, nil
	}
	return false, nil
}

func (m *mockAdminUserStore) EnsureGoogleUser(email string) {}

// MFA stubs — these existing tests don't exercise MFA; the stubs satisfy
// the AdminUserStore interface contract.
func (m *mockAdminUserStore) HasTOTP(email string) bool                          { return false }
func (m *mockAdminUserStore) SetTOTPSecret(email, plaintextSecret string) error  { return nil }
func (m *mockAdminUserStore) VerifyTOTP(email, code string) (bool, error)        { return false, nil }
func (m *mockAdminUserStore) ClearTOTPSecret(email string) error                 { return nil }

func TestHandleAdminLogin_POST_ValidCredentials(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetUserStore(&mockAdminUserStore{
		roles:     map[string]string{"admin@test.com": "admin"},
		statuses:  map[string]string{"admin@test.com": "active"},
		passwords: map[string]string{"admin@test.com": "secret123"},
	})

	csrfToken := "test-csrf-value"
	form := url.Values{
		"email":      {"admin@test.com"},
		"password":   {"secret123"},
		"redirect":   {"/admin/ops"},
		"csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 (redirect on success). Body: %s", rr.Code, rr.Body.String())
	}
	location := rr.Header().Get("Location")
	if location != "/admin/ops" {
		t.Errorf("Location = %q, want /admin/ops", location)
	}
	// Check auth cookie was set (uses cookieName constant)
	var authCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == cookieName {
			authCookie = c
			break
		}
	}
	if authCookie == nil {
		t.Errorf("Expected %s cookie to be set", cookieName)
	}
}


func TestHandleAdminLogin_POST_WrongPassword(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetUserStore(&mockAdminUserStore{
		roles:     map[string]string{"admin@test.com": "admin"},
		statuses:  map[string]string{"admin@test.com": "active"},
		passwords: map[string]string{"admin@test.com": "secret123"},
	})

	csrfToken := "test-csrf"
	form := url.Values{
		"email":      {"admin@test.com"},
		"password":   {"wrong-password"},
		"csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (re-rendered form with error)", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Invalid email or password") {
		t.Errorf("Expected error message in body, got: %s", rr.Body.String())
	}
}


func TestHandleAdminLogin_POST_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetUserStore(&mockAdminUserStore{
		roles:     map[string]string{"user@test.com": "trader"},
		statuses:  map[string]string{"user@test.com": "active"},
		passwords: map[string]string{"user@test.com": "secret123"},
	})

	csrfToken := "test-csrf"
	form := url.Values{
		"email":      {"user@test.com"},
		"password":   {"secret123"},
		"csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (rejected, not admin)", rr.Code)
	}
}


func TestHandleAdminLogin_POST_InactiveAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetUserStore(&mockAdminUserStore{
		roles:     map[string]string{"admin@test.com": "admin"},
		statuses:  map[string]string{"admin@test.com": "suspended"},
		passwords: map[string]string{"admin@test.com": "secret123"},
	})

	csrfToken := "test-csrf"
	form := url.Values{
		"email":      {"admin@test.com"},
		"password":   {"secret123"},
		"csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (rejected, inactive)", rr.Code)
	}
}


func TestHandleAdminLogin_POST_VerifyError(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetUserStore(&mockAdminUserStore{
		roles:     map[string]string{"admin@test.com": "admin"},
		statuses:  map[string]string{"admin@test.com": "active"},
		verifyErr: fmt.Errorf("bcrypt error"),
	})

	csrfToken := "test-csrf"
	form := url.Values{
		"email":      {"admin@test.com"},
		"password":   {"anything"},
		"csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (rejected, verify error)", rr.Code)
	}
}


func TestHandleAdminLogin_POST_OpenRedirectPrevention(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetUserStore(&mockAdminUserStore{
		roles:     map[string]string{"admin@test.com": "admin"},
		statuses:  map[string]string{"admin@test.com": "active"},
		passwords: map[string]string{"admin@test.com": "secret123"},
	})

	csrfToken := "test-csrf"
	form := url.Values{
		"email":      {"admin@test.com"},
		"password":   {"secret123"},
		"redirect":   {"//evil.com"},
		"csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("Status = %d, want 302", rr.Code)
	}
	location := rr.Header().Get("Location")
	if location != "/admin/ops" {
		t.Errorf("Expected /admin/ops (safe default), got: %q", location)
	}
}


func TestHandleAdminLogin_POST_EmptyRedirect(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetUserStore(&mockAdminUserStore{
		roles:     map[string]string{"admin@test.com": "admin"},
		statuses:  map[string]string{"admin@test.com": "active"},
		passwords: map[string]string{"admin@test.com": "secret123"},
	})

	csrfToken := "test-csrf"
	form := url.Values{
		"email":      {"admin@test.com"},
		"password":   {"secret123"},
		"redirect":   {""},
		"csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("Status = %d, want 302", rr.Code)
	}
	location := rr.Header().Get("Location")
	if location != "/admin/ops" {
		t.Errorf("Expected /admin/ops (default), got: %q", location)
	}
}



// ===========================================================================
// HandleAdminLogin — GET with redirect param
// ===========================================================================
func TestHandleAdminLogin_GET_WithRedirect_SSOFile(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/admin-login?redirect=/custom-page", nil)
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
}



// ===========================================================================
// HandleAdminLogin — POST with email case normalization
// ===========================================================================
func TestHandleAdminLogin_POST_EmailCaseNormalization(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetUserStore(&mockAdminUserStore{
		roles:     map[string]string{"admin@test.com": "admin"},
		statuses:  map[string]string{"admin@test.com": "active"},
		passwords: map[string]string{"admin@test.com": "secret123"},
	})

	csrfToken := "csrf-norm"
	form := url.Values{
		"email":      {"  Admin@TEST.com  "}, // mixed case with whitespace
		"password":   {"secret123"},
		"csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	// Should succeed — email is normalized to lowercase + trimmed
	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 (email case normalized). Body: %s", rr.Code, rr.Body.String())
	}
}



// ===========================================================================
// HandleAdminLogin — GET
// ===========================================================================
func TestHandleAdminLogin_POST_NoCSRF(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	form := url.Values{
		"email":    {"admin@test.com"},
		"password": {"test123"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	// Should render the form again (CSRF failure)
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (re-rendered form)", rr.Code)
	}
}



// ===========================================================================
// HandleAdminLogin — GET serves form
// ===========================================================================
func TestHandleAdminLogin_GET_ServesForm(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/admin-login", nil)
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "text/html") {
		t.Error("Expected HTML content type")
	}
}



// ===========================================================================
// HandleAdminLogin — POST no user store
// ===========================================================================
func TestHandleAdminLogin_POST_NoUserStore_Final(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	csrfToken := "csrf-admin"
	form := url.Values{
		"email":      {"admin@test.com"},
		"password":   {"secret"},
		"redirect":   {"/admin/ops"},
		"csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (form re-rendered with error)", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "not configured") {
		t.Errorf("Body should contain 'not configured'")
	}
}



// ===========================================================================
// HandleAdminLogin — POST CSRF mismatch
// ===========================================================================
func TestHandleAdminLogin_POST_CSRFMismatch(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	form := url.Values{
		"email":      {"admin@test.com"},
		"password":   {"secret"},
		"redirect":   {"/admin/ops"},
		"csrf_token": {"form-csrf"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: "cookie-csrf"})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (form re-rendered)", rr.Code)
	}
}



// ===========================================================================
// HandleAdminLogin — POST wrong password
// ===========================================================================

// mockAdminUserStoreFinal implements AdminUserStore for testing.
type mockAdminUserStoreFinal struct {
	roles    map[string]string
	statuses map[string]string
}

func (m *mockAdminUserStoreFinal) GetRole(email string) string {
	return m.roles[email]
}

func (m *mockAdminUserStoreFinal) GetStatus(email string) string {
	return m.statuses[email]
}

func (m *mockAdminUserStoreFinal) VerifyPassword(email, password string) (bool, error) {
	if email == "admin@test.com" && password == "correct-password" {
		return true, nil
	}
	return false, nil
}

func (m *mockAdminUserStoreFinal) EnsureGoogleUser(email string) {}

// MFA stubs — these existing tests don't exercise MFA; the stubs satisfy
// the AdminUserStore interface contract.
func (m *mockAdminUserStoreFinal) HasTOTP(email string) bool                          { return false }
func (m *mockAdminUserStoreFinal) SetTOTPSecret(email, plaintextSecret string) error  { return nil }
func (m *mockAdminUserStoreFinal) VerifyTOTP(email, code string) (bool, error)        { return false, nil }
func (m *mockAdminUserStoreFinal) ClearTOTPSecret(email string) error                 { return nil }

func TestHandleAdminLogin_POST_WrongPassword_Final(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetUserStore(&mockAdminUserStoreFinal{
		roles:    map[string]string{"admin@test.com": "admin"},
		statuses: map[string]string{"admin@test.com": "active"},
	})

	csrfToken := "csrf"
	form := url.Values{
		"email":      {"admin@test.com"},
		"password":   {"wrong-password"},
		"redirect":   {"/admin/ops"},
		"csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (form re-rendered)", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Invalid email or password") {
		t.Errorf("Body should contain 'Invalid email or password'")
	}
}



// ===========================================================================
// HandleAdminLogin — POST success
// ===========================================================================
func TestHandleAdminLogin_POST_Success(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetUserStore(&mockAdminUserStoreFinal{
		roles:    map[string]string{"admin@test.com": "admin"},
		statuses: map[string]string{"admin@test.com": "active"},
	})

	csrfToken := "csrf"
	form := url.Values{
		"email":      {"admin@test.com"},
		"password":   {"correct-password"},
		"redirect":   {"/admin/ops"},
		"csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 (redirect on success)", rr.Code)
	}
}



// ===========================================================================
// HandleAdminLogin — POST open redirect prevention
// ===========================================================================
func TestHandleAdminLogin_POST_OpenRedirectPrevention_Final(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetUserStore(&mockAdminUserStoreFinal{
		roles:    map[string]string{"admin@test.com": "admin"},
		statuses: map[string]string{"admin@test.com": "active"},
	})

	csrfToken := "csrf"
	form := url.Values{
		"email":      {"admin@test.com"},
		"password":   {"correct-password"},
		"redirect":   {"//evil.com"}, // open redirect attempt
		"csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302", rr.Code)
	}
	location := rr.Header().Get("Location")
	if strings.Contains(location, "evil.com") {
		t.Errorf("Open redirect should be blocked, got: %q", location)
	}
}



// ===========================================================================
// HandleAdminLogin — POST with verify error
// ===========================================================================
func TestHandleAdminLogin_POST_VerifyError_Final(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetUserStore(&mockAdminUserStoreFinalWithError{})

	csrfToken := "csrf"
	form := url.Values{
		"email":      {"admin@test.com"},
		"password":   {"any"},
		"redirect":   {"/admin/ops"},
		"csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	// Should show login form with error (verify error + !match)
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
}
