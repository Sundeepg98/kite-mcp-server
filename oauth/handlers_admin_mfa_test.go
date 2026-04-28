package oauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/users"
)

// mfaTestStore is a real users.Store wrapped to satisfy AdminUserStore.
// We use a real store (not a fake) so the encryption + role-gate
// invariants are exercised end-to-end in the HTTP test.
type mfaTestStore struct {
	*users.Store
}

func (m *mfaTestStore) EnsureGoogleUser(_ string) {}

// newMFATestHandler returns a Handler with a real users.Store wired and an
// admin user pre-created. encryptionEnabled controls whether the store has
// an encryption key — for "no-key" failure-path tests.
func newMFATestHandler(t *testing.T, adminEmail string, encryptionEnabled bool) (*Handler, *users.Store) {
	t.Helper()
	h := newTestHandler() // shared test fixture: parses templates + mocks signer/exchanger.

	store := users.NewStore()
	if encryptionEnabled {
		// 32-byte deterministic key — production derives via HKDF.
		key := make([]byte, 32)
		for i := range key {
			key[i] = 0x42
		}
		store.SetEncryptionKey(key)
	}
	require.NoError(t, store.Create(&users.User{
		ID:    "u_admin",
		Email: adminEmail,
		Role:  users.RoleAdmin,
	}))
	h.SetUserStore(&mfaTestStore{store})
	return h, store
}

// TestHandleAdminMFAEnroll_GET_RendersForm — un-enrolled admin GET shows
// the enrollment form with a freshly generated secret in a hidden input.
func TestHandleAdminMFAEnroll_GET_RendersForm(t *testing.T) {
	t.Parallel()
	h, _ := newMFATestHandler(t, "admin@test.com", true)
	req := httptest.NewRequest(http.MethodGet, "/auth/admin-mfa/enroll", nil)
	// Email is taken from context (set by the upstream admin auth middleware).
	req = req.WithContext(ContextWithEmail(req.Context(), "admin@test.com"))
	rec := httptest.NewRecorder()
	h.HandleAdminMFAEnroll(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, `name="secret"`)
	assert.Contains(t, body, `name="code"`)
	assert.Contains(t, body, `Issuer:`) // template literal label
}

// TestHandleAdminMFAEnroll_GET_NoEmailContext — missing email context is
// a hard 401; the handler must NOT render or expose a secret.
func TestHandleAdminMFAEnroll_GET_NoEmailContext(t *testing.T) {
	t.Parallel()
	h, _ := newMFATestHandler(t, "admin@test.com", true)
	req := httptest.NewRequest(http.MethodGet, "/auth/admin-mfa/enroll", nil)
	rec := httptest.NewRecorder()
	h.HandleAdminMFAEnroll(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestHandleAdminMFAEnroll_POST_ValidCode_Enrolls — POSTing a valid code
// (computed from the form's secret) persists the enrollment, sets the
// MFA-verified cookie, and redirects.
func TestHandleAdminMFAEnroll_POST_ValidCode_Enrolls(t *testing.T) {
	t.Parallel()
	h, store := newMFATestHandler(t, "admin@test.com", true)
	secret, err := users.GenerateTOTPSecret()
	require.NoError(t, err)
	code, err := users.GenerateTOTPCode(secret, time.Now())
	require.NoError(t, err)

	form := url.Values{}
	form.Set("secret", secret)
	form.Set("code", code)
	form.Set("redirect", "/admin/ops")
	form.Set("csrf_token", "csrf-test-token")
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-mfa/enroll", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin_mfa", Value: "csrf-test-token"})
	req = req.WithContext(ContextWithEmail(req.Context(), "admin@test.com"))
	rec := httptest.NewRecorder()
	h.HandleAdminMFAEnroll(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code, "expected redirect on success")
	assert.Equal(t, "/admin/ops", rec.Header().Get("Location"))
	assert.True(t, store.HasTOTP("admin@test.com"), "secret must be persisted")

	// MFA-verified cookie must be set so the very next admin request passes.
	cookies := rec.Result().Cookies()
	var mfaCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "kite_admin_mfa" {
			mfaCookie = c
		}
	}
	require.NotNil(t, mfaCookie, "MFA-verified cookie must be set on enrollment")
	assert.True(t, mfaCookie.HttpOnly)
	assert.True(t, mfaCookie.Secure)
}

// TestHandleAdminMFAEnroll_POST_WrongCode_Refused — wrong code does NOT
// persist and re-renders the form. The store must remain un-enrolled.
func TestHandleAdminMFAEnroll_POST_WrongCode_Refused(t *testing.T) {
	t.Parallel()
	h, store := newMFATestHandler(t, "admin@test.com", true)
	secret, err := users.GenerateTOTPSecret()
	require.NoError(t, err)
	form := url.Values{}
	form.Set("secret", secret)
	form.Set("code", "000000")
	form.Set("redirect", "/admin/ops")
	form.Set("csrf_token", "csrf-test-token")
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-mfa/enroll", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin_mfa", Value: "csrf-test-token"})
	req = req.WithContext(ContextWithEmail(req.Context(), "admin@test.com"))
	rec := httptest.NewRecorder()
	h.HandleAdminMFAEnroll(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "form re-renders with error, not redirect")
	assert.False(t, store.HasTOTP("admin@test.com"), "wrong code must not persist enrollment")
}

// TestHandleAdminMFAEnroll_POST_BadCSRF_Refused — missing or mismatched
// CSRF cookie is rejected; nothing is persisted.
func TestHandleAdminMFAEnroll_POST_BadCSRF_Refused(t *testing.T) {
	t.Parallel()
	h, store := newMFATestHandler(t, "admin@test.com", true)
	secret, err := users.GenerateTOTPSecret()
	require.NoError(t, err)
	code, _ := users.GenerateTOTPCode(secret, time.Now())
	form := url.Values{}
	form.Set("secret", secret)
	form.Set("code", code)
	form.Set("redirect", "/admin/ops")
	form.Set("csrf_token", "form-token")
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-mfa/enroll", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Cookie token does not match form token — CSRF reject.
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin_mfa", Value: "different-token"})
	req = req.WithContext(ContextWithEmail(req.Context(), "admin@test.com"))
	rec := httptest.NewRecorder()
	h.HandleAdminMFAEnroll(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "CSRF mismatch re-renders form")
	assert.False(t, store.HasTOTP("admin@test.com"))
}

// TestHandleAdminMFAVerify_GET_RendersForm — GET shows the verification
// form for an already-enrolled admin.
func TestHandleAdminMFAVerify_GET_RendersForm(t *testing.T) {
	t.Parallel()
	h, store := newMFATestHandler(t, "admin@test.com", true)
	secret, err := users.GenerateTOTPSecret()
	require.NoError(t, err)
	require.NoError(t, store.SetTOTPSecret("admin@test.com", secret))

	req := httptest.NewRequest(http.MethodGet, "/auth/admin-mfa/verify", nil)
	req = req.WithContext(ContextWithEmail(req.Context(), "admin@test.com"))
	rec := httptest.NewRecorder()
	h.HandleAdminMFAVerify(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `name="code"`)
}

// TestHandleAdminMFAVerify_GET_NotEnrolled_RedirectsToEnroll — an admin
// hitting verify without enrollment is routed to enroll first.
func TestHandleAdminMFAVerify_GET_NotEnrolled_RedirectsToEnroll(t *testing.T) {
	t.Parallel()
	h, _ := newMFATestHandler(t, "admin@test.com", true)
	req := httptest.NewRequest(http.MethodGet, "/auth/admin-mfa/verify", nil)
	req = req.WithContext(ContextWithEmail(req.Context(), "admin@test.com"))
	rec := httptest.NewRecorder()
	h.HandleAdminMFAVerify(rec, req)
	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Contains(t, rec.Header().Get("Location"), "/auth/admin-mfa/enroll")
}

// TestHandleAdminMFAVerify_POST_ValidCode_SetsCookie — valid code mints
// the MFA-verified cookie and redirects.
func TestHandleAdminMFAVerify_POST_ValidCode_SetsCookie(t *testing.T) {
	t.Parallel()
	h, store := newMFATestHandler(t, "admin@test.com", true)
	secret, err := users.GenerateTOTPSecret()
	require.NoError(t, err)
	require.NoError(t, store.SetTOTPSecret("admin@test.com", secret))
	code, _ := users.GenerateTOTPCode(secret, time.Now())

	form := url.Values{}
	form.Set("code", code)
	form.Set("redirect", "/admin/ops")
	form.Set("csrf_token", "csrf-verify-token")
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-mfa/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin_mfa", Value: "csrf-verify-token"})
	req = req.WithContext(ContextWithEmail(req.Context(), "admin@test.com"))
	rec := httptest.NewRecorder()
	h.HandleAdminMFAVerify(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, "/admin/ops", rec.Header().Get("Location"))

	cookies := rec.Result().Cookies()
	var mfaCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "kite_admin_mfa" {
			mfaCookie = c
		}
	}
	require.NotNil(t, mfaCookie)
	assert.NotEmpty(t, mfaCookie.Value)
}

// TestHandleAdminMFAVerify_POST_WrongCode_Refused — wrong code re-renders
// and does NOT mint the cookie.
func TestHandleAdminMFAVerify_POST_WrongCode_Refused(t *testing.T) {
	t.Parallel()
	h, store := newMFATestHandler(t, "admin@test.com", true)
	secret, err := users.GenerateTOTPSecret()
	require.NoError(t, err)
	require.NoError(t, store.SetTOTPSecret("admin@test.com", secret))

	form := url.Values{}
	form.Set("code", "000000")
	form.Set("redirect", "/admin/ops")
	form.Set("csrf_token", "csrf-verify-token")
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-mfa/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin_mfa", Value: "csrf-verify-token"})
	req = req.WithContext(ContextWithEmail(req.Context(), "admin@test.com"))
	rec := httptest.NewRecorder()
	h.HandleAdminMFAVerify(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	for _, c := range rec.Result().Cookies() {
		assert.NotEqual(t, "kite_admin_mfa", c.Name, "no MFA cookie should be set on wrong code")
	}
}

// TestRequireAdminMFA_NoCookie_Redirects — admin path without MFA cookie
// must redirect to /auth/admin-mfa/verify (or /enroll if not enrolled).
func TestRequireAdminMFA_NoCookie_Redirects_ToEnroll(t *testing.T) {
	t.Parallel()
	h, _ := newMFATestHandler(t, "admin@test.com", true)
	mw := h.RequireAdminMFA(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler must not be reached without MFA")
	}))
	req := httptest.NewRequest(http.MethodGet, "/admin/ops", nil)
	req = req.WithContext(ContextWithEmail(req.Context(), "admin@test.com"))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Contains(t, rec.Header().Get("Location"), "/auth/admin-mfa/enroll")
}

// TestRequireAdminMFA_NoCookie_Enrolled_RedirectsToVerify — already-
// enrolled admin without an active MFA cookie goes to verify.
func TestRequireAdminMFA_NoCookie_Enrolled_RedirectsToVerify(t *testing.T) {
	t.Parallel()
	h, store := newMFATestHandler(t, "admin@test.com", true)
	secret, _ := users.GenerateTOTPSecret()
	require.NoError(t, store.SetTOTPSecret("admin@test.com", secret))

	mw := h.RequireAdminMFA(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler must not be reached without MFA")
	}))
	req := httptest.NewRequest(http.MethodGet, "/admin/ops", nil)
	req = req.WithContext(ContextWithEmail(req.Context(), "admin@test.com"))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Contains(t, rec.Header().Get("Location"), "/auth/admin-mfa/verify")
}

// TestRequireAdminMFA_ValidCookie_Passes — admin with a valid kite_admin_mfa
// cookie reaches the inner handler.
func TestRequireAdminMFA_ValidCookie_Passes(t *testing.T) {
	t.Parallel()
	h, store := newMFATestHandler(t, "admin@test.com", true)
	secret, _ := users.GenerateTOTPSecret()
	require.NoError(t, store.SetTOTPSecret("admin@test.com", secret))

	// Mint a valid MFA cookie via the same path the verify handler uses.
	token, err := h.MintAdminMFAToken("admin@test.com")
	require.NoError(t, err)

	called := false
	mw := h.RequireAdminMFA(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/admin/ops", nil)
	req = req.WithContext(ContextWithEmail(req.Context(), "admin@test.com"))
	req.AddCookie(&http.Cookie{Name: "kite_admin_mfa", Value: token})
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	assert.True(t, called, "inner handler must be reached with valid MFA cookie")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestRequireAdminMFA_CookieForDifferentEmail_Refused — a stolen MFA
// cookie minted for user A must not authenticate user B (token Subject
// is bound to email).
func TestRequireAdminMFA_CookieForDifferentEmail_Refused(t *testing.T) {
	t.Parallel()
	h, store := newMFATestHandler(t, "admin@test.com", true)
	secret, _ := users.GenerateTOTPSecret()
	require.NoError(t, store.SetTOTPSecret("admin@test.com", secret))

	// Token minted for adminA, presented for adminB.
	tokenA, err := h.MintAdminMFAToken("adminA@test.com")
	require.NoError(t, err)
	mw := h.RequireAdminMFA(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler must not be reached with mismatched cookie")
	}))
	req := httptest.NewRequest(http.MethodGet, "/admin/ops", nil)
	req = req.WithContext(ContextWithEmail(req.Context(), "admin@test.com"))
	req.AddCookie(&http.Cookie{Name: "kite_admin_mfa", Value: tokenA})
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusFound, rec.Code, "expected redirect when cookie subject != context email")
}

// TestRequireAdminMFA_NoEmail_Unauthorized — RequireAdminMFA presupposes
// the upstream admin gate has set email in context. Missing email is 401.
func TestRequireAdminMFA_NoEmail_Unauthorized(t *testing.T) {
	t.Parallel()
	h, _ := newMFATestHandler(t, "admin@test.com", true)
	mw := h.RequireAdminMFA(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler must not be reached without email context")
	}))
	req := httptest.NewRequest(http.MethodGet, "/admin/ops", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
