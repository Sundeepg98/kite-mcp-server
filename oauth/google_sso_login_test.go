package oauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ===========================================================================
// HandleGoogleLogin
// ===========================================================================

func TestHandleGoogleLogin_NotConfigured(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/google/login", nil)
	rr := httptest.NewRecorder()

	h.HandleGoogleLogin(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Status = %d, want 404 (SSO not configured)", rr.Code)
	}
}


func TestHandleGoogleLogin_RedirectsToGoogle(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetGoogleSSO(&GoogleSSOConfig{
		ClientID:     "test-google-client-id",
		ClientSecret: "test-google-secret",
		RedirectURL:  "https://test.example.com/auth/google/callback",
	})

	req := httptest.NewRequest(http.MethodGet, "/auth/google/login?redirect=/dashboard", nil)
	rr := httptest.NewRecorder()

	h.HandleGoogleLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("Status = %d, want 302", rr.Code)
	}

	location := rr.Header().Get("Location")
	if !strings.Contains(location, "accounts.google.com") {
		t.Errorf("Expected redirect to Google, got: %q", location)
	}

	// Check state cookie was set
	cookies := rr.Result().Cookies()
	var stateCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == googleStateCookieName {
			stateCookie = c
			break
		}
	}
	if stateCookie == nil {
		t.Fatal("Expected state cookie to be set")
	}
	if !strings.Contains(stateCookie.Value, "|/dashboard") {
		t.Errorf("State cookie should contain redirect, got: %q", stateCookie.Value)
	}
}


func TestHandleGoogleLogin_DefaultRedirect(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetGoogleSSO(&GoogleSSOConfig{
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		RedirectURL:  "https://test.example.com/auth/google/callback",
	})

	// No redirect param
	req := httptest.NewRequest(http.MethodGet, "/auth/google/login", nil)
	rr := httptest.NewRecorder()

	h.HandleGoogleLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("Status = %d, want 302", rr.Code)
	}

	cookies := rr.Result().Cookies()
	for _, c := range cookies {
		if c.Name == googleStateCookieName {
			if !strings.Contains(c.Value, "|/dashboard") {
				t.Errorf("Expected default redirect /dashboard in cookie, got: %q", c.Value)
			}
			break
		}
	}
}


func TestHandleGoogleLogin_OpenRedirectPrevention(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetGoogleSSO(&GoogleSSOConfig{
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		RedirectURL:  "https://test.example.com/auth/google/callback",
	})

	// Try to redirect to external URL
	req := httptest.NewRequest(http.MethodGet, "/auth/google/login?redirect=//evil.com", nil)
	rr := httptest.NewRecorder()

	h.HandleGoogleLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("Status = %d, want 302", rr.Code)
	}

	cookies := rr.Result().Cookies()
	for _, c := range cookies {
		if c.Name == googleStateCookieName {
			if strings.Contains(c.Value, "evil.com") {
				t.Errorf("State cookie should not contain evil.com, got: %q", c.Value)
			}
			if !strings.Contains(c.Value, "|/dashboard") {
				t.Errorf("Expected /dashboard fallback, got: %q", c.Value)
			}
			break
		}
	}
}
