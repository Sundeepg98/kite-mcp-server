package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// echoEmailHandler is a simple handler that writes the email from context to the response.
func echoEmailHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email := EmailFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(email))
	})
}

func TestRequireAuth_ValidBearer(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Generate a valid token
	token, err := h.jwt.GenerateToken("alice@test.com", "client-123")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	handler := h.RequireAuth(echoEmailHandler())
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
	if body := rr.Body.String(); body != "alice@test.com" {
		t.Errorf("Body = %q, want %q", body, "alice@test.com")
	}
}

func TestRequireAuth_MissingAuth(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	handler := h.RequireAuth(echoEmailHandler())
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want 401", rr.Code)
	}
	wwwAuth := rr.Header().Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, "Bearer") {
		t.Errorf("WWW-Authenticate header missing Bearer: %q", wwwAuth)
	}
	if !strings.Contains(wwwAuth, "resource_metadata") {
		t.Errorf("WWW-Authenticate should contain resource_metadata URL: %q", wwwAuth)
	}
}

func TestRequireAuth_InvalidToken(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	handler := h.RequireAuth(echoEmailHandler())
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer invalid-token-garbage")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want 401", rr.Code)
	}
	wwwAuth := rr.Header().Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, "invalid_token") {
		t.Errorf("WWW-Authenticate should indicate invalid_token: %q", wwwAuth)
	}
}

func TestRequireAuth_DashboardTokenRejected(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Generate a dashboard-only token
	token, err := h.jwt.GenerateToken("alice@test.com", "dashboard")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	handler := h.RequireAuth(echoEmailHandler())
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want 401 (dashboard tokens should be rejected on MCP endpoints)", rr.Code)
	}
}

func TestRequireAuth_ExpiredKiteToken(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Set kite token checker to always return false (expired)
	h.SetKiteTokenChecker(func(email string) bool {
		return false
	})

	token, err := h.jwt.GenerateToken("alice@test.com", "client-123")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	handler := h.RequireAuth(echoEmailHandler())
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want 401 (expired Kite token should trigger re-auth)", rr.Code)
	}
}

func TestRequireAuth_NoKiteTokenYet(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Kite token checker returns true (valid or no token yet)
	h.SetKiteTokenChecker(func(email string) bool {
		return true
	})

	token, err := h.jwt.GenerateToken("alice@test.com", "client-123")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	handler := h.RequireAuth(echoEmailHandler())
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
}

func TestRequireAuthBrowser_ValidCookie(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Generate a dashboard-audience token (what SetAuthCookie produces)
	token, err := h.jwt.GenerateToken("bob@test.com", "dashboard")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	handler := h.RequireAuthBrowser(echoEmailHandler())
	req := httptest.NewRequest(http.MethodGet, "/admin/ops", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
	if body := rr.Body.String(); body != "bob@test.com" {
		t.Errorf("Body = %q, want %q", body, "bob@test.com")
	}
}

func TestRequireAuthBrowser_ValidBearerToken(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	token, err := h.jwt.GenerateToken("carol@test.com", "dashboard")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	handler := h.RequireAuthBrowser(echoEmailHandler())
	req := httptest.NewRequest(http.MethodGet, "/admin/ops", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
	if body := rr.Body.String(); body != "carol@test.com" {
		t.Errorf("Body = %q, want %q", body, "carol@test.com")
	}
}

func TestRequireAuthBrowser_NoCookie(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	handler := h.RequireAuthBrowser(echoEmailHandler())
	req := httptest.NewRequest(http.MethodGet, "/admin/ops", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 redirect", rr.Code)
	}
	location := rr.Header().Get("Location")
	if !strings.Contains(location, "/auth/browser-login") {
		t.Errorf("Location = %q, should redirect to browser-login", location)
	}
}

func TestRequireAuthBrowser_InvalidCookie(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	handler := h.RequireAuthBrowser(echoEmailHandler())
	req := httptest.NewRequest(http.MethodGet, "/admin/ops", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: "invalid-jwt-token"})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 redirect", rr.Code)
	}
	location := rr.Header().Get("Location")
	if !strings.Contains(location, "/auth/browser-login") {
		t.Errorf("Location = %q, should redirect to browser-login", location)
	}
}

func TestRequireAuthBrowser_NonDashboardCookieRejected(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Generate a non-dashboard token
	token, err := h.jwt.GenerateToken("user@test.com", "mcp-client-xyz")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	handler := h.RequireAuthBrowser(echoEmailHandler())
	req := httptest.NewRequest(http.MethodGet, "/admin/ops", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should redirect because the cookie has wrong audience
	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 (non-dashboard audience cookie should be rejected)", rr.Code)
	}
}

func TestSetAuthCookie(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	rr := httptest.NewRecorder()
	err := h.SetAuthCookie(rr, "user@test.com")
	if err != nil {
		t.Fatalf("SetAuthCookie failed: %v", err)
	}

	cookies := rr.Result().Cookies()
	var found *http.Cookie
	for _, c := range cookies {
		if c.Name == cookieName {
			found = c
			break
		}
	}
	if found == nil {
		t.Fatal("SetAuthCookie should set a cookie named kite_jwt")
	}
	if !found.HttpOnly {
		t.Error("Cookie should be HttpOnly")
	}
	if !found.Secure {
		t.Error("Cookie should be Secure")
	}
	if found.SameSite != http.SameSiteLaxMode {
		t.Errorf("Cookie SameSite = %v, want Lax", found.SameSite)
	}
	if found.Path != "/" {
		t.Errorf("Cookie Path = %q, want /", found.Path)
	}
	if found.MaxAge != 14400 {
		t.Errorf("Cookie MaxAge = %d, want 14400", found.MaxAge)
	}

	// The cookie value should be a valid JWT with dashboard audience
	claims, err := h.jwt.ValidateToken(found.Value, "dashboard")
	if err != nil {
		t.Fatalf("Cookie JWT validation failed: %v", err)
	}
	if claims.Subject != "user@test.com" {
		t.Errorf("JWT Subject = %q, want %q", claims.Subject, "user@test.com")
	}
}

func TestEmailFromContext(t *testing.T) {
	t.Parallel()

	// Empty context
	if email := EmailFromContext(context.Background()); email != "" {
		t.Errorf("EmailFromContext on empty context = %q, want empty", email)
	}

	// Context with email
	ctx := context.WithValue(context.Background(), emailContextKey{}, "test@example.com")
	if email := EmailFromContext(ctx); email != "test@example.com" {
		t.Errorf("EmailFromContext = %q, want %q", email, "test@example.com")
	}

	// Context with wrong type
	ctx = context.WithValue(context.Background(), emailContextKey{}, 42)
	if email := EmailFromContext(ctx); email != "" {
		t.Errorf("EmailFromContext with wrong type = %q, want empty", email)
	}
}

func TestRequireAuthBrowser_OpenRedirectProtection(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	handler := h.RequireAuthBrowser(echoEmailHandler())

	tests := []struct {
		name     string
		path     string
		wantPath string // expected redirect= query param value (URL-decoded)
	}{
		{"normal path", "/admin/ops", "/admin/ops"},
		{"double slash", "//evil.com", "/admin/ops"},    // should default to safe path
		{"no leading slash", "evil.com", "/admin/ops"},  // httptest builds Path="/evil.com" which starts with / but doesn't start with //
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "https://test.example.com/test", nil)
			// Override URL.Path for edge cases
			req.URL.Path = tc.path
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusFound {
				t.Errorf("Status = %d, want 302", rr.Code)
			}
			location := rr.Header().Get("Location")
			parsed, err := url.Parse(location)
			if err != nil {
				t.Fatalf("Failed to parse Location URL: %v", err)
			}
			redirectParam := parsed.Query().Get("redirect")
			if redirectParam != tc.wantPath {
				t.Errorf("redirect param = %q, want %q (full Location: %q)", redirectParam, tc.wantPath, location)
			}
		})
	}
}
