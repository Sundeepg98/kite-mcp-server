package app

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"golang.org/x/time/rate"
)

// ===========================================================================
// Test server helper
// ===========================================================================

// newTestServer creates a minimal HTTP server with key routes for testing.
// Uses httptest.NewServer so no real port binding is needed. It registers
// the same handler logic used in production (pricing page, checkout success,
// healthz, security.txt, robots.txt, accept-invite) without requiring a
// full kc.Manager or MCP server.
func newTestServer(t *testing.T, opts ...testServerOption) *httptest.Server {
	t.Helper()

	cfg := &testServerConfig{}
	for _, o := range opts {
		o(cfg)
	}

	mux := http.NewServeMux()

	// Pricing page (static HTML, no tier detection in test mode).
	mux.HandleFunc("/pricing", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, pricingPageHTML)
	})

	// Post-purchase welcome page.
	mux.HandleFunc("/checkout/success", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, checkoutSuccessHTML)
	})

	// Health check endpoint.
	startTime := time.Now()
	version := "v0.0.0-test"
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"uptime":  time.Since(startTime).Truncate(time.Second).String(),
			"version": version,
			"tools":   94, // placeholder count for tests
		})
	})

	// security.txt
	mux.HandleFunc("/.well-known/security.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("Contact: mailto:sundeepg8@gmail.com\nExpires: 2027-04-02T00:00:00.000Z\nPreferred-Languages: en\n"))
	})

	// robots.txt
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "User-agent: *\nDisallow: /dashboard/\nDisallow: /admin/\nDisallow: /auth/\nDisallow: /oauth/\nDisallow: /mcp\nDisallow: /sse\nAllow: /\nAllow: /terms\nAllow: /privacy\n")
	})

	// Accept-invite endpoint (only if an InvitationStore is provided).
	if cfg.invStore != nil {
		mux.HandleFunc("/auth/accept-invite", func(w http.ResponseWriter, r *http.Request) {
			token := r.URL.Query().Get("token")
			if token == "" {
				http.Error(w, "missing token", http.StatusBadRequest)
				return
			}
			inv := cfg.invStore.Get(token)
			if inv == nil {
				http.Error(w, "invitation not found", http.StatusNotFound)
				return
			}
			if inv.Status != "pending" {
				http.Error(w, "invitation already "+inv.Status, http.StatusGone)
				return
			}
			if time.Now().After(inv.ExpiresAt) {
				http.Error(w, "invitation expired", http.StatusGone)
				return
			}
			if err := cfg.invStore.Accept(token); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/auth/login?msg=welcome", http.StatusFound)
		})
	}

	// Rate-limited endpoint for testing rate limiting behaviour.
	if cfg.rateLimiter != nil {
		mux.Handle("/rate-limited", rateLimitFunc(cfg.rateLimiter, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "OK")
		}))
	}

	// Wrap the mux with the production securityHeaders middleware.
	handler := securityHeaders(mux)

	return httptest.NewServer(handler)
}

// testServerConfig holds optional dependencies injected into the test server.
type testServerConfig struct {
	invStore    *users.InvitationStore
	rateLimiter *ipRateLimiter
}

type testServerOption func(*testServerConfig)

func withInvitationStore(s *users.InvitationStore) testServerOption {
	return func(c *testServerConfig) { c.invStore = s }
}

func withRateLimiter(rl *ipRateLimiter) testServerOption {
	return func(c *testServerConfig) { c.rateLimiter = rl }
}

// ===========================================================================
// Pricing page integration tests
// ===========================================================================

func TestIntegration_PricingPage(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/pricing")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	assert.Contains(t, bodyStr, "Solo Pro")
	assert.Contains(t, bodyStr, "Family Pro")
	assert.Contains(t, bodyStr, "Premium")
	assert.Contains(t, bodyStr, "\u20B9199") // ₹199
	assert.Contains(t, bodyStr, "\u20B9349") // ₹349
	assert.Contains(t, bodyStr, "\u20B9699") // ₹699
}

func TestIntegration_PricingPage_ContentType(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/pricing")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")
}

// ===========================================================================
// Health check integration tests
// ===========================================================================

func TestIntegration_HealthCheck(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "application/json")

	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	assert.Equal(t, "ok", result["status"])
	assert.Equal(t, "v0.0.0-test", result["version"])
	assert.Equal(t, float64(94), result["tools"])
	assert.NotEmpty(t, result["uptime"])
}

// ===========================================================================
// Checkout success integration tests
// ===========================================================================

func TestIntegration_CheckoutSuccess(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/checkout/success")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	assert.Contains(t, bodyStr, "Welcome to Pro")
	assert.Contains(t, bodyStr, "Go to Dashboard")
	assert.Contains(t, bodyStr, "Manage Subscription")
	assert.Contains(t, bodyStr, "Live order execution")
}

// ===========================================================================
// Security headers integration tests
// ===========================================================================

func TestIntegration_SecurityHeaders(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	// Check headers on multiple endpoints to verify middleware wraps everything.
	endpoints := []string{"/pricing", "/checkout/success", "/healthz", "/robots.txt"}

	for _, ep := range endpoints {
		t.Run(ep, func(t *testing.T) {
			resp, err := http.Get(srv.URL + ep)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"), "missing X-Frame-Options on %s", ep)
			assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"), "missing X-Content-Type-Options on %s", ep)
			assert.Contains(t, resp.Header.Get("Strict-Transport-Security"), "max-age=", "missing HSTS on %s", ep)
			assert.NotEmpty(t, resp.Header.Get("Referrer-Policy"), "missing Referrer-Policy on %s", ep)
			assert.NotEmpty(t, resp.Header.Get("Content-Security-Policy"), "missing CSP on %s", ep)
			assert.NotEmpty(t, resp.Header.Get("Permissions-Policy"), "missing Permissions-Policy on %s", ep)
		})
	}
}

func TestIntegration_SecurityHeaders_CSPContent(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/pricing")
	require.NoError(t, err)
	defer resp.Body.Close()

	csp := resp.Header.Get("Content-Security-Policy")
	assert.Contains(t, csp, "default-src 'self'")
	assert.Contains(t, csp, "script-src")
	assert.Contains(t, csp, "style-src")
}

// ===========================================================================
// Rate limiting integration tests
// ===========================================================================

func TestIntegration_RateLimiting(t *testing.T) {
	// Very tight limit: 1 req/sec, burst 1.
	limiter := newIPRateLimiter(rate.Limit(1), 1)
	srv := newTestServer(t, withRateLimiter(limiter))
	defer srv.Close()

	// Use a custom client that does not follow redirects and allows us to
	// set a consistent RemoteAddr header. httptest.Server connections all
	// come from 127.0.0.1, so rate limiting applies to the same IP.
	client := srv.Client()

	// First request should succeed.
	resp1, err := client.Get(srv.URL + "/rate-limited")
	require.NoError(t, err)
	defer resp1.Body.Close()
	assert.Equal(t, http.StatusOK, resp1.StatusCode)

	// Second request (immediately) should be rate limited.
	resp2, err := client.Get(srv.URL + "/rate-limited")
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusTooManyRequests, resp2.StatusCode)
}

func TestIntegration_RateLimiting_DifferentEndpointsIndependent(t *testing.T) {
	// Even with tight rate limiting on /rate-limited, other endpoints are unaffected.
	limiter := newIPRateLimiter(rate.Limit(1), 1)
	srv := newTestServer(t, withRateLimiter(limiter))
	defer srv.Close()

	client := srv.Client()

	// Exhaust rate limit on /rate-limited.
	resp1, err := client.Get(srv.URL + "/rate-limited")
	require.NoError(t, err)
	resp1.Body.Close()
	assert.Equal(t, http.StatusOK, resp1.StatusCode)

	resp2, err := client.Get(srv.URL + "/rate-limited")
	require.NoError(t, err)
	resp2.Body.Close()
	assert.Equal(t, http.StatusTooManyRequests, resp2.StatusCode)

	// /healthz is not rate-limited by this limiter — should still work.
	resp3, err := client.Get(srv.URL + "/healthz")
	require.NoError(t, err)
	resp3.Body.Close()
	assert.Equal(t, http.StatusOK, resp3.StatusCode)
}

// ===========================================================================
// Accept-invite integration tests
// ===========================================================================

// newInMemoryInvitationStore creates an InvitationStore backed only by in-memory
// state (no SQLite). This is sufficient for integration testing the HTTP handler.
func newInMemoryInvitationStore() *users.InvitationStore {
	return users.NewInvitationStore(nil) // nil db = in-memory only
}

func TestIntegration_AcceptInvite_MissingToken(t *testing.T) {
	invStore := newInMemoryInvitationStore()
	srv := newTestServer(t, withInvitationStore(invStore))
	defer srv.Close()

	// No redirect following so we can inspect response directly.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := client.Get(srv.URL + "/auth/accept-invite")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "missing token")
}

func TestIntegration_AcceptInvite_InvalidToken(t *testing.T) {
	invStore := newInMemoryInvitationStore()
	srv := newTestServer(t, withInvitationStore(invStore))
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := client.Get(srv.URL + "/auth/accept-invite?token=nonexistent-token")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "invitation not found")
}

func TestIntegration_AcceptInvite_ExpiredToken(t *testing.T) {
	invStore := newInMemoryInvitationStore()

	// Create an invitation that expired 1 hour ago.
	inv := &users.FamilyInvitation{
		ID:           "expired-token-123",
		AdminEmail:   "admin@test.com",
		InvitedEmail: "member@test.com",
		Status:       "pending",
		CreatedAt:    time.Now().Add(-48 * time.Hour),
		ExpiresAt:    time.Now().Add(-1 * time.Hour), // expired
	}
	require.NoError(t, invStore.Create(inv))

	srv := newTestServer(t, withInvitationStore(invStore))
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := client.Get(srv.URL + "/auth/accept-invite?token=expired-token-123")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusGone, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "invitation expired")
}

func TestIntegration_AcceptInvite_AlreadyAccepted(t *testing.T) {
	invStore := newInMemoryInvitationStore()

	inv := &users.FamilyInvitation{
		ID:           "accepted-token-456",
		AdminEmail:   "admin@test.com",
		InvitedEmail: "member@test.com",
		Status:       "pending",
		CreatedAt:    time.Now().Add(-24 * time.Hour),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}
	require.NoError(t, invStore.Create(inv))

	// Accept it first.
	require.NoError(t, invStore.Accept("accepted-token-456"))

	srv := newTestServer(t, withInvitationStore(invStore))
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := client.Get(srv.URL + "/auth/accept-invite?token=accepted-token-456")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusGone, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "invitation already accepted")
}

func TestIntegration_AcceptInvite_ValidToken(t *testing.T) {
	invStore := newInMemoryInvitationStore()

	inv := &users.FamilyInvitation{
		ID:           "valid-token-789",
		AdminEmail:   "admin@test.com",
		InvitedEmail: "member@test.com",
		Status:       "pending",
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(48 * time.Hour),
	}
	require.NoError(t, invStore.Create(inv))

	srv := newTestServer(t, withInvitationStore(invStore))
	defer srv.Close()

	// Don't follow redirects so we can verify the 302 and Location header.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := client.Get(srv.URL + "/auth/accept-invite?token=valid-token-789")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "/auth/login?msg=welcome")

	// Verify the invitation was actually marked as accepted in the store.
	updated := invStore.Get("valid-token-789")
	require.NotNil(t, updated)
	assert.Equal(t, "accepted", updated.Status)
	assert.False(t, updated.AcceptedAt.IsZero())
}

func TestIntegration_AcceptInvite_RevokedToken(t *testing.T) {
	invStore := newInMemoryInvitationStore()

	inv := &users.FamilyInvitation{
		ID:           "revoked-token-111",
		AdminEmail:   "admin@test.com",
		InvitedEmail: "member@test.com",
		Status:       "pending",
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(48 * time.Hour),
	}
	require.NoError(t, invStore.Create(inv))
	require.NoError(t, invStore.Revoke("revoked-token-111"))

	srv := newTestServer(t, withInvitationStore(invStore))
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := client.Get(srv.URL + "/auth/accept-invite?token=revoked-token-111")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusGone, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "invitation already revoked")
}

// ===========================================================================
// Well-known endpoint integration tests
// ===========================================================================

func TestIntegration_SecurityTxt(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/.well-known/security.txt")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/plain")

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	assert.Contains(t, bodyStr, "Contact:")
	assert.Contains(t, bodyStr, "Expires:")
	assert.Contains(t, bodyStr, "Preferred-Languages: en")
}

func TestIntegration_RobotsTxt(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/robots.txt")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	assert.Contains(t, bodyStr, "User-agent: *")
	assert.Contains(t, bodyStr, "Disallow: /dashboard/")
	assert.Contains(t, bodyStr, "Disallow: /admin/")
	assert.Contains(t, bodyStr, "Disallow: /auth/")
	assert.Contains(t, bodyStr, "Disallow: /oauth/")
	assert.Contains(t, bodyStr, "Allow: /")
	assert.Contains(t, bodyStr, "Allow: /terms")
	assert.Contains(t, bodyStr, "Allow: /privacy")
}

// ===========================================================================
// Cross-cutting HTTP behaviour tests
// ===========================================================================

func TestIntegration_MethodNotAllowed_HealthzAcceptsPOST(t *testing.T) {
	// Standard Go mux does not enforce methods, so POST to /healthz should
	// still return 200 (the handler doesn't check method). This documents
	// current behaviour.
	srv := newTestServer(t)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/healthz", "application/json", strings.NewReader("{}"))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestIntegration_NotFound(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/nonexistent-path")
	require.NoError(t, err)
	defer resp.Body.Close()

	// Go's default mux returns 404 for unknown paths.
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestIntegration_SecurityHeaders_OnNotFound(t *testing.T) {
	// Security headers should be present even on 404 responses because
	// securityHeaders wraps the entire mux.
	srv := newTestServer(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/does-not-exist")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
}

func TestIntegration_HeadRequest(t *testing.T) {
	// HEAD requests should succeed and return headers without body.
	srv := newTestServer(t)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodHead, srv.URL+"/healthz", nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	// Body should be empty for HEAD.
	body, _ := io.ReadAll(resp.Body)
	assert.Empty(t, body)
}
