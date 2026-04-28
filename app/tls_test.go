package app

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTLSAutocertConfig_FromMap verifies ConfigFromMap parses the two
// TLS env vars (TLS_AUTOCERT_DOMAIN, TLS_AUTOCERT_CACHE_DIR) into the
// matching Config fields.
func TestTLSAutocertConfig_FromMap(t *testing.T) {
	t.Parallel()

	cfg := ConfigFromMap(map[string]string{
		"TLS_AUTOCERT_DOMAIN":    "mcp.example.com",
		"TLS_AUTOCERT_CACHE_DIR": "/var/lib/kite-mcp/autocert",
	})
	assert.Equal(t, "mcp.example.com", cfg.TLSAutocertDomain)
	assert.Equal(t, "/var/lib/kite-mcp/autocert", cfg.TLSAutocertCacheDir)
}

// TestTLSAutocertConfig_DefaultEmpty: when neither env var is set, both
// Config fields default to empty strings (TLS off, plain HTTP).
func TestTLSAutocertConfig_DefaultEmpty(t *testing.T) {
	t.Parallel()

	cfg := ConfigFromMap(map[string]string{})
	assert.Empty(t, cfg.TLSAutocertDomain)
	assert.Empty(t, cfg.TLSAutocertCacheDir)
}

// TestTLSAutocertEnabled_DomainGate: TLSAutocertEnabled returns true iff
// TLSAutocertDomain is non-empty. Cache-dir-only or empty domain should
// produce false (defensive fail-safe — never serve TLS without an
// explicit domain on which to terminate).
func TestTLSAutocertEnabled_DomainGate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		domain   string
		cacheDir string
		want     bool
	}{
		{"both unset", "", "", false},
		{"cache-dir only — defensive false", "", "/var/cache", false},
		{"domain only — true (cache uses default)", "mcp.example.com", "", true},
		{"both set — true", "mcp.example.com", "/var/cache", true},
		{"domain whitespace — false", "   ", "/var/cache", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := &Config{
				TLSAutocertDomain:   tc.domain,
				TLSAutocertCacheDir: tc.cacheDir,
			}
			assert.Equal(t, tc.want, cfg.TLSAutocertEnabled())
		})
	}
}

// TestTLSAutocertManager_NoOpWhenDisabled: when TLS is disabled, the
// helper returns (nil, nil) — no autocert.Manager allocated, no error.
// This is the production-safe default for Fly.io / Cloudflare-terminated
// deployments.
func TestTLSAutocertManager_NoOpWhenDisabled(t *testing.T) {
	t.Parallel()

	cfg := &Config{}
	mgr, err := newAutocertManager(cfg)
	require.NoError(t, err)
	assert.Nil(t, mgr)
}

// TestTLSAutocertManager_BuildsWhenEnabled: when TLSAutocertDomain is
// set, newAutocertManager returns a configured *autocert.Manager whose
// HostPolicy whitelists the configured domain (and rejects others).
//
// This test does NOT actually drive the ACME challenge — it only
// verifies the manager is constructed and the host-allowlist policy is
// applied. Real ACME flows are exercised in production / staging via
// the runbook in docs/tls-self-host.md.
func TestTLSAutocertManager_BuildsWhenEnabled(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	cfg := &Config{
		TLSAutocertDomain:   "mcp.example.com",
		TLSAutocertCacheDir: cacheDir,
	}
	mgr, err := newAutocertManager(cfg)
	require.NoError(t, err)
	require.NotNil(t, mgr)

	// HostPolicy must allow the configured domain.
	err = mgr.HostPolicy(t.Context(), "mcp.example.com")
	assert.NoError(t, err, "configured domain must pass HostPolicy")

	// HostPolicy must reject any other domain (defends against ACME
	// being challenged for an attacker-controlled hostname pointed at
	// our IP).
	err = mgr.HostPolicy(t.Context(), "attacker.example.com")
	assert.Error(t, err, "non-configured domain must fail HostPolicy")
}

// TestTLSAutocertManager_DefaultCacheDir: when TLSAutocertCacheDir is
// empty but TLSAutocertDomain is set, the manager defaults to a
// well-known per-user cache dir under HOME (or /var/lib/kite-mcp on
// systems without HOME).
//
// This makes the env var optional — operators set TLS_AUTOCERT_DOMAIN
// alone and get reasonable cache placement.
func TestTLSAutocertManager_DefaultCacheDir(t *testing.T) {
	t.Parallel()

	cfg := &Config{TLSAutocertDomain: "mcp.example.com"}
	mgr, err := newAutocertManager(cfg)
	require.NoError(t, err)
	require.NotNil(t, mgr)

	// We can't assert the exact path (depends on HOME), but the cache
	// must be set to SOME DirCache (not the autocert.DirCache zero
	// value).
	assert.NotNil(t, mgr.Cache, "Cache must default to a non-nil DirCache")
}

// TestTLSAutocertManager_RejectsCommaSeparatedDomains: until we add
// multi-domain support, supplying multiple comma-separated domains
// should be rejected as a config error rather than silently treated
// as a single literal hostname.
//
// Defensive: accidentally setting TLS_AUTOCERT_DOMAIN="a.com,b.com"
// would otherwise produce a manager that silently failed to acquire
// certs for either name (ACME would try to validate the literal
// "a.com,b.com" and fail). Returning an error at startup makes the
// misconfiguration visible.
func TestTLSAutocertManager_RejectsCommaSeparatedDomains(t *testing.T) {
	t.Parallel()

	cfg := &Config{TLSAutocertDomain: "mcp.example.com,other.example.com"}
	mgr, err := newAutocertManager(cfg)
	assert.Error(t, err)
	assert.Nil(t, mgr)
	assert.Contains(t, strings.ToLower(err.Error()), "single domain")
}

// TestTLSAutocertManager_RejectsBareIP: ACME does not issue certs for
// IP addresses. A user setting TLS_AUTOCERT_DOMAIN="1.2.3.4" would get
// a runtime ACME failure; better to reject at startup with a clear
// error.
func TestTLSAutocertManager_RejectsBareIP(t *testing.T) {
	t.Parallel()

	tests := []string{
		"127.0.0.1",
		"192.168.1.10",
		"203.0.113.5",
	}
	for _, domain := range tests {
		t.Run(domain, func(t *testing.T) {
			t.Parallel()
			cfg := &Config{TLSAutocertDomain: domain}
			mgr, err := newAutocertManager(cfg)
			assert.Error(t, err)
			assert.Nil(t, mgr)
			assert.Contains(t, strings.ToLower(err.Error()), "domain")
		})
	}
}

// TestTLSRedirectHandler_RedirectsHTTPToHTTPS: when the autocert path
// is enabled, port-80 listener serves a small handler that
//  1. responds to ACME http-01 challenges (mgr.HTTPHandler does this)
//  2. redirects everything else to HTTPS
//
// This test exercises (2) — verifying the redirect target preserves
// the request path and query string AND uses the explicit configured
// domain (not the inbound Host header) to defend against Host-header
// reflection attacks.
func TestTLSRedirectHandler_RedirectsHTTPToHTTPS(t *testing.T) {
	t.Parallel()

	cfg := &Config{TLSAutocertDomain: "mcp.example.com"}
	mgr, err := newAutocertManager(cfg)
	require.NoError(t, err)
	require.NotNil(t, mgr)

	handler := newTLSRedirectHandler(mgr, cfg.TLSAutocertDomain)
	tests := []struct {
		name       string
		host       string // inbound Host header
		path       string
		query      string
		wantTarget string
	}{
		{"root", "mcp.example.com", "/", "", "https://mcp.example.com/"},
		{"path", "mcp.example.com", "/mcp", "", "https://mcp.example.com/mcp"},
		{"path+query", "mcp.example.com", "/dashboard", "tab=alerts", "https://mcp.example.com/dashboard?tab=alerts"},
		// Host-header reflection defence: even when an attacker hits
		// our IP with a forged Host header, the redirect target uses
		// the ACME-validated domain, not the attacker's Host.
		{"host-header injection", "attacker.example.com", "/login", "", "https://mcp.example.com/login"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req, _ := http.NewRequest(http.MethodGet, "http://"+tc.host+tc.path, nil)
			if tc.query != "" {
				req.URL.RawQuery = tc.query
			}
			rec := newTestResponseRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusMovedPermanently, rec.code)
			assert.Equal(t, tc.wantTarget, rec.headers.Get("Location"))
		})
	}
}

// TestTLSRedirectHandler_PassesACMEChallengeThrough: when the inbound
// request path starts with /.well-known/acme-challenge/, the handler
// must defer to the autocert manager's HTTPHandler instead of
// redirecting (otherwise ACME validation fails in a redirect loop).
func TestTLSRedirectHandler_PassesACMEChallengeThrough(t *testing.T) {
	t.Parallel()

	cfg := &Config{TLSAutocertDomain: "mcp.example.com"}
	mgr, err := newAutocertManager(cfg)
	require.NoError(t, err)
	require.NotNil(t, mgr)

	handler := newTLSRedirectHandler(mgr, cfg.TLSAutocertDomain)
	req, _ := http.NewRequest(http.MethodGet, "http://mcp.example.com/.well-known/acme-challenge/abc123", nil)
	rec := newTestResponseRecorder()
	handler.ServeHTTP(rec, req)
	// We can't easily verify the autocert manager's exact response
	// shape (it would 404 for the unknown token), but we CAN verify
	// the response is NOT the 301 redirect — that would mean we
	// short-circuited the ACME path.
	assert.NotEqual(t, http.StatusMovedPermanently, rec.code,
		".well-known/acme-challenge/* must not be redirected")
}

// testResponseRecorder is a minimal http.ResponseWriter for the redirect
// tests. We use this rather than httptest.NewRecorder to avoid pulling
// in the full httptest package for two-field assertions.
type testResponseRecorder struct {
	code    int
	headers http.Header
	body    []byte
}

func newTestResponseRecorder() *testResponseRecorder {
	return &testResponseRecorder{
		code:    http.StatusOK,
		headers: http.Header{},
	}
}

func (r *testResponseRecorder) Header() http.Header        { return r.headers }
func (r *testResponseRecorder) Write(b []byte) (int, error) { r.body = append(r.body, b...); return len(b), nil }
func (r *testResponseRecorder) WriteHeader(code int)       { r.code = code }
