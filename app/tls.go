package app

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

// TLS self-host integration. Inline ACME via golang.org/x/crypto/acme/autocert
// for off-Fly.io single-binary deployments. See docs/tls-self-host.md for the
// operator runbook (DNS prerequisites, port-forwarding, rate-limit awareness,
// cache-dir persistence requirements).
//
// Default: TLS_AUTOCERT_DOMAIN unset → plain HTTP, TLS terminated upstream
// (Fly.io / Cloudflare / reverse proxy). Setting TLS_AUTOCERT_DOMAIN flips
// the server into inline-TLS mode (binds 443, handles 80 for ACME challenges,
// redirects everything else to HTTPS, caches issued certs in TLS_AUTOCERT_CACHE_DIR).

// TLSAutocertEnabled returns true iff TLSAutocertDomain is non-empty after
// trim. Defensive against accidental whitespace ("   " in env). Cache-dir
// alone with empty domain produces false (never serve TLS without an
// explicit hostname allowlist — defends against attacker-controlled DNS
// pointed at our IP).
func (c *Config) TLSAutocertEnabled() bool {
	if c == nil {
		return false
	}
	return strings.TrimSpace(c.TLSAutocertDomain) != ""
}

// newAutocertManager constructs an *autocert.Manager when TLS is enabled.
// Returns (nil, nil) when disabled — the caller treats that as "stay in
// plain-HTTP mode".
//
// Error cases: comma-separated domains (multi-domain support not yet
// implemented; reject loudly rather than silently fail ACME validation
// against a literal "a.com,b.com" hostname); bare IP addresses (ACME
// will not issue certs for IPs).
func newAutocertManager(cfg *Config) (*autocert.Manager, error) {
	if cfg == nil || !cfg.TLSAutocertEnabled() {
		return nil, nil
	}

	domain := strings.TrimSpace(cfg.TLSAutocertDomain)

	// Reject comma-separated lists — multi-domain support requires
	// per-domain HostPolicy + cache layout decisions; not yet
	// implemented. Make the misconfiguration visible at startup.
	if strings.Contains(domain, ",") {
		return nil, fmt.Errorf("tls: TLS_AUTOCERT_DOMAIN must be a single domain (got %q); multi-domain not yet supported", domain)
	}

	// Reject bare IP addresses — ACME does not issue certs for IPs;
	// the request would fail anyway, but the error from autocert is
	// cryptic. Catching it here makes the misconfiguration explicit.
	if ip := net.ParseIP(domain); ip != nil {
		return nil, fmt.Errorf("tls: TLS_AUTOCERT_DOMAIN must be a hostname not an IP (got %q); ACME does not issue certs for IPs", domain)
	}

	// Reject empty / dot / wildcard — autocert won't actually issue
	// for any of these; clearer error here.
	if domain == "." || domain == "*" || strings.HasPrefix(domain, "*.") {
		return nil, fmt.Errorf("tls: TLS_AUTOCERT_DOMAIN must be a concrete hostname (got %q); wildcard certs require DNS-01 challenge which is not implemented", domain)
	}

	cacheDir := strings.TrimSpace(cfg.TLSAutocertCacheDir)
	if cacheDir == "" {
		cacheDir = defaultAutocertCacheDir()
	}

	// HostPolicy is the allowlist that prevents an attacker who points
	// some-other-domain.com → our IP from coercing us into requesting
	// a cert for their domain (which would burn our ACME rate-limit
	// budget and create audit-trail spam).
	policy := autocert.HostWhitelist(domain)

	return &autocert.Manager{
		Cache:      autocert.DirCache(cacheDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: policy,
	}, nil
}

// defaultAutocertCacheDir picks a sensible default cache location when
// TLS_AUTOCERT_CACHE_DIR is unset. Prefers ${HOME}/.cache/kite-mcp/autocert
// for typical user-mode self-hosts; falls back to /var/lib/kite-mcp/autocert
// on systems without HOME (eg. some container init scenarios).
//
// IMPORTANT: this directory MUST be on persistent storage. ACME's rate
// limit is 50 certificates per registered domain per week; losing the
// cache forces re-issuance on every restart and rapidly exhausts the
// budget. The runbook in docs/tls-self-host.md restates this prominently.
func defaultAutocertCacheDir() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".cache", "kite-mcp", "autocert")
	}
	return filepath.Join("/var", "lib", "kite-mcp", "autocert")
}

// newTLSRedirectHandler returns the HTTP-side handler we install on
// port 80 when TLS is enabled. It serves two purposes:
//
//  1. ACME http-01 challenges hit /.well-known/acme-challenge/<token> —
//     these MUST be answered by the autocert manager's HTTPHandler so
//     that initial cert acquisition + renewal succeed.
//  2. Every other plain-HTTP request gets a 301 redirect to the HTTPS
//     equivalent — preserves path + query string, sets the configured
//     domain as Host (so curl http://1.2.3.4/ → https://mcp.example.com/
//     even when the request hits by IP).
//
// The redirect target is built from the ACME-validated domain (NOT the
// inbound Host header), so an attacker who points their domain at our
// IP cannot reflect a redirect to attacker.example.com. This defends
// against the Host-header reflection class of bugs.
//
// mgr.HTTPHandler(fallback) gives us a handler that:
//   - serves /.well-known/acme-challenge/* directly (ACME http-01)
//   - delegates everything else to our fallback (the 301 redirect)
func newTLSRedirectHandler(mgr *autocert.Manager, domain string) http.Handler {
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := "https://" + domain + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
	return mgr.HTTPHandler(fallback)
}
