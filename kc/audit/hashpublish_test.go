package audit

import (
	"net"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// ValidateS3Endpoint — SSRF blocklist on AUDIT_HASH_PUBLISH_S3_ENDPOINT
//
// An operator who misconfigures the S3 endpoint env var to point at an
// internal address (169.254.169.254, 10.x, 127.x, ::1, etc.) would cause the
// hash publisher to leak SigV4-signed HMAC-authenticated PUTs to that host
// — potentially exposing the R2 access key + body to any local service that
// listens. Worse: 169.254.169.254 is the AWS / GCP / Azure instance metadata
// endpoint — a classic SSRF target.
//
// The validator runs at config-load time (startup) so misconfig fails fast
// rather than silently at the first publish tick.
// ---------------------------------------------------------------------------

func TestValidateS3Endpoint_RejectsMetadataIP(t *testing.T) {
	t.Parallel()
	// 169.254.169.254 = AWS/GCP/Azure IMDS — classic SSRF sink
	err := ValidateS3Endpoint("http://169.254.169.254/")
	if err == nil {
		t.Fatal("expected error for AWS metadata IP, got nil")
	}
	if !strings.Contains(err.Error(), "internal") && !strings.Contains(err.Error(), "link-local") {
		t.Errorf("error should mention internal/link-local: %v", err)
	}
}

func TestValidateS3Endpoint_RejectsLinkLocalRange(t *testing.T) {
	t.Parallel()
	// Full 169.254.0.0/16 range must be rejected (not just the IMDS IP)
	for _, addr := range []string{
		"http://169.254.1.1/",
		"http://169.254.100.50/",
		"https://169.254.255.254/",
	} {
		if err := ValidateS3Endpoint(addr); err == nil {
			t.Errorf("expected error for link-local %s, got nil", addr)
		}
	}
}

func TestValidateS3Endpoint_RejectsRFC1918(t *testing.T) {
	t.Parallel()
	// RFC 1918 private ranges — all three blocks
	for _, addr := range []string{
		"http://10.0.0.1/",
		"http://10.255.255.255/",
		"http://172.16.0.1/",
		"http://172.20.10.5/",
		"http://172.31.255.255/",
		"http://192.168.0.1/",
		"http://192.168.1.100/",
	} {
		if err := ValidateS3Endpoint(addr); err == nil {
			t.Errorf("expected error for RFC1918 address %s, got nil", addr)
		}
	}
}

func TestValidateS3Endpoint_RejectsLoopback(t *testing.T) {
	t.Parallel()
	// 127.0.0.0/8 IPv4 loopback + ::1 IPv6 loopback
	for _, addr := range []string{
		"http://127.0.0.1/",
		"http://127.0.0.1:8080/",
		"http://127.99.99.99/",
		"http://[::1]/",
		"http://localhost/", // resolves to loopback on virtually every host
	} {
		if err := ValidateS3Endpoint(addr); err == nil {
			t.Errorf("expected error for loopback %s, got nil", addr)
		}
	}
}

func TestValidateS3Endpoint_RejectsMalformed(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{
		"",                       // empty
		"not-a-url",              // no scheme
		"://example.com",         // missing scheme
		"http://",                // empty host
		"ht!tp://example.com",    // invalid scheme chars
	} {
		if err := ValidateS3Endpoint(bad); err == nil {
			t.Errorf("expected error for malformed URL %q, got nil", bad)
		}
	}
}

func TestValidateS3Endpoint_RejectsNonHTTPScheme(t *testing.T) {
	t.Parallel()
	// file://, gopher://, ftp://, etc. could enable other SSRF classes.
	for _, bad := range []string{
		"file:///etc/passwd",
		"gopher://example.com/",
		"ftp://example.com/",
		"javascript:alert(1)",
	} {
		if err := ValidateS3Endpoint(bad); err == nil {
			t.Errorf("expected error for non-http scheme %q, got nil", bad)
		}
	}
}

func TestValidateS3Endpoint_AcceptsPublicR2(t *testing.T) {
	t.Parallel()
	// Canonical Cloudflare R2 endpoint — MUST be accepted.
	// (If DNS is unavailable in CI, the validator should still let it pass:
	// we cannot prove a name is private without resolution, so unresolvable
	// hosts are allowed here. Internal-IP literals ARE rejected upstream.)
	// This test exercises the resolver path — if DNS works, we verify the
	// public IP isn't a false-positive. If DNS fails, we skip.
	host := "r2.cloudflarestorage.com"
	if _, err := net.LookupIP(host); err != nil {
		t.Skipf("DNS unavailable in test env, skipping: %v", err)
	}
	if err := ValidateS3Endpoint("https://example.r2.cloudflarestorage.com"); err != nil {
		t.Errorf("public R2 endpoint rejected: %v", err)
	}
}

func TestValidateS3Endpoint_AcceptsPublicS3(t *testing.T) {
	t.Parallel()
	// AWS S3 public endpoint.
	host := "s3.amazonaws.com"
	if _, err := net.LookupIP(host); err != nil {
		t.Skipf("DNS unavailable in test env, skipping: %v", err)
	}
	if err := ValidateS3Endpoint("https://s3.amazonaws.com"); err != nil {
		t.Errorf("public S3 endpoint rejected: %v", err)
	}
}

func TestValidateS3Endpoint_AcceptsPublicIPLiteral(t *testing.T) {
	t.Parallel()
	// 8.8.8.8 is Google DNS (public IP, not private/loopback/link-local).
	// Should be accepted — we don't require a hostname, only not-private.
	if err := ValidateS3Endpoint("http://8.8.8.8/"); err != nil {
		t.Errorf("public IP literal 8.8.8.8 rejected: %v", err)
	}
}

// --- isPrivateIP unit tests -------------------------------------------------

func TestIsPrivateIP_RFC1918(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"10.0.0.1":         true,
		"10.255.255.255":   true,
		"172.16.0.1":       true,
		"172.31.255.255":   true,
		"192.168.1.1":      true,
		"192.168.255.255":  true,
		"8.8.8.8":          false,
		"1.1.1.1":          false,
		"172.15.0.1":       false, // just below 172.16.0.0/12
		"172.32.0.1":       false, // just above 172.31.255.255
		"192.167.255.255":  false, // just below 192.168.0.0/16
		"192.169.0.1":      false, // just above 192.168.255.255
	}
	for ip, want := range cases {
		got := isPrivateIP(net.ParseIP(ip))
		if got != want {
			t.Errorf("isPrivateIP(%s) = %v, want %v", ip, got, want)
		}
	}
}

// --- Load integration -------------------------------------------------------

// LoadHashPublishConfig + ValidateS3Endpoint wiring: if the env var points at
// 169.254.169.254, LoadHashPublishConfig should still populate the struct,
// but the validator (called at app init) should reject it. We test the
// validator returns the expected error; the env-var-driven path is tested
// implicitly via app start in integration tests.
func TestValidateS3Endpoint_ErrorMessageIncludesReason(t *testing.T) {
	t.Parallel()
	err := ValidateS3Endpoint("http://10.0.0.1/")
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	// Should include the problematic address or a clear reason
	if !strings.Contains(msg, "10.0.0.1") && !strings.Contains(msg, "private") {
		t.Errorf("error message should identify the private address: %q", msg)
	}
}

// TestLoadHashPublishConfigFromGetenv_PureParser verifies the pure-parser
// variant accepts a caller-supplied getenv func so tests can drive every
// AUDIT_HASH_PUBLISH_* branch via a map literal — no t.Setenv, t.Parallel
// safe. Mirrors the envCheckWithGetenv pattern (app/envcheck.go:54).
//
// T1.2: prior LoadHashPublishConfig read env directly inside the function
// body. This test asserts the new pure parser reads from the injected
// callback only — the production shim wires os.Getenv at the boundary.
func TestLoadHashPublishConfigFromGetenv_PureParser(t *testing.T) {
	t.Parallel()
	getenv := func(k string) string {
		return map[string]string{
			"AUDIT_HASH_PUBLISH_S3_ENDPOINT": "https://example-account.r2.cloudflarestorage.com",
			"AUDIT_HASH_PUBLISH_BUCKET":      "my-bucket",
			"AUDIT_HASH_PUBLISH_ACCESS_KEY":  "AKIA-test",
			"AUDIT_HASH_PUBLISH_SECRET_KEY":  "secret-test",
			"AUDIT_HASH_PUBLISH_REGION":      "apac",
			"AUDIT_HASH_PUBLISH_INTERVAL":    "30m",
			"AUDIT_HASH_PUBLISH_KEY":         "dedicated-hmac-key",
		}[k]
	}
	cfg := LoadHashPublishConfigFromGetenv([]byte("jwt-fallback"), getenv)
	if cfg.S3Endpoint != "https://example-account.r2.cloudflarestorage.com" {
		t.Errorf("S3Endpoint not from injected getenv: %q", cfg.S3Endpoint)
	}
	if cfg.Bucket != "my-bucket" {
		t.Errorf("Bucket not from injected getenv: %q", cfg.Bucket)
	}
	if cfg.AccessKey != "AKIA-test" {
		t.Errorf("AccessKey not from injected getenv: %q", cfg.AccessKey)
	}
	if cfg.SecretKey != "secret-test" {
		t.Errorf("SecretKey not from injected getenv: %q", cfg.SecretKey)
	}
	if cfg.Region != "apac" {
		t.Errorf("Region not from injected getenv: %q", cfg.Region)
	}
	if cfg.Interval.String() != "30m0s" {
		t.Errorf("Interval not parsed from injected getenv: %v", cfg.Interval)
	}
	if string(cfg.SigningKey) != "dedicated-hmac-key" {
		t.Errorf("SigningKey not from injected AUDIT_HASH_PUBLISH_KEY: %q", string(cfg.SigningKey))
	}
	if cfg.SchemaVersion != 1 {
		t.Errorf("SchemaVersion default not 1: %d", cfg.SchemaVersion)
	}
	if !cfg.Enabled() {
		t.Errorf("Enabled() should be true with all required fields set")
	}
}

// TestLoadHashPublishConfigFromGetenv_DefaultsAndJWTFallback verifies the
// default Region ("auto"), default Interval (1h), and JWT fallback when
// AUDIT_HASH_PUBLISH_KEY is unset.
func TestLoadHashPublishConfigFromGetenv_DefaultsAndJWTFallback(t *testing.T) {
	t.Parallel()
	getenv := func(k string) string { return "" } // empty environment
	cfg := LoadHashPublishConfigFromGetenv([]byte("jwt-fallback"), getenv)
	if cfg.Region != "auto" {
		t.Errorf("Region default should be 'auto' (R2): %q", cfg.Region)
	}
	if cfg.Interval != 3600_000_000_000 { // 1h in nanoseconds
		t.Errorf("Interval default should be 1h: %v", cfg.Interval)
	}
	if string(cfg.SigningKey) != "jwt-fallback" {
		t.Errorf("SigningKey should fall back to passed signingKey: %q", string(cfg.SigningKey))
	}
	if cfg.Enabled() {
		t.Errorf("Enabled() should be false without S3Endpoint/Bucket/AccessKey/SecretKey")
	}
}
