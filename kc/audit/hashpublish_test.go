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
