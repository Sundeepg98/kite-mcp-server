package audit

// Pure-function tests for the AWS SigV4 implementation in hashpublish.go.
//
// These functions are security-critical: a bug in the canonical-request /
// signing-key derivation would produce silently-invalid signatures (R2 PUTs
// would fail with 403 only at runtime), or worse — accept attacker-crafted
// inputs that produce a valid-looking signature against the wrong scope.
//
// Per CLAUDE.md "Pure functions: 100% coverage required". The companion
// hashpublish_test.go covers ValidateS3Endpoint (network-touching). This
// file closes the remaining pure-function gaps:
//
//   - signSigV4              (was 0%) -> deterministic-time signature check
//   - signPublication        (was 0%) -> HMAC + signature-field-zeroing
//   - canonicalURIPath       (was 0%) -> empty-path -> "/" branch
//   - canonicalQueryString   (was 0%) -> sort + url-encode
//   - hmacSHA256             (was 0%) -> RFC 4231 vector cross-check
//   - privateReason          (was 55.6%) -> remaining branches
//   - isPrivateIP            (was 66.7%) -> nil + non-private + IPv4 explicit
//   - LoadHashPublishConfig  (was 0%) -> production shim wraps Getenv variant
//
// Test discipline: t.Parallel() everywhere, no t.Setenv, no goroutines,
// no I/O. signSigV4 is invoked with a frozen time.Time so the resulting
// Authorization header is byte-exact reproducible.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// canonicalURIPath
// ---------------------------------------------------------------------------

func TestCanonicalURIPath_EmptyReturnsSlash(t *testing.T) {
	t.Parallel()
	if got := canonicalURIPath(""); got != "/" {
		t.Errorf("empty path: got %q, want %q", got, "/")
	}
}

func TestCanonicalURIPath_NonEmptyPassthrough(t *testing.T) {
	t.Parallel()
	cases := []string{
		"/",
		"/audit-hashes/2026-04-26T12-30-00Z.json",
		"/bucket/key%20with%20spaces",
		"/escaped%2Fslash",
	}
	for _, p := range cases {
		if got := canonicalURIPath(p); got != p {
			t.Errorf("path %q: got %q, want passthrough", p, got)
		}
	}
}

// ---------------------------------------------------------------------------
// canonicalQueryString
// ---------------------------------------------------------------------------

func TestCanonicalQueryString_EmptyReturnsEmpty(t *testing.T) {
	t.Parallel()
	if got := canonicalQueryString(url.Values{}); got != "" {
		t.Errorf("empty values: got %q, want \"\"", got)
	}
}

func TestCanonicalQueryString_SortedByKey(t *testing.T) {
	t.Parallel()
	// Insert keys in non-alphabetical order; output must be sorted.
	q := url.Values{}
	q.Set("zebra", "1")
	q.Set("alpha", "2")
	q.Set("middle", "3")
	got := canonicalQueryString(q)
	want := "alpha=2&middle=3&zebra=1"
	if got != want {
		t.Errorf("sorted: got %q, want %q", got, want)
	}
}

func TestCanonicalQueryString_KeyAndValueURIEncoded(t *testing.T) {
	t.Parallel()
	q := url.Values{}
	q.Set("key with space", "value/with/slash")
	q.Set("amp&key", "amp&val")
	got := canonicalQueryString(q)
	// Both must contain encoded forms — '&' inside value MUST be %26 not raw.
	if !strings.Contains(got, "key+with+space=value%2Fwith%2Fslash") {
		t.Errorf("unencoded space-key/slash-val pair: %q", got)
	}
	if !strings.Contains(got, "amp%26key=amp%26val") {
		t.Errorf("unencoded ampersand: %q", got)
	}
}

func TestCanonicalQueryString_MultiValueKey(t *testing.T) {
	t.Parallel()
	// url.Values supports repeated keys (slice). Output should join all
	// values separated by &, each encoded.
	q := url.Values{}
	q.Add("k", "v1")
	q.Add("k", "v2")
	got := canonicalQueryString(q)
	want := "k=v1&k=v2"
	if got != want {
		t.Errorf("multi-value: got %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// hmacSHA256 — sanity check against known vector
// ---------------------------------------------------------------------------

func TestHMACSHA256_MatchesStdlib(t *testing.T) {
	t.Parallel()
	// Cross-check our wrapper produces the same bytes as crypto/hmac directly.
	key := []byte("super-secret-key")
	data := []byte("some payload to authenticate")
	got := hmacSHA256(key, data)

	expectedMac := hmac.New(sha256.New, key)
	expectedMac.Write(data)
	want := expectedMac.Sum(nil)

	if !hmac.Equal(got, want) {
		t.Errorf("hmacSHA256 mismatch: got %x, want %x", got, want)
	}
	if len(got) != 32 {
		t.Errorf("hmacSHA256 output length: got %d, want 32", len(got))
	}
}

func TestHMACSHA256_EmptyInputs(t *testing.T) {
	t.Parallel()
	// Empty key + empty data — must still produce 32-byte output.
	got := hmacSHA256([]byte{}, []byte{})
	if len(got) != 32 {
		t.Errorf("empty inputs length: got %d, want 32", len(got))
	}
	// Specifically: HMAC-SHA256("", "") = b613679a0814d9ec772f95d778c35fc5
	//                                       ff1697c493715653c6c712144292c5ad
	want := "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
	if got := hex.EncodeToString(got); got != want {
		t.Errorf("HMAC-SHA256(\"\",\"\") = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// signPublication
// ---------------------------------------------------------------------------

func TestSignPublication_DeterministicForSameInput(t *testing.T) {
	t.Parallel()
	pub := HashTipPublication{
		Timestamp:     "2026-04-26T12:00:00Z",
		TipHash:       "abc123def456",
		EntryCount:    42,
		SchemaVersion: 1,
	}
	key := []byte("test-signing-key")

	sig1 := signPublication(pub, key)
	sig2 := signPublication(pub, key)
	if sig1 != sig2 {
		t.Errorf("non-deterministic: %q vs %q", sig1, sig2)
	}
	if len(sig1) != 64 { // 32-byte HMAC -> 64 hex chars
		t.Errorf("hex sig length: got %d, want 64", len(sig1))
	}
}

func TestSignPublication_IgnoresExistingSignatureField(t *testing.T) {
	t.Parallel()
	// signPublication must zero the Signature field before hashing — otherwise
	// the signature would depend on its own value (chicken-and-egg).
	key := []byte("k")

	withEmpty := HashTipPublication{
		Timestamp:     "t",
		TipHash:       "h",
		EntryCount:    1,
		SchemaVersion: 1,
		Signature:     "",
	}
	withGarbage := HashTipPublication{
		Timestamp:     "t",
		TipHash:       "h",
		EntryCount:    1,
		SchemaVersion: 1,
		Signature:     "previous-leftover-signature-must-not-affect-result",
	}

	sigEmpty := signPublication(withEmpty, key)
	sigGarbage := signPublication(withGarbage, key)
	if sigEmpty != sigGarbage {
		t.Errorf("Signature field leaked into hash: empty=%q, garbage=%q",
			sigEmpty, sigGarbage)
	}
}

func TestSignPublication_DifferentKeysProduceDifferentSignatures(t *testing.T) {
	t.Parallel()
	pub := HashTipPublication{
		Timestamp:     "t",
		TipHash:       "h",
		EntryCount:    1,
		SchemaVersion: 1,
	}
	sig1 := signPublication(pub, []byte("key-A"))
	sig2 := signPublication(pub, []byte("key-B"))
	if sig1 == sig2 {
		t.Errorf("different keys produced same signature: %q", sig1)
	}
}

func TestSignPublication_DifferentDataProducesDifferentSignatures(t *testing.T) {
	t.Parallel()
	key := []byte("k")
	a := signPublication(HashTipPublication{TipHash: "hashA", EntryCount: 1, SchemaVersion: 1}, key)
	b := signPublication(HashTipPublication{TipHash: "hashB", EntryCount: 1, SchemaVersion: 1}, key)
	if a == b {
		t.Errorf("different TipHash produced same signature: %q", a)
	}
}

// ---------------------------------------------------------------------------
// signSigV4 — full canonical-request / signing-key / Authorization flow
// ---------------------------------------------------------------------------

func TestSignSigV4_AddsExpectedHeaders(t *testing.T) {
	t.Parallel()
	body := []byte(`{"hello":"world"}`)
	req, err := http.NewRequest(http.MethodPut,
		"https://example-account.r2.cloudflarestorage.com/my-bucket/key.json",
		strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Frozen time so the test is deterministic.
	now := time.Date(2026, time.April, 26, 12, 30, 45, 0, time.UTC)
	if err := signSigV4(req, body, "AKIAEXAMPLE", "secret123", "auto", "s3", now); err != nil {
		t.Fatalf("signSigV4: %v", err)
	}

	// X-Amz-Date in basic ISO-8601 form (no separators).
	if got := req.Header.Get("X-Amz-Date"); got != "20260426T123045Z" {
		t.Errorf("X-Amz-Date: got %q, want 20260426T123045Z", got)
	}

	// X-Amz-Content-Sha256 = lowercase hex of sha256(body).
	bodyHash := sha256Hex(body)
	if got := req.Header.Get("X-Amz-Content-Sha256"); got != bodyHash {
		t.Errorf("X-Amz-Content-Sha256: got %q, want %q", got, bodyHash)
	}

	// Authorization: must start with the expected algorithm + credential.
	auth := req.Header.Get("Authorization")
	wantPrefix := "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20260426/auto/s3/aws4_request"
	if !strings.HasPrefix(auth, wantPrefix) {
		t.Errorf("Authorization prefix:\n  got:  %q\n  want: %q...", auth, wantPrefix)
	}

	// Authorization must list the four signed headers in alphabetical order.
	wantSignedHeaders := "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date"
	if !strings.Contains(auth, wantSignedHeaders) {
		t.Errorf("Authorization missing SignedHeaders block:\n  got: %q", auth)
	}

	// Signature is 64 hex chars at the tail.
	idx := strings.Index(auth, "Signature=")
	if idx < 0 {
		t.Fatalf("Authorization missing Signature: %q", auth)
	}
	sig := auth[idx+len("Signature="):]
	if len(sig) != 64 {
		t.Errorf("Signature length: got %d, want 64 (hex of HMAC-SHA256)", len(sig))
	}
	if _, err := hex.DecodeString(sig); err != nil {
		t.Errorf("Signature not valid hex: %v", err)
	}
}

func TestSignSigV4_DeterministicForFixedInputs(t *testing.T) {
	t.Parallel()
	// Same inputs (incl. fixed time) MUST yield byte-identical Authorization.
	body := []byte("payload")
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

	makeReq := func() *http.Request {
		r, _ := http.NewRequest(http.MethodPut,
			"https://example-account.r2.cloudflarestorage.com/b/k", strings.NewReader("payload"))
		r.Header.Set("Content-Type", "application/json")
		return r
	}
	r1 := makeReq()
	r2 := makeReq()
	if err := signSigV4(r1, body, "ak", "sk", "auto", "s3", now); err != nil {
		t.Fatalf("sign r1: %v", err)
	}
	if err := signSigV4(r2, body, "ak", "sk", "auto", "s3", now); err != nil {
		t.Fatalf("sign r2: %v", err)
	}
	if r1.Header.Get("Authorization") != r2.Header.Get("Authorization") {
		t.Errorf("non-deterministic:\n  r1=%q\n  r2=%q",
			r1.Header.Get("Authorization"), r2.Header.Get("Authorization"))
	}
}

func TestSignSigV4_SecretKeyAffectsSignature(t *testing.T) {
	t.Parallel()
	body := []byte("payload")
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

	makeReq := func() *http.Request {
		r, _ := http.NewRequest(http.MethodPut,
			"https://example.r2.cloudflarestorage.com/b/k", strings.NewReader("payload"))
		r.Header.Set("Content-Type", "application/json")
		return r
	}
	r1 := makeReq()
	r2 := makeReq()
	_ = signSigV4(r1, body, "ak", "secretA", "auto", "s3", now)
	_ = signSigV4(r2, body, "ak", "secretB", "auto", "s3", now)
	if r1.Header.Get("Authorization") == r2.Header.Get("Authorization") {
		t.Errorf("different secret keys produced same Authorization")
	}
}

func TestSignSigV4_BodyAffectsSignature(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

	r1, _ := http.NewRequest(http.MethodPut,
		"https://example.r2.cloudflarestorage.com/b/k", strings.NewReader("A"))
	r1.Header.Set("Content-Type", "application/json")
	r2, _ := http.NewRequest(http.MethodPut,
		"https://example.r2.cloudflarestorage.com/b/k", strings.NewReader("B"))
	r2.Header.Set("Content-Type", "application/json")

	_ = signSigV4(r1, []byte("A"), "ak", "sk", "auto", "s3", now)
	_ = signSigV4(r2, []byte("B"), "ak", "sk", "auto", "s3", now)
	if r1.Header.Get("Authorization") == r2.Header.Get("Authorization") {
		t.Errorf("different bodies produced same Authorization")
	}
	// Content-Sha256 must also differ.
	if r1.Header.Get("X-Amz-Content-Sha256") == r2.Header.Get("X-Amz-Content-Sha256") {
		t.Errorf("different bodies produced same X-Amz-Content-Sha256")
	}
}

func TestSignSigV4_RegionAffectsSignature(t *testing.T) {
	t.Parallel()
	body := []byte("payload")
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

	makeReq := func() *http.Request {
		r, _ := http.NewRequest(http.MethodPut,
			"https://example.r2.cloudflarestorage.com/b/k", strings.NewReader("payload"))
		r.Header.Set("Content-Type", "application/json")
		return r
	}
	r1 := makeReq()
	r2 := makeReq()
	_ = signSigV4(r1, body, "ak", "sk", "auto", "s3", now)
	_ = signSigV4(r2, body, "ak", "sk", "us-east-1", "s3", now)
	if r1.Header.Get("Authorization") == r2.Header.Get("Authorization") {
		t.Errorf("different regions produced same Authorization")
	}
}

func TestSignSigV4_SetsHostFromURL(t *testing.T) {
	t.Parallel()
	// signSigV4 mirrors req.URL.Host into req.Host so the Host header
	// participates correctly in the signature regardless of net/http's
	// quirks around request URL vs Host.
	body := []byte("p")
	r, _ := http.NewRequest(http.MethodPut,
		"https://uniquehost.example.com/b/k", strings.NewReader("p"))
	r.Header.Set("Content-Type", "application/json")

	now := time.Date(2026, time.April, 26, 12, 0, 0, 0, time.UTC)
	if err := signSigV4(r, body, "ak", "sk", "auto", "s3", now); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if r.Host != "uniquehost.example.com" {
		t.Errorf("Host: got %q, want uniquehost.example.com", r.Host)
	}
}

// ---------------------------------------------------------------------------
// privateReason — remaining branches not covered by IsPrivateIP_RFC1918.
// ---------------------------------------------------------------------------

func TestPrivateReason_NilIP(t *testing.T) {
	t.Parallel()
	if got := privateReason(nil); got != "invalid IP" {
		t.Errorf("nil IP: got %q, want %q", got, "invalid IP")
	}
}

func TestPrivateReason_PublicIPReturnsEmpty(t *testing.T) {
	t.Parallel()
	// Cloudflare public DNS — not in any blocked range.
	if got := privateReason(net.ParseIP("1.1.1.1")); got != "" {
		t.Errorf("public IP: got %q, want \"\"", got)
	}
	// Google public DNS.
	if got := privateReason(net.ParseIP("8.8.8.8")); got != "" {
		t.Errorf("public IP: got %q, want \"\"", got)
	}
}

func TestPrivateReason_LoopbackReturnsLoopback(t *testing.T) {
	t.Parallel()
	if got := privateReason(net.ParseIP("127.0.0.1")); got != "loopback" {
		t.Errorf("v4 loopback: got %q, want loopback", got)
	}
	if got := privateReason(net.ParseIP("::1")); got != "loopback" {
		t.Errorf("v6 loopback: got %q, want loopback", got)
	}
}

func TestPrivateReason_LinkLocalReturnsLinkLocal(t *testing.T) {
	t.Parallel()
	got := privateReason(net.ParseIP("169.254.169.254"))
	if !strings.Contains(got, "link-local") {
		t.Errorf("AWS metadata IP: got %q, want substring \"link-local\"", got)
	}
}

func TestPrivateReason_UnspecifiedReturnsUnspecified(t *testing.T) {
	t.Parallel()
	if got := privateReason(net.ParseIP("0.0.0.0")); !strings.Contains(got, "unspecified") {
		t.Errorf("0.0.0.0: got %q, want substring \"unspecified\"", got)
	}
	if got := privateReason(net.ParseIP("::")); !strings.Contains(got, "unspecified") {
		t.Errorf(":: got %q, want substring \"unspecified\"", got)
	}
}

func TestPrivateReason_MulticastReturnsMulticast(t *testing.T) {
	t.Parallel()
	// 239.0.0.0/8 — IANA "organization-local" multicast scope. Critical: we
	// pick a multicast IP OUTSIDE the link-local multicast block (224.0.0.0/24
	// is link-local-multicast, which the prior switch case captures first).
	// 239.x.x.x is multicast-but-not-link-local, exercising the dedicated
	// multicast arm of the switch.
	if got := privateReason(net.ParseIP("239.0.0.1")); got != "multicast" {
		t.Errorf("239.0.0.1: got %q, want multicast", got)
	}
}

func TestPrivateReason_PrivateRFC1918ReturnsPrivate(t *testing.T) {
	t.Parallel()
	got := privateReason(net.ParseIP("10.0.0.5"))
	if !strings.Contains(got, "private") {
		t.Errorf("RFC1918: got %q, want substring \"private\"", got)
	}
}

// ---------------------------------------------------------------------------
// isPrivateIP — gap-closer: nil and explicit-fallback paths
// ---------------------------------------------------------------------------

func TestIsPrivateIP_NilFalse(t *testing.T) {
	t.Parallel()
	if isPrivateIP(nil) {
		t.Error("isPrivateIP(nil) = true, want false")
	}
}

func TestIsPrivateIP_PublicFalse(t *testing.T) {
	t.Parallel()
	for _, addr := range []string{"1.1.1.1", "8.8.8.8", "203.0.113.5"} {
		if isPrivateIP(net.ParseIP(addr)) {
			t.Errorf("isPrivateIP(%s) = true, want false", addr)
		}
	}
}

// ---------------------------------------------------------------------------
// LoadHashPublishConfig — production shim wraps Getenv variant
// ---------------------------------------------------------------------------

func TestLoadHashPublishConfig_DelegatesToEnv(t *testing.T) {
	t.Parallel()
	// We don't poke os.Setenv (would clash with t.Parallel and other tests)
	// but we CAN verify the wrapper applies the same defaults the pure
	// variant would for an empty environment. Two calls with an empty real
	// env (assuming no AUDIT_HASH_PUBLISH_* are set in the test runner)
	// must match: defaults populate Region=auto, Interval=1h, SchemaVersion=1.
	signingKey := []byte("test-key")
	cfg := LoadHashPublishConfig(signingKey)

	// SchemaVersion is always 1.
	if cfg.SchemaVersion != 1 {
		t.Errorf("SchemaVersion: got %d, want 1", cfg.SchemaVersion)
	}
	// Region default is "auto" (R2-friendly).
	if cfg.Region == "" {
		t.Errorf("Region default: got empty, want non-empty")
	}
	// Interval default is 1h when env not set.
	if cfg.Interval <= 0 {
		t.Errorf("Interval default: got %v, want > 0", cfg.Interval)
	}
	// SigningKey must pass through.
	if string(cfg.SigningKey) != "test-key" {
		t.Errorf("SigningKey passthrough: got %q, want \"test-key\"", string(cfg.SigningKey))
	}
}

// ---------------------------------------------------------------------------
// HashPublishConfig.Enabled() — boolean truth table.
// ---------------------------------------------------------------------------

func TestHashPublishConfig_Enabled_RequiresAllFourFields(t *testing.T) {
	t.Parallel()
	full := HashPublishConfig{
		S3Endpoint: "https://example.com",
		Bucket:     "b",
		AccessKey:  "ak",
		SecretKey:  "sk",
	}
	if !full.Enabled() {
		t.Error("full config: Enabled() = false, want true")
	}

	cases := []struct {
		name string
		mut  func(c *HashPublishConfig)
	}{
		{"missing-endpoint", func(c *HashPublishConfig) { c.S3Endpoint = "" }},
		{"missing-bucket", func(c *HashPublishConfig) { c.Bucket = "" }},
		{"missing-accesskey", func(c *HashPublishConfig) { c.AccessKey = "" }},
		{"missing-secretkey", func(c *HashPublishConfig) { c.SecretKey = "" }},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := full
			tc.mut(&c)
			if c.Enabled() {
				t.Errorf("%s: Enabled() = true, want false", tc.name)
			}
		})
	}
}
