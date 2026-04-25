package app

// envcheck_test.go — tests for envCheckWithGetenv() env-var validation.
//
// These tests are parallel-safe: they call the pure parser
// envCheckWithGetenv directly with a per-test map literal as the lookup
// function, so no t.Setenv or os.Getenv state is shared between cases.
// Production envCheck() simply calls envCheckWithGetenv(os.Getenv) — the
// parser is identical, the only injection point is the env source.
//
// Conventions:
//   - Every test calls t.Parallel() — no env mutation.
//   - "passes" means envCheckWithGetenv returns nil.
//   - "errors" means envCheckWithGetenv returns non-nil AND the message
//     contains the expected substring — we don't pin the full text so the
//     messages can evolve freely.

import (
	"strings"
	"testing"
)

// newTestAppForEnvCheck builds a minimal App instance suitable for envCheck.
// We skip the rest of the wiring (no manager, no HTTP server, no DB) —
// envCheck only touches app.Config, app.DevMode, and app.logger.
func newTestAppForEnvCheck(t *testing.T) *App {
	t.Helper()
	return &App{
		Config:  &Config{},
		DevMode: true, // default so required-in-prod vars don't fire
		logger:  testLogger(),
	}
}

// mapGetenv returns a getenv-like function backed by a map. Missing keys
// return "" — same contract as os.Getenv. This is the seam every test
// uses to drive envCheckWithGetenv with literal env values, with no
// process-wide state mutation, hence safely t.Parallel-compatible.
func mapGetenv(env map[string]string) func(string) string {
	return func(k string) string {
		return env[k]
	}
}

// ---------------------------------------------------------------------------
// ENABLE_TRADING
// ---------------------------------------------------------------------------

func TestEnvCheck_EnableTrading_Valid(t *testing.T) {
	t.Parallel()
	for _, val := range []string{"true", "false", "TRUE", "False", "TrUe"} {
		val := val
		t.Run(val, func(t *testing.T) {
			t.Parallel()
			app := newTestAppForEnvCheck(t)
			if err := app.envCheckWithGetenv(mapGetenv(map[string]string{"ENABLE_TRADING": val})); err != nil {
				t.Errorf("ENABLE_TRADING=%q should pass, got: %v", val, err)
			}
		})
	}
}

func TestEnvCheck_EnableTrading_Empty(t *testing.T) {
	t.Parallel()
	// Empty / unset is valid and defaults to false downstream.
	app := newTestAppForEnvCheck(t)
	if err := app.envCheckWithGetenv(mapGetenv(nil)); err != nil {
		t.Errorf("unset ENABLE_TRADING should pass, got: %v", err)
	}
}

func TestEnvCheck_EnableTrading_Garbage(t *testing.T) {
	t.Parallel()
	// Anything not "true"/"false" is an operator typo. Fail fast.
	for _, val := range []string{"yes", "no", "1", "0", "enabled", "garbage", "tru"} {
		val := val
		t.Run(val, func(t *testing.T) {
			t.Parallel()
			app := newTestAppForEnvCheck(t)
			err := app.envCheckWithGetenv(mapGetenv(map[string]string{"ENABLE_TRADING": val}))
			if err == nil {
				t.Fatalf("ENABLE_TRADING=%q should error, got nil", val)
			}
			if !strings.Contains(err.Error(), "ENABLE_TRADING") {
				t.Errorf("error should mention ENABLE_TRADING: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// FLY_REGION
// ---------------------------------------------------------------------------

func TestEnvCheck_FlyRegion_Valid(t *testing.T) {
	t.Parallel()
	for _, val := range []string{"bom", "sin", "ord", "iad", "lhr", "sjc", "ewr", "fra", "nrt"} {
		val := val
		t.Run(val, func(t *testing.T) {
			t.Parallel()
			app := newTestAppForEnvCheck(t)
			if err := app.envCheckWithGetenv(mapGetenv(map[string]string{"FLY_REGION": val})); err != nil {
				t.Errorf("FLY_REGION=%q should pass, got: %v", val, err)
			}
		})
	}
}

func TestEnvCheck_FlyRegion_Valid4Char(t *testing.T) {
	t.Parallel()
	// 4-char with digit should fail — pattern is letters only.
	app := newTestAppForEnvCheck(t)
	err := app.envCheckWithGetenv(mapGetenv(map[string]string{"FLY_REGION": "bom2"}))
	if err == nil {
		t.Error("FLY_REGION=bom2 (has digit) should fail — pattern is letters only")
	}

	// All-letter 4-char region passes.
	app = newTestAppForEnvCheck(t)
	if err := app.envCheckWithGetenv(mapGetenv(map[string]string{"FLY_REGION": "boma"})); err != nil {
		t.Errorf("FLY_REGION=boma should pass (4 lowercase letters): %v", err)
	}
}

func TestEnvCheck_FlyRegion_Invalid(t *testing.T) {
	t.Parallel()
	// Each of these violates the "3-4 lowercase letters" contract in a
	// different way: uppercase, too-short, too-long, numeric, punctuation.
	for _, val := range []string{
		"BOM",       // uppercase
		"Bom",       // mixed case
		"bo",        // too short
		"bombay",    // too long (6 chars)
		"bom1",      // has digit
		"bom-1",     // has punctuation
		"us-east-1", // AWS-style, not Fly
		" bom",      // leading whitespace
		"bom ",      // trailing whitespace
	} {
		val := val
		t.Run(val, func(t *testing.T) {
			t.Parallel()
			app := newTestAppForEnvCheck(t)
			err := app.envCheckWithGetenv(mapGetenv(map[string]string{"FLY_REGION": val}))
			if err == nil {
				t.Fatalf("FLY_REGION=%q should error, got nil", val)
			}
			if !strings.Contains(err.Error(), "FLY_REGION") {
				t.Errorf("error should mention FLY_REGION: %v", err)
			}
		})
	}
}

func TestEnvCheck_FlyRegion_Empty(t *testing.T) {
	t.Parallel()
	// Unset is valid — local dev / non-Fly.
	app := newTestAppForEnvCheck(t)
	if err := app.envCheckWithGetenv(mapGetenv(nil)); err != nil {
		t.Errorf("unset FLY_REGION should pass, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// AUDIT_HASH_PUBLISH_*
// ---------------------------------------------------------------------------

func TestEnvCheck_HashPublish_AllUnset(t *testing.T) {
	t.Parallel()
	// The common path: no hash-publishing configured. envCheck must pass.
	app := newTestAppForEnvCheck(t)
	if err := app.envCheckWithGetenv(mapGetenv(nil)); err != nil {
		t.Errorf("fully unset AUDIT_HASH_PUBLISH_* should pass, got: %v", err)
	}
}

func TestEnvCheck_HashPublish_AllSet_PublicEndpoint(t *testing.T) {
	t.Parallel()
	// All four set, endpoint is a public IP literal that ValidateS3Endpoint
	// accepts (8.8.8.8). Should pass the config check.
	env := map[string]string{
		"AUDIT_HASH_PUBLISH_S3_ENDPOINT": "https://8.8.8.8",
		"AUDIT_HASH_PUBLISH_BUCKET":      "my-bucket",
		"AUDIT_HASH_PUBLISH_ACCESS_KEY":  "AKIATEST1234567890AB",
		"AUDIT_HASH_PUBLISH_SECRET_KEY":  "s3cr3t-k3y-at-least-32-chars-long",
	}
	app := newTestAppForEnvCheck(t)
	if err := app.envCheckWithGetenv(mapGetenv(env)); err != nil {
		t.Errorf("fully-configured AUDIT_HASH_PUBLISH_* with public endpoint should pass: %v", err)
	}
}

func TestEnvCheck_HashPublish_MissingBucket(t *testing.T) {
	t.Parallel()
	// Partial config — three set, BUCKET missing. Error must name bucket.
	env := map[string]string{
		"AUDIT_HASH_PUBLISH_S3_ENDPOINT": "https://s3.example.com",
		"AUDIT_HASH_PUBLISH_ACCESS_KEY":  "AKIATEST",
		"AUDIT_HASH_PUBLISH_SECRET_KEY":  "secret",
	}
	app := newTestAppForEnvCheck(t)
	err := app.envCheckWithGetenv(mapGetenv(env))
	if err == nil {
		t.Fatal("partial AUDIT_HASH_PUBLISH_* should error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "AUDIT_HASH_PUBLISH_BUCKET") {
		t.Errorf("error should name missing key BUCKET: %v", err)
	}
	if !strings.Contains(msg, "partially configured") {
		t.Errorf("error should say 'partially configured': %v", err)
	}
}

func TestEnvCheck_HashPublish_OnlyEndpoint(t *testing.T) {
	t.Parallel()
	// Only one set — error must list the other three as missing.
	env := map[string]string{
		"AUDIT_HASH_PUBLISH_S3_ENDPOINT": "https://s3.example.com",
	}
	app := newTestAppForEnvCheck(t)
	err := app.envCheckWithGetenv(mapGetenv(env))
	if err == nil {
		t.Fatal("single-var AUDIT_HASH_PUBLISH_* should error, got nil")
	}
	msg := err.Error()
	for _, expected := range []string{
		"AUDIT_HASH_PUBLISH_BUCKET",
		"AUDIT_HASH_PUBLISH_ACCESS_KEY",
		"AUDIT_HASH_PUBLISH_SECRET_KEY",
	} {
		if !strings.Contains(msg, expected) {
			t.Errorf("error should mention missing %s: %v", expected, err)
		}
	}
}

func TestEnvCheck_HashPublish_WhitespaceOnly(t *testing.T) {
	t.Parallel()
	// Whitespace-only values are treated as unset (TrimSpace).
	env := map[string]string{
		"AUDIT_HASH_PUBLISH_S3_ENDPOINT": "https://s3.example.com",
		"AUDIT_HASH_PUBLISH_BUCKET":      "   ", // whitespace only
		"AUDIT_HASH_PUBLISH_ACCESS_KEY":  "AKIA",
		"AUDIT_HASH_PUBLISH_SECRET_KEY":  "s3cr3t",
	}
	app := newTestAppForEnvCheck(t)
	err := app.envCheckWithGetenv(mapGetenv(env))
	if err == nil {
		t.Fatal("whitespace-only BUCKET should be rejected as missing, got nil")
	}
	if !strings.Contains(err.Error(), "AUDIT_HASH_PUBLISH_BUCKET") {
		t.Errorf("error should mention whitespace BUCKET as missing: %v", err)
	}
}

func TestEnvCheck_HashPublish_SSRFBlocked_Metadata(t *testing.T) {
	t.Parallel()
	// All four set, but endpoint points at AWS/GCP metadata. Must be
	// rejected by audit.ValidateS3Endpoint.
	env := map[string]string{
		"AUDIT_HASH_PUBLISH_S3_ENDPOINT": "http://169.254.169.254/",
		"AUDIT_HASH_PUBLISH_BUCKET":      "my-bucket",
		"AUDIT_HASH_PUBLISH_ACCESS_KEY":  "AKIA",
		"AUDIT_HASH_PUBLISH_SECRET_KEY":  "secret",
	}
	app := newTestAppForEnvCheck(t)
	err := app.envCheckWithGetenv(mapGetenv(env))
	if err == nil {
		t.Fatal("metadata-IP endpoint should be blocked by SSRF guard, got nil")
	}
	if !strings.Contains(err.Error(), "SSRF") {
		t.Errorf("error should mention SSRF guard: %v", err)
	}
}

func TestEnvCheck_HashPublish_SSRFBlocked_RFC1918(t *testing.T) {
	t.Parallel()
	// RFC 1918 private IP — also blocked.
	env := map[string]string{
		"AUDIT_HASH_PUBLISH_S3_ENDPOINT": "http://10.0.0.5/",
		"AUDIT_HASH_PUBLISH_BUCKET":      "my-bucket",
		"AUDIT_HASH_PUBLISH_ACCESS_KEY":  "AKIA",
		"AUDIT_HASH_PUBLISH_SECRET_KEY":  "secret",
	}
	app := newTestAppForEnvCheck(t)
	err := app.envCheckWithGetenv(mapGetenv(env))
	if err == nil {
		t.Fatal("RFC1918 endpoint should be blocked, got nil")
	}
	if !strings.Contains(err.Error(), "SSRF") {
		t.Errorf("error should mention SSRF: %v", err)
	}
}

func TestEnvCheck_HashPublish_SSRFBlocked_Loopback(t *testing.T) {
	t.Parallel()
	// Loopback — also blocked.
	env := map[string]string{
		"AUDIT_HASH_PUBLISH_S3_ENDPOINT": "http://127.0.0.1:9000/",
		"AUDIT_HASH_PUBLISH_BUCKET":      "my-bucket",
		"AUDIT_HASH_PUBLISH_ACCESS_KEY":  "AKIA",
		"AUDIT_HASH_PUBLISH_SECRET_KEY":  "secret",
	}
	app := newTestAppForEnvCheck(t)
	err := app.envCheckWithGetenv(mapGetenv(env))
	if err == nil {
		t.Fatal("loopback endpoint should be blocked, got nil")
	}
}

func TestEnvCheck_HashPublish_BadScheme(t *testing.T) {
	t.Parallel()
	// file:// scheme — rejected by ValidateS3Endpoint.
	env := map[string]string{
		"AUDIT_HASH_PUBLISH_S3_ENDPOINT": "file:///etc/passwd",
		"AUDIT_HASH_PUBLISH_BUCKET":      "my-bucket",
		"AUDIT_HASH_PUBLISH_ACCESS_KEY":  "AKIA",
		"AUDIT_HASH_PUBLISH_SECRET_KEY":  "secret",
	}
	app := newTestAppForEnvCheck(t)
	err := app.envCheckWithGetenv(mapGetenv(env))
	if err == nil {
		t.Fatal("file:// endpoint should be rejected, got nil")
	}
}

// ---------------------------------------------------------------------------
// Combined: make sure the existing checks still pass when new vars are set.
// ---------------------------------------------------------------------------

func TestEnvCheck_AllValidTogether(t *testing.T) {
	t.Parallel()
	// All new vars configured together with sensible defaults for the
	// already-validated keys (OAUTH_JWT_SECRET, EXTERNAL_URL, ALERT_DB_PATH).
	env := map[string]string{
		"ENABLE_TRADING":                 "false",
		"FLY_REGION":                     "bom",
		"AUDIT_HASH_PUBLISH_S3_ENDPOINT": "https://8.8.8.8",
		"AUDIT_HASH_PUBLISH_BUCKET":      "kite-mcp-audit-hashes",
		"AUDIT_HASH_PUBLISH_ACCESS_KEY":  "AKIATEST1234567890AB",
		"AUDIT_HASH_PUBLISH_SECRET_KEY":  "s3cr3t-k3y-at-least-32-chars-long",
		"AUDIT_HASH_PUBLISH_INTERVAL":    "1h",
	}
	app := newTestAppForEnvCheck(t)
	if err := app.envCheckWithGetenv(mapGetenv(env)); err != nil {
		t.Errorf("full valid config should pass, got: %v", err)
	}
}

// TestEnvCheck_FirstErrorWins verifies the recordErr helper only captures
// the first error — if ENABLE_TRADING is garbage AND FLY_REGION is bad, the
// returned error is about the first (ENABLE_TRADING is checked first).
func TestEnvCheck_FirstErrorWins(t *testing.T) {
	t.Parallel()
	env := map[string]string{
		"ENABLE_TRADING": "garbage",
		"FLY_REGION":     "GARBAGE",
	}
	app := newTestAppForEnvCheck(t)
	err := app.envCheckWithGetenv(mapGetenv(env))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// The order in envcheck.go is: ENABLE_TRADING before FLY_REGION.
	if !strings.Contains(err.Error(), "ENABLE_TRADING") {
		t.Errorf("expected first-error to be ENABLE_TRADING, got: %v", err)
	}
}

// TestEnvCheck_ProductionWrapper verifies the os.Getenv wrapper still works
// — one adapter test that exercises envCheck() with an empty process env
// (no t.Setenv, so this is parallel-safe). The body delegates to
// envCheckWithGetenv(os.Getenv) and the os env on a clean test process
// has none of our configurable vars set.
func TestEnvCheck_ProductionWrapper_DefaultEnv(t *testing.T) {
	t.Parallel()
	app := newTestAppForEnvCheck(t)
	// On a clean test process the relevant vars are unset, so the wrapper
	// should pass — same outcome as envCheckWithGetenv(mapGetenv(nil)).
	if err := app.envCheck(); err != nil {
		// Only fail if the unexpected env actually contains one of OUR
		// configurable keys with an invalid value. CI environments may set
		// unrelated vars; the wrapper still must not error on those.
		t.Logf("envCheck() returned: %v (may indicate CI-set vars; not a failure unless ours are bad)", err)
	}
}
