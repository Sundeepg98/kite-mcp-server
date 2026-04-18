package app

// envcheck_test.go — tests for envCheck() env-var validation.
//
// These tests don't touch the filesystem or network. They stub the app's
// Config + logger, set env vars via t.Setenv (which auto-cleans on test
// exit), and verify envCheck returns the expected error (or nil).
//
// Conventions:
//   - Every test t.Parallel()-free because t.Setenv is incompatible with
//     parallel tests (stdlib enforces this).
//   - "passes" means envCheck returns nil.
//   - "errors" means envCheck returns non-nil AND the message contains the
//     expected substring — we don't pin the full text so the messages can
//     evolve freely.

import (
	"os"
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

// clearHashPublishEnv wipes all AUDIT_HASH_PUBLISH_* vars for a clean
// per-test baseline. The test harness does not guarantee a pristine env
// between cases when os.Getenv is used — t.Setenv only adds, it doesn't
// subtract unless paired with a prior set.
func clearHashPublishEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"AUDIT_HASH_PUBLISH_S3_ENDPOINT",
		"AUDIT_HASH_PUBLISH_BUCKET",
		"AUDIT_HASH_PUBLISH_ACCESS_KEY",
		"AUDIT_HASH_PUBLISH_SECRET_KEY",
		"AUDIT_HASH_PUBLISH_INTERVAL",
		"ENABLE_TRADING",
		"FLY_REGION",
		"LOG_LEVEL",
	} {
		t.Setenv(k, "")
		// t.Setenv restores the original value after test; setting to ""
		// is sufficient for os.Getenv-based checks since our envcheck
		// treats "" as "not set".
		_ = os.Unsetenv(k)
	}
}

// ---------------------------------------------------------------------------
// ENABLE_TRADING
// ---------------------------------------------------------------------------

func TestEnvCheck_EnableTrading_Valid(t *testing.T) {
	clearHashPublishEnv(t)
	for _, val := range []string{"true", "false", "TRUE", "False", "TrUe"} {
		t.Run(val, func(t *testing.T) {
			clearHashPublishEnv(t)
			t.Setenv("ENABLE_TRADING", val)
			app := newTestAppForEnvCheck(t)
			if err := app.envCheck(); err != nil {
				t.Errorf("ENABLE_TRADING=%q should pass, got: %v", val, err)
			}
		})
	}
}

func TestEnvCheck_EnableTrading_Empty(t *testing.T) {
	clearHashPublishEnv(t)
	// Empty / unset is valid and defaults to false downstream.
	app := newTestAppForEnvCheck(t)
	if err := app.envCheck(); err != nil {
		t.Errorf("unset ENABLE_TRADING should pass, got: %v", err)
	}
}

func TestEnvCheck_EnableTrading_Garbage(t *testing.T) {
	// Anything not "true"/"false" is an operator typo. Fail fast.
	for _, val := range []string{"yes", "no", "1", "0", "enabled", "garbage", "tru"} {
		t.Run(val, func(t *testing.T) {
			clearHashPublishEnv(t)
			t.Setenv("ENABLE_TRADING", val)
			app := newTestAppForEnvCheck(t)
			err := app.envCheck()
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
	for _, val := range []string{"bom", "sin", "ord", "iad", "lhr", "sjc", "ewr", "fra", "nrt"} {
		t.Run(val, func(t *testing.T) {
			clearHashPublishEnv(t)
			t.Setenv("FLY_REGION", val)
			app := newTestAppForEnvCheck(t)
			if err := app.envCheck(); err != nil {
				t.Errorf("FLY_REGION=%q should pass, got: %v", val, err)
			}
		})
	}
}

func TestEnvCheck_FlyRegion_Valid4Char(t *testing.T) {
	// 4-char regions exist (e.g., future multi-AZ codes) — accepted.
	clearHashPublishEnv(t)
	t.Setenv("FLY_REGION", "bom2")
	// Whoops — 4 chars includes digits. The pattern is ^[a-z]{3,4}$, so
	// digits should FAIL. Use an all-letter 4-char region instead.
	app := newTestAppForEnvCheck(t)
	err := app.envCheck()
	if err == nil {
		t.Error("FLY_REGION=bom2 (has digit) should fail — pattern is letters only")
	}

	// All-letter 4-char region passes.
	clearHashPublishEnv(t)
	t.Setenv("FLY_REGION", "boma")
	app = newTestAppForEnvCheck(t)
	if err := app.envCheck(); err != nil {
		t.Errorf("FLY_REGION=boma should pass (4 lowercase letters): %v", err)
	}
}

func TestEnvCheck_FlyRegion_Invalid(t *testing.T) {
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
		t.Run(val, func(t *testing.T) {
			clearHashPublishEnv(t)
			t.Setenv("FLY_REGION", val)
			app := newTestAppForEnvCheck(t)
			err := app.envCheck()
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
	// Unset is valid — local dev / non-Fly.
	clearHashPublishEnv(t)
	app := newTestAppForEnvCheck(t)
	if err := app.envCheck(); err != nil {
		t.Errorf("unset FLY_REGION should pass, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// AUDIT_HASH_PUBLISH_*
// ---------------------------------------------------------------------------

func TestEnvCheck_HashPublish_AllUnset(t *testing.T) {
	// The common path: no hash-publishing configured. envCheck must pass.
	clearHashPublishEnv(t)
	app := newTestAppForEnvCheck(t)
	if err := app.envCheck(); err != nil {
		t.Errorf("fully unset AUDIT_HASH_PUBLISH_* should pass, got: %v", err)
	}
}

func TestEnvCheck_HashPublish_AllSet_PublicEndpoint(t *testing.T) {
	// All four set, endpoint is a public IP literal that ValidateS3Endpoint
	// accepts (8.8.8.8). Should pass the config check.
	clearHashPublishEnv(t)
	t.Setenv("AUDIT_HASH_PUBLISH_S3_ENDPOINT", "https://8.8.8.8")
	t.Setenv("AUDIT_HASH_PUBLISH_BUCKET", "my-bucket")
	t.Setenv("AUDIT_HASH_PUBLISH_ACCESS_KEY", "AKIATEST1234567890AB")
	t.Setenv("AUDIT_HASH_PUBLISH_SECRET_KEY", "s3cr3t-k3y-at-least-32-chars-long")
	app := newTestAppForEnvCheck(t)
	if err := app.envCheck(); err != nil {
		t.Errorf("fully-configured AUDIT_HASH_PUBLISH_* with public endpoint should pass: %v", err)
	}
}

func TestEnvCheck_HashPublish_MissingBucket(t *testing.T) {
	// Partial config — three set, BUCKET missing. Error must name bucket.
	clearHashPublishEnv(t)
	t.Setenv("AUDIT_HASH_PUBLISH_S3_ENDPOINT", "https://s3.example.com")
	t.Setenv("AUDIT_HASH_PUBLISH_ACCESS_KEY", "AKIATEST")
	t.Setenv("AUDIT_HASH_PUBLISH_SECRET_KEY", "secret")
	app := newTestAppForEnvCheck(t)
	err := app.envCheck()
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
	// Only one set — error must list the other three as missing.
	clearHashPublishEnv(t)
	t.Setenv("AUDIT_HASH_PUBLISH_S3_ENDPOINT", "https://s3.example.com")
	app := newTestAppForEnvCheck(t)
	err := app.envCheck()
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
	// Whitespace-only values are treated as unset (TrimSpace).
	clearHashPublishEnv(t)
	t.Setenv("AUDIT_HASH_PUBLISH_S3_ENDPOINT", "https://s3.example.com")
	t.Setenv("AUDIT_HASH_PUBLISH_BUCKET", "   ") // whitespace only
	t.Setenv("AUDIT_HASH_PUBLISH_ACCESS_KEY", "AKIA")
	t.Setenv("AUDIT_HASH_PUBLISH_SECRET_KEY", "s3cr3t")
	app := newTestAppForEnvCheck(t)
	err := app.envCheck()
	if err == nil {
		t.Fatal("whitespace-only BUCKET should be rejected as missing, got nil")
	}
	if !strings.Contains(err.Error(), "AUDIT_HASH_PUBLISH_BUCKET") {
		t.Errorf("error should mention whitespace BUCKET as missing: %v", err)
	}
}

func TestEnvCheck_HashPublish_SSRFBlocked_Metadata(t *testing.T) {
	// All four set, but endpoint points at AWS/GCP metadata. Must be
	// rejected by audit.ValidateS3Endpoint.
	clearHashPublishEnv(t)
	t.Setenv("AUDIT_HASH_PUBLISH_S3_ENDPOINT", "http://169.254.169.254/")
	t.Setenv("AUDIT_HASH_PUBLISH_BUCKET", "my-bucket")
	t.Setenv("AUDIT_HASH_PUBLISH_ACCESS_KEY", "AKIA")
	t.Setenv("AUDIT_HASH_PUBLISH_SECRET_KEY", "secret")
	app := newTestAppForEnvCheck(t)
	err := app.envCheck()
	if err == nil {
		t.Fatal("metadata-IP endpoint should be blocked by SSRF guard, got nil")
	}
	if !strings.Contains(err.Error(), "SSRF") {
		t.Errorf("error should mention SSRF guard: %v", err)
	}
}

func TestEnvCheck_HashPublish_SSRFBlocked_RFC1918(t *testing.T) {
	// RFC 1918 private IP — also blocked.
	clearHashPublishEnv(t)
	t.Setenv("AUDIT_HASH_PUBLISH_S3_ENDPOINT", "http://10.0.0.5/")
	t.Setenv("AUDIT_HASH_PUBLISH_BUCKET", "my-bucket")
	t.Setenv("AUDIT_HASH_PUBLISH_ACCESS_KEY", "AKIA")
	t.Setenv("AUDIT_HASH_PUBLISH_SECRET_KEY", "secret")
	app := newTestAppForEnvCheck(t)
	err := app.envCheck()
	if err == nil {
		t.Fatal("RFC1918 endpoint should be blocked, got nil")
	}
	if !strings.Contains(err.Error(), "SSRF") {
		t.Errorf("error should mention SSRF: %v", err)
	}
}

func TestEnvCheck_HashPublish_SSRFBlocked_Loopback(t *testing.T) {
	// Loopback — also blocked.
	clearHashPublishEnv(t)
	t.Setenv("AUDIT_HASH_PUBLISH_S3_ENDPOINT", "http://127.0.0.1:9000/")
	t.Setenv("AUDIT_HASH_PUBLISH_BUCKET", "my-bucket")
	t.Setenv("AUDIT_HASH_PUBLISH_ACCESS_KEY", "AKIA")
	t.Setenv("AUDIT_HASH_PUBLISH_SECRET_KEY", "secret")
	app := newTestAppForEnvCheck(t)
	err := app.envCheck()
	if err == nil {
		t.Fatal("loopback endpoint should be blocked, got nil")
	}
}

func TestEnvCheck_HashPublish_BadScheme(t *testing.T) {
	// file:// scheme — rejected by ValidateS3Endpoint.
	clearHashPublishEnv(t)
	t.Setenv("AUDIT_HASH_PUBLISH_S3_ENDPOINT", "file:///etc/passwd")
	t.Setenv("AUDIT_HASH_PUBLISH_BUCKET", "my-bucket")
	t.Setenv("AUDIT_HASH_PUBLISH_ACCESS_KEY", "AKIA")
	t.Setenv("AUDIT_HASH_PUBLISH_SECRET_KEY", "secret")
	app := newTestAppForEnvCheck(t)
	err := app.envCheck()
	if err == nil {
		t.Fatal("file:// endpoint should be rejected, got nil")
	}
}

// ---------------------------------------------------------------------------
// Combined: make sure the existing checks still pass when new vars are set.
// ---------------------------------------------------------------------------

func TestEnvCheck_AllValidTogether(t *testing.T) {
	// All new vars configured together with sensible defaults for the
	// already-validated keys (OAUTH_JWT_SECRET, EXTERNAL_URL, ALERT_DB_PATH).
	clearHashPublishEnv(t)
	t.Setenv("ENABLE_TRADING", "false")
	t.Setenv("FLY_REGION", "bom")
	t.Setenv("AUDIT_HASH_PUBLISH_S3_ENDPOINT", "https://8.8.8.8")
	t.Setenv("AUDIT_HASH_PUBLISH_BUCKET", "kite-mcp-audit-hashes")
	t.Setenv("AUDIT_HASH_PUBLISH_ACCESS_KEY", "AKIATEST1234567890AB")
	t.Setenv("AUDIT_HASH_PUBLISH_SECRET_KEY", "s3cr3t-k3y-at-least-32-chars-long")
	t.Setenv("AUDIT_HASH_PUBLISH_INTERVAL", "1h")

	app := newTestAppForEnvCheck(t)
	if err := app.envCheck(); err != nil {
		t.Errorf("full valid config should pass, got: %v", err)
	}
}

// TestEnvCheck_FirstErrorWins verifies the recordErr helper only captures
// the first error — if ENABLE_TRADING is garbage AND FLY_REGION is bad, the
// returned error is about the first (ENABLE_TRADING is checked first).
func TestEnvCheck_FirstErrorWins(t *testing.T) {
	clearHashPublishEnv(t)
	t.Setenv("ENABLE_TRADING", "garbage")
	t.Setenv("FLY_REGION", "GARBAGE")
	app := newTestAppForEnvCheck(t)
	err := app.envCheck()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// The order in envcheck.go is: ENABLE_TRADING before FLY_REGION.
	if !strings.Contains(err.Error(), "ENABLE_TRADING") {
		t.Errorf("expected first-error to be ENABLE_TRADING, got: %v", err)
	}
}
