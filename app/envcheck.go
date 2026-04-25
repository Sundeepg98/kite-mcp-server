package app

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/audit"
)

// flyRegionPattern matches Fly.io region codes: 3-4 lowercase letters.
// Fly.io uses codes like "bom" (Mumbai), "sin" (Singapore), "ord" (Chicago),
// "iad" (Ashburn). Older codes are 3 chars; newer multi-AZ codes are 4.
// Uppercase or mixed-case is invalid and would fail silently in Fly's
// platform — catch it here so operators see the mistake at startup.
var flyRegionPattern = regexp.MustCompile(`^[a-z]{3,4}$`)

// envCheck runs targeted validation of environment variables at startup.
//
// Production wrapper around envCheckWithGetenv: the latter is the pure
// parser tests use directly with map literals (no t.Setenv, parallel-safe).
//
// It only validates vars where a wrong value causes subtle breakage
// (silent downgrade, runtime panic, OAuth callback mismatch, etc.). For
// most opt-in flags we rely on the feature itself to fail loudly when
// misconfigured — no need to duplicate that here.
//
// Logging contract:
//   - INFO: var is set, value looks valid (secrets are masked)
//   - WARN: var is unset but has a safe default we fall back to
//   - ERROR: var is required or malformed — returned as an error so the
//     caller can choose whether to abort startup
//
// Full inventory of every env var consumed by the server lives in
// docs/env-vars.md. This function is intentionally a subset.
func (app *App) envCheck() error {
	return app.envCheckWithGetenv(os.Getenv)
}

// envCheckWithGetenv is the pure parser. Caller injects the env-lookup
// function so tests can drive every branch with map literals — no env,
// no t.Setenv, parallel-safe. Production calls with os.Getenv.
//
// Note: app.Config fields (KiteAPIKey, ExternalURL, AlertDBPath, AppMode,
// OAuthJWTSecret) are read from the App struct, not the getenv callback —
// those fields are populated upstream by ConfigFromMap. Only the env vars
// NOT plumbed through Config (LOG_LEVEL, ENABLE_TRADING, FLY_REGION,
// AUDIT_HASH_PUBLISH_*) flow through getenv.
func (app *App) envCheckWithGetenv(getenv func(string) string) error {
	logger := app.logger
	var firstErr error
	recordErr := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}

	// --- OAUTH_JWT_SECRET ---
	//
	// Doubles as: JWT HMAC key, AES-GCM-via-HKDF root secret, audit-chain
	// HMAC, and fallback HMAC for external hash publishing. A short or
	// guessable value compromises every one of those at once. 32 bytes
	// gives HMAC-SHA256 its full security margin.
	//
	// In single-user/dev mode OAuth is off; a missing value is fine.
	if jwt := app.Config.OAuthJWTSecret; jwt != "" {
		switch {
		case len(jwt) < 32:
			recordErr(fmt.Errorf("OAUTH_JWT_SECRET is %d bytes; need at least 32 for HMAC-SHA256 security", len(jwt)))
			logger.Error("env var OAUTH_JWT_SECRET too short", "length", len(jwt), "min", 32)
		case strings.Contains(strings.ToLower(jwt), "your-secret") ||
			strings.Contains(strings.ToLower(jwt), "changeme") ||
			strings.Contains(strings.ToLower(jwt), "placeholder"):
			recordErr(fmt.Errorf("OAUTH_JWT_SECRET looks like a placeholder value — replace with a high-entropy secret"))
			logger.Error("env var OAUTH_JWT_SECRET looks like placeholder")
		default:
			logger.Info("env var OAUTH_JWT_SECRET set", "value", maskSecret(jwt))
		}
	} else if !app.DevMode {
		// Only a soft note — app.LoadConfig() is the authoritative gate.
		logger.Warn("env var OAUTH_JWT_SECRET not set; multi-user OAuth disabled")
	}

	// --- EXTERNAL_URL ---
	//
	// Baked into every OAuth redirect URL. A trailing slash produces
	// `https://example.com//auth/callback` (double slash) which some
	// clients reject. Wrong scheme (e.g. a bare `example.com`) makes the
	// browser open the raw string as a relative URL.
	if ext := app.Config.ExternalURL; ext != "" {
		u, err := url.Parse(ext)
		switch {
		case err != nil:
			recordErr(fmt.Errorf("EXTERNAL_URL is not a valid URL: %w", err))
			logger.Error("env var EXTERNAL_URL unparseable", "value", ext, "error", err)
		case u.Scheme != "http" && u.Scheme != "https":
			recordErr(fmt.Errorf("EXTERNAL_URL must use http:// or https:// scheme, got %q", u.Scheme))
			logger.Error("env var EXTERNAL_URL bad scheme", "value", ext, "scheme", u.Scheme)
		case u.Host == "":
			recordErr(fmt.Errorf("EXTERNAL_URL has no host: %q", ext))
			logger.Error("env var EXTERNAL_URL no host", "value", ext)
		case strings.HasSuffix(ext, "/"):
			// Trailing slash is a footgun — warn but don't fail.
			logger.Warn("env var EXTERNAL_URL has a trailing slash; OAuth callbacks will contain double slashes", "value", ext)
		default:
			logger.Info("env var EXTERNAL_URL set", "value", ext)
		}
	}

	// --- ALERT_DB_PATH ---
	//
	// If the parent directory doesn't exist, SQLite silently errors at
	// open time and audit/riskguard wiring fails downstream with a less
	// obvious error. Checking here produces a clearer message.
	if dbPath := app.Config.AlertDBPath; dbPath != "" {
		dir := filepath.Dir(dbPath)
		if dir == "." || dir == "" {
			logger.Info("env var ALERT_DB_PATH set", "value", dbPath, "dir", "(cwd)")
		} else if info, err := os.Stat(dir); err != nil {
			recordErr(fmt.Errorf("ALERT_DB_PATH parent directory %q does not exist: %w", dir, err))
			logger.Error("env var ALERT_DB_PATH parent missing", "path", dbPath, "dir", dir, "error", err)
		} else if !info.IsDir() {
			recordErr(fmt.Errorf("ALERT_DB_PATH parent %q is not a directory", dir))
			logger.Error("env var ALERT_DB_PATH parent not a dir", "path", dbPath, "dir", dir)
		} else {
			logger.Info("env var ALERT_DB_PATH set", "value", dbPath)
		}
	} else if !app.DevMode {
		logger.Warn("env var ALERT_DB_PATH not set; audit, riskguard, and user store will fail to initialize in production")
	}

	// --- LOG_LEVEL ---
	//
	// main.go silently falls back to INFO when unrecognized — which
	// hides debug-mode typos like `LOG_LEVEL=debugg` until an operator
	// notices the missing logs. Call it out here.
	if lvl := getenv("LOG_LEVEL"); lvl != "" {
		switch strings.ToLower(lvl) {
		case "debug", "info", "warn", "error":
			logger.Info("env var LOG_LEVEL set", "value", lvl)
		default:
			logger.Warn("env var LOG_LEVEL unrecognized; falling back to info", "value", lvl, "valid", "debug|info|warn|error")
		}
	}

	// --- APP_MODE ---
	//
	// Unknown mode means the server starts but never registers any
	// transport — requests hang with no error. Validate up front.
	if mode := app.Config.AppMode; mode != "" {
		switch mode {
		case ModeHTTP, ModeSSE, ModeStdIO, ModeHybrid:
			logger.Info("env var APP_MODE set", "value", mode)
		default:
			recordErr(fmt.Errorf("APP_MODE %q unknown; valid: %s, %s, %s, %s", mode, ModeHTTP, ModeSSE, ModeStdIO, ModeHybrid))
			logger.Error("env var APP_MODE unknown", "value", mode)
		}
	}

	// --- ENABLE_TRADING ---
	//
	// Gates every order-placement tool (place_order, modify_order,
	// GTT, MF, trailing stops, native alerts). Default is FALSE so a
	// hosted multi-user deployment that forgets to configure this
	// cannot silently accept orders — and thus does not fall under the
	// NSE/INVG/69255 Annexure I Para 2.8 "Algo Provider" classification.
	// We accept only the strings "true" or "false" (case-insensitive).
	// Anything else is an error: a typo like ENABLE_TRADING=yes means
	// Config.EnableTrading silently becomes false — the operator thinks
	// they enabled trading, but order tools are gated. Fail fast rather
	// than ship a misconfigured deployment.
	if raw := getenv("ENABLE_TRADING"); raw != "" {
		switch strings.ToLower(raw) {
		case "true":
			logger.Warn("env var ENABLE_TRADING=true — order-placement tools ENABLED (intended for local single-user only)")
		case "false":
			logger.Info("env var ENABLE_TRADING=false — order-placement tools gated (hosted safe mode)")
		default:
			recordErr(fmt.Errorf("ENABLE_TRADING %q is invalid; must be \"true\" or \"false\" (case-insensitive)", raw))
			logger.Error("env var ENABLE_TRADING invalid value", "value", raw, "valid", "true|false")
		}
	} else {
		logger.Info("env var ENABLE_TRADING not set — defaulting to false (order-placement gated)")
	}

	// --- FLY_REGION ---
	//
	// Set by Fly.io at runtime (e.g. "bom" for Mumbai). Exposed via
	// server_version tool and used as a correlation field in logs. If
	// an operator sets it manually on non-Fly infra and gets the format
	// wrong (uppercase, underscores, digits), downstream dashboards that
	// group by region will silently split our metrics into two buckets.
	// Validate format so the mistake is visible. Empty is fine — local
	// dev / non-Fly deployments don't set it.
	if raw := getenv("FLY_REGION"); raw != "" {
		if !flyRegionPattern.MatchString(raw) {
			recordErr(fmt.Errorf("FLY_REGION %q is invalid; expected 3-4 lowercase letters (e.g. \"bom\", \"sin\", \"ord\")", raw))
			logger.Error("env var FLY_REGION invalid format", "value", raw, "pattern", "^[a-z]{3,4}$")
		} else {
			logger.Info("env var FLY_REGION set", "value", raw)
		}
	}

	// --- AUDIT_HASH_PUBLISH_* inventory ---
	//
	// The hash-chain publisher (kc/audit/hashpublish.go) speaks raw S3
	// SigV4 to an external bucket (R2). Misconfiguring ANY of these
	// quietly disables the publisher — you lose the external tamper-
	// evidence anchor that SEBI CSCRF audit requires. Worse, a half-
	// configured set (endpoint + bucket but no access key) used to log
	// "disabled (no storage configured)" with no hint at what's missing.
	//
	// Rules:
	//   - All four core vars (ENDPOINT, BUCKET, ACCESS_KEY, SECRET_KEY)
	//     must be set OR all four unset. Partial configuration errors.
	//   - ENDPOINT must survive the SSRF guard (delegated to
	//     audit.ValidateS3Endpoint — the same check StartHashPublisher
	//     runs, so we fail at envcheck instead of later at startup).
	//   - BUCKET must be a non-empty string (empty value != unset).
	//   - ACCESS_KEY / SECRET_KEY must be non-empty.
	//
	// Interval is validated below (separate block, already present).
	hashEndpoint := getenv("AUDIT_HASH_PUBLISH_S3_ENDPOINT")
	hashBucket := getenv("AUDIT_HASH_PUBLISH_BUCKET")
	hashAccessKey := getenv("AUDIT_HASH_PUBLISH_ACCESS_KEY")
	hashSecretKey := getenv("AUDIT_HASH_PUBLISH_SECRET_KEY")

	hashKeys := map[string]string{
		"AUDIT_HASH_PUBLISH_S3_ENDPOINT": hashEndpoint,
		"AUDIT_HASH_PUBLISH_BUCKET":      hashBucket,
		"AUDIT_HASH_PUBLISH_ACCESS_KEY":  hashAccessKey,
		"AUDIT_HASH_PUBLISH_SECRET_KEY":  hashSecretKey,
	}
	var hashSet, hashMissing []string
	for k, v := range hashKeys {
		if strings.TrimSpace(v) == "" {
			hashMissing = append(hashMissing, k)
		} else {
			hashSet = append(hashSet, k)
		}
	}

	switch {
	case len(hashSet) == 0:
		// Fully unset — publisher is disabled, no-op. This is the common
		// local-dev path. Don't log every time; the publisher itself
		// logs one "disabled" line at startup.
	case len(hashMissing) > 0:
		// Partial config — operator forgot some vars. Stable-sort the
		// missing keys so the error message is deterministic for tests
		// (map iteration order is randomized by Go runtime).
		sortedMissing := append([]string{}, hashMissing...)
		sort.Strings(sortedMissing)
		recordErr(fmt.Errorf("AUDIT_HASH_PUBLISH_* partially configured; set all of [%s] or none (missing: [%s])",
			strings.Join([]string{
				"AUDIT_HASH_PUBLISH_S3_ENDPOINT",
				"AUDIT_HASH_PUBLISH_BUCKET",
				"AUDIT_HASH_PUBLISH_ACCESS_KEY",
				"AUDIT_HASH_PUBLISH_SECRET_KEY",
			}, ", "),
			strings.Join(sortedMissing, ", "),
		))
		logger.Error("env var AUDIT_HASH_PUBLISH_* partial configuration",
			"set", hashSet, "missing", sortedMissing)
	default:
		// All four set — validate endpoint against SSRF guard now, so
		// the operator sees the failure at envcheck rather than later
		// from StartHashPublisher's one-line error log.
		if err := audit.ValidateS3Endpoint(hashEndpoint); err != nil {
			recordErr(fmt.Errorf("AUDIT_HASH_PUBLISH_S3_ENDPOINT blocked by SSRF guard: %w", err))
			logger.Error("env var AUDIT_HASH_PUBLISH_S3_ENDPOINT rejected",
				"value", hashEndpoint, "error", err)
		} else {
			logger.Info("env var AUDIT_HASH_PUBLISH_* fully configured",
				"endpoint", hashEndpoint,
				"bucket", hashBucket,
				"access_key", maskSecret(hashAccessKey))
		}
	}

	// --- AUDIT_HASH_PUBLISH_INTERVAL ---
	//
	// LoadHashPublishConfig silently ignores an unparseable value and
	// keeps the 1h default — operator thinks they set 5m, but nothing
	// changes. Validate syntax here so the mistake is visible.
	if raw := getenv("AUDIT_HASH_PUBLISH_INTERVAL"); raw != "" {
		if d, err := time.ParseDuration(raw); err != nil {
			logger.Warn("env var AUDIT_HASH_PUBLISH_INTERVAL not a valid duration; keeping default 1h", "value", raw, "error", err)
		} else if d <= 0 {
			logger.Warn("env var AUDIT_HASH_PUBLISH_INTERVAL must be positive; keeping default 1h", "value", raw)
		} else {
			logger.Info("env var AUDIT_HASH_PUBLISH_INTERVAL set", "value", d.String())
		}
	}

	return firstErr
}

// maskSecret returns a fixed-width redacted form of a secret for logging.
// Keeps the first two and last two bytes so operators can sanity-check
// they're looking at the right secret without leaking the body.
func maskSecret(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}
