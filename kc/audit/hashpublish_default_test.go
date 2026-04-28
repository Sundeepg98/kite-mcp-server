package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// hashpublish_default_test.go — coverage for the "default-on" log
// upgrade per .research/scorecard-final-v2.md Phase 3 item #1.
//
// Pre-upgrade behaviour: when AUDIT_HASH_PUBLISH_* env vars were
// unset, StartHashPublisher emitted ONE info-level line ("Audit
// hash publishing disabled (no storage configured)") and returned.
// The level masked a SEBI CSCRF compliance gap: in production with
// OAUTH_JWT_SECRET set, the operator has an HMAC anchor available
// — the absence of external storage is a config oversight, not
// a benign default.
//
// Post-upgrade behaviour:
//
//   - When NO signing key is available (OAUTH_JWT_SECRET unset
//     AND AUDIT_HASH_PUBLISH_KEY unset), the message stays INFO —
//     the operator has chosen unsigned-only deployment and the
//     publisher could not run anyway.
//
//   - When a signing key IS available but external storage is
//     unconfigured, the message escalates to WARN with
//     "tamper-evidence anchor missing" + actionable hint. This is
//     the "production deployed without external anchor" case the
//     SEBI CSCRF rubric flags.
//
// The two-tier severity preserves the dev-mode unconfigured-OK
// path while making the production gap loud at startup.
//
// What's measured here:
//   - INFO when neither signing key nor external storage configured
//   - WARN when signing key available but external storage not
//   - WARN message includes "tamper-evidence" or "CSCRF" so log
//     filters can route to the right severity bucket
//   - Hint text identifies the env vars to set
//   - The publisher returns without panicking in both paths

// captureLogger returns a slog.Logger that writes JSON-encoded
// records to the supplied buffer. Mirrors kc/logger/logger_test.go's
// helper pattern. Level is set to Debug so all records are
// captured for later parsing.
func captureLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}

// TestStartHashPublisher_Disabled_WithSigningKey_LogsAtWarn pins
// the post-upgrade behaviour: when external storage is unset but
// OAUTH_JWT_SECRET is available, the disabled-publisher log is
// at WARN with a CSCRF-anchored message + actionable hint.
func TestStartHashPublisher_Disabled_WithSigningKey_LogsAtWarn(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := captureLogger(&buf)

	cfg := HashPublishConfig{
		// All external storage fields empty — Enabled() is false.
		// SigningKey is provided — operator has HMAC anchor capability.
		SigningKey: []byte("not-a-real-jwt-secret-for-tests-only"),
	}

	// store is non-nil; the disabled gate fires after the nil-store
	// guard. Use a zero-value Store value via &Store{} since the
	// gate path doesn't dereference any field.
	StartHashPublisher(context.Background(), &Store{}, cfg, logger)

	// Parse log lines — there should be exactly one record at WARN.
	records := decodeLogLines(t, buf.String())
	if len(records) != 1 {
		t.Fatalf("expected exactly 1 log record, got %d (%s)", len(records), buf.String())
	}
	rec := records[0]

	if got := rec["level"]; got != "WARN" {
		t.Errorf("expected level=WARN, got %v", got)
	}
	msg, _ := rec["msg"].(string)
	// Must mention tamper-evidence or CSCRF so the log filter can
	// route to the right severity bucket.
	if !strings.Contains(strings.ToLower(msg), "tamper") &&
		!strings.Contains(strings.ToLower(msg), "cscrf") &&
		!strings.Contains(strings.ToLower(msg), "anchor") {
		t.Errorf("WARN message must reference tamper-evidence/CSCRF/anchor; got %q", msg)
	}
	// Must surface the env vars the operator needs to set.
	hint, _ := rec["hint"].(string)
	if !strings.Contains(hint, "AUDIT_HASH_PUBLISH_") {
		t.Errorf("hint must reference AUDIT_HASH_PUBLISH_* env vars; got %q", hint)
	}
}

// TestStartHashPublisher_Disabled_WithoutSigningKey_LogsAtInfo
// pins the dev-mode-friendly path: with NO signing key available,
// the message stays at INFO. Operator has chosen unsigned-only
// deployment (or running locally without OAUTH_JWT_SECRET) and
// the publisher could not run regardless of external storage.
func TestStartHashPublisher_Disabled_WithoutSigningKey_LogsAtInfo(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := captureLogger(&buf)

	cfg := HashPublishConfig{
		// All fields empty — no signing key, no external storage.
		// Models DEV_MODE without OAUTH_JWT_SECRET set.
	}

	StartHashPublisher(context.Background(), &Store{}, cfg, logger)

	records := decodeLogLines(t, buf.String())
	if len(records) != 1 {
		t.Fatalf("expected exactly 1 log record, got %d (%s)", len(records), buf.String())
	}
	rec := records[0]

	if got := rec["level"]; got != "INFO" {
		t.Errorf("expected level=INFO (dev-friendly), got %v", got)
	}
}

// TestStartHashPublisher_Disabled_NoStorageWarnDoesNotStartGoroutine
// confirms the post-upgrade WARN path still returns without
// starting the publisher goroutine — severity escalation is a
// logging-only change; behaviour at the dispatch level is
// unchanged.
func TestStartHashPublisher_Disabled_NoStorageWarnDoesNotStartGoroutine(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := captureLogger(&buf)

	cfg := HashPublishConfig{
		SigningKey: []byte("sk"),
		// All external-storage fields empty.
	}

	// We can't directly observe goroutine start without timing
	// instrumentation; instead we assert that the function returns
	// promptly and the only log line is the disabled-WARN message
	// (no "Audit hash publisher started" line, which would indicate
	// the goroutine path was taken).
	StartHashPublisher(context.Background(), &Store{}, cfg, logger)

	out := buf.String()
	if strings.Contains(out, "Audit hash publisher started") {
		t.Errorf("disabled path must not log 'started'; got: %s", out)
	}
}

// decodeLogLines parses the buffer's newline-delimited JSON records
// and returns them as a slice of maps. Skips any blank lines so
// callers can pass raw buffer.String() output directly.
func decodeLogLines(t *testing.T, out string) []map[string]interface{} {
	t.Helper()
	var records []map[string]interface{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec map[string]interface{}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("could not parse log line %q: %v", line, err)
		}
		records = append(records, rec)
	}
	return records
}
