# Phase 2i — HIGH Error Handling Fixes

Three HIGH-severity findings from Phase 2g audit (`.research/resume-error-audit.md`) fixed. Tests added for H3; H1/H2 are wire-up changes verified by `go vet` and code review.

## H1 — Audit init failure no longer silently disables audit middleware

**File:** `app/wire.go:56-96`
**Before:** `InitTable()` + `EnsureEncryptionSalt()` failures were `Error`-logged but execution continued, leaving `auditMiddleware == nil` and tool calls unlogged — silent compliance gap.

**After:** Three fail-fast branches gated on `!app.DevMode`:

1. `InitTable()` failure → `return … fmt.Errorf("audit trail required in production: init table: %w", err)`
2. `EnsureEncryptionSalt()` failure → return wrapped error (encryption is required for HMAC email hashing and hash chaining)
3. Missing `alertDB` (no `ALERT_DB_PATH` configured) → return error

DevMode still logs and continues so local development without a DB keeps working. All three branches include a `(DevMode: continuing…)` marker in the log line.

## H2 — Riskguard LoadLimits failure no longer wipes user kill switch

**File:** `app/wire.go:98-123`
**Before:** `riskGuard.InitTable()` and `riskGuard.LoadLimits()` were `Error`-logged and execution continued with in-memory defaults. A user-configured kill switch (or daily value cap, qty limit, etc.) would silently disappear on a transient DB error, allowing trades to proceed without safety controls.

**After:** Both calls fail fast in production mode. The `LoadLimits` error message explicitly says `refusing to start without user-configured limits` so operators understand the reason. Missing `alertDB` also fails fast (riskguard persistence requires the DB).

## H3 — Audit Enqueue drops are now tracked and logged

**Files:**
- `kc/audit/store.go` — Store struct + Enqueue + DroppedCount + incDropped
- `kc/audit/store_edge_test.go` — 2 new tests

**Before:**
```go
func (s *Store) Enqueue(entry *ToolCall) {
    if s.writeCh == nil {
        _ = s.Record(entry)  // error swallowed
        return
    }
    select {
    case s.writeCh <- entry:
    default:
        if s.logger != nil {
            s.logger.Warn("Audit buffer full, dropping entry", ...)  // Warn, no counter
        }
    }
}
```

**After:**
- New `droppedCount int64` + `droppedMu sync.Mutex` on `Store`
- New `DroppedCount() int64` public accessor for ops/monitoring
- New `incDropped()` helper
- Sync-fallback path (`writeCh == nil`) now calls `computeChainLink` + `Record`, logs `Error` with `tool` field and increments `droppedCount` on failure
- Buffer-full path logs at `Error` (was `Warn`) with `dropped_total` field and increments counter
- Log messages call out `(compliance gap)` so ops knows to alert

**Tests added (`store_edge_test.go`):**
- `TestEnqueue_BufferFull_IncrementsDroppedCount` — 3 enqueues into a 1-capacity buffer with no consumer: asserts `DroppedCount() == 2`.
- `TestEnqueue_SyncFallback_RecordFailureIncrementsDroppedCount` — closes the DB to force `Record` errors on the sync fallback path, asserts `DroppedCount() == 2`.

Both tests pass:
```
--- PASS: TestEnqueue_SyncFallback_RecordFailureIncrementsDroppedCount (0.01s)
--- PASS: TestEnqueue_BufferFull_IncrementsDroppedCount (0.01s)
--- PASS: TestEnqueue_BufferFull (0.01s)
--- PASS: TestEnqueue_BufferFull_NoLogger (0.01s)
```

## Verification

- `go vet ./...` — clean
- `go build ./...` — clean
- `go test ./kc/audit/...` — all pass (3.56s)
- `go test ./app/...` — 3 pre-existing unrelated failures in `TestInitScheduler_NoTasks_Minimal`, `TestInitializeServices_WithAdminEmails`, `TestInitializeServices_DevMode`, all failing with HTTP 429 from `api.kite.trade/instruments.json` during manager bootstrap (before any of my changed code runs). These are upstream rate-limit issues unrelated to Phase 2i.

## Impact on existing tests

- `TestInitializeServices_AuditEncryption_Push100` (app_edge_test.go:162) — uses `DevMode=true` + `:memory:` alert DB. `:memory:` SQLite has no failure mode, so hits the success branch. No change required.
- `TestInitializeServices_RiskGuardFreezeAndAutoFreeze_Push100` (app_edge_test.go:196) — same DevMode + :memory:. No change required.

Production mode fail-fast behavior is a straight-line `return` in wire.go; code review verifies the change. Integration tests for production-mode fail-fast would require a fault-injecting DB or mock layer that currently doesn't exist in the test suite — out of scope for this phase.

## Files changed

1. `app/wire.go` — H1 + H2 fail-fast branches (+26 lines net)
2. `kc/audit/store.go` — H3 DroppedCount + improved Enqueue (+35 lines net)
3. `kc/audit/store_edge_test.go` — 2 new tests (+49 lines)

All changes are self-contained; no API surface removed, only added. `DroppedCount()` is new but exported so ops endpoints can wire it into `/healthz` or `admin_server_status` later.
