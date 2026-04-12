# Error Handling + Silent Failure Audit

Scope: `D:\kite-mcp-temp` production `.go` files (excludes `*_test.go`). Date: 2026-04-12.

Methodology: grep for `_ =` error-swallow, `recover()`, `defer Close`, patterns where `err` is logged-but-not-returned, and init-time fallbacks.

## Summary

| Severity | Count | Notes |
|---|---|---|
| HIGH | 3 | Audit/riskguard silent-degrade, audit buffer fallback drops entries |
| MED  | 6 | Registry state writes, DB/in-memory divergence, background cleanup |
| LOW  | ~25 | DDL migrations, intentional timing-safe bcrypt, http encoder errors, documented `#nosec G104` |

Total production-code `_ = …` occurrences scanned: 34 (excluding tests which have ~100+ but are out of scope).

---

## HIGH severity

### H1. Audit store init failure → server starts without audit trail
**File:** `app/wire.go:60-82`
```go
if err := app.auditStore.InitTable(); err != nil {
    app.logger.Error("Failed to initialize audit table", "error", err)
} else { /* ... enable audit middleware ... */ }
```
**Issue:** If audit table creation fails, `auditMiddleware` remains nil and every tool call proceeds unlogged. This is a compliance gap (SEBI/regulatory audit trail silently disabled).
**Fix:** Return fatal error from `wire.go` when audit init fails in production mode (gate on `DevMode`). At minimum, set a "degraded" flag exposed on `/healthz` so ops can detect it.

### H2. Risk limits load failure → trades continue with defaults
**File:** `app/wire.go:88-93`
```go
if err := riskGuard.InitTable(); err != nil {
    app.logger.Error("Failed to initialize risk_limits table", "error", err)
}
if err := riskGuard.LoadLimits(); err != nil {
    app.logger.Error("Failed to load risk limits", "error", err)
}
```
**Issue:** If either call fails, riskguard runs with in-memory defaults — user-configured limits (kill switch, daily value cap, qty limits) are silently absent. A user who previously set a kill switch could have it cleared.
**Fix:** Either (a) fail-closed: refuse to start if `LoadLimits` fails, or (b) set riskguard into "hard block all writes" mode until operator intervenes.

### H3. Audit buffer fallback silently drops entries
**File:** `kc/audit/store.go:160-172`
```go
func (s *Store) Enqueue(entry *ToolCall) {
    if s.writeCh == nil {
        _ = s.Record(entry)  // synchronous fallback — error ignored
        return
    }
    select {
    case s.writeCh <- entry:
    default:
        if s.logger != nil {
            s.logger.Warn("Audit buffer full, dropping entry", "call_id", entry.CallID)
        }
    }
}
```
**Issue:** The worker-not-started fallback swallows `Record` errors. The buffer-full branch logs a `Warn` but still drops. Both lose audit records.
**Fix:** Synchronous fallback should at least log on failure. Buffer-full should escalate to `Error` and increment a metric so monitoring can detect audit loss.

---

## MED severity

### M1. Registry reassignment on conflict silently swallowed
**File:** `app/adapters.go:249`
```go
} else if existing.AssignedTo != lowerEmail {
    _ = a.registryStore.Update(existing.ID, lowerEmail, "", "")
}
```
**Issue:** API key reassignment (changing AssignedTo) ignores update failure. A user whose key failed to reassign continues using a stale mapping.
**Fix:** Log Warn on error; consider returning it up.

### M2. Background metrics cleanup swallows error
**File:** `app/metrics/metrics.go:195`
```go
case <-time.After(delay):
    _ = m.CleanupOldData()
```
**Issue:** If cleanup fails every week, the DB grows unbounded with no signal.
**Fix:** `if err := m.CleanupOldData(); err != nil { m.logger.Error(...) }`.

### M3. Invitation expiry DB update ignored
**File:** `kc/users/invitations.go:175`
```go
if s.db != nil {
    _ = s.db.ExecInsert(`UPDATE family_invitations SET status = 'expired' WHERE id = ?`, inv.ID)
}
```
**Issue:** In-memory status flips to "expired" but DB may retain "pending". Restart rehydrates stale state, allowing already-expired invitations to be accepted.
**Fix:** Log on error; skip in-memory flip if DB write fails (atomic).

### M4. Session UpdateSessionField ignored
**File:** `kc/session_service.go:221`
```go
_ = ss.sessionManager.UpdateSessionField(mcpSessionID, func(data any) { ... })
```
**Issue:** Context-dependent. If this is persisting Kite session data, loss is a re-auth for the user. Needs inspection to know the failure mode.
**Fix:** Log Warn with session_id on error.

### M5. MCP after-hooks errors discarded with no log
**File:** `mcp/registry.go:92`
```go
for _, hook := range afterHooks {
    _ = hook(toolName, args)
}
```
**Issue:** After-hooks are design-level fire-and-forget, but a failing hook is invisible. If an audit/metrics hook panics or errors, operators never know.
**Fix:** At minimum log hook errors with tool name.

### M6. Billing checkout response encode ignored
**File:** `kc/billing/checkout.go:99`, `kc/ops/handler_admin.go:131/140/248`
```go
_ = json.NewEncoder(w).Encode(...)
```
**Issue:** Encoder errors after headers are written are usually unrecoverable, but a failing response for billing/admin endpoints could silently give users blank results. This is Go convention so LOW-MED at worst.
**Fix:** Optional — add `logger.Debug` for diagnostics.

---

## LOW severity (intentional / conventional)

### L1. SQLite idempotent DDL migrations
**Files:**
- `kc/users/store.go:159,161` — `ALTER TABLE users ADD COLUMN …`
- `kc/billing/store.go:69,75,79,89,90,91` — billing table migration
- `kc/audit/store.go:219-226` — tool_calls column migration
- `kc/riskguard/guard.go:707` — `_ = g.db.ExecDDL(m) // ignore "duplicate column" errors`

**Assessment:** Standard "ADD COLUMN" migrations where "column already exists" error is expected on subsequent boots. Acknowledged as ACCEPTED RISK in `SECURITY_PENTEST_RESULTS.md`.
**Fix:** None. Could be tightened to parse the error and only swallow "duplicate column", but low value.

### L2. Timing-safe bcrypt on missing user
**File:** `kc/users/store.go:620` — `_ = bcrypt.CompareHashAndPassword(...)`
**Assessment:** Intentional timing-attack mitigation. Comment documents it.
**Fix:** None.

### L3. `r.ParseForm()` swallowed before `FormValue`
**Files:**
- `oauth/handlers_browser.go:157` — `_ = r.ParseForm() // #nosec G104 — non-fatal`
- `oauth/handlers_admin.go:22` — same pattern

**Assessment:** Annotated. `FormValue` returns empty string on parse error, which handlers treat as missing input. Safe.
**Fix:** None.

### L4. Audit `DeleteOlderThan` pre-scan
**File:** `kc/audit/store.go:512`
```go
_ = s.db.QueryRow(...).Scan(&lastDeletedHash)
```
**Assessment:** Hash chain continuity pre-scan. Failure leaves `lastDeletedHash == ""` which disables the marker insert — chain VerifyChain will detect the gap on next verify.
**Fix:** Log Debug to aid diagnostics.

### L5. HTTP JSON encode errors
**File:** `app/http.go:297,444`; several ops handlers.
**Assessment:** By Go convention, `json.NewEncoder(w).Encode(...)` errors on an already-written `http.ResponseWriter` are unrecoverable.
**Fix:** None.

### L6. CSV writer errors
**File:** `kc/ops/api_activity.go:135,141`
**Assessment:** `cw.Write` errors during streaming CSV export are also unrecoverable mid-stream.
**Fix:** Track error, check `cw.Flush()` at end and log if any write failed.

### L7. `_ = ltcgRate` — unused variable placeholder
**File:** `kc/ops/api_tax.go:98`
**Assessment:** Dead placeholder. Not an error-handling issue but flagged for dead-code audit (task #6).
**Fix:** Remove.

---

## Panic / recover() sites (both logged — OK)

1. `kc/scheduler/scheduler.go:159` — per-task goroutine recover; logs `"Scheduler: task panicked"` with task name.
2. `mcp/common.go:231` — `callWithNilKiteGuard` recovers DEV_MODE panics when tools dereference nil Kite client. Logs `Warn` and returns user-friendly error. Only active in DEV_MODE.

No unlogged recovers found.

---

## defer Close() without error check

36 sites across 13 files (sql rows, http bodies, file handles). All follow Go convention of `defer rows.Close()` which is idiomatic — the resource cleanup error is not actionable at the call site. No HIGH/MED findings.

Notable: `cmd/rotate-key/main.go` has 2 such; `kc/audit/store.go` has 7; `kc/alerts/db_queries.go` has 9. All standard patterns.

---

## Recommended prioritization

1. **Must fix before next deploy:** H1, H2 — server should not silently run with audit OR riskguard degraded.
2. **Should fix:** H3, M1-M5 — observability gaps that mask real failures.
3. **Defer:** L1-L7 — documented intentional patterns; address during a codebase polish pass if desired.

## Out-of-scope observations

- Test files have ~100+ `_ = …` patterns (mostly setup helpers). Not production risk.
- `#nosec G104` annotations are used consistently where gosec was suppressed — verified to be legitimate.
- No `panic()` calls in production code outside of `cmd/` main functions (verified by earlier pentest report).
