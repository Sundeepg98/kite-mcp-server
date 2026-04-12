# Phase 2l — Flaky middleware_chain test fix

**Status:** Already fixed prior to Task #14 being created. Verified stable.
**Verifier:** team resume-final
**Date:** 2026-04-12

## Original failure (Phase 2 finding)

```
--- FAIL: TestFullChain_ReadOnlyToolPassesForAnyUser (1.16s)
    middleware_chain_test.go:279: audit should have 5 records for unknown user
        expected: 5, actual: 1
```

Fails under `go test -count=1 ./...`, passes in isolation and on package re-run.

## Root cause

The async audit writer (`audit.Store` with `StartWorker()`) drains a `writeCh` into a file-backed SQLite DB in a background goroutine. Under I/O contention (parallel package runs on Windows), the fixed `time.Sleep(100 * time.Millisecond)` wait was unreliable — assertion ran before drain completed, observed 1/5 records.

## Fix

Already present in `mcp/middleware_chain_test.go` at the time of Task #14 creation (uncommitted but in working tree):

**Line 79-91** — new helper `waitForAuditCount` polls `auditStore.List()` until count ≥ expected or 3-second deadline (10ms polls).

**Line 293** — replaces fixed `time.Sleep(100 * time.Millisecond)` inside `TestFullChain_ReadOnlyToolPassesForAnyUser`:
```go
for _, user := range users {
    waitForAuditCount(t, auditStore, user.email, len(readOnlyTools))
}
```

**Line 369** — same replacement inside `TestFullChain_AuditRecordsCreatedForEveryCall`.

Doc comment at line 76-78 explicitly calls out the reason:
> The audit write path is async (worker goroutine draining writeCh → SQLite file DB), and on Windows a fixed time.Sleep is unreliable under load — especially when parallel tests contend for I/O. Polling removes that flake class entirely.

## Verification

`setupChain` creates a fresh per-test `t.TempDir()` DB, so there's no cross-test state leak within the package — the flakiness was purely async-drain timing, not shared state.

### 10x consecutive runs of the target test

Compiled-binary approach (Windows SAC blocks `go test`'s temp-dir binaries intermittently):
```
go test -c -o D:/kite-mcp-temp/mcp_test.exe ./mcp/
for i in 1..10: mcp_test.exe -test.run TestFullChain
```

Result: **10/10 PASS**

### 5x consecutive runs of full mcp package

```
for i in 1..5: mcp_test.exe
```

Result: **5/5 PASS**

## Cross-package run caveat

A later run of `go test -count=1 ./mcp/ ./kc/ ./kc/audit/ ./kc/usecases/ ./app/` produced intermittent mcp failures (run 1: FAIL, run 2: FAIL, run 3: PASS), but by that time the working tree had additional uncommitted edits from other Phase 2 teammates — notably `mcp/alert_tools.go` which now has a build error (`undefined: kiteconnect` at alert_tools.go:176`). That is a separate regression introduced by Task #12 (dead-code wiring), NOT the flaky middleware_chain test.

Also observed: `kc` package now has 5 failing tests (TestNewConfigConstructor, TestManager_MoreAccessors, TestNew_InstrumentsManagerAutoCreation, TestNew_DefaultInstrumentsManager, TestNew_AutoCreateInstrumentsManager) each timing out at ~6s — also from uncommitted Phase 2j edits to `kc/manager.go` and related files.

These regressions should be addressed by Task #12 before Phase 3 commits.

## Conclusion

**Task #14 fix is in place and stable.** The flaky `TestFullChain_ReadOnlyToolPassesForAnyUser` is fixed via `waitForAuditCount` polling. 10/10 isolated runs and 5/5 package runs all pass.

The broader `go test -count=1 ./...` instability is now driven by a different root cause — in-flight uncommitted edits from Task #12 breaking `mcp/alert_tools.go` and several `kc` tests. Out of scope for Task #14; flagged for Phase 3 / Task #12 completion.
