# `context.Background()` Audit — Production Code

**Source-of-truth gap**: Cross-cutting Go-idiom defect. C1 (Pass 15) covered 8 sites in `app/adapters.go`. This audit covers the **remaining 40 production-code sites** (excluding `*_test.go` and `app/adapters.go`).

**Audited HEAD**: `d9fdd06`.

**Charter**: Read-only research deliverable. No source-file edits.

---

## 1. Top-line counts

```
grep -rn "context.Background()" --include="*.go" . | grep -v _test.go | grep -v "app/adapters.go" | grep -v worktree
```

- **43 raw matches** (excluding tests + adapters.go + worktree)
- **3 comment-only references** (`app/http.go:1093`, `kc/manager.go:64`, `kc/options.go:16,64` — ignore)
- **40 actual call sites** to classify

### Category breakdown

| Category | Count | Action |
|---|---|---|
| **A — Legitimate root** (cmd startup, signal handlers, scheduler-loop roots, package init, fixture builders) | 18 | KEEP |
| **B — Should propagate** (mid-flight call inside a request/handler chain that already has ctx) | 19 | FIX |
| **C — Borderline** (background goroutines: outbox pump, scheduler ticker, audit writers — judgment call) | 3 | discuss |

Net: **19 sites worth fixing immediately, 3 sites for design discussion.**

---

## 2. Site-by-site enumeration

### Category A — Legitimate (18 sites, KEEP)

These are entry points where there is no parent ctx to derive from. `context.Background()` is correct.

| File:line | Reason |
|---|---|
| `main.go:89` | Top-level `ctx, cancel := context.WithCancel(context.Background())` for the entire process lifetime. Correct. |
| `app/http.go:52` | Server-startup ctx with cancel; passed to all servers. Correct. |
| `app/http.go:61` | `signal.NotifyContext(context.Background(), ...)` — root for SIGTERM handler. Correct. |
| `app/http.go:86` | `context.WithTimeout(context.Background(), 10*time.Second)` for the post-shutdown drain — process is exiting, no parent ctx exists. Correct. |
| `app/http.go:1095` | Cancellable ctx for stdio server — explicitly documented at `:1093` comment as a fix from a prior bug where it was rooted, now bound to shutdownCh. Correct. |
| `app/wire.go:55` | `kc.NewWithOptions(context.Background(), ...)` at app boot. Manager's lifetime IS the process lifetime. Correct. |
| `app/wire.go:158` | Hash-publisher pump goroutine root ctx (long-running background worker). See discussion in Category C below. |
| `app/wire.go:495` | Invitation cleanup loop root ctx. Same pattern. |
| `kc/instruments/manager.go:149` | Instruments scheduler root ctx for the periodic-update goroutine. Correct. |
| `kc/manager.go:72` | `New()` legacy constructor delegates to `NewWithOptions(context.Background(), ...)` — explicit "legacy entry point" per godoc at `:64`. Correct. |
| `kc/manager.go:97` | `o.Ctx = context.Background()` default in options struct when caller didn't pass one. Correct fallback. |
| `kc/scheduling_service.go:25` | `sessionManager.StartCleanupRoutine(context.Background())` — service-init wiring. Correct (cleanup loop lives for process lifetime). |
| `kc/session.go:85` | Session-cleanup goroutine root ctx. Correct. |
| `kc/session.go:98` | Session-eviction goroutine root ctx. Correct. |
| `kc/session_service.go:73` | `sessionManager.StartCleanupRoutine(context.Background())` — same pattern as `kc/scheduling_service.go:25`. Correct. |
| `kc/telegram/bot.go:131` | Telegram long-poll goroutine root ctx. Correct. |
| `kc/ticker/service.go:93` | Ticker WebSocket connect goroutine root ctx. Correct. |
| `kc/ticker/service.go:279` | Ticker reconnect goroutine root ctx. Correct. |

`testutil/kcfixture/manager.go:151` is also legitimate (test fixture; matches charter exclusion implicitly).

### Category B — Mid-flight propagation needed (19 sites, FIX)

These are inside tool handler closures or use case bodies that **already receive ctx from upstream** (the MCP framework, an HTTP handler, or a SimpleToolHandler closure). They drop ctx and pass `context.Background()` to the bus instead. **Cancellation, X-Request-ID, request-scoped values are all lost.**

The dominant pattern is `manager.QueryBus().DispatchWithResult(context.Background(), ...)` from inside a `SimpleToolHandler` closure. `SimpleToolHandler` (`mcp/common.go:479-491`) **does receive ctx** at line 481 from the framework, but its `apiCall` parameter signature is `func(*kc.KiteSessionData) (any, error)` — **no ctx**. So the closures fall back to `context.Background()`.

| # | File:line | Current call (paraphrased) | Recommended action | LOC |
|---|---|---|---|---|
| B1 | `mcp/get_tools.go:29` | `QueryBus().DispatchWithResult(context.Background(), GetProfileQuery{...})` | Thread ctx via `SimpleToolHandler` signature change OR closure capture | 1 |
| B2 | `mcp/get_tools.go:47` | same pattern, `GetMarginsQuery` | same | 1 |
| B3 | `mcp/get_tools.go:72` | same pattern, `GetPortfolioQuery` (holdings) | same | 1 |
| B4 | `mcp/get_tools.go:112` | same pattern, `GetPortfolioQuery` (positions) | same | 1 |
| B5 | `mcp/get_tools.go:160` | same pattern, `GetTradesQuery` | same | 1 |
| B6 | `mcp/get_tools.go:194` | same pattern, `GetOrdersQuery` | same | 1 |
| B7 | `mcp/get_tools.go:228` | same pattern, `GetGTTsQuery` | same | 1 |
| B8 | `mcp/mf_tools.go:34` | same pattern, `GetMFOrdersQuery` | same | 1 |
| B9 | `mcp/mf_tools.go:68` | same pattern, `GetMFSIPsQuery` | same | 1 |
| B10 | `mcp/mf_tools.go:102` | same pattern, `GetMFHoldingsQuery` | same | 1 |
| B11 | `mcp/plugin_widget_margin_gauge.go:37` | `QueryBus().DispatchWithResult(context.Background(), GetMarginsQuery{...})` | widget handler — has ctx via `WidgetDataFunc` signature; thread it | 1 |
| B12 | `mcp/plugin_widget_returns_matrix.go:44` | same pattern, `GetPortfolioQuery` | same | 1 |
| B13 | `mcp/plugin_widget_sector_donut.go:35` | same pattern, `GetPortfolioQuery` | same | 1 |
| B14 | `mcp/ext_apps.go:552` | `manager.QueryBus().DispatchWithResult(context.Background(), GetPortfolioForWidgetQuery{...})` | inside widget `Handler` closure (has ctx via `gomcp.ReadResourceRequest` ctx); thread it | 1 |
| B15 | `mcp/ext_apps.go:570` | `cqrs.WithWidgetAuditStore(context.Background(), ...)` | derive from request ctx instead of rooting | 1 |
| B16 | `mcp/ext_apps.go:583` | same as B15 | same | 1 |
| B17 | `mcp/ext_apps.go:596` | `manager.QueryBus().DispatchWithResult(context.Background(), GetAlertsForWidgetQuery{...})` | same as B14 | 1 |
| B18 | `mcp/trailing_tools.go:170` | `manager.CommandBus().DispatchWithResult(context.Background(), SetTrailingStopCommand{...})` | `doSetTrailingStop` helper takes ctx already through `*ToolHandler`; add `ctx context.Context` parameter explicitly | 1 |
| B19 | `mcp/ext_apps.go:570/583` (the `cqrs.WithWidgetAuditStore`) — already counted in B15/B16 | same |

**LOC delta**: each fix is mechanical 1 LOC change at the callsite. **Total prod LOC: ~19 LOC at the leaf sites + 1 signature change in `SimpleToolHandler` + 1 signature change in `WidgetDataFunc` if we go that route = ~25 LOC prod.**

**BUT** — if we change `SimpleToolHandler`'s `apiCall` signature from `func(*kc.KiteSessionData) (any, error)` to `func(context.Context, *kc.KiteSessionData) (any, error)`, **every caller** of `SimpleToolHandler` breaks: ~10 sites in get_tools.go + mf_tools.go + others. Each needs a 1-LOC update. **Total cascade: ~30 LOC prod + ~30 LOC test fixture updates** (mocks/fakes that consume the helper).

### Category C — Borderline (3 sites, discuss)

These are background goroutines whose lifetime is the process lifetime. Wiring a parent ctx WITH the option to cancel at shutdown gives clean shutdown but is more invasive. Already-correct in spirit; question is whether they should derive from `app.shutdownCh` for early exit.

| # | File:line | Current pattern | Discussion |
|---|---|---|---|
| C1 | `kc/eventsourcing/outbox.go:96` | `p.store.Drain(context.Background())` — startup drain | Outbox pump runs forever. Startup drain is process-init time; rooting is fine. **KEEP** unless we want to abort startup if drain hangs (then derive from main ctx with timeout). |
| C2 | `kc/eventsourcing/outbox.go:108` | `p.store.Drain(context.Background())` — shutdown drain | "One last drain so any in-flight events make it through." Comment makes intent clear: this MUST complete. Rooting is correct because parent ctx is already canceling. **KEEP.** |
| C3 | `kc/eventsourcing/outbox.go:113` | `p.store.Drain(context.Background())` — periodic ticker drain | Each tick is independent. Could derive from pump's owning ctx (`p.stop`-derived). Minor — Drain timeout would let DB-pool issues surface. ~5 LOC fix. **OPTIONAL.** |

Same pattern exists in `kc/scheduler/scheduler.go:215` (per Pass 11/Pass 13 audits — scheduler tasks `go fn()` without ctx). Out of this audit's scope (the file uses `go func()` not `context.Background()` directly), but related.

**LOC delta if we close C3**: ~5 LOC. Probably fold with the outbox pattern overhaul in Sprint 4.

### Comment-only references (ignore)

| File:line | Note |
|---|---|
| `app/http.go:1093` | Comment documenting a prior fix |
| `kc/manager.go:64` | Godoc on `New()` |
| `kc/options.go:16` | Godoc explaining default behavior |
| `kc/options.go:64` | Same |

---

## 3. Summary table

| File | Total | Cat A keep | Cat B fix | Cat C borderline | LOC delta if B+C closed |
|---|---|---|---|---|---|
| `main.go` | 1 | 1 | 0 | 0 | 0 |
| `app/http.go` | 5 (1 comment) | 4 | 0 | 0 | 0 |
| `app/wire.go` | 3 | 3 | 0 | 0 | 0 |
| `kc/eventsourcing/outbox.go` | 3 | 0 | 0 | 3 | 0-5 (optional) |
| `kc/instruments/manager.go` | 1 | 1 | 0 | 0 | 0 |
| `kc/manager.go` | 3 (1 comment) | 2 | 0 | 0 | 0 |
| `kc/options.go` | 2 (both comments) | 0 | 0 | 0 | 0 |
| `kc/scheduling_service.go` | 1 | 1 | 0 | 0 | 0 |
| `kc/session.go` | 2 | 2 | 0 | 0 | 0 |
| `kc/session_service.go` | 1 | 1 | 0 | 0 | 0 |
| `kc/telegram/bot.go` | 1 | 1 | 0 | 0 | 0 |
| `kc/ticker/service.go` | 2 | 2 | 0 | 0 | 0 |
| `mcp/ext_apps.go` | 4 | 0 | 4 | 0 | ~5 |
| `mcp/get_tools.go` | 7 | 0 | 7 | 0 | ~7 |
| `mcp/mf_tools.go` | 3 | 0 | 3 | 0 | ~3 |
| `mcp/plugin_widget_margin_gauge.go` | 1 | 0 | 1 | 0 | ~1 |
| `mcp/plugin_widget_returns_matrix.go` | 1 | 0 | 1 | 0 | ~1 |
| `mcp/plugin_widget_sector_donut.go` | 1 | 0 | 1 | 0 | ~1 |
| `mcp/trailing_tools.go` | 1 | 0 | 1 | 0 | ~1 |
| `testutil/kcfixture/manager.go` | 1 | 1 (fixture) | 0 | 0 | 0 |
| **Total** | **43** | **18** | **19** | **3** | **~25 prod LOC** |

Plus required signature change cascade:
- `SimpleToolHandler` signature change: +1 LOC + ~10 caller updates = ~11 LOC.
- `WidgetDataFunc` signature change (if needed): +1 LOC + ~5 caller updates = ~6 LOC.
- Test fixture updates: ~30 LOC across ~6 test files.

**Total estimated effort: ~50 LOC prod + ~30 LOC test = 80 LOC across ~25 files.**

---

## 4. Sprint plan — Category B by upstream caller depth

Ranked shallow-first (lowest risk):

### Phase 1 — Direct closure capture (no signature changes) — ~5 LOC, 1 commit

**Sites**: B14, B15, B16, B17 (`mcp/ext_apps.go`).

These widget Handler closures already receive ctx via the `gomcp.ReadResourceRequest` ctx parameter — no API change needed. Just rename the closure-bound ctx variable and use it.

```go
// Before:
result, err := manager.QueryBus().DispatchWithResult(context.Background(), cqrs.GetPortfolioForWidgetQuery{Email: email})
// After (ctx already in scope from outer Handler):
result, err := manager.QueryBus().DispatchWithResult(ctx, cqrs.GetPortfolioForWidgetQuery{Email: email})
```

LOC delta: ~5 LOC. Test impact: minimal (widget tests pass ctx in already).

### Phase 2 — Widget data func signature change — ~10 LOC, 1 commit

**Sites**: B11, B12, B13 (`mcp/plugin_widget_*.go`).

These are called from `RegisterBuiltinWidgetPack` via a closure-captured `manager`. The widget data function signature is `func(manager *kc.Manager, email string) any` (per `mcp/plugin_widgets_pack.go:24 builtinWidgetDataFunc`). Add `ctx context.Context` to the signature.

LOC delta: ~10 LOC (signature + 5 callers + 5 tests).

### Phase 3 — `SimpleToolHandler` signature change — ~30 LOC, 1 commit

**Sites**: B1-B10 (`mcp/get_tools.go`, `mcp/mf_tools.go`).

Change `apiCall func(*kc.KiteSessionData) (any, error)` to `apiCall func(context.Context, *kc.KiteSessionData) (any, error)`. Update 10 closure callers + 1 internal call. Update any test mocks of `SimpleToolHandler` (verify zero — most tests call tool's `.Handler()` directly).

LOC delta: ~30 LOC (signature + 10 callers + 1 internal + ~5 test fixture).

### Phase 4 — Helper-function ctx threading — ~5 LOC, 1 commit

**Site**: B18 (`mcp/trailing_tools.go:170`). `doSetTrailingStop` helper takes Manager + parameters but no ctx. Add `ctx context.Context` parameter; pass from caller (already has ctx).

LOC delta: ~5 LOC.

### Phase 5 — Optional — outbox pump ctx-derived drains — ~5 LOC, 1 commit

**Site**: C3 (`kc/eventsourcing/outbox.go:113`). Derive periodic-tick Drain ctx from `p.stop` channel via `context.WithCancel`. Lets DB hangs surface as ctx-cancel rather than goroutine block.

LOC delta: ~5 LOC. **Optional** — not required for honest closure of the gap.

**Total across Phases 1-4 (mandatory): ~50 LOC across ~6 files.**

**Recommended commit batching: 4 sequential PRs** (Phase 1 → 4), each 1 commit, each independently reviewable. Phase 5 deferred or merged with Phase 1.

---

## 5. Score-lift estimate

Catalogue C1 entry: high severity, 40 LOC scoped originally. C1 actually delivered ~100 LOC across `app/adapters.go` + interface cascade (per `7a36300` plan). This audit adds ~50 LOC of mid-flight ctx-propagation completing the Go-idiom story.

**Catalogue impact**:
- **E-series (Go-idiom) dimension**: today honest 92/100 (per Pass 23 13-dim aggregate). Closing all 19 Category B sites lifts **Go-idiom dim 92 → 95**. C1 delivered most of the 88→92 lift; this audit closes the residual.
- **13-dim weighted aggregate**: +0.15pt (small relative weight).
- **Real engineering value beyond score**:
  - X-Request-ID propagates correctly through the bus → audit log correlation works end-to-end.
  - Future timeout middleware (e.g., per-tool 30s timeout) can actually cancel mid-bus-dispatch.
  - Cancellation semantics align with Go community expectations — easier for new contributors.

**Verdict**: this is **real value at low cost**. ~50 LOC of mechanical fixes close a real correctness story. No ceremony.

---

## 6. Recommended sprint placement

- **Phase 1 (ext_apps): ship as a satellite to Sprint 2** (already lands ES-outbox there; cohesive).
- **Phases 2-3 (widgets + SimpleToolHandler): bundle into a single Sprint 4b PR** `refactor(mcp): thread ctx through tool/widget handlers (B audit)` — ~40 LOC, low risk.
- **Phase 4 (trailing helper): bundle with above OR Sprint 3b's pen-1/2/3 hardening cluster.**
- **Phase 5 (outbox): defer to Sprint 4 polish if appetite remains.**

Total: 4 PRs across 2 sprints. Risk uniformly LOW.

---

## 7. Out-of-scope deferrals (preserved from C1)

Per `7a36300` C1 plan §"Out-of-scope deferrals":
- `kc/manager_commands_oauth.go:320,324 oauthClientStoreAdapter.SaveClient/DeleteClient` — bridges to `alerts.DB`, no Dispatch on these. Out of scope.
- `kc/alerts/db_commands.go:198,220 DB.SaveClient/DeleteClient` — SQL-level. Threading ctx into SQL queries (`db.ExecContext`) is its own work item.

This audit covers **only** `context.Background()` calls. SQL-level ctx threading is a separate, larger refactor.

---

*Generated 2026-04-25 against HEAD `d9fdd06`. Read-only research deliverable; no source files modified.*
