# Wave D Phase 3 Package 6 — mcp/ Logger sweep scoping

**Status**: Read-only research. Zero code edits.
**HEAD**: `931080a` (post-Package 5g)
**Companion docs**:
- `.research/go-irreducible-evaluation.md` (`e84a8f4`) — language-fit evaluation; recommends framing this kind of decision as "design choice ceiling not Go-irreducible"
- `feedback_decoupling_denominator.md` — three-axis ROI framework
- `feedback_narrow_test_scope_no_stash.md` — case-study rule on per-package narrow test scope (no `git stash`)

This doc resolves the structural design question I flagged in the
Package 5g honest-stop: **how should mcp/ tool handlers consume Logger
post-sweep?** Packages 1-5g (kc-side) all migrated struct fields and
private setters. The mcp/ layer is structurally different — its
"Logger" surface is a public-API parameter (`mcp.RegisterTools(...,
logger *slog.Logger, ...)`) and a shared ToolHandlerDeps field consumed
by 50+ call sites that never thread ctx today.

---

## 1. Empirical scope inventory

### 1.1 Direct `*slog.Logger` field/parameter sites in mcp/

12 sites across 8 production files (verified via
`grep '\\*slog\\.Logger' mcp/*.go`):

| File | Site | Shape |
|---|---|---|
| `mcp/common_deps.go:22` | `ToolHandlerDeps.Logger *slog.Logger` | **Struct field** (1 — the keystone) |
| `mcp/common_deps.go:146` | `func (h *ToolHandler) Logger() *slog.Logger` | **Public accessor** returning the field |
| `mcp/read_deps.go:19` | `ReadDepsFields.Logger *slog.Logger` | **Struct field** (intermediate builder) |
| `mcp/mcp.go:180` | `func RegisterTools(..., logger *slog.Logger, ...)` | **Public API** called from `app/wire.go:739` |
| `mcp/mcp.go:190` | `func RegisterToolsForRegistry(..., logger *slog.Logger, ...)` | **Public API** |
| `mcp/resources.go:182` | `func docReadHandler(..., logger *slog.Logger)` | **Internal closure factory** |
| `mcp/resources.go:221` | `func RegisterDocResources(..., logger *slog.Logger)` | **Public API** |
| `mcp/plugin_widgets_pack.go:59` | `func RegisterBuiltinWidgetPack(..., logger *slog.Logger)` | **Public API** |
| `mcp/ext_apps.go:463` | `func RegisterAppResources(..., logger *slog.Logger)` | **Public API** |
| `mcp/plugin_sbom_signature.go:59` | `Registry.logger *slog.Logger` | **Struct field** (sub-registry) |
| `mcp/plugin_sbom_signature.go:103` | `func (r *Registry) SetSignerLogger(logger *slog.Logger)` | **Public setter** |
| `mcp/plugin_watcher.go:99` | `func SetPluginWatcherLogger(logger *slog.Logger)` | **Package-global setter** |
| `mcp/plugin_watcher.go:105` | `func watcherLogger() *slog.Logger` | **Package-global getter** |

Special case — `mcp/plugin_watcher.go:58` declares
`var pluginWatcherLogger atomic.Pointer[slog.Logger]`. This is NOT a
plain field; it's a runtime-swappable global so the watcher's fsnotify
goroutine can write log lines without holding a lock. Migrating this
to `atomic.Pointer[logport.Logger]` is mechanically possible but
breaks the runtime-default-fallback semantics (`slog.Default()` at
load-time, replaced via `Store`).

### 1.2 `deps.Logger` consumer sites (the migration surface)

58 calls across 13 files (verified via
`grep -c 'deps\\.Logger\\|handler\\.Logger' mcp/*.go`, excluding
test files):

| File | Sites | Notes |
|---|---:|---|
| `mcp/setup_tools.go` | 20 | The hot file — login flow, registry sync, OAuth bridge calls |
| `mcp/common.go` | 13 | Session establishment, token expiry, dev-mode panic recovery |
| `mcp/post_tools.go` | 5 | Order placement post-trade hooks |
| `mcp/common_response.go` | 3 | Marshal-failure logging on tool result emission |
| `mcp/gtt_tools.go` | 3 | GTT order tool wrappers |
| `mcp/alert_tools.go` | 2 | Auto-start ticker, auto-subscribe instrument warnings |
| `mcp/exit_tools.go` | 2 | Position-exit lifecycle |
| `mcp/session_admin_tools.go` | 2 | Admin session enumeration |
| `mcp/trailing_tools.go` | 2 | Trailing-stop tool wrappers |
| `mcp/watchlist_tools.go` | 2 | Watchlist tool wrappers |
| `mcp/composite_alert_tool.go` | 1 | Composite alert info-log |
| `mcp/context_tool.go` | 1 | Trading-context aggregation |
| `mcp/volume_spike_tool.go` | 1 | Volume-spike analytics |

All 58 sites are of the shape `h.deps.Logger.Warn("msg", "key",
val, "error", err)` or `handler.Logger().Warn(...)` — the slog-native
"alternating key-value pairs" idiom, NEVER threaded with ctx.

### 1.3 Tool-handler ctx-availability

Every tool handler receives `ctx context.Context` as the first
parameter — see `mcp/common.go:81-139`:

```go
func (h *ToolHandler) WithViewerBlock(ctx context.Context, toolName string)
func (h *ToolHandler) WithTokenRefresh(ctx context.Context, toolName string, ...)
func (h *ToolHandler) WithSession(ctx context.Context, toolName string, fn func(...))
```

So **ctx threading is FREE at every call site** — it's already in
scope. The reason tool handlers don't thread ctx into Logger is purely
that slog's surface doesn't require it.

### 1.4 ToolHandlerDeps construction sites

Empirically: **one** production construction site
(`common_deps.go:90 NewToolHandler(manager)`). Tests don't construct
the struct directly; they call `NewToolHandler(testManager)`. So
field-type changes have a single touch point.

### 1.5 Public-API call sites in app/wire.go

Verified at `app/wire.go:739`:
```go
mcp.RegisterToolsForRegistry(mcpServer, kcManager, app.Config.ExcludedTools,
    app.auditStore, app.logger, app.Config.EnableTrading, app.registry)
```

Plus the corresponding `RegisterDocResources` / `RegisterAppResources` /
`RegisterBuiltinWidgetPack` / `SetSignerLogger` / `SetPluginWatcherLogger`
calls. All take `*slog.Logger` directly today.

---

## 2. Two-and-a-half design options

### 2.1 Option A — Full migration (logport.Logger + ctx everywhere)

Match the Packages 1-5g pattern: `ToolHandlerDeps.Logger logport.Logger`,
all consumers thread ctx.

**Required changes**:
1. `ToolHandlerDeps.Logger *slog.Logger` → `logport.Logger`
2. `read_deps.go:19` field type change + `newReadDeps` wraps via
   `logport.NewSlog(...)`
3. Public API converters: `RegisterTools(..., logger logport.Logger, ...)`
   OR keep `*slog.Logger` and wrap at the boundary
4. `Logger()` accessor on ToolHandler returns `logport.Logger`
5. **All 58 call sites**: `h.deps.Logger.Warn("msg", k, v)` →
   `h.deps.Logger.Warn(ctx, "msg", k, v)`. For `Error`, signature
   becomes `Error(ctx, "msg", err, k, v)` — error promoted to
   positional.
6. `mcp/plugin_watcher.go`'s `atomic.Pointer[slog.Logger]` → either
   keep slog (special-case) or migrate to `atomic.Pointer[logport.Logger]`
   with a wrapped default
7. `mcp/plugin_sbom_signature.go` Registry field + setter
8. Tests: 0 production-side test changes expected (no test constructs
   ToolHandlerDeps directly), but assertions on log output via
   `slog.NewJSONHandler` capture would break if any exist.

**LOC estimate**: ~700-1500 production LOC. Likely needs splitting
into 3-4 sub-commits per the brief's "split per tool family if needed"
guidance:
- 6a: `ToolHandlerDeps` field + `read_deps` + `Logger()` accessor + 5
  trivial files (composite_alert / context / volume_spike /
  alert_tools / watchlist_tools / trailing_tools = 9 sites total) —
  ~150 LOC
- 6b: `setup_tools.go` standalone (20 sites — heaviest single file)
  — ~250 LOC
- 6c: `common.go` (13 sites) + `common_response.go` (3) — ~200 LOC
- 6d: `post_tools.go` (5) + `gtt_tools.go` (3) + `exit_tools.go` (2)
  + `session_admin_tools.go` (2) — ~150 LOC
- 6e: public API conversions in `mcp.go` / `resources.go` /
  `plugin_widgets_pack.go` / `ext_apps.go` + matching `app/wire.go`
  call sites — couples to Package 7/8, defer
- 6f: `plugin_watcher.go` atomic special-case + `plugin_sbom_signature.go`
  registry — ~100 LOC

**Pros**:
- Consistent pattern across kc/ and mcp/ — auditors see one shape
- Forced ctx threading propagates request-id / trace context through
  log lines automatically (every log gets the contextual fields the
  middleware injected)
- Future cross-cutting concerns (OpenTelemetry log SDK, structured
  audit field injection) plug in once at the port boundary

**Cons**:
- Tool handlers receive ctx as first parameter already — re-passing
  it to every log call is structural ceremony with limited semantic
  payoff
- 58 call-site edits is the largest single-package surface in the
  whole sweep
- For `Error`, the signature change (positional `err` argument) is a
  semantic shift that's easy to miscompose ("should the err go
  positional or as a key-value pair?") at every call site
- `plugin_watcher.go`'s atomic pattern needs careful migration —
  default-fallback on nil-Pointer.Load() is load-bearing for the
  fsnotify goroutine

### 2.2 Option B — Boundary preservation (*slog.Logger stays at tool handler entry)

Tool handlers continue consuming `*slog.Logger` natively through
`h.deps.Logger`. The mcp/ layer's public API stays slog-typed. Only
the **internal type seam** at `ToolHandlerDeps` could be `logport.Logger`
if we want, but the consumer side stays slog-shape.

**Required changes**:
- Zero. mcp/ stays as-is.
- Optionally: `Logger()` accessor could return both
  (`Logger() *slog.Logger` + `LoggerPort() logport.Logger`) for any
  future caller that wants the typed port — but this is speculative.

**Pros**:
- Zero code churn (Wave D Package 6 becomes a no-op)
- Tool handlers stay simple — slog's variadic key-value pairs match
  the existing 58-call-site idiom
- `plugin_watcher.go` atomic pattern stays unmolested (the load-bearing
  default-fallback semantics are slog-specific)
- Public API at `mcp.RegisterTools(...)` doesn't churn — `app/wire.go`
  doesn't need to flip for this package

**Cons**:
- Hybrid surface: `kc/*` uses port, `mcp/*` uses slog — auditors
  see two patterns and have to know "where the boundary is"
- Future cross-cutting log policies (e.g. OpenTelemetry log SDK)
  would need to handle two shapes in mcp/ → kc/
- Ceiling on the Wave D portability narrative — `feedback_decoupling_denominator.md`
  3rd-axis benefits don't extend to mcp/

### 2.3 Option C — Minimal (only the typed seam at ToolHandlerDeps)

`ToolHandlerDeps.Logger logport.Logger` stored internally; the
`Logger()` accessor returns the inner `*slog.Logger` via a port helper
(`logport.UnwrapSlog(...)`). All 58 call sites stay slog-shape.

**Required changes**:
1. `ToolHandlerDeps.Logger *slog.Logger` → `logport.Logger`
2. `newReadDeps` wraps via `logport.NewSlog`
3. `Logger() *slog.Logger` accessor unwraps via a new
   `logport.AsSlog(logport.Logger) *slog.Logger` helper
4. Add the `AsSlog` helper to `kc/logger/slog_adapter.go`
5. Public APIs (`RegisterTools` etc.) stay slog-typed at the wire.go
   boundary

**LOC estimate**: ~80-120 production LOC across 3 files
(`mcp/common_deps.go`, `mcp/read_deps.go`, `kc/logger/slog_adapter.go`).
**No call-site edits** required — the 58 consumer sites continue to
work because `Logger()` still returns `*slog.Logger`.

**Pros**:
- Achieves the Fx-graph-typing benefit (the deps struct member is
  now port-typed, so future graph-composition can inject test fakes
  that satisfy `logport.Logger`)
- Zero call-site churn — preserves the 58 working slog idioms
- Public API at `RegisterTools` unchanged — no wire.go coupling
- The hybrid shows up only at the type-graph edges, not in
  consumer code

**Cons**:
- Adds a new helper (`AsSlog`) to the port — the port now has both
  "wrap to" (NewSlog) and "unwrap to" (AsSlog) sides, which is
  conceptually weaker than a one-way port
- Auditors who scan for `*slog.Logger` references in mcp/ still see
  58 hits — the migration looks "incomplete" by the same metric
  Packages 1-5g were measured against
- Marginal-benefit-margin: the typed-seam is only useful when something
  actually depends on the port at the deps boundary. Today nothing
  does

---

## 3. Three-denominator analysis

Per `feedback_decoupling_denominator.md`:

### 3.1 Axis A — User-MRR

Zero impact for all three options. mcp/ Logger refactoring ships no
user-visible feature.

### 3.2 Axis B — Agent-concurrency

**Option A**: REDUCES Mode-2 friction on `mcp/common.go` (a hot file
— 13 deps.Logger sites means 13 potential edit collisions). Forcing
ctx threading also means new tool handlers being added by parallel
agents converge on the same `(ctx, msg, err, ...)` shape — easier to
review.

**Option B**: NEUTRAL. Status quo Mode-2 friction unchanged. Tool
handlers added in parallel still collide on `mcp/common.go` and
`mcp/setup_tools.go` whenever logging is involved.

**Option C**: NEUTRAL. Same as Option B at consumer sites; the typed
seam at `ToolHandlerDeps` gets parallel-edit friction because
`common_deps.go` is touched by every new field, but that's the
existing constructor-decomposition pattern (Investment K) which
already split builders per context. No new agent friction.

### 3.3 Axis C — Tech-stack portability

Per `e84a8f4` `.research/go-irreducible-evaluation.md`: "Go-irreducible"
means the choice of language is genuinely forced (e.g. kiteconnect
SDK is Go). For Logger, the choice is **design-driven, not Go-
irreducible** — every language has a structured logger; the question
is which contract wraps it.

**Option A**: Strongest Axis-C posture. The port boundary is
language-translatable: a future Rust rewrite of mcp/ defines a
`Logger` trait with the same five methods.

**Option B**: Weakest Axis-C posture. Tool handlers become coupled
to slog's variadic-args idiom. A Rust rewrite would need to invent
its own equivalent (the Rust `log`/`tracing` ecosystem doesn't have
a 1:1 of slog's `(msg, args...)` shape).

**Option C**: Middle ground. The deps boundary is portable; the
consumer-side idiom is not. A Rust rewrite would migrate the deps
seam mechanically and rewrite all 58 call sites to use Rust idioms
anyway (since the language change forces consumer rewrite), so the
loss of portability at the consumer side doesn't actually cost
anything beyond what a language swap would already require.

### 3.4 Combined verdict

| Axis | A (Full) | B (Preserve) | C (Minimal) |
|---|---|---|---|
| User-MRR | 0 | 0 | 0 |
| Agent-concurrency | + | 0 | 0 |
| Portability | + | − | 0 |
| **LOC budget** | 700-1500 | 0 | 80-120 |
| **Risk** | medium (58 edits, semantic shift on Error) | nil | low |

---

## 4. Recommendation

**Option C (Minimal: typed seam at ToolHandlerDeps only)**.

Rationale:

1. **Honest cost-benefit**: Option A is 700-1500 LOC for a benefit
   that materializes only when a future cross-cutting log concern
   (OpenTelemetry log SDK, structured audit field injection) actually
   ships. Option C delivers the typed-seam payoff at 80-120 LOC.
2. **Pattern continuity is preserved at the seam**: Auditors looking
   for "did mcp/ migrate to logport?" see `ToolHandlerDeps.Logger
   logport.Logger` and recognize the pattern continuation. The
   consumer-side slog idiom is then a deliberate exception, not an
   oversight.
3. **No premature ceremony**: Tool handlers receive ctx as the first
   parameter. Forcing a re-thread to every log call doesn't add
   semantic value today — request-id propagation already happens via
   `app.LoggerWithRequestID(logger, ctx)` upstream of the tool layer.
   When we DO need contextual log fields, we wire them at the
   middleware boundary, not at every leaf call site.
4. **Eliminates the `plugin_watcher.go` atomic special-case**:
   Option A would force a decision on the load-bearing default-fallback
   semantics. Option C leaves it untouched.
5. **Public API stability**: `RegisterTools(..., logger *slog.Logger,
   ...)` doesn't churn. `app/wire.go` doesn't need to flip for this
   package — Package 8 (wire.go) can decide independently.
6. **Portability ceiling honesty**: Per `e84a8f4`, this is design
   choice ceiling, not Go-irreducible. We're explicitly choosing to
   stop the Logger sweep at the typed-seam in mcp/ because the
   consumer-side idiom is not the bottleneck for any plausible
   future swap (a Rust rewrite would rewrite the consumer sites
   anyway).

---

## 5. Package 6 commit scope (under Option C)

**Deliverable**: a single commit `refactor(mcp): Wave D Phase 3 Package
6 — typed Logger seam at ToolHandlerDeps boundary` (~80-120 LOC).

### Files touched

1. **`kc/logger/slog_adapter.go`** (~10 LOC):
   Add `func AsSlog(l Logger) *slog.Logger` — extracts the underlying
   `*slog.Logger` from a `slogAdapter`, or constructs a fresh wrapping
   adapter for a non-slog Logger. The latter case is rare; main
   purpose is the `slogAdapter`-fast-path.

2. **`mcp/common_deps.go`** (~10 LOC):
   - `ToolHandlerDeps.Logger *slog.Logger` → `logport.Logger`
   - `func (h *ToolHandler) Logger() *slog.Logger` returns
     `logport.AsSlog(h.deps.Logger)`
   - Add `func (h *ToolHandler) LoggerPort() logport.Logger` for any
     future caller that wants the typed port directly

3. **`mcp/read_deps.go`** (~5 LOC):
   - `ReadDepsFields.Logger *slog.Logger` → `logport.Logger`
   - `newReadDeps(...)` wraps via `logport.NewSlog(manager.Logger)`

4. **No other mcp/*.go changes**. The 58 `deps.Logger` and `handler.Logger()`
   call sites continue to work unchanged because `Logger()` still
   returns `*slog.Logger`.

### Tests

Existing tests pass unchanged — `Logger()` accessor signature and
return shape preserved. No new test required (the seam is structural,
verified by compile).

If TDD discipline insists on a test artifact: add a small sanity
test in `mcp/common_deps_test.go` asserting `tool.LoggerPort() != nil`
when constructed via `NewToolHandler(manager)` with a real logger.
~10 LOC.

### WSL2 verification scope

```
go test ./mcp/ ./kc/logger/ -count=1
```

Per `feedback_narrow_test_scope_no_stash.md`. Don't run `./...` —
order-pilot or Slice 5 may have unrelated WIP.

---

## 6. Honest opacity (questions warranting user decision)

1. **Has the Axis-C portability rationale shifted?** If a concrete
   per-component language swap is queued for mcp/ (Rust / TS) within
   24 months, Option A's full migration becomes worth its 700-1500
   LOC. If not (per `kite-mrr-reality.md`'s ₹15-25k MRR projection),
   Option C is the honest call. Option C is recommended unless the
   user names a concrete swap trigger.

2. **`plugin_watcher.go`'s atomic.Pointer pattern**: Option C leaves
   it slog-typed. If the user wants a "uniform" mcp/ Logger story,
   Option A's 6f sub-commit covers it (~30 LOC for the atomic seam).
   If not, plugin_watcher stays as the documented exception (matches
   `feedback_decoupling_denominator.md`'s "state preconditions
   explicitly" guidance).

3. **Test fixtures in mcp/*_test.go**: I confirmed no test directly
   constructs `ToolHandlerDeps`; all go through `NewToolHandler(...)`.
   But order-pilot's emergency Money-cascade test-fixture audit might
   touch mcp/*_test.go — Package 6 should diff against test files
   pre-commit and abort if there's overlap. Same `feedback_narrow_test_scope_no_stash.md`
   discipline as Packages 5c-5g.

4. **Ordering vs Package 7 (app/) and 8 (wire.go)**: Option C avoids
   wire.go coupling. If Option A is chosen instead, the public-API
   sub-commits (6e: `RegisterTools` / `RegisterDocResources` /
   `RegisterAppResources` / `RegisterBuiltinWidgetPack`) MUST be
   bundled with the matching wire.go change, OR ship as a no-op
   conversion (accept `*slog.Logger` at the API and wrap internally).

---

## 7. TL;DR

| Option | LOC | Risk | Axis-C lift | Recommend? |
|---|---|---|---|---|
| **A** Full migration | 700-1500 | medium | + | only if concrete portability trigger named |
| **B** Boundary preservation | 0 | nil | − | no — leaves the typed seam unwired |
| **C** Minimal typed seam | 80-120 | low | 0 | **YES** — payoff matched to cost; no premature ceremony |

Recommend **Option C** as Package 6. ~80-120 LOC, single commit,
no consumer-side churn, no `plugin_watcher` atomic special-case
to navigate. Defer Option A unless a concrete cross-cutting log
concern (OpenTelemetry SDK, audit-field injector) forces the issue
later.
