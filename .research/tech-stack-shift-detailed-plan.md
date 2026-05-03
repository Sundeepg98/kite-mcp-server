# Tech-Stack Shift — Per-Component Detailed Plan

**Date**: 2026-05-02
**HEAD audited**: `5437c32` (post `disintegrate-and-holistic-architecture.md`).
**Charter**: research deliverable. **NO ship of code.** Builds on the
go.work foundation identified in `5437c32` and the existing IPC,
swap-shortlist, and parallel-tracks docs to produce a per-candidate
plan with empirical baselines, IPC method lists, triggers, mechanics,
toolchain readiness, costs, and reversibility.

**Anchor docs**:
- `.research/disintegrate-and-holistic-architecture.md` (`5437c32`) —
  go.work workspace pattern; Move 1+2+3 (~3 weeks); the structural
  precondition for any swap.
- `.research/component-language-swap-plan.md` (`a03694a`) — 24-month
  per-component shortlist (widgets→TS, riskguard→Rust, analytics→
  Python, telegram→TS aspirational, ticker→Rust aspirational).
- `.research/parallel-stack-shift-roadmap.md` (`8361409`) — Foundation
  phase §1 (4-5 weeks shared across tracks); per-track sequencing;
  counter-rec stay-in-Go analysis.
- `.research/ipc-contract-spec.md` (`4fa5a39`) — JSON-RPC 2.0 over
  stdio; capability handshake; error codes; cancellation; type
  mapping table.
- `docs/adr/0007-canonical-cross-language-plugin-ipc.md` (`202b993`)
  — netRPC over stdio (current riskguard pattern, gob-shape).
- `docs/adr/0009-...` (`a6fbe38`) — IPC contract + stack-shift
  deferral pair.
- `.research/algo2go-umbrella-product-strategy.md` (`645c034`) —
  Algo2Go reserved-but-not-active; triggers gate any rename.
- `feedback_decoupling_denominator.md` — three-axis ROI framework
  (user-MRR / agent-concurrency / tech-stack-portability).

**Empirical anchors at HEAD `5437c32`** (validated locally):

| Candidate | Prod LOC (current) | Test LOC | Internal kc/* deps | mcp-go coupling |
|---|---:|---:|---|---|
| `kc/riskguard/` | 3,550 | 6,498 | `kc/alerts`, `kc/domain`, `kc/logger`, `oauth` | YES — `middleware.go` |
| `kc/audit/` | 3,967 | 6,421 | `kc/alerts`, `kc/domain`, `kc/logger`, `oauth` | YES — `middleware.go` |
| `oauth/` | 2,736 | 13,087 | `kc/templates`, `kc/users` | NO |
| `kc/templates/` | 14,754 (HTML+JS) | n/a | n/a | n/a (consumed by `mcp/`) |
| `mcp/ext_apps.go` | 996 | (in widget tests) | n/a | YES |
| `mcp/sector_tool.go` | 413 | (in mcp/) | usecases | indirect (handler) |
| `mcp/indicators_tool.go` | 322 | (in mcp/) | usecases | indirect |
| `mcp/options_greeks_tool.go` | 825 | (in mcp/) | usecases | indirect |
| `mcp/backtest_tool.go` | 581 | (in mcp/) | usecases | indirect |

**Note**: `kc/credstore/` does NOT exist as a separate package today.
Encrypted credential storage is implemented in `kc/alerts/crypto.go`
(252 LOC AES-256-GCM helpers) plus stores embedded in `kc/alerts`
(KiteTokenStore / KiteCredentialStore / ClientStore). This doc
treats Candidate D's "kc/credstore/" target as the encryption-
helper subset of `kc/alerts/`, not a separate package — the broader
`kc/alerts/` package itself is too tangled to swap (4 internal deps,
9 external, used by 53 reverse callers per `5437c32` §1.2).

---

## TL;DR — what's justified TODAY (lead with verdict)

**No stack-shift is justified for execution today.** The empirical
baseline (latency budget unspent, agent-team scaling not at 4+
people, no paying-customer demand for second broker, MCP wire
protocol stable across hosts) does not fire any of the five
trigger conditions.

**However, two foundation investments ARE justified independently
of any swap decision** because they pay off on Axis B (agent
concurrency) regardless:

1. **Ship `go.work` Move 1+2+3** per `5437c32` (~3 weeks).
   This is the **strict prerequisite** for every swap below, and
   is positive-ROI on agent-concurrency alone.
2. **Extend ADR-0007 to JSON-RPC 2.0 spec** (already drafted in
   `4fa5a39`, ~300 LOC ADR amendment) — a doc-only deliverable
   that costs ~3 dev-days and unblocks any future swap decision
   without committing to one.

Of the five candidates, the highest-leverage near-term swap is
**Candidate B (Widgets→TS)**, but only IF a concrete UX-iteration
trigger fires (≥1 widget per week sustained AND >4-hour Go-template
iteration pain measured). Today neither holds. Candidate A
(Riskguard→Rust), C (Analytics→Python), D (OAuth/credstore→Rust)
all defer until concrete triggers. Candidate E (Audit Go-lib
spin-out) is **trigger-gated to 50+ parent-repo stars** per
`multi-product-and-repo-structure.md` §5.5 and does not require
a stack-shift at all.

The honest action is: ship `go.work`, draft IPC ADR, then **stop**
until a concrete trigger fires. Do not pre-build Rust/TS/Python
foundations on speculative Axis-C grounds — that's the failure
mode `feedback_decoupling_denominator.md` warns against.

---

## Phase 1 — Per-candidate deep dives

### Candidate A — `kc/riskguard/` → Rust

#### A.1 Empirical baseline

Per `5437c32` §1.2:
- **Prod LOC**: 3,550 across ~22 files (`check.go`, `guard.go`,
  `circuit_limit.go`, `dedup.go`, `subprocess_check.go`, etc.).
- **Test LOC**: 6,498 (high-quality coverage; gold-test data exists).
- **Internal `kc/*` deps**: `kc/alerts`, `kc/domain`, `kc/logger`,
  `oauth`. Plus subpackage `kc/riskguard/checkrpc/` (216 LOC) which
  is already the cross-language IPC contract per ADR-0007.
- **External deps**: 6, including `mcp-go` and
  `hashicorp/go-plugin`.
- **Reverse-deps (callers)**: 24 (per `5437c32` §1.2). Top
  callers: `kc/usecases`, `kc/papertrading`, `kc/telegram`, `mcp/`.
- **mcp-go coupling**: `kc/riskguard/middleware.go` imports
  `mark3labs/mcp-go/server` and `mark3labs/mcp-go/mcp`. This is
  the adapter that needs to move to `kc/riskguard/mcpadapter/`
  (~2-3 dev-days per `5437c32` §1.3) for clean library spin-out
  AND for any language port.

#### A.2 Stack-shift rationale

Go is fine here at current load — risk-check latency is dominated
by broker round-trip (~50-200ms), not local compute (~0.1-2ms). The
Rust case is **NOT performance-essential today**. It IS justified
on:
- **Predictable latency under bursty load** — eliminate GC pause
  variance on the order-placement critical path (Rust has no GC).
- **Memory-safe ownership** for the rolling-window anomaly state
  (μ+3σ tracker) — Rust's borrow checker prevents the data-race
  patterns Go's `sync.Mutex` discipline must enforce manually.
- **Throughput headroom** if SEBI Algo-ID enforcement raises us
  to 1k+ orders/min sustained.

None of these are pressing. Go's ~1-3 ms p99 worst case is well
within the 50ms Kite API round-trip envelope.

#### A.3 IPC boundary design

Per `4fa5a39` §3.1 (capability handshake) and existing `checkrpc/`
shape, the riskguard subprocess advertises:

| Method | Direction | Purpose |
|---|---|---|
| `riskguard.checkOrder` | host → plugin | pre-trade order safety check (returns `CheckResult`) |
| `riskguard.checkPosition` | host → plugin | optional — pre-position check for hedging |
| `riskguard.killSwitch.set` | host → plugin | flip global kill switch on/off |
| `riskguard.killSwitch.get` | host → plugin | query kill-switch state |
| `riskguard.dailyStats.reset` | host → plugin | clean daily-counter rollover at IST midnight |
| `riskguard.anomaly.observe` | host → plugin | feed post-execution sample to baseline tracker |
| `riskguard.anomaly.getBaseline` | host → plugin | query rolling μ+3σ for tool/user |
| `riskguard.config.update` | host → plugin | hot-update limits without restart |
| `riskguard.metrics.snapshot` | host → plugin | scrape per-check metrics for Prometheus |
| `riskguard.shutdown` | host → plugin | graceful exit (per §4.4 IPC spec) |

What stays in-process Go-side (does NOT cross IPC): the **9
middleware-chain checks** that wrap Riskguard above (Audit, Hooks,
CircuitBreaker, RateLimiter, Billing, PaperTrading) per
`CLAUDE.md` middleware list. Those are Go-native HTTP/MCP
middleware; they call into `riskguard.checkOrder` via the IPC
boundary as one node in the chain, but the chain itself stays Go.

#### A.4 Trigger condition

Concrete + measurable. Any ONE of:
1. **Latency**: P99 of `riskguard.checkOrder` exceeds 5ms under
   sustained 100 RPS load (Prometheus histogram from
   `metrics.snapshot`). Today: nowhere near.
2. **Throughput**: sustained order rate > 1k/min — sec/min figure
   from production aggregation. Today: low-thousands per DAY.
3. **GC pause incident**: production incident attributable to Go GC
   pause crossing the order-placement critical path (postmortem-
   documented, not speculative). Today: no recorded incident.
4. **SEBI Algo-ID enforcement** raises throughput requirement
   beyond Go's comfortable envelope. Today: not enacted.

#### A.5 Migration mechanics

Step-by-step, dev-weeks per step, assuming `go.work` Move 1+2 has
already landed (precondition):

| Step | What | Dev-weeks |
|---|---|---|
| 1 | (precondition) `kc/riskguard/` already a workspace member with own `go.mod` per `5437c32` Move 2 — and `mcpadapter/` split out. | 0 (already done) |
| 2 | Stand up Rust crate `riskguard-rs`. `cargo init`. Pull `tokio`, `serde_json`, `serde`, `jsonrpc-core` (or hand-roll JSON-RPC 2.0 over stdio per `4fa5a39`). Implement `Initialize` handshake and one capability (`riskguard.checkOrder` minimal stub returning `Allow`). | 2 |
| 3 | Port the 9 checks to Rust one-at-a-time. Each check has Go gold-test data; run Rust crate against the same JSON fixtures and assert byte-equal `CheckResult` output. **Critical**: the existing 6,498 LOC of Go tests becomes the parity oracle. | 4-6 |
| 4 | Cutover. Replace `kc/riskguard/`'s implementation with a thin Go proxy that spawns the Rust subprocess and forwards JSON-RPC. Keep the public Go API (`riskguard.Check(ctx, order)`) identical so callers don't change. | 2 |
| 5 | Archive Go original. The proxy reduces to ~50 LOC. The 3,550 LOC of Go core becomes documentation/reference. Tests stay alive (they now exercise the proxy → Rust path). | 1 |

**Total Step 2-5**: 9-11 dev-weeks single-developer (NOT counting
Foundation IPC work which is shared).

#### A.6 Tooling/ecosystem readiness (Aug 2025 / current)

- **Rust 1.85**: Stable. Native async via `tokio` 1.40+.
- **JSON-RPC**: `jsonrpc-core` is unmaintained; recommend hand-roll
  per `4fa5a39` §9.1 reference impl (~250 LOC). Alternative:
  `tower-jsonrpc` is current.
- **`serde_json`**: standard, fast, mature.
- **`prometheus-client`**: native `/metrics` endpoint per Foundation
  §1.4.
- **`chrono`**: time/RFC-3339 per IPC type mapping §2.3.
- **`rust_decimal`**: deferred (per `4fa5a39` §2.4, decimal-mode is
  YAGNI for this codebase today).
- **No `gokiteconnect` equivalent in Rust** — but riskguard does NOT
  need a broker SDK; it's pure local compute.

Verdict: **ecosystem is ready**. No blockers.

#### A.7 Cost estimate

| Scenario | Dev-weeks |
|---|---|
| Optimistic | 9 (smooth port, no surprises, single dev who knows Rust) |
| Realistic | 14 (port + Rust onboarding 4 wk if dev is new + minor surprises) |
| Pessimistic | 20+ (Rust onboarding stretches; ecosystem-gap surfaces in `tokio` async semantics; CI Windows-Rust toolchain friction) |

**Realistic 14 weeks is consistent with `8361409` §4.5
(8-10 weeks for C.1 plus 4-8 weeks Rust onboarding).**

#### A.8 Reversibility

**Cheap.** The cutover at Step 4 keeps the public Go API
identical. Reverting = restore the archived Go core, replace
the proxy, remove `riskguard-rs/` from the workspace, drop the
Rust subprocess. The IPC contract IS the boundary; reverting is
a `git revert` of the cutover commit plus archiving the Rust
crate. ~1 dev-day to revert.

---

### Candidate B — Widgets / `kc/templates/*` + `mcp/ext_apps.go` → TypeScript

#### B.1 Empirical baseline

Per `5437c32` and HEAD listing:
- **Prod LOC**: 14,754 LOC across `kc/templates/` (HTML/CSS/JS;
  ~36 templates including `dashboard.html` 59,922 bytes,
  `chart_app.html` 31,712 bytes, `activity.html` 30,686 bytes).
  Plus `mcp/ext_apps.go` 996 LOC + `mcp/plugin_widgets*.go`
  ~1,000 LOC + 6 individual widgets ~100-200 LOC each.
- **Test LOC**: tests are in `mcp/plugin_widgets_test.go` (215)
  and per-widget tests; templates themselves have no Go tests
  beyond rendering smoke.
- **Internal `kc/*` deps**: templates are consumed by `mcp/` and
  `kc/ops/`; no internal kc/ deps OUT.
- **External deps**: `appbridge.js` (135 LOC) embedded inline per
  widget per MCP protocol constraint.
- **Reverse-deps**: every widget tool handler in `mcp/`.
- **mcp-go coupling**: `ext_apps.go` registers MCP `ui://` resources
  per the SDK; the widget bodies themselves are HTML+JS strings
  served as resource content.

#### B.2 Stack-shift rationale

The MCP Apps SDK widget surface is JS-native by design. Today we
ship Go-templated HTML+JS strings; iteration goes:

```
edit Go template → rebuild binary → restart server →
  reload Claude.ai → check render.
```

A TypeScript+esbuild build pipeline replaces Go templating with:

```
edit TSX → esbuild watcher rebuilds bundle → Go server serves
  the bundle artifact → reload Claude.ai → check render.
```

What Go fails to provide elegantly: **type-safe AppBridge
typings** (`window.openai` API), **JSX/TSX templating
ergonomics**, **hot-reload** (esbuild has it; Go's
`html/template` does not natively). This is a developer-velocity
issue, not a runtime issue.

#### B.3 IPC boundary design

**Track A's IPC question is unusual** — there is no plugin/host
runtime split. The widget bundle is BUILT in TS at compile/dev
time and SERVED as bytes by the Go runtime. So the "IPC" is
build-time:

| Boundary | Direction | Mechanism |
|---|---|---|
| Build-time | TS → Go | `esbuild` outputs `dist/widget-X.js` bundle; Go embeds via `//go:embed` directive into binary |
| Runtime widget→Go | TS (browser) → Go (server) | MCP `ui://` resource fetch; existing protocol — no change |
| Runtime Go→TS | Go server → TS (browser) | response data injection via `structuredContent` per MCP spec; existing protocol — no change |

So the IPC boundary at `4fa5a39` is NOT exercised by Track A —
there's no subprocess. The "swap" is really a build-toolchain
swap, not a runtime split. This is structurally simpler than
Track A or C below.

#### B.4 Trigger condition

Concrete + measurable. Any ONE of:
1. **Iteration friction**: time-to-add-new-widget exceeds 4 hours
   (measured: clock from "decide to add chart widget X" to
   "deployed and rendering"). Today: 6 hours per widget per
   `8361409` §8.1; trigger nearly fired but velocity isn't user-
   visible bottleneck.
2. **Sustained widget demand**: customer requests for new widgets
   ≥1 per week sustained over 4+ weeks. Today: <1 per month.
3. **ChatGPT Apps SDK adoption** demands TS-native widgets (the
   `openai/outputTemplate` shim mentioned in
   `kite-launch-blockers-apr18.md` becomes mandatory). Today: shim
   is a 2-line patch deferred.
4. **MCP SDK upstream forces TS** — the Go MCP SDK (mark3labs/mcp-go)
   stops shipping widget primitives. Today: parity at `e8ccd34`.

#### B.5 Migration mechanics

Assuming `go.work` Move 1 has landed:

| Step | What | Dev-weeks |
|---|---|---|
| 1 | (precondition) Add `kc/widgets-ts/` workspace member with `package.json`, `tsconfig.json`, `esbuild.config.js`. Embed AppBridge typings. | 0.5 |
| 2 | Port one widget (recommend `pnl_sparkline.go` 192 LOC — smallest) to React/TSX. Validate rendering parity in Claude.ai + Claude Desktop + Cursor. | 1.5 |
| 3 | Build pipeline: esbuild watcher + Go `//go:embed` of bundle output + CI step that runs `pnpm build` before `go build`. | 1 |
| 4 | Port remaining 5 widgets (margin_gauge, returns_matrix, sector_donut, ip_whitelist, plus the per-tool widgets in plugin_widgets_pack.go). Each ~3-5 days. | 3-4 |
| 5 | Port `kc/templates/dashboard.html`, `activity.html` (the long-form dashboard pages). These are SSR'd by `kc/ops/`; this is the larger chunk. **Consider deferring this** — Go-side SSR for dashboards is fine; TS only buys widget-pace iteration. | 4-6 (optional) |
| 6 | Archive Go template strings → keep as fallbacks for non-MCP HTTP routes. | 0.5 |

**Total Step 1-4**: 6-7 dev-weeks for widget bodies only.
**Total Step 1-5**: 10-13 dev-weeks if dashboard SSR also moves.

#### B.6 Tooling/ecosystem readiness

- **TypeScript 5.5+**: stable, mature.
- **Build tool**: **esbuild** (Go-native binary, fast) is the
  recommended primary; Bun is an option but Bun-as-runtime is
  not needed (we only need the build); Vite is overkill (no SPA
  routing). esbuild as bundler + tsc as type-check is the lean
  combo.
- **Framework**: react@18+ for components (stable). Alternative:
  Preact for smaller bundle. **Avoid Nest.js / Next.js** —
  those are server frameworks; we need just a compiled bundle.
- **Package manager**: pnpm (matches mcp-remote ecosystem per
  `8361409` §1.2).
- **Type-safety**: `@modelcontextprotocol/sdk` exposes the
  `window.openai` AppBridge types per MCP Apps SDK; available
  on npm as official upstream.
- **Testing**: vitest for unit; Playwright for visual diff.

Verdict: **ecosystem is ready and mature**. The widget swap is
the lowest-risk of the five candidates because the build artifact
(JS bundle) is just bytes the Go server serves — no runtime
process split.

#### B.7 Cost estimate

| Scenario | Dev-weeks (widgets only, Step 1-4) |
|---|---|
| Optimistic | 5 (dev knows React/esbuild; smooth bundling; minimal AppBridge surprises) |
| Realistic | 7 |
| Pessimistic | 10 (esbuild → Go //go:embed integration surfaces minor friction; per-widget visual-parity QA stretches) |

For full Step 1-5 including dashboard SSR: realistic 10-13
dev-weeks per `8361409` §2.5.

#### B.8 Reversibility

**Trivially cheap.** Widgets are bundle artifacts; reverting =
delete `kc/widgets-ts/`, remove the embed directive, restore
the Go-templated HTML strings (which stay in git history). The
runtime sees no difference because the IPC is the MCP `ui://`
resource bytes — they're produced by either toolchain. ~0.5
dev-day to revert.

---

### Candidate C — Analytics tools → Python

(`mcp/sector_tool.go` + `mcp/indicators_tool.go` +
`mcp/options_greeks_tool.go` + `mcp/backtest_tool.go`)

#### C.1 Empirical baseline

| File | Prod LOC | What |
|---|---:|---|
| `mcp/sector_tool.go` | 413 | 150+ stocks → 20+ sectors; portfolio sector exposure |
| `mcp/indicators_tool.go` | 322 | RSI, SMA, EMA, MACD, Bollinger Bands |
| `mcp/options_greeks_tool.go` | 825 | Black-Scholes Greeks (delta, gamma, theta, vega, IV) + 8 multi-leg strategy builders |
| `mcp/backtest_tool.go` | 581 | 4 strategies (SMA crossover, RSI reversal, breakout, mean reversion) + Sharpe ratio + max drawdown |
| **Total** | **2,141** | pure-function compute; no SQL, no broker calls |

- **Internal `kc/*` deps**: route through `kc/usecases/` and
  receive plain Go structs (Quote, Holding, Position) — minimal.
- **External deps**: stdlib only for the math; broker DTO types.
- **Reverse-deps**: none — these are leaf tools called by the MCP
  router, not consumed by other packages.
- **mcp-go coupling**: indirect (via tool handler registration in
  `mcp/`); the compute kernels themselves are pure Go.
- **Test LOC**: each tool has 50-100 LOC of test in `mcp/`.

#### C.2 Stack-shift rationale

The "ecosystem mismatch" framing per `a03694a` §2.5 is
**accurate and well-documented**:

| Function | Go (current) | Python equivalent |
|---|---|---|
| Sharpe ratio | hand-rolled | `scipy.stats` 1 line |
| RSI / MACD / Bollinger | hand-rolled | `pandas-ta.{rsi,macd,bbands}` 1 line each |
| Black-Scholes Greeks | hand-rolled (180 LOC) | `scipy.stats.norm` + closed-form ~50 LOC |
| Multi-leg strategies | hand-rolled (645 LOC) | `quantlib.OptionStrategy` built-in |
| Backtest engine | hand-rolled (581 LOC) | `vectorbt.Portfolio.from_signals` ~30 LOC |

This is NOT performance — Python via subprocess + pandas batch
is on par with Go for analytics. It's **roadmap velocity**: new
analytics tools (PCA, factor models, Monte-Carlo VaR) are 1-2
day tasks in Python vs 1-2 week tasks in Go. The recent
`analyze_concall` / `peer_compare` / `fii_dii_flow` tools shipped
as **LLM-coordinator** pattern (delegating analysis to Claude)
precisely because the Go-side compute is too expensive to write.

#### C.3 IPC boundary design

Per `4fa5a39` §3.1:

| Method | Direction | Purpose |
|---|---|---|
| `analytics.computeSharpe` | host → plugin | Sharpe ratio from price series |
| `analytics.computeMaxDrawdown` | host → plugin | max drawdown from equity curve |
| `analytics.indicators.rsi` | host → plugin | RSI series from OHLC |
| `analytics.indicators.macd` | host → plugin | MACD line/signal/hist |
| `analytics.indicators.bbands` | host → plugin | Bollinger upper/middle/lower |
| `analytics.indicators.ema` | host → plugin | EMA series (parameterized period) |
| `analytics.indicators.sma` | host → plugin | SMA series |
| `analytics.options.greeks` | host → plugin | BS delta/gamma/theta/vega/IV |
| `analytics.options.buildStrategy` | host → plugin | multi-leg payoff diagram |
| `analytics.backtest.run` | host → plugin | backtest a strategy across price history |
| `analytics.sector.exposure` | host → plugin | portfolio → sector breakdown |
| `analytics.shutdown` | host → plugin | graceful exit |

**Critical wire-format note**: backtest results return ~10-100KB
of equity-curve JSON per call. Per `4fa5a39` §1.2, JSON-RPC adds
~2-5ms parse overhead at this size. Acceptable for analytics
(human-perceived response times). Not acceptable for ticker
dispatch — but ticker is not in scope here.

What stays Go: tool registration, MCP arg parsing, response
shaping, audit logging. Only the **numeric kernel** crosses IPC.

#### C.4 Trigger condition

Concrete + measurable. Any ONE of:
1. **Roadmap throughput**: ≥10 new analytics tools requested per
   quarter where each genuinely benefits from numpy/pandas/scipy.
   Today: 3-5 deferred (PCA, factor models, MC VaR). Below
   threshold.
2. **LLM-coordinator pattern grows uncomfortably**: ≥3 tools
   land as "LLM does the math" because Go-side compute was too
   expensive to write. Today: 3 such tools shipped Apr 2026
   (`analyze_concall`, `peer_compare`, `fii_dii_flow`); right at
   the threshold but not over.
3. **Customer demand for Python-style features** — paying users
   request volatility surfaces, MC VaR, factor regressions.
   Today: not seen.

#### C.5 Migration mechanics

Assuming `go.work` Move 1 has landed AND IPC contract spec is
ratified (Foundation §1.1):

| Step | What | Dev-weeks |
|---|---|---|
| 1 | (precondition) Add `kc/analytics-py/` workspace member with `pyproject.toml` (uv-managed), `pandas`, `numpy`, `scipy`, `pandas-ta`, `quantlib`, `vectorbt`. Stub `analytics.shutdown` capability. | 1 |
| 2 | Stand up Python subprocess JSON-RPC server (~200 LOC of `aiohttp`-style stdio server, or hand-rolled per `4fa5a39` §9.2). Implement Initialize handshake. | 1 |
| 3 | Port one tool first — recommend `sector_tool.go` (413 LOC, lowest risk, dict comprehension + groupby). Run gold-test parity vs Go. | 1 |
| 4 | Port remaining tools (indicators, options-greeks, backtest). Each 1-1.5 weeks. | 4-5 |
| 5 | Cutover. Replace each Go tool's compute body with a thin proxy that calls the Python subprocess. Keep MCP-side tool registration / arg parsing in Go. | 1.5 |
| 6 | Add new analytics features (PCA, factor models, MC VaR). **THIS is where the velocity payoff lands.** | 2-3 |

**Total Step 1-5**: 8-10 dev-weeks. Step 6 is bonus value (new
features that wouldn't exist in Go-only timeline).

#### C.6 Tooling/ecosystem readiness

- **Python 3.12+**: stable, mature.
- **uv**: 10× faster than poetry per March 2026 benchmarks; the
  recommended package manager (matches `8361409` §1.2).
- **aiohttp / hand-roll JSON-RPC**: hand-roll is ~150 LOC, no
  framework lock-in.
- **pandas 2.2+, numpy 2.0+, scipy 1.13+**: standard stack.
- **pandas-ta**: 100+ technical indicators, MIT license.
- **quantlib-python**: BSD-style license, mature, used in
  production at major banks.
- **vectorbt**: Apache-2.0, fast vectorized backtester.

Verdict: **ecosystem is exceptionally mature**. This is the
language ecosystem with the smallest gap-to-greenfield.

#### C.7 Cost estimate

| Scenario | Dev-weeks (Step 1-5, port only) |
|---|---|
| Optimistic | 7 (Python proficient dev; smooth pandas marshalling; minimal IPC surprises) |
| Realistic | 9 |
| Pessimistic | 13 (DataFrame ↔ JSON marshalling friction; per-call cold-start surprises; Windows uv toolchain edge cases) |

Step 6 (new features) is **roadmap-positive on Axis A user-MRR**
per `8361409` §3.4 — the only candidate that pays user-MRR
directly via shipped features.

#### C.8 Reversibility

**Cheap.** Same pattern as A: keep Go API identical; cutover at
Step 5 inserts a proxy. Reverting = restore the Go compute body,
delete the Python workspace member, drop the subprocess. ~1
dev-day.

---

### Candidate D — `oauth/` + credstore (`kc/alerts/crypto.go`) → Rust

#### D.1 Empirical baseline

- **`oauth/` Prod LOC**: 2,736 across 11 files (`config.go`,
  `handlers.go`, `middleware.go`, `stores.go`, etc.).
- **`oauth/` Test LOC**: 13,087 (very high — auth is correctness-
  critical).
- **`oauth/` Internal `kc/*` deps**: `kc/templates`, `kc/users`.
  No `kc/alerts` or `kc/domain` direct.
- **`oauth/` External deps**: 4 (golang-jwt/jwt, gorilla/sessions,
  google sso libs).
- **Reverse-deps**: 20+ (used by every authenticated path).
- **`kc/alerts/crypto.go`**: 252 LOC AES-256-GCM helpers via HKDF
  from `OAUTH_JWT_SECRET`. Used by KiteTokenStore,
  KiteCredentialStore, ClientStore.
- **mcp-go coupling**: NO direct.

**Critical caveat**: `kc/alerts/` itself has 53 reverse callers
and 4 internal deps; the crypto helpers can be extracted but the
**stores** (KiteTokenStore etc.) live inside `kc/alerts/` and
cannot be cleanly extracted without first separating crypto from
storage. This is a non-trivial precondition that the current
audit doesn't account for.

#### D.2 Stack-shift rationale

`a03694a` §2.8 says **stay-in-Go** for OAuth: "JWT libraries are
mature in every language; the OAuth dance has fewer ergonomic
differences across stacks than other domains." The Rust framing
(`a03694a` "constant-time crypto + memory-safe primitives") is
**qualitative, not quantitative**: Go's `crypto/aes` and
`crypto/hkdf` are battle-tested with constant-time implementations
already; `golang-jwt/jwt` has 5+ years of production hardening
with no known CVE in our usage.

The honest case for Rust here is:
- **Compile-time guarantees against key reuse** (Rust's ownership
  forbids holding two mutable refs to a key)
- **`zeroize` crate** — explicit secret-clearing on drop
- **`subtle` crate** — constant-time comparison primitives
  enforced at compile time

These are real qualitative improvements but produce **zero
measurable security incident reduction** at current scale. There
is no recorded incident in production attributable to Go's crypto
stack.

#### D.3 IPC boundary design

If swapped, the Rust subprocess becomes **`oauth-rs`** advertising:

| Method | Direction | Purpose |
|---|---|---|
| `oauth.token.issue` | host → plugin | mint JWT (access/refresh) |
| `oauth.token.verify` | host → plugin | verify JWT signature + claims; return claims dict |
| `oauth.token.rotate` | host → plugin | rotate signing key (zero-downtime) |
| `oauth.dcr.register` | host → plugin | dynamic client registration → client_id + encrypted client_secret |
| `oauth.pkce.verify` | host → plugin | PKCE challenge/verifier check |
| `oauth.crypto.encrypt` | host → plugin | AES-256-GCM encrypt blob (for token store) |
| `oauth.crypto.decrypt` | host → plugin | AES-256-GCM decrypt blob |
| `oauth.shutdown` | host → plugin | graceful exit |

**Risk**: every authenticated request hits `oauth.token.verify`.
At 10 req/s steady, that's 10 IPC calls/s — JSON-RPC over stdio
~1ms p99 per call adds 10ms/s wall-clock load distributed across
requests. **Not catastrophic but measurable.** A persistent
`unix-socket + binary protocol` could cut this to ~50µs but adds
implementation complexity per `4fa5a39` §11 deferred work.

What stays Go: the HTTP handler chain (`oauth/handlers.go`),
session middleware, cookie management, redirect URL building.
Only the cryptographic kernel crosses IPC.

#### D.4 Trigger condition

Concrete + measurable. Any ONE of:
1. **Production crypto incident**: a CVE or audit finding
   attributable to the Go crypto stack used in `oauth/` or
   `kc/alerts/crypto.go`. Today: none.
2. **External security audit demands**: SOC 2 / ISO 27001
   auditor flags Go crypto vs Rust crypto as a finding. Today:
   audit not in flight per `kite-cost-estimates.md`.
3. **JWT signing key compromised** + rotation hot-path needs
   memory-safe guarantees against window-of-vulnerability key
   leak. Today: not happened.
4. **Regulatory mandate** — SEBI requires constant-time crypto
   primitives by spec (currently no such requirement).

#### D.5 Migration mechanics

Same shape as Candidate A, but **larger surface** (2,736 LOC vs
3,550 — comparable; but with 13,087 LOC of correctness-critical
tests):

| Step | What | Dev-weeks |
|---|---|---|
| 1 | (precondition) `oauth/` becomes a workspace member. Crypto helpers split out from `kc/alerts/` into `kc/crypto/` workspace member. **This precondition itself is ~2 weeks** because of `kc/alerts/`'s tangle. | 2 |
| 2 | Stand up Rust crate. Pull `jsonwebtoken`, `aes-gcm`, `hkdf`, `zeroize`, `subtle`, `argon2`, `rand_chacha`. Implement Initialize. | 2 |
| 3 | Port crypto helpers (AES-256-GCM, HKDF). Run vs Go gold-test cipher-text fixtures. | 2 |
| 4 | Port JWT issuer/verifier. Run vs golang-jwt cross-validation (issue in Go, verify in Rust; issue in Rust, verify in Go). | 3 |
| 5 | Port DCR + PKCE. Port HTTP-handler-side glue stays Go. | 3 |
| 6 | Cutover. Replace `oauth/` crypto kernel with proxy. | 2 |
| 7 | Archive Go original. | 1 |

**Total Step 1-7**: 15 dev-weeks. Pessimistic adds Rust-onboarding
weeks per Candidate A.

#### D.6 Tooling/ecosystem readiness

- **Rust crypto crates**: `aes-gcm`, `hkdf`, `argon2`, `chacha20-poly1305`
  — RustCrypto ecosystem; well-maintained; FIPS-aligned.
- **`jsonwebtoken`**: mature; matches the JOSE spec subset we use.
- **`zeroize` / `subtle`**: standard.
- **JSON-RPC**: same as Candidate A.

Verdict: **ecosystem is ready**. The blocker is the precondition
(splitting crypto from `kc/alerts/`), not the Rust side.

#### D.7 Cost estimate

| Scenario | Dev-weeks |
|---|---|
| Optimistic | 12 |
| Realistic | 17 |
| Pessimistic | 25+ (Rust onboarding + `kc/alerts/` tangle takes longer to split + cross-language JWT bug-for-bug parity surprises) |

#### D.8 Reversibility

**Moderate.** Same proxy pattern as A and C, but the
correctness-critical surface (auth) raises the stakes — a rollback
mid-incident requires confidence the Go fallback is current with
the Rust state (e.g., key rotations, DCR registrations).
Operationally: ~2 dev-days to revert + plus a synchronization
window. **Don't deploy this without a tested rollback drill.**

---

### Candidate E — `kc/audit/` standalone Go library (NO stack-shift)

Included for contrast — to show what a clean Go-lib spin-out looks
like without language porting.

#### E.1 Empirical baseline

Per `5437c32` §1.2:
- **Prod LOC**: 3,967 across ~24 files.
- **Test LOC**: 6,421.
- **Internal `kc/*` deps**: `kc/alerts`, `kc/domain`, `kc/logger`,
  `oauth`. (Same as riskguard.)
- **External deps**: 6, including `mcp-go`.
- **Reverse-deps**: 34.
- **mcp-go coupling**: `kc/audit/middleware.go` exposes
  `ToolHandlerMiddleware` — must move to `kc/audit/mcpadapter/`
  (~2-3 dev-days per `5437c32` §1.3).

#### E.2 Stack-shift rationale

**None — stay Go.** SQLite-go binding is mature; SigV4 hash
publisher is thin; rolling baseline is 100 LOC of stats. No
performance, no ecosystem-mismatch case. The "swap" here is to
**a separate Go module with its own `go.mod`** — i.e. the
`go.work` Move 2 from `5437c32`.

#### E.3 IPC boundary design

**No IPC.** It stays in-process Go. The boundary is the **Go
package API**: `audit.Logger`, `audit.HashChain`, `audit.Anomaly`.

#### E.4 Trigger condition

Per `multi-product-and-repo-structure.md` §5.5:
1. 50+ stars on parent repo
2. ≥2 inbound questions about standalone use within 30 days
3. ≥5 forks of the `kc/audit/` subdirectory
4. FLOSS-fund pitch needs separable artifact
5. Second consumer integrates (e.g., a non-Kite MCP server
   adopts the audit pattern)

These triggers are **moderate-probability** in 24mo (per
`fork-loc-split-and-tier3-promotion.md` §3) — combined ~20%.

#### E.5 Migration mechanics

| Step | What | Dev-weeks |
|---|---|---|
| 1 | (precondition) `kc/audit/` already a workspace member per `5437c32` Move 2. mcp-go adapter split out. | 0 (already done in Move 2) |
| 2 | Decide: stay in monorepo as workspace member (free), OR promote to standalone repo `tool-call-audit-go`. | 0.2 |
| 3 | If promoted: `git filter-repo` history into new repo; tag v0.1.0; update parent `go.mod`. | 1.5 |
| 4 | Document. Wire CI in new repo. | 0.5 |

**Total**: ~2 dev-weeks for full spin-out (vs 9-15 for the
language-porting candidates). This is the cheapest "disintegration"
move.

#### E.6 Tooling/ecosystem readiness

Already met — Go workspace pattern handles this trivially per
`5437c32` Phase 2A.

#### E.7 Cost estimate

| Scenario | Dev-weeks |
|---|---|
| Optimistic | 1.5 |
| Realistic | 2 |
| Pessimistic | 3 (history-rewrite hiccups; CI plumbing surprises) |

#### E.8 Reversibility

**Cheapest of all.** A Go-lib spin-out can always be re-vendored
into the monorepo by un-doing the `git filter-repo`. ~0.5 dev-day
to revert.

---

## Phase 2 — Cross-component synergies / sequencing

### 2.1 Foundation phase (shared across language tracks)

Per `8361409` §1: ~4-5 weeks single-developer Foundation work that
**any** language track shares. Components:

| Item | Calendar | Notes |
|---|---|---|
| §1.1 IPC contract spec (extending ADR-0007 to JSON-RPC 2.0) | 1.5-2 wk | DRAFTED at `4fa5a39`; needs ADR amendment + reference Go client |
| §1.2 Per-language CI (one of TS/Python/Rust at a time) | 1 wk per language | parallelizable across languages |
| §1.3 Multi-process deploy plumbing (Fly.io memory budgets) | 3-5 days | shared |
| §1.4 Per-language observability glue | 1 wk per language | shared schema |
| §1.5 SBOM + dep-scan per language | 2-3 days each | shared |

**`go.work` adoption (per `5437c32` Move 1+2+3, ~3 weeks) is a
strict precondition for the Foundation phase** — without module
boundaries the IPC boundary has nowhere to attach.

### 2.2 Track sequencing within each language

| Track | First-component PoC | Foundation cost | First-component cost | Incremental cost per add'l component |
|---|---|---|---|---|
| **A — TS** | `pnl_sparkline` widget (192 LOC) | 4-5 wk shared + 1 wk TS-CI | 1.5 wk | 1 wk per widget |
| **B — Python** | `sector_tool` (413 LOC) | 4-5 wk shared + 1 wk Py-CI | 1 wk | 1-1.5 wk per analytics tool |
| **C — Rust** | `riskguard.checkOrder` minimal | 4-5 wk shared + 1 wk Rust-CI + **4-8 wk Rust onboarding** | 4-6 wk | 2-3 wk per check |

**Track A first-PoC threshold**: 4-5 wk Foundation + 1 wk TS-CI +
1.5 wk widget = **~7 wk total for first widget on TS infra**.

**Track B first-PoC threshold**: 4-5 wk Foundation + 1 wk Py-CI +
1 wk sector_tool = **~7 wk total**.

**Track C first-PoC threshold**: 4-5 wk + 1 wk + (4-8 wk
onboarding) + 4-6 wk first check = **~14-19 wk total** — by far
the highest first-component cost, dominated by Rust onboarding.

### 2.3 Optimal order if multiple tracks activate

If only ONE track activates: **B (Python) first** has the lowest
combined cost AND is the only track with direct Axis-A user-MRR
upside (new analytics features that don't exist today, per
`8361409` §3.4 B.5).

If TWO tracks activate: **A then B**. Track A widgets validate
build-toolchain integration (no runtime IPC); Track B validates
runtime IPC on a less-critical surface than C (analytics is not
an order-placement hot path).

If THREE tracks activate: **A → B → C**. Track C last because:
- highest onboarding cost
- highest correctness-criticality (riskguard guards orders)
- Rust ecosystem lessons from C apply nowhere else if the team
  doesn't have Rust experience

### 2.4 Foundation cost amortization

Foundation §1.1 (IPC contract) is ~2 wk one-time. If only ONE
track activates, that 2 wk is borne by that track. If three
tracks activate, each track effectively bears 0.7 wk Foundation.
**Foundation does NOT scale linearly** — it's mostly fixed-cost.

---

## Phase 3 — Honest "should we?" per candidate

| Candidate | Verdict | Reasoning |
|---|---|---|
| **A. Riskguard → Rust** | **DEFER-TO-TRIGGER** | No latency incident; throughput within Go envelope; no SEBI Algo-ID throughput pressure; Rust onboarding cost (4-8 wk) eats the realistic 14-week budget; Reversibility is cheap so revisit when triggers fire. Per `8361409` §10 verdict. |
| **B. Widgets → TS** | **DEFER-TO-TRIGGER (highest probability of firing within 24mo)** | UX-iteration trigger nearly fires (6 hr per widget vs 4 hr threshold) but customer-pace demand is <1/month. Build-only swap (no runtime IPC) makes this the lowest-risk candidate. **Recommend**: gate on first widget that takes >5 hr Go-template iteration AND a sustained week of customer requests. Per `8361409` §8.1. |
| **C. Analytics → Python** | **DEFER-TO-TRIGGER (Axis-A positive when triggered)** | Roadmap throughput threshold (10 new tools/quarter) not met today (3-5 deferred); LLM-coordinator pattern at 3 tools right at threshold. **Unique among candidates**: Step 6 (new features) is direct user-MRR upside per `8361409` §3.4. If Axis-A demand for advanced analytics emerges, this is the highest-leverage swap. |
| **D. OAuth/credstore → Rust** | **NEVER (at current scale)** | `a03694a` §2.8 already says stay-Go: JWT/AES libraries equally mature in both languages; qualitative crypto improvements yield zero measurable incident reduction; auth is correctness-critical so cutover risk dominates; precondition (`kc/alerts/` tangle split) adds 2 wk; total 17 wk realistic for a Negative-ROI swap on Axis A and Axis B both. Stay-Go via Go 1.25 crypto stack. |
| **E. Audit standalone Go-lib** | **DEFER-TO-TRIGGER (cheapest move, gated on adoption)** | Workspace member already covered by `5437c32` Move 2. Spin-out adds 2 wk only when star/fork triggers fire per `multi-product-and-repo-structure.md` §5.5. **NOT a stack-shift** — included here for contrast. |

### 3.1 Three-axis ROI per candidate

Per `feedback_decoupling_denominator.md`:

| Candidate | Axis A (user-MRR) | Axis B (agent-concurrency) | Axis C (portability) |
|---|---|---|---|
| A. Riskguard→Rust | 0 | +0.1 (clearer module boundary) | +1 (Rust slot proven) |
| B. Widgets→TS | +0.5 (faster iteration → more shipped widgets) | +0.5 (TS team can work in parallel on widget surface) | +1 (TS slot proven) |
| C. Analytics→Python | **+1.5** (new features that don't exist Go-only) | +0.3 (Python can be pulled by data-scientist agent) | +1 |
| D. OAuth→Rust | 0 | -0.2 (cross-language test review tax) | +1 |
| E. Audit Go-lib | 0 | +0.3 (own go.mod = own CI graph) | +0.5 (Go-lib spin-out portability proxy) |

**Highest combined-axis score**: C (Analytics→Python) at +2.8.
**Highest portability-pure score**: A=B=C=D tied at +1 (each
proves a new language slot).
**Cheapest move**: E at 2 wk realistic vs 7-15 wk for others.

### 3.2 Standing-rule compliance

Per `feedback_decoupling_denominator.md` 2026-04-27 amendment:
**Axis B (agent-concurrency) is the primary denominator, not user-MRR**.
Under that rule:
- A (+0.1), B (+0.5), C (+0.3), D (-0.2), E (+0.3) — B is leading.
- But B's Axis B is achieved cheaply by the `go.work` Move ALONE,
  without the TS swap. Move 1+2+3 gives multiple workspace members
  → multiple parallel agent contexts → Axis B benefit.

**Conclusion**: **`go.work` Move 1+2+3 (per `5437c32`) captures
~80% of the Axis-B benefit at ~3 weeks vs 7-15 weeks for any
language swap.** This is the dominant strategy under the
standing rules.

---

## Phase 4 — Holistic dev experience after multi-stack

### 4.1 IDE setup for cross-stack work

If 3 stacks activate, an agent (or human) editing the cross-IPC
boundary needs:

| Language | LSP | Notes |
|---|---|---|
| Go | gopls (workspace-aware since 1.20) | works today |
| TypeScript | tsserver (vscode/zed default) | works today |
| Python | pyright (better than pylsp for typing) | works today |
| Rust | rust-analyzer | works today |

Per MEMORY.md "LSP Setup": cclsp + per-language plugins coexist
via `~/.claude/cclsp.json`. **All four LSPs running simultaneously
is established prior art — no new IDE work**.

Workspace structure that makes this work:
```
kite-mcp-server/
  go.work                    # lists all Go modules
  go.mod                     # root Go module
  kc/audit/go.mod            # workspace member (Move 2)
  kc/riskguard/go.mod        # workspace member (Move 2)
  kc/widgets-ts/             # TS workspace member (Track A)
    package.json
    tsconfig.json
    src/
  kc/analytics-py/           # Python workspace member (Track B)
    pyproject.toml
    src/
  riskguard-rs/              # Rust workspace member (Track C)
    Cargo.toml
    src/
```

Each language tree has its own root marker for its LSP. The
workspace pattern from `5437c32` is **the structural shape that
makes per-language LSP boundaries clean** — without it, gopls
sees the whole repo and the per-language LSPs see nothing.

### 4.2 Cross-stack refactor — agent workflow

Scenario: rename `riskguard.checkOrder` → `riskguard.evaluateOrder`.
TS-side calls it; Rust-side implements; Go-side proxies through
the workspace member.

| Phase | Agent action |
|---|---|
| 1. Update IPC schema | Edit `kite-mcp.schema.json` (root-level shared schema per `4fa5a39` §2). Bump capability schema version. |
| 2. Update Rust impl | `cargo build` in `riskguard-rs/`; rename `fn check_order` → `fn evaluate_order`; update capability advertisement. |
| 3. Update Go proxy | Edit `kc/riskguard/proxy.go`; rename Go method; update IPC method-name string. |
| 4. Update TS callers | `pnpm tsc` in `kc/widgets-ts/`; rename calls. Type-check fails until updated. |
| 5. Update Go tests | `go test ./...` in workspace; gold-test fixtures need rename. |
| 6. CI | Per-language CI gates each stack independently; cross-language integration test (Foundation §1.4) catches IPC name mismatch. |

**Without `go.work`**: this refactor is a single Go repo edit
where rename-tooling handles it. **With `go.work` + multi-language**:
the refactor IS atomic in one PR (the workspace coordinates the
build) BUT requires 4 separate language toolchains to all
green-light. Refactor calendar inflates ~2-3× per cross-IPC
rename. **This is the #1 cost of multi-stack** — it isn't
visible until you actually do a cross-IPC rename.

### 4.3 Test orchestration

| Test type | Where | Owner |
|---|---|---|
| Per-language unit tests | each language's tooling | language-specific agent |
| Golden tests (parity) | shared fixture dir, e.g., `testdata/riskguard-checkorder/` | language-of-implementation owns; Go-side validates |
| IPC contract conformance | `cmd/ipc-test/` Go binary that exercises every advertised capability against a live subprocess | Foundation-phase deliverable |
| Cross-language integration | docker-compose-up of all 4 processes; one e2e scenario per release | release-phase deliverable |

**Critical**: golden-test parity is the cheap insurance against
language-port regressions. Every existing Go test in `kc/riskguard/`
becomes a JSON fixture; the Rust crate runs the same fixtures
and asserts byte-equal output. The 6,498 LOC of riskguard tests
is **the migration safety net** — without it, the Rust port is
a flag-day rewrite with no ground truth.

### 4.4 CI per-language pipeline

Per `8361409` §1.2:
- Go: golangci-lint, go test, govulncheck, goreleaser (today)
- TS: pnpm typecheck, eslint, vitest, npm-audit
- Python: ruff, mypy, pytest, pip-audit (uv-managed)
- Rust: clippy, rustfmt, cargo test, cargo-audit

All four parallelize on GitHub Actions. Wall-clock unchanged
(~2 min per language); billable minutes ~50% increase per CI run.
**Cost-per-month assuming 100 PRs/month**: ~$5-15 delta on
GitHub Actions.

### 4.5 SBOM aggregation

Per `8361409` §1.5: each language emits its own SBOM
(`cyclonedx-bom` for TS, `cyclonedx-py` for Python, `cargo-cyclonedx`
for Rust, `goreleaser sbom` for Go). Aggregate at release time
into a single CycloneDX bundle. **Tool**: `cyclonedx-cli merge`
is the standard.

### 4.6 Single-binary deploy regression

**Today**: `flyctl deploy -a kite-mcp-server` ships ONE Go binary
in a Dockerfile. Users self-hosting via `docker compose up` get
ONE process.

**Post-multi-stack**: the Fly.io app machine boots and spawns:
- Go MCP server (host)
- Rust riskguard subprocess (if Track C)
- Python analytics subprocess (if Track B)
- TS widgets — NOT a runtime process; just bundle artifact

**Self-hosting users now need 3 runtimes**: Go binary + Python
3.12 + Rust binary. Three failure modes:
1. **Bundled binaries** — Dockerfile embeds Python via `python:3.12-slim`
   base + `apt-get install` Rust binary. Works. ~150MB image
   instead of ~30MB Go-alone.
2. **Distroless minimization** — multistage build; final image is
   distroless+Go+Rust+Python. Per ALPINE_TZDATA gotcha in
   MEMORY.md, layer ordering matters. ~80MB realistic.
3. **User self-installs runtimes** — per language doc the user
   needs Python 3.12 + Rust 1.85 ON THEIR HOST. **This is a
   deal-breaker for self-host adoption** — a key Algo2Go
   product surface (per `645c034` P1).

**Recommended approach**: option (1) — bundled binaries. The Docker
image gets larger but self-hosting UX stays a single
`docker compose up`. Document the new size in MEMORY.md and
launch blockers.

This is a **real user-facing cost** of multi-stack adoption. It
trades developer-velocity gain for self-host friction. The trade
is justified if the gain exceeds the friction; today, with no
proven gain trigger, the friction is gratuitous.

---

## Phase 5 — Empirical evidence requirements

### 5.1 Riskguard→Rust evidence

**Required to prove ROI**:
- Latency benchmark: P50/P95/P99/P999 of `riskguard.checkOrder`
  under sustained 100 RPS load. Compare Go-current vs Rust-port.
  Acceptable: <1ms P99 reduction on Rust side.
- GC-attributable latency: `runtime/pprof` GC traces show GC
  pause >2ms during pre-trade chain. Today: not observed.
- Memory pressure: Go HEAP grows linearly with concurrent users
  and triggers GC at 60% interval. Rust constant memory.

**Acceptable proxy if can't get full data**:
- Synthetic load test (`hey` or `vegeta` against
  `/mcp` endpoint with `place_order` calls) showing P99
  histogram under 100 concurrent virtual users.
- Per-tool-call latency from `server_metrics` tool (already
  exposed per CLAUDE.md "Observability") — current per-tool
  P99 measured as a baseline.

### 5.2 Widgets→TS evidence

**Required to prove ROI**:
- Time-to-add-new-widget benchmark: clock time from "decide to
  add widget X" to "deployed and rendering in Claude.ai".
  Measured today (Go-template path) and again post-TS-port.
  Acceptable: ≥4 hr → ≤2 hr per widget.
- Bug-rate: rendering issues per widget shipped. Go-template
  vs TS-port. Difficult to measure absent shipped widgets.

**Acceptable proxy if can't get full data**:
- Subjective developer-velocity ratings from agents adding
  widgets in each toolchain.
- Bundle size + render-perf via Lighthouse on a representative
  widget.

### 5.3 Analytics→Python evidence

**Required to prove ROI**:
- Numerical-precision audit: for every analytics function,
  Go-side output and Python-side output for 100 representative
  inputs. Per-function relative error <0.1%.
- Library-coverage gap: list each Python library function that
  replaces Go custom code. Estimate per-replacement LOC delta
  (e.g., `scipy.stats.sharpe_ratio` replaces 50 LOC of Go ⇒
  net -49 LOC in `kc/analytics-py/`).
- Roadmap-velocity benchmark: time-to-add a new analytics tool
  (PCA, factor model, MC VaR) — clock time in Go vs Python.

**Acceptable proxy**:
- Empirical from past `analyze_concall` / `peer_compare`
  decisions: "we punted to LLM-coordinator because Go custom
  code was too expensive." Quantify the cost the LLM-coordinator
  is paying (tokens per call × calls per day × $/1k tokens).

### 5.4 OAuth→Rust evidence

**Required to prove ROI**:
- Crypto-incident postmortem: at least ONE production incident
  attributable to Go's `crypto/aes` or `golang-jwt/jwt` that
  Rust's stack would have prevented.
- External audit finding: SOC 2 / ISO 27001 / pen-test report
  that flags Go crypto stack.
- Throughput latency at 100 RPS auth: P99 of token-verify call.

**Acceptable proxy**: Honest answer is **none — there is no
proxy that justifies this swap absent a real incident**. The
qualitative case is sufficient at "be aware of"; not at "ship".

### 5.5 Audit Go-lib spin-out evidence

**Required to prove ROI**:
- Star count on parent repo ≥50 sustained.
- Inbound issues on `kc/audit/` subdirectory ≥2 from external
  consumers.
- Forks of the subdirectory ≥5 (per `multi-product-and-repo-structure.md`
  §5.5 trigger).

These are **public-facing observable metrics**, not internal
benchmarks. Track via GitHub repo metrics directly.

---

## 6. Net verdict — concrete actions for orchestrator

### 6.1 Today (committed by this doc)

1. **Ship `go.work` Move 1+2+3** per `5437c32` (~3 weeks).
   - This is positive-ROI on Axis B regardless of any swap.
   - It is the strict precondition for every swap below.
   - It does NOT commit to any language swap.
2. **Draft ADR-0009 amendment** to canonicalize JSON-RPC 2.0 over
   stdio per `4fa5a39`. ~3 dev-days. Doc-only.
3. **Stop**. Do not pre-build language CI / observability /
   Foundation infrastructure on speculative grounds.

### 6.2 Trigger-gated near-term actions

| Trigger | Action |
|---|---|
| Customer requests ≥4 widgets in 4 weeks (sustained UX demand) | Activate Track A — start with `pnl_sparkline` PoC; budget 7 wk Foundation+first |
| Analytics roadmap accumulates ≥10 deferred features OR 3rd LLM-coordinator tool ships | Activate Track B — start with `sector_tool` port; budget 7 wk Foundation+first |
| Latency incident attributable to Go GC in pre-trade chain | Activate Track C — start with `riskguard.checkOrder` PoC; budget 14-19 wk Foundation+onboarding+first |
| Parent repo crosses 50 stars | Activate Candidate E — spin out `tool-call-audit-go`; 2 wk |

### 6.3 Never-gated

- **Candidate D (OAuth→Rust)** does not have a credible 24-month
  trigger. Drop from active candidates list. Stay-Go.

### 6.4 Reversibility note

All four language candidates (A, B, C, D) are **structurally
reversible** because the IPC contract is the boundary. The Go
module always exists in git history; reverting = restore the
Go body, replace the proxy with the original implementation, drop
the language workspace member. **The workspace pattern (`go.work`)
makes this reversibility cheap.** Without workspaces, reverting
is a flag-day rewrite. With workspaces, it's a `git revert`.

This is the highest-value insight from `5437c32` repeated here:
**workspaces are the optionality lever**. They make every swap
both committable AND revocable on a per-component basis. Polyrepo
spin-out (Candidate E shipped as separate repo) is a one-way door;
workspace promotion is two-way.

---

## Sources

- `.research/disintegrate-and-holistic-architecture.md` (`5437c32`)
  — go.work foundation, 3-week Move 1+2+3 plan, empirical LOC per
  workspace member.
- `.research/component-language-swap-plan.md` (`a03694a`) — 24-mo
  shortlist with target languages per component.
- `.research/parallel-stack-shift-roadmap.md` (`8361409`) — Foundation
  phase + per-track sequencing + counter-rec stay-in-Go analysis.
- `.research/ipc-contract-spec.md` (`4fa5a39`) — JSON-RPC 2.0 wire
  format choice + capability handshake + error codes + type mapping.
- `docs/adr/0007-canonical-cross-language-plugin-ipc.md` (`202b993`)
  — current `checkrpc/` netRPC pattern.
- `.research/multi-product-and-repo-structure.md` (`39577c3`) §5.5
  — five concrete triggers for monorepo → polyrepo promotion.
- `.research/algo2go-umbrella-product-strategy.md` (`645c034`) —
  Algo2Go reservation; trigger gates for any rename / spin-out.
- `feedback_decoupling_denominator.md` — three-axis ROI framework.
- Empirical LOC measurements at HEAD `5437c32` via Git Bash
  (`find . -name "*.go" | xargs wc -l` and direct `wc -l` per file).

---

*Generated 2026-05-02, read-only research deliverable. NO ship of
code. Per-candidate plan covering empirical baseline, IPC boundary,
trigger condition, migration mechanics, ecosystem readiness, cost
estimate, reversibility. Cross-component sequencing, per-axis ROI,
holistic-dev workflow, evidence requirements. Lead verdict: ship
`go.work` Move 1+2+3 + ADR-0009 amendment; defer all five
language swaps to triggers.*
