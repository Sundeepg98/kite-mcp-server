# Component Language-Swap Plan — concrete 24-month horizon

**Date**: 2026-04-27
**HEAD audited**: `4b5120b` (Wave D Phase 2 P2.1 scoping doc; Wave D
agent in flight on the actual sprint).
**Anchor docs**:
- `feedback_decoupling_denominator.md` — three-axis ROI framework
  (user-MRR, agent-concurrency, tech-stack portability). The 2026-04-27
  amendment introduced Axis C and named "per-component swap freedom"
  as the third denominator.
- `.research/wave-d-phase-2-wire-fx-plan.md` (`4b5120b`) — Phase 2
  scoping; §5 Item 2 explicitly asked for "per-component
  language-swap intent" as the open question that gates Axis C.
- `.research/agent-concurrency-decoupling-plan.md` — the original
  decoupling-investment matrix that Phase 2 sits inside.

This doc grounds Axis C with concrete component candidates so the
authorization for Phase 2 (which the user gave on portability
grounds) is no longer rationale-only. If the answer is "no concrete
swap is plausible within 24 months", the user's authorization
needs re-anchoring on Axis B (agent-concurrency) alone — and §4
revisits whether Phase 2 still pays at that bar.

---

## 1. Component inventory

The codebase decomposes into the packages below. LOC counts are
non-test source only (where a quick distinction was easy). Boundary
characterisation is what would survive an honest swap-effort
estimate.

| Component | Path | LOC | Boundary characteristic |
|---|---|---:|---|
| **HTTP composition root** | `app/` (24163 LOC incl. tests) | ~5k prod | Bespoke wiring; `app/wire.go` 985 LOC; lifecycle hooks; middleware chain assembly. Wave D Phase 2 target. |
| **Manager God-object** | `kc/manager*.go` | ~3.5k prod | 60-field struct + 16 init helpers + 12 hoisted UCs. Single-binary glue. |
| **Use-case layer** | `kc/usecases/` (55 files) | ~6k prod | Pure CQRS handlers; `mockBrokerClient` driven; mostly pure-function transformations of broker DTOs. |
| **MCP tool surface** | `mcp/` (201 files) | ~20k prod | 80+ tool handlers, ~6 widget renderers, middleware (cache, circuitbreaker, correlation, elicit). |
| **Riskguard** | `kc/riskguard/` (~40 files) | ~9.5k incl tests | 9 pre-trade checks: kill switch, value cap, count, rate, dedup, idempotency key, OTR-band, anomaly, off-hours. Subprocess plugin RPC for ext checks. |
| **Audit + Anomaly** | `kc/audit/` | ~5k prod | SQLite audit log + retention + rolling μ+3σ baseline + LRU cache (15-min TTL, 10K bound). HashChain + SigV4 publisher. |
| **Billing** | `kc/billing/` | ~1.5k prod | Stripe webhook + tier gating + checkout. Tier table is dormant per-Path-2; only OAUTH_JWT_SECRET-driven encryption is hot. |
| **Paper trading** | `kc/papertrading/` | ~10k incl tests | Virtual portfolio engine + LIMIT-fill monitor + SQLite store. Self-contained. |
| **Alerts + briefings** | `kc/alerts/` | ~10k prod incl tests | Price alerts + Telegram briefings + DailyPnL snapshot service + SQLite. Encrypted token/credential stores live here too. |
| **Telegram** | `kc/telegram/` | ~5k prod | Long-poll bot + trading commands + plugin commands. |
| **Ticker (WebSocket)** | `kc/ticker/` | ~2.7k incl tests | Per-user `kiteticker` WebSocket connection; goroutine-per-user. |
| **Scheduler** | `kc/scheduler/` | ~1k incl tests | Cron-shape jobs (briefings 9 AM IST, P&L 3:35 PM IST, retention 04:00 UTC). |
| **Instruments** | `kc/instruments/` | ~600 prod | Master CSV download + in-memory search index. |
| **Ports** | `kc/ports/` | 231 LOC | 5 narrow interfaces (alert, credential, instrument, order, session). Phase 3a target. |
| **Domain VOs** | `kc/domain/` | ~3k prod incl tests | Money, Quantity, InstrumentKey, Position, Holding, Order, Alert, events. Pure Go. |
| **Eventsourcing** | `kc/eventsourcing/` | ~2k prod incl tests | Event store + projector + outbox. SQLite-backed. |
| **OAuth** | `oauth/` | ~5k prod incl tests | JWT + dynamic-client-registration + PKCE + Kite-OAuth bridge. |
| **Broker port** | `broker/broker.go` | 622 LOC | Pure interface. Wire-level INR-typed DTOs. Multi-broker-ready (Zerodha + mock today). |
| **Broker Zerodha adapter** | `broker/zerodha/` | ~3.4k prod incl tests | Wraps `gokiteconnect/v4` SDK. Retry, ratelimit, conversion to broker DTOs. |
| **Broker mock adapter** | `broker/mock/` | ~1.5k prod | Test double. |
| **Ops dashboard** | `kc/ops/` | ~16.5k prod incl tests | Server-side rendered HTML dashboard + admin panel + JSON APIs. Direct kiteconnect path bypasses broker port (acknowledged debt). |

The codebase **already separates** the SDK-coupled surface (`broker/`,
`kc/ticker/`) from the domain/use-case core. The kiteconnect import
leaks into **17 files outside `broker/`** today (mostly `kc/alerts/*`
plus `kc/ops/api_portfolio.go`); those leaks are scope debt, not
architectural commitment.

---

## 2. Per-component swap candidates

For each, the question is: **"if you sat down to rewrite ONLY this
component in another language, how hard is it and would the result
be better?"** Estimates are gross — the point is relative ranking.

### 2.1 Riskguard (`kc/riskguard/`)

- **Current language**: Go. Pure CPU-bound checks (in-memory limit
  comparisons, rolling aggregates, dedup hash, anomaly Z-score).
- **Plausible target**: **Rust** for the hot-path checks. The
  subprocess plugin RPC at `kc/riskguard/checkrpc/` already proves
  the IPC seam — a Rust `riskguard-checker` binary is a drop-in.
- **Why Rust**: predictable latency (no GC pauses on the order-
  placement critical path), zero-copy parsing of the JSON proto,
  unsafe-free in-place stats (μ+3σ rolling window). Rust's
  ownership model is a good match for the audit-of-state-changes
  semantic.
- **Effort to swap**: ~9.5k LOC of Go → ~4-6k LOC of Rust + 4-8
  weeks. The plugin proto already exists; the in-process path
  needs a thin FFI shim or an out-of-process IPC commit.
- **Benefit**: 1-3 ms p99 latency reduction on the order-placement
  pre-trade chain. Resume-on-crash semantics improve.
- **Cost of NOT swapping**: minimal. Go is fine here at current
  throughput (low-thousands of orders/day). Risk-check latency is
  dominated by the broker round-trip, not the local check.
- **24-month feasibility**: **realistic**. Plugin seam exists.
  No business reason to do it unless we're pursuing SEBI Algo-ID
  throughput (high-frequency desk volumes). If MRR stays at
  ₹15-25k as `kite-mrr-reality.md` projects, we never get there.

### 2.2 Audit + Anomaly (`kc/audit/`)

- **Current language**: Go. SQLite + rolling stats + SigV4 hash
  publisher.
- **Plausible target**: **Stay Go**. SQLite-go binding is mature
  and fast; SigV4 is a thin HTTP signing concern; the rolling
  baseline is 100 LOC of stats.
- **Effort to swap**: not worth scoping. No language choice
  meaningfully helps here.
- **24-month feasibility**: **blocked**. No reason to swap.

### 2.3 Telegram bot (`kc/telegram/`)

- **Current language**: Go. Long-poll handler + command dispatcher
  + Stripe-confirmation flow.
- **Plausible target**: **TypeScript / Bun**, for ecosystem
  alignment with `grammY` / `telegraf`. Bot framework ecosystems
  are notably stronger in TS than Go (3-5× more libraries on
  inline-keyboard ergonomics, FSM patterns).
- **Effort to swap**: ~5k LOC of Go → ~3k LOC of TS + 3-5 weeks.
  IPC contract is "broker port + JSON over HTTP" — already in
  shape because `kc/telegram/handler*.go` calls into use cases
  via interfaces.
- **Benefit**: ergonomic command-dispatch DSL; richer
  inline-keyboard widget vocabulary. **No latency benefit** —
  Telegram polling is the bottleneck.
- **Cost of NOT swapping**: low. Go is acceptable; the bot already
  ships and works.
- **24-month feasibility**: **aspirational**. Plausible only if
  Telegram-bot product line expands beyond the current trading-
  command set (e.g., social-trading, copy-trading bots) where TS
  ecosystem buys real velocity.

### 2.4 Ticker (`kc/ticker/`)

- **Current language**: Go. `gorilla/websocket` via `kiteticker`
  SDK.
- **Plausible target**: **Rust** (with `tokio-tungstenite`) OR
  **stay Go**. The current code is lean (2.7k LOC incl tests).
  Per-user goroutine model maps cleanly to a Rust async task
  pool.
- **Why a swap might pay**: at 1000+ concurrent users, Go's
  goroutine scheduler overhead becomes measurable; Rust's
  task-stealing scheduler is more predictable. Memory per
  connection (8KB stack vs ~1KB Rust task frame) matters at scale.
- **Effort to swap**: ~2.7k LOC Go → ~2k LOC Rust + 3-4 weeks.
  Coupled to `gokiteconnect`'s ticker subprotocol — would need
  to re-implement the binary frame parser. **This is the
  largest hidden cost.**
- **Benefit**: ~10× memory headroom at high connection counts;
  predictable WebSocket reconnect semantics.
- **Cost of NOT swapping**: minimal at <100 concurrent users.
  Real cost arrives somewhere between 1k and 10k connections —
  far past current scale.
- **24-month feasibility**: **aspirational**. Real only if user
  count crosses ~1k concurrent.

### 2.5 Analytics + Backtest (`mcp/backtest_tool.go`,
       `mcp/analytics_tools.go`, `mcp/peer_compare_tool.go`,
       `mcp/sector_tool.go`, `mcp/dividend_tool.go`,
       `mcp/tax_tools.go`, `mcp/indicators_tool.go`,
       `mcp/options_greeks_tool.go`, `mcp/concall_tool.go`,
       `mcp/fii_dii_tool.go`)

- **Current language**: Go. ~3k LOC of pure-function compute
  (Sharpe ratio, max drawdown, RSI/MACD/Bollinger, Black-Scholes
  Greeks, 8 multi-leg option-strategy builders).
- **Plausible target**: **Python** (numpy/pandas/scipy) **for the
  numeric kernels** OR **stay Go**.
- **Why Python**: ecosystem is unmatched — `pandas-ta`, `vectorbt`,
  `quantlib`, `scipy.stats` are 10× the surface area of Go's
  numeric ecosystem. New analytics tools (volatility surfaces,
  factor models, backtester variants) are 10× faster to write
  in Python.
- **Why NOT Python**: you'd need an out-of-process boundary
  (subprocess or microservice). The MCP tool handler stays Go;
  it shells out to a Python kernel via a JSON proto. That's a
  180 LOC boundary to add (request schema + response schema +
  error mapping + timeout).
- **Effort to swap**: ~3k LOC Go pure compute → ~1.5k LOC Python
  numeric + ~180 LOC Go IPC shim + 3-4 weeks. Plugin RPC pattern
  in `kc/riskguard/checkrpc` is the precedent.
- **Benefit**: massively richer analytics roadmap (factor models,
  PCA, monte-carlo VaR) become 1-2 day tasks, not 1-2 week
  tasks. Tool-builder velocity is the lever.
- **Cost of NOT swapping**: real. Every new analytics tool that
  reaches for "I wish we had numpy here" is friction. The
  `mcp/concall_tool.go` and `mcp/fii_dii_tool.go` already
  delegate the actual analysis to the LLM (LLM-coordinator
  pattern) precisely because Go can't compete with the alternative.
- **24-month feasibility**: **realistic**. The `analyze_concall`
  / `peer_compare` / `fii_dii_flow` tools landed in Apr 2026 as
  "LLM-coordinator" because writing the analysis in-process was
  too expensive in Go. A Python analytics microservice would
  reverse that trade-off for a non-trivial slice of the analytics
  roadmap.

### 2.6 Widgets / dashboard render (`mcp/ext_apps.go`,
       `mcp/plugin_widget_*.go`, `kc/templates/*.html`,
       `kc/ops/`)

- **Current language**: Go HTML/template + a copy of
  `kc/templates/appbridge.js` inlined per widget.
- **Plausible target**: **TypeScript / React** for the widget
  bodies (the LLM-rendered chart UI), **stay Go** for the SSR
  dashboard at `kc/ops/`.
- **Why TS**: MCP Apps SDK widgets are deployed inline in
  Claude.ai / Claude Desktop / ChatGPT. The host environments
  are JS-only. Today we ship Go-templated HTML+JS; a TS toolchain
  with a proper build (esbuild / Bun) makes widget UX iteration
  faster.
- **Why NOT touch `kc/ops/`**: SSR dashboard is fine in Go;
  rewrite would add no value.
- **Effort to swap (widgets only)**: ~1k LOC Go templates +
  inline JS → ~700 LOC TSX + ~200 LOC build pipeline + 2-3
  weeks. Each widget's data feed stays Go.
- **Benefit**: ergonomic widget development (hot reload,
  TypeScript types on `window.openai` AppBridge). New widgets
  (heatmaps, candle charts) become 1-day tasks.
- **Cost of NOT swapping**: medium. Widget UX iteration is a
  visible product surface; Go templating slows it.
- **24-month feasibility**: **realistic**. Likely the highest-
  ROI swap on this list when the user is also reachable for UX
  iteration cycles.

### 2.7 Broker Zerodha adapter (`broker/zerodha/`)

- **Current language**: Go. **Mandatorily** Go because
  `gokiteconnect/v4` is Go.
- **Plausible target**: stay Go OR rewrite the SDK in another
  language (multi-month effort, no benefit). Reject any swap.
- **24-month feasibility**: **blocked** — Go is the right choice
  here, not incidental.

### 2.8 OAuth (`oauth/`)

- **Current language**: Go. JWT + DCR + PKCE.
- **Plausible target**: stay Go. JWT libraries are mature in
  every language; the OAuth dance has fewer ergonomic
  differences across stacks than other domains.
- **24-month feasibility**: **blocked**. No reason to swap.

### 2.9 Paper trading (`kc/papertrading/`)

- **Current language**: Go. ~10k LOC incl tests. Self-contained
  virtual-broker engine + LIMIT-fill monitor + SQLite store.
- **Plausible target**: stay Go. The bottleneck is the broker
  data feed, not the engine. The state machine is small enough
  that no language buys you anything material.
- **24-month feasibility**: **blocked**. Stay Go.

### 2.10 Domain VOs (`kc/domain/`)

- **Current language**: Go. Pure value objects (Money, Quantity,
  Position wrapper, Holding wrapper, events).
- **Plausible target**: **stay Go**, but worth mentioning: this
  package is **format-portable** by design. Money's
  `(Amount float64, Currency string)` shape is a JSON-serializable
  record any language can model. If we ever do per-component
  swaps, the domain VOs are the wire boundary that survives.
- **24-month feasibility**: not a swap candidate; it's the
  *interface* every other swap goes through.

---

## 3. Concrete swap shortlist (24 months)

Filtering §2 to "realistic-OR-aspirational with concrete trigger":

| # | Component | Target lang | Trigger | Approx start | Effort (LOC + person-weeks) |
|---|---|---|---|---|---|
| 1 | **Widgets / Apps SDK** (`mcp/plugin_widget_*.go` + `mcp/ext_apps.go`) | **TypeScript + React** | First widget UX iteration that takes >1 day in Go templating; OR ChatGPT widget surface adoption demanding richer UX | Q3 2026 if widget-driven product play; Q1 2027 otherwise | ~1k LOC Go → ~700 LOC TSX; **2-3 weeks**, 1 person |
| 2 | **Analytics numeric kernels** (Sharpe / Drawdown / RSI / Black-Scholes / `peer_compare`) | **Python (numpy + scipy + quantlib)** behind a subprocess JSON-RPC | Two consecutive analytics tools land as "LLM-coordinator" because the in-process Go compute is too expensive to write | Q4 2026 | ~3k LOC Go → ~1.5k LOC Python + 180 LOC Go IPC; **3-4 weeks**, 1 person |
| 3 | **Riskguard hot-path** (the 9 pre-trade checks) | **Rust** as a subprocess (the existing `checkrpc` plugin shape, promoted to standard) | SEBI Algo-ID throughput requirement, OR sustained order rate >1k/min where 1-3 ms latency reductions matter | Q2 2027 — only if the throughput trigger lands | ~9.5k LOC Go → ~4-6k LOC Rust; **4-8 weeks**, 1 person |
| 4 | **Telegram bot** | **TypeScript / Bun (`grammY` or `telegraf`)** | Telegram-bot product line expands (social trading, copy trading, multi-tenant inline-keyboard FSMs) | Q1 2027 — only if Telegram surface gets a strategic bet | ~5k LOC Go → ~3k LOC TS; **3-5 weeks**, 1 person |
| 5 | **Ticker WebSocket** (`kc/ticker/`) | **Rust + tokio-tungstenite** | >1k concurrent connected users — far past current scale | **Not within 24 months** unless growth wildly exceeds `kite-mrr-reality.md` projections | ~2.7k LOC Go → ~2k LOC Rust; **3-4 weeks**, 1 person |

**Of these five, only #1 (widgets) and #2 (analytics)** are
realistically triggerable on the current 24-month roadmap. #3 and
#4 require business shifts. #5 is far-future.

**Total realistic 24-month swap surface**: ~4k LOC Go reduced to
~2k LOC TSX + ~1.5k Python = **about 5-7 person-weeks of work**
spread over 12-18 months, gated on triggers that may or may not fire.

---

## 4. Honest assessment — does Phase 2 actually help?

The user authorized Phase 2 partly on the rationale "shipping it
makes future per-component swaps possible". The question this doc
exists to answer is whether the architectural elements Phase 2
delivers (ports + DI container + Fx-modules) **materially
accelerate** any of the §3 shortlisted swaps.

### 4.1 What Phase 2 actually delivers

Per `wave-d-phase-2-wire-fx-plan.md`:

- **`go.uber.org/fx` providers** replacing `app/wire.go`'s 985-LOC
  bespoke composition. Adding a service becomes "declare a
  provider in a new file" instead of "edit
  `initializeServices`".
- **Lifecycle hooks** via `fx.Lifecycle.Append({OnStart, OnStop})`,
  isomorphic to the existing `app.lifecycle.Append` pattern.
- **Typed provider graph** that can be machine-introspected.

What Phase 2 **does NOT** deliver:

- New IPC boundaries.
- New process / language seams.
- Anything the broker port doesn't already provide.

### 4.2 Per-shortlisted-swap, does Phase 2 help?

| Swap | Phase 2 helps? | How / why not |
|---|---|---|
| **Widgets → TSX** | **No, marginal at best** | Widget surface is already a function in `mcp/ext_apps.go` returning HTML+JS as a string. The seam is already explicit (the MCP tool result IS the IPC contract). Fx providers don't make TSX adoption easier. **The actual work is a Bun/esbuild build pipeline + AppBridge typing, not DI plumbing.** |
| **Analytics → Python subprocess** | **No** | Subprocess RPC follows the `kc/riskguard/checkrpc` precedent — a thin Go wrapper that shells out and parses JSON. Fx graph membership is irrelevant; the Python kernel is invoked from a use-case method that already exists. |
| **Riskguard → Rust subprocess** | **Marginally yes** | Riskguard already has a `subprocess_check` plugin shape. Phase 2 might modestly help if the Rust-built artifact is an Fx-managed lifecycle resource (start subprocess on app startup, stop on shutdown) — that's where Fx's `Lifecycle.Append` hooks would replace the current bespoke lifecycle handling. **But the bespoke lifecycle is already <50 LOC**; Phase 2 saves maybe 20 LOC on this swap. |
| **Telegram → TS** | **No** | Telegram bot is already a separate goroutine fleet in `kc/telegram/bot.go`. The IPC contract is "use case interface" — already explicit. Fx doesn't help. |
| **Ticker → Rust** | **No** | Ticker is a subsystem with its own goroutine model. The seam is the "TickerService interface" in `kc/interfaces.go:421`. Phase 2 might let `fx.Provide(NewRustTicker)` replace `fx.Provide(NewGoTicker)` — but that's identical to a today's `app.NewWithOptions(WithTicker(...))` swap. **Marginal.** |

**Combined verdict on Axis C for Phase 2**:

> **Phase 2 does NOT meaningfully accelerate any of the §3
> shortlisted swaps.** The seams those swaps would use already
> exist (broker port, riskguard plugin RPC, MCP tool result
> contract, TickerService interface, use-case interfaces). Phase
> 2's value is overwhelmingly **Axis B (agent concurrency on
> `app/wire.go`)**, not Axis C.

### 4.3 What WOULD help Axis C (if portability is the real anchor)

If the user genuinely cares about per-component swap freedom in
the next 24 months, the architectural investments that pay off
are NOT Wire/fx. They are:

1. **Plugin RPC standardization** — promote
   `kc/riskguard/checkrpc/` to a first-class IPC contract that
   any subsystem can opt into. This is what unlocks the §3.3
   Rust riskguard swap and the §3.2 Python analytics swap.
2. **Static asset toolchain (Bun / esbuild)** — first-class
   build pipeline for `mcp/plugin_widget_*.go` widget JS
   bodies. This is what unlocks the §3.1 TSX swap.
3. **Single canonical broker port leak audit** — clean up the
   17 files outside `broker/` that import `kiteconnect`
   directly (`kc/alerts/briefing.go`, `kc/ops/api_portfolio.go`,
   etc.). This is what makes the broker port a real
   substitution-ready boundary.

None of these are Wire/fx work. None of them are in Wave D
Phase 2's scope.

---

## 5. The 3rd-denominator validation — the honest answer

The user's "tech-stack portability" rationale, applied to Phase 2
specifically:

- **Claim**: shipping Wire/fx makes per-component language swaps
  possible.
- **Empirical reality** (§4.2): the seams those swaps would use
  ALREADY EXIST. Wire/fx doesn't widen them; it just relocates the
  composition root from one Go file to another Go provider graph.
- **Conclusion**: **Axis C does NOT justify Phase 2**.

This means the user's authorization needs re-anchoring. The honest
choices are:

### Option A — Re-authorize Phase 2 on Axis B alone

Per `wave-d-phase-2-wire-fx-plan.md` §4.2: ROI is "POSITIVE if
6+ sustained agents are foreseeable; MARGINAL at the current
observed 3-4 agents". If the user's plan IS to scale to 6+
sustained agents (the user-team-agents memory points to this),
Phase 2 still ships — but on the agent-concurrency rationale,
not the portability one.

### Option B — Pivot to the actual Axis-C-helping investments

If portability is genuinely the goal, redirect Phase 2's effort
to one of:

1. **Plugin RPC standardization** (§4.3 #1). Promotes
   `checkrpc` shape to a reusable IPC contract. Effort: ~400
   LOC + 1-2 weeks. Concretely unlocks Rust and Python
   subprocess swaps.
2. **Bun / esbuild widget pipeline** (§4.3 #2). Bootstraps the
   widget TSX swap. Effort: ~600 LOC scaffolding + 1 week.
3. **Broker-port leak audit + cleanup** (§4.3 #3). Removes the
   17 `kiteconnect` direct-imports outside `broker/`. Effort:
   ~200 LOC + 3-5 days.

Together these three are ~1.2k LOC and ~3 weeks — comparable to
Phase 2's estimated effort, but with **direct** Axis-C lift
rather than indirect.

### Option C — Acknowledge no swap is concretely planned

If the user can't point to a Q3 2026 / Q4 2026 / Q1-2 2027
trigger that makes any of §3's 5 candidates shippable, then both
Phase 2 (Axis C indirect) and Option B's investments (Axis C
direct) are speculative. In that case, the only Axis that
matters is Axis B, and the question collapses to:

> Will sustained 6+ agent work be the norm in 2026-2027?

If yes — ship Phase 2 on Axis B alone. If no — defer everything
in this document and pocket the ~3 weeks elsewhere.

---

## 6. Recommendation

1. **Re-anchor Phase 2's authorization on Axis B (agent
   concurrency)**, not Axis C (portability). The Axis-C
   benefit is real but small; the user's reasoning on
   `feedback_decoupling_denominator.md`'s 2026-04-27 amendment
   over-credited Phase 2.
2. **If Axis C matters**, the actual investments are §4.3 items
   (plugin RPC, Bun pipeline, broker-port leak cleanup), not
   Wire/fx.
3. **The realistic 24-month swap shortlist** is §3 items #1
   (widgets → TSX) and #2 (analytics → Python). Both ship
   without Phase 2; both ship without §4.3 #1. Both DO benefit
   modestly from §4.3 #2 (widget toolchain) and §4.3 #3 (port
   cleanup).
4. **The aspirational swaps** (#3 Rust riskguard, #4 TS
   Telegram, #5 Rust ticker) need business triggers that the
   current `kite-mrr-reality.md` projection does not predict
   firing within 24 months.

**Honest opacity to the user**: this analysis does not change
whether Phase 2 SHOULD ship. Wave D Phase 2 may still be the
right call on Axis B alone. But the user's stated portability
rationale was inferred from general principles, not from a
concrete plan — and concretely, Phase 2 is about agent
concurrency. The portability story should anchor on §4.3 items
if/when shipped, not on Phase 2.
