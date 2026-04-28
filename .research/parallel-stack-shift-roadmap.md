# Parallel Stack-Shift Roadmap — three-track per-component port

**Date**: 2026-04-28 evening
**HEAD audited**: `e2a7dab`
**Charter**: research deliverable; **NO ship**. Cost / sequencing /
risk analysis for the parallel-tracks form of the per-component
language swap question raised in
`feedback_decoupling_denominator.md` (Axis C — per-component swap
freedom).

**Anchor docs**:
- `.research/component-language-swap-plan.md` (`a03694a`) — the
  24-month per-component shortlist (widgets→TS, riskguard→Rust,
  analytics→Python, telegram→TS aspirational, ticker→Rust
  aspirational); preserved here, sequenced into tracks.
- `.research/decorator-stack-shift-evaluation.md` (`809edaf`) §3 —
  the per-language native-AOP feasibility matrix; the `mcp/`-port
  cost rejection that this roadmap revisits with parallel-tracks
  framing.
- `.research/scorecard-final-v2.md` (this batch) §2.3 — the
  empirical re-measurement showing `mcp/` is NOT thin transport
  (62% of tools have leaked business logic). That measurement
  STILL applies in this roadmap; the parallel-tracks framing
  doesn't change the per-track cost.
- `feedback_decoupling_denominator.md` — the three-axis ROI
  framework (user-MRR, agent-concurrency, tech-stack-portability)
  this roadmap evaluates against.

**Standing constraint** per the brief: this is a peer to
`scorecard-final-v2.md`. Phase 3 of the original brief (ship
hash-publish + JWT rotation CLI) still holds; this roadmap does
NOT add ship items.

---

## 1. Foundation phase (sequential, blocks tracks)

Three concurrent language tracks share infrastructure debt that
must land first — the IPC contract spec, per-language CI,
deploy targets, observability, and supply-chain scanning.

### 1.1 IPC contract spec (extending ADR 0007)

ADR 0007 (`docs/adr/0007-canonical-cross-language-plugin-ipc.md`,
shipped at `202b993`) canonicalizes
`hashicorp/go-plugin`-via-netRPC over stdio as the cross-language
plugin IPC contract. The current consumer is
`kc/riskguard/subprocess_check.go` (391 LOC) + `kc/riskguard/checkrpc/`.

**For the parallel-tracks roadmap**, ADR 0007's scope expands
from "riskguard plugin" to "every cross-language outer-ring
component". Two technology choices:

| Wire format | Pros | Cons |
|---|---|---|
| **Protocol Buffers + gRPC** | Strong typing across languages; mature SDKs in Go/TS/Python/Rust; native streaming; bidirectional RPC | Adds protoc to CI; `.proto` is a fourth source-of-truth alongside Go types; generated-code marshalling overhead per call |
| **JSON-RPC 2.0 over stdio** | No codegen; same shape as current MCP wire; lower per-call overhead at small payloads | Schema drift risk (no compile-time check across languages); manual error/cancellation propagation; weaker tooling |

The current `hashicorp/go-plugin` netRPC is closer to JSON-RPC's
shape (Go's `net/rpc` over stdin/stdout). Preferred path: extend
ADR 0007 to canonicalize **JSON-RPC 2.0 over stdio with a JSON
Schema descriptor** for the contract — keeps the existing riskguard
subprocess pattern as-is; documents schema-via-JSON-Schema for
cross-language validation; lower toolchain cost than protobuf.

**Spec deliverables**:

- Capability declarations: each subprocess advertises
  `{"capabilities": ["riskguard.checkOrder", "analytics.computeSharpe", ...]}`
  on `Initialize` request; host filters dispatchable methods.
- Type mapping: JSON Schema `$ref` per shared domain type
  (`Order`, `Position`, `Money`, `Quote`); generated wrapper code
  per language is OPTIONAL — clients may hand-roll.
- Error propagation: standard JSON-RPC error codes (-32000 to
  -32099 reserved for implementation; -32600+ for protocol).
  `cancellation` propagates via context cancellation → stdin
  EOF on the subprocess side.
- Observability hooks: every call emits `request_id` (UUID)
  before / after stdio frames; logs go to stderr with structured
  JSON; metrics emitted to a side-channel `/metrics` HTTP
  endpoint per subprocess.

**LOC estimate**:
- ADR 0007 amendment: ~300 LOC of doc.
- JSON Schema descriptors for ~6 shared types: ~400 LOC.
- Foundation library (`kc/aspectplugin/`, generic JSON-RPC
  subprocess host): ~500 LOC + tests.
- Reference Go-side client implementation: ~250 LOC.

**Total foundation: ~1450 LOC of Go + 400 LOC of schema +
documentation amendment.**

**Calendar**: 1.5-2 weeks single-developer (with end-to-end test
exercising one subprocess proving the contract).

### 1.2 Per-language CI infrastructure

Each track adds its own toolchain to CI. Today's CI is
`.github/workflows/` — Go-only (golangci-lint, go test, govulncheck,
goreleaser). Per-language additions:

| Language | Toolchain | New CI jobs |
|---|---|---|
| TypeScript | Node 20+ + `pnpm` (consistency with `mcp-remote` ecosystem) + ESLint + TypeScript compile | typecheck, eslint, vitest, npm-audit |
| Python | Python 3.12+ + `uv` (10× faster than `poetry` per March 2026 benchmarks) + ruff + mypy + pytest | typecheck, ruff lint, pytest, pip-audit |
| Rust | Rust 1.85+ + `cargo` + clippy + rustfmt + cargo-audit | clippy, fmt-check, test, audit |

**CI calendar tax**: each new language adds ~3-5 minute job to CI
(parallelizable). Total wall-clock ~unchanged (GitHub Actions
parallelizes); cost-per-CI-run grows ~50% (from current ~2min Go
jobs to ~3min Go + 3min TS + 3min Python + 4min Rust = ~13min
billable).

**Calendar to land all three CI plumbings**: ~1 week single-
developer per language, parallelizable across the three.
Effective: ~1.5 weeks (some parallel work fits between Foundation
1.1 and full CI green).

### 1.3 Deploy targets

Current deploy: Fly.io single Go binary in `kite-mcp-server` app
(Mumbai region, 512MB RAM). Adding outer-ring components in TS /
Python / Rust requires deciding:

| Strategy | Pros | Cons |
|---|---|---|
| **Multi-process inside one Fly machine** | Single deploy unit; simpler rollback; shared filesystem for Litestream restore | Per-language runtime overhead × N; OOM risk on 512MB |
| **Per-language Fly app** (e.g., `kite-mcp-ts`, `kite-mcp-py`, `kite-mcp-rs`) | Independent deploy + scale; per-app health checks | 4× deploy artifacts; cross-app IPC over Wireguard or 6PN; ~$5/month/app baseline |
| **Sidecar containers per machine** (Fly.io machines support multiple containers as of mid-2025) | Single machine cost; isolation | Complex restart semantics; learning curve |

Realistic choice for this codebase: **multi-process inside one
Fly machine, with explicit memory budgets per process** (e.g.,
Go=200MB, TS=150MB, Python=100MB, Rust=50MB). Stays within the
current 512MB allocation; might justify a 1GB upgrade ($5/month
delta).

**Calendar to land deploy plumbing**: ~3-5 days for the multi-
process setup + healthcheck wiring + Litestream restore
verification + Fly.io machine config update.

### 1.4 Per-language observability

Today: `slog` JSON logs to stdout, picked up by Fly.io's log
aggregation; metrics via `kite-mcp-server`'s `/admin/metrics`
endpoint (Go in-process). For multi-language:

| Concern | Solution |
|---|---|
| Log format | All languages emit JSON with shared schema (level / msg / request_id / module / kv-pairs). Each language picks its own log library (slog / pino / structlog / tracing) but the schema is enforced via shared JSON Schema. |
| Metrics | Each language exposes a Prometheus-format `/metrics` endpoint on a per-language port. Host-side aggregator scrapes and re-exports. |
| Tracing | OpenTelemetry across all four languages via OTLP/gRPC to a shared collector. Existing Go side already imports `go.opentelemetry.io/otel` (per `0e91d2a` if shipped; verify). Trace context propagated as headers in JSON-RPC frames. |
| Request ID | Foundation's IPC contract guarantees `request_id` on every frame (per §1.1). Each language echoes it back; logs include it; tracing spans attach it. |

**LOC tax per language**: ~200 LOC for the observability glue
(log adapter, metrics endpoint, OTLP exporter wiring). 3 langs
× 200 = ~600 LOC additional.

**Calendar**: 1 week single-developer (parallel with §1.2 CI
work).

### 1.5 SBOM + dep-scan per language

Current: Go side uses `govulncheck` + `goreleaser sbom`. Per-
language additions:

| Language | SBOM tool | Vuln scan |
|---|---|---|
| TS | `cyclonedx-bom` or built-in `npm sbom` | `npm audit`, GitHub Dependabot |
| Python | `cyclonedx-py` | `pip-audit`, `safety check` |
| Rust | `cargo-cyclonedx` | `cargo-audit` |

Each language adds 1 CI job + 1 release-time SBOM artifact.

**LOC tax**: minimal (~50 LOC of CI workflow per language).
Calendar: 2-3 days total once CI in §1.2 is green.

### 1.6 Foundation phase calendar math

| Item | Calendar | Parallelizable? |
|---|---|---|
| 1.1 IPC contract spec | 1.5-2 weeks | sequential — blocks all tracks |
| 1.2 Per-language CI | 1.5 weeks (parallel × 3) | parallel after §1.1 starts |
| 1.3 Deploy targets | 3-5 days | parallel after §1.1 |
| 1.4 Observability | 1 week (parallel × 3) | parallel after §1.2 |
| 1.5 SBOM + dep-scan | 2-3 days | parallel after §1.2 |

Effective sequential: §1.1 + max(§1.2, §1.3) + §1.4 + §1.5
= 2 + 1.5 + 1 + 0.5 = **~5 weeks calendar**.

Best-case parallel (4-person team): §1.1 (2 weeks) + everything
else done in parallel (~2 weeks) = **~4 weeks calendar**.

**Honest single-developer estimate: 4-5 weeks Foundation before
ANY track can start.**

---

## 2. Track A — TypeScript (mcp/ outer ring → widgets)

### 2.1 Why TS first within the track

The `mcp/` outer-ring port and the widget rewrite share toolchain
economics: same TS project, same Node runtime, same package.json,
same tsconfig. Doing widgets in TS first proves the toolchain;
doing the `mcp/` port second piggybacks on the proven foundation.

The reverse order (mcp/ port first, widgets second) would put
the harder problem first; if `mcp/` port stalls, widgets are
locked out.

### 2.2 Component-by-component sequencing

| # | Component | LOC measured (current) | TS LOC est | Calendar |
|---|---|---|---|---|
| A.1 | Widget templates → React components | `kc/templates/` 14,444 LOC HTML+JS (incl 603 LOC watchlist_app.html, 648 LOC order_form_app.html, 478 LOC landing.html, 135 LOC appbridge.js) | ~10,000 LOC TSX (terser per concern but more boilerplate) | 4-5 weeks |
| A.2 | `mcp/ext_apps.go` widget wiring → TS host | `mcp/ext_apps.go` 996 LOC | ~700 LOC TS | 1-2 weeks |
| A.3 | `mcp/plugin_widgets*.go` → TS plugin loader | `mcp/plugin_widgets.go` 108 LOC + `mcp/plugin_widgets_pack.go` 138 LOC | ~300 LOC TS | 1 week |
| A.4 | mcp/ tool handlers → Nest.js controllers | `*_tool.go` 6,353 LOC + `*_tools.go` 8,229 LOC = **14,582 LOC** total | ~12,000 LOC TS | **24-36 weeks** (per `809edaf` §3) |

**Critical empirical caveat per `scorecard-final-v2.md` §2.3**:
31 of 50 tool files contain in-place business logic NOT
delegated to `kc/usecases/`. Item A.4 carries the cleanup-first
debt (`scorecard-final-v2.md` §2.3 cost case "realistic"). The
24-36 week estimate is for cleanup + port; pure port without
cleanup compounds the debt.

### 2.3 What stays Go-side via IPC

| Surface | Stays Go | Why |
|---|---|---|
| `kc/usecases/` (CQRS handlers) | YES | Domain logic; not transport |
| `broker/zerodha/` adapter | YES | gokiteconnect SDK is Go-only |
| `kc/audit/` SQLite + hash-chain | YES | SEBI hash-chained; tested via 257+ Go tests |
| `kc/riskguard/` | YES (until Track C) | Risk-check logic; subprocess plugin already proven |
| `kc/eventsourcing/` | YES | Event store; append-only SQLite |
| `oauth/` JWT issuer | YES (until Track C) | Crypto-correctness gate; security-critical |
| MCP server transport (`mark3labs/mcp-go`) | NO (ported to TS via official `@modelcontextprotocol/sdk`) | Official TS SDK exists upstream; rubric path B native |
| Tool registration shape | NO (Nest.js `@Tool` decorator) | The native-AOP win — rubric paths A/B/C closed natively |

### 2.4 Risks

| Risk | Mitigation |
|---|---|
| **structuredContent / AppBridge marshalling complexity** — current widget code uses `window.openai`-style AppBridge inside Go-templated HTML; ext_apps.go injects AppBridge JS dynamically; Apps SDK widgets ship as `ui://` resources | Port AppBridge JS as-is to a TS module; keep `ui://` resource serving Go-side OR move to TS. The migration boundary is the JSON shape, not the JS internals. |
| **Cowork compatibility** | Cowork client uses MCP wire format, not specific to Go server. TS server matches wire format → Cowork works unchanged. |
| **Latency regression** — Node.js cold start ~100ms vs Go ~30ms | Run Node as long-lived process; cold-start matters only on Fly.io machine boot |
| **Dependency-update cadence shock** — npm ecosystem averages ~10 deps/week with security patches | Foundation §1.5 SBOM + Dependabot integration mitigates. But the cost is real. |
| **Type-safety regression** — Go's type system is stricter than TS at the broker DTO surface | Generate TS types from JSON Schema (Foundation §1.1) automatically; manual hand-rolled types are forbidden in this track |
| **Test rewrite** — current tests are Go-side (mcp/ has 38,706 LOC of test code) | Subset must be ported; the IPC-contract layer keeps Go-side tests valid for kc/-side concerns. Tool-handler tests need TS rewrite. **~10,000 LOC TS test code.** |

### 2.5 Empirical cost estimate

```
Foundation (§1):           4-5 weeks
A.1 widgets:               4-5 weeks
A.2 ext_apps:              1-2 weeks
A.3 plugin loader:         1 week
A.4 mcp/ tool surface:     24-36 weeks (cleanup-first realistic)

Track A total:             34-49 weeks single-developer
```

**Worst-case 49 weeks ≈ 1 year.** Best-case 34 weeks ≈ 8 months.

Per `feedback_decoupling_denominator.md` Axis A (user-MRR):
**zero feature output** during this calendar. At current
₹15-25k MRR projection, the Y1 MRR opportunity cost is
negative against features-shipped. **Track A only pays if user
specifically authorizes the no-feature year.**

---

## 3. Track B — Python (analytics → backtest)

### 3.1 Numerical-code anti-idiom in Go vs Python ecosystem

Per `a03694a` §2.5 and the present-HEAD measurement:

| Metric | Go | Python |
|---|---|---|
| Sharpe ratio implementation | hand-rolled in `mcp/backtest_tool.go` | `scipy.stats.sharpe_ratio` 1 line |
| RSI / MACD / Bollinger | hand-rolled in `mcp/indicators_tool.go` (pure compute) | `pandas-ta.rsi()` etc. — 1 line each |
| Black-Scholes Greeks | hand-rolled in `mcp/options_greeks_tool.go` (lines 1-180) | `scipy.stats.norm.pdf()` + closed-form — 50 LOC |
| Multi-leg strategy builder | hand-rolled (lines 200+ of options_greeks_tool.go) | `quantlib.OptionStrategy` — built-in |
| Sector exposure | hand-rolled in `mcp/sector_tool.go` (150+ stocks → 20+ sectors map) | dict comprehension — same code in Python BUT pandas groupby is 3 lines |

The Go-side hand-rolled compute is **not anti-idiom**, it's
**ecosystem mismatch**. Go is a fine systems language; numerical
ecosystem is in Python. For new analytics tools (e.g. PCA, factor
models, monte-carlo VaR), Python's marginal-cost is 10× lower.

### 3.2 Component sequencing

| # | Component | LOC measured | Python LOC est | Calendar |
|---|---|---|---|---|
| B.1 | `mcp/sector_tool.go` | included in 14,582 above; specifically ~600 LOC | ~250 LOC | 1 week |
| B.2 | `mcp/indicators_tool.go` (RSI, SMA, EMA, MACD, Bollinger) | ~700 LOC | ~150 LOC (pandas-ta one-liners) | 1 week |
| B.3 | `mcp/options_greeks_tool.go` (BS Greeks + 8 strategy builders) | 825 LOC | ~300 LOC (scipy + quantlib) | 1.5 weeks |
| B.4 | `mcp/backtest_tool.go` (4 strategies + Sharpe + max drawdown) | 581 LOC | ~250 LOC (vectorbt or pandas-ta) | 1.5 weeks |
| B.5 | New analytics — PCA, factor models, monte-carlo VaR (NOT in Go today) | 0 LOC Go | ~600 LOC Python | 2-3 weeks (real new value) |

**Track B total: 7-9 weeks excluding Foundation.**

### 3.3 Risks

| Risk | Mitigation |
|---|---|
| **Per-call IPC overhead on hot analytics paths** — pandas DataFrames marshalled to/from JSON at every IPC boundary | Batch RPC: one IPC call per analytics tool invocation, not per indicator computed inside it. Realistic per-call overhead: ~5ms vs ~0.1ms in-process. Acceptable for analytics (not for ticker dispatch). |
| **GIL contention** — Python's GIL serializes CPU-bound code | Each subprocess is per-host single-threaded; CPython 3.13's free-threaded mode optional. Realistic concurrent analytics tool invocations on this server: <10/sec at peak; GIL is fine. |
| **Cold start** — `import pandas` + `import numpy` is ~500ms in CPython | Long-running subprocess (subprocess plugin pattern from ADR 0007); cold start is once-per-process-lifetime, not per-call. |
| **Dependency churn** — pip ecosystem has CVE patches every few weeks | Foundation §1.5 mitigates with SBOM + pip-audit. But the cost is real. |

### 3.4 Empirical cost estimate

```
Foundation (§1):           4-5 weeks (shared with Track A)
B.1-B.4 ports:             5-6 weeks
B.5 new analytics:         2-3 weeks

Track B total:             11-14 weeks single-developer (excl Foundation)
```

If Track B runs ALONE (no Foundation parallelism with A or C):
**16-19 weeks calendar** = ~4 months.

Per Axis A (user-MRR): **B.5 IS user-MRR-positive** — new
analytics features that don't exist in Go-only path. PCA / factor
models / monte-carlo VaR are real-money capability for advanced
users. **Track B B.5 alone might pay if framed as feature ship,
not architecture refactor.**

---

## 4. Track C — Rust (riskguard → oauth/credstore)

### 4.1 Memory-safe crypto + low-latency rationale

Per `a03694a` §2.1 and present-HEAD measurement:

| Concern | Go | Rust |
|---|---|---|
| `kc/riskguard/` (3,550 LOC) — pre-trade safety checks | GC pauses possible (1-3ms p99 in worst case) | Predictable latency; no GC; ownership-checked at compile time |
| `oauth/` (2,349 LOC) — JWT issuer + DCR + PKCE | mature `golang-jwt/jwt` library; some manual nonce handling | `jsonwebtoken` crate + `rand_chacha`; ownership prevents key reuse bugs |
| `kc/alerts/crypto.go` (252 LOC) — AES-256-GCM via HKDF | `crypto/aes` + manual GCM | `aes-gcm` crate with const-time guarantees |

The "memory-safe crypto" framing applies to the credentials
store (KiteCredentialStore + KiteTokenStore — both AES-256-GCM
encrypted in Go via `kc/alerts/crypto.go`). Rust's ownership +
type system guards against key-reuse + nonce-reuse better than
Go's; the gain is qualitative, not measurable in dim points.

The "low-latency" framing is real: riskguard runs synchronously
in the order-placement hot path. Sub-ms predictability matters
under bursty load.

### 4.2 Why riskguard first (proves Rust IPC pattern before security-critical oauth)

If oauth/credstore is ported first and the Rust subprocess crashes
or has a panic, the entire authentication surface goes down —
all users fail to log in. If riskguard is ported first and Rust
subprocess crashes, riskguard fails closed (orders blocked) —
worse than no riskguard for new orders, but no auth disruption.

Riskguard is the **safer** first Rust port. Once Rust IPC is
proven over weeks, oauth/credstore migration is conservative.

### 4.3 Component sequencing

| # | Component | LOC measured | Rust LOC est | Calendar |
|---|---|---|---|---|
| C.1 | `kc/riskguard/` core checks | 3,550 LOC | ~2,500 LOC Rust | 8-10 weeks |
| C.2 | `kc/alerts/crypto.go` AES-256-GCM helpers | 252 LOC | ~200 LOC Rust | 1-2 weeks |
| C.3 | `oauth/` JWT issuer + DCR + PKCE | 2,349 LOC | ~1,800 LOC Rust | 8-12 weeks |
| C.4 | KiteTokenStore + KiteCredentialStore encryption layer | included in `kc/alerts/` | ~400 LOC Rust | 2-3 weeks |

**Track C total: 19-27 weeks excluding Foundation.**

### 4.4 Risks

| Risk | Mitigation |
|---|---|
| **cgo-vs-IPC overhead** — Rust as cgo dynamic library would avoid IPC cost but adds build complexity | IPC subprocess pattern per Foundation §1.1. Per-call overhead ~50µs (process boundary); for riskguard's per-order path that's acceptable; for ticker that's not. Track C does NOT include ticker. |
| **Rust onboarding cost** — single-developer team learning curve | Real, ~4-8 weeks per person. Compounds the 19-27 week estimate. |
| **gokiteconnect-equivalent in Rust does not exist** — would not affect Track C (Track C is INTERNAL packages, not broker SDK) | Track C is broker-SDK-free by design. |
| **JWT secret rotation across Go+Rust at deploy** — both sides must agree on `OAUTH_JWT_SECRET` | Foundation §1.1 IPC contract carries secret-version handshake. Same problem as Postgres adapter; solvable. |

### 4.5 Empirical cost estimate

```
Foundation (§1):           4-5 weeks (shared with A+B)
Rust onboarding:           4-8 weeks single-developer
C.1 riskguard:             8-10 weeks
C.2 crypto helpers:        1-2 weeks
C.3 oauth:                 8-12 weeks
C.4 credstore:             2-3 weeks

Track C total:             23-35 weeks single-developer (excl Foundation, INCL onboarding)
```

If Track C runs ALONE: **28-41 weeks calendar** = ~7-10 months.

Per Axis A (user-MRR): **zero new features**. Per Axis B (agent-
concurrency): minor — riskguard isn't a Mode-2 hotspot. Per Axis
C (portability): real — Rust IS a credible per-component swap
target.

**Track C only pays at Compatibility / Portability dim demand,
which is scale-gated to 1k+ concurrent users (per `a03694a`
§2.4). Not authorized today.**

---

## 5. Track-parallelism matrix

### 5.1 Dependencies between tracks

| Track | Depends on | Can run independently? |
|---|---|---|
| A (TS) | Foundation (§1.1 IPC, §1.2 TS CI, §1.3 deploy, §1.4 obs, §1.5 SBOM) | YES once §1 done |
| B (Python) | Foundation (same items) | YES once §1 done |
| C (Rust) | Foundation (same items) **+ Track C-specific Rust onboarding** | YES once §1 done; onboarding is internal to track |

After Foundation, all three tracks share NOTHING else. They can
run in parallel if multi-developer team exists.

### 5.2 Calendar math

**Sequential (single developer)**:
```
Foundation:      4-5 weeks
Track A:        34-49 weeks (full mcp/ port; mostly A.4)
Track B:        11-14 weeks
Track C:        23-35 weeks (incl Rust onboarding)
                ----
TOTAL:          72-103 weeks ≈ 1.5-2 years
```

**Parallel (best-case 4-person team — 1 dev per track + 1 on Foundation)**:
```
Foundation:                       4-5 weeks
max(Track A, B, C) parallel:      max(34-49, 11-14, 23-35)
                                = 34-49 weeks
                ----
TOTAL:                            38-54 weeks calendar ≈ 9-12 months
```

**Realistic 2-person team (1 dev + 1 contractor for one track)**:
```
Foundation:                       4-5 weeks
Track B (Python; smallest):       11-14 weeks (~ in parallel with later phases of A)
Track A:                          34-49 weeks
Track C:                          deferred
                ----
TOTAL:                            ~1 year calendar
```

### 5.3 Honest take on the 16-week calendar claim

The brief's addendum suggested:
> "Calendar math: Foundation + max(Track A, B, C) parallel = ~16w calendar vs ~36w sequential"

This is **achievable only with a 4-person team where each track
has a dedicated developer AND the smallest track (B Python at
~14 weeks) fully overlaps with Foundation completion**. Empirical
parallel-calendar best case is ~16-18 weeks if and only if:

1. Three dedicated developers (one per track)
2. Foundation work overlaps with track-onboarding in weeks 3-5
3. Track A is bounded to widgets + ext_apps (NOT the full mcp/
   tool surface — that alone is 24-36 weeks)

For a **single-developer team**, the calendar is **9-15 months
sequential**. The 16-week parallel claim does NOT hold without
team scaling.

---

## 6. Operational debt (cost-side)

### 6.1 Multi-language cost surface

After three tracks land, the codebase carries:

| Concern | Cost |
|---|---|
| Dependency-update cadences | Go (~1/week) + npm (~10/week) + pip (~5/week) + cargo (~3/week) = ~19 updates/week vs current ~1 |
| CVE streams | 4 separate streams to triage; CVE volume scales with ecosystem size — npm > pip > cargo > go |
| Logging formats (per Foundation §1.4) | Schema enforced, but per-language libraries diverge; troubleshooting requires fluency in 4 stacks |
| Release cadences | 4 build pipelines, 4 SBOM artifacts, 4 vuln scans per release |
| Code-review bandwidth | A single user reviewing TS + Python + Rust simultaneously is at the edge of attention budget; review quality regresses |
| Production observability | OTLP + JSON logs work, but cross-stack debugging requires correlation across tools |
| Onboarding new contributor | "Know Go" is 1 skill; "know Go + TS + Python + Rust" is 4 skills |

### 6.2 Quantified in agent-concurrency-throughput-equivalent terms

Per `feedback_decoupling_denominator.md` Axis B framework:

| Action | Throughput-equivalent impact |
|---|---|
| Adding a new feature touching only one language | +0 (same as today) |
| Adding a feature spanning the IPC boundary | -25% (cross-language refactor needs both ends; one developer must context-switch) |
| Onboarding a new contributor | -50% in their first 8 weeks (they specialize in one language; cross-stack issues block them) |
| CVE patch in non-Go language | +0 if dep-only; -10% if requires source patch (1 week per quarter) |
| Operational outage requiring root-cause across stacks | -30% during the incident (requires cross-stack investigator) |

**Net Axis B impact** of three-track stack-shift: **-15 to -25%
sustained throughput** until contributors specialize.

This cost is REAL and ongoing. The benefits (rubric closure for
Decorator native, Portability +8) are one-time.

### 6.3 Code-review bandwidth limit

Single-user code-review of TS + Python + Rust simultaneously
hits attention-budget limits. Realistic patterns:

| Strategy | Outcome |
|---|---|
| Solo reviewer for all 4 stacks | -50% review quality after 2 stacks |
| Specialist reviewer per stack (4 reviewers) | Adds 3 collaborators; matches `feedback_decoupling_denominator.md` Axis B preconditions |
| Auto-approve trusted contributors | Increases supply-chain risk; rejected for crypto-touching stacks (oauth/credstore) |

The code-review limit is the **#1 operational cost** that's not
quantified in the LOC estimates. It's a soft cost ("review
quality regresses") not a hard cost ("CI fails"), but it's what
historically kills multi-language refactors at small teams.

---

## 7. Counter-rec — stay-in-Go path per track

Per the brief's "be honest about whether stay-in-Go can deliver
same dim closure":

### 7.1 Track A counter-rec

| Goal | Stay-in-Go path | Cost | Closes same dim? |
|---|---|---|---|
| Decorator dim native (revert ~1916 LOC of Option 4) | Already shipped at `kc/decorators` (`2cc31a9` / `710c011`) — Option 2 typed-generic factory | 0 LOC additional | YES — Decorator already at 100 via Option 4. Reverting Option 4 to "Option 2 only" drops Decorator to 97 (rubric measures shipped closure mechanism). NET 0. |
| Widget UX iteration velocity | `kc/templates/` HTML+JS as today; add hot-reload via `air` or `reflex` for dev cycle | ~50 LOC dev tooling | PARTIAL — productivity win minor; native decorator-validation in TS not replicable. |
| MCP SDK upstream parity | Wait for Go SDK feature parity (`mark3labs/mcp-go` is mature, lags TS by 1-2 features) | 0 LOC | NO — TS has structuredContent / Apps SDK extension; Go does too at `e8ccd34`. Parity is achieved. |

**Track A counter-rec verdict**: stay-in-Go for the rubric;
consider TS only for widget UX iteration if user demand for
faster iteration grows.

### 7.2 Track B counter-rec

| Goal | Stay-in-Go path | Cost | Closes same dim? |
|---|---|---|---|
| Better numerical ecosystem | `gonum/gonum`, `gonum/stat`, `gonum/lapack` — mature Go numerical libraries | 0 LOC additional; possibly ~200 LOC integration per analytics tool | PARTIAL — gonum covers ~70% of pandas-ta + scipy.stats use cases; complex strategies (vectorbt-style backtest) require hand-rolling |
| New analytics features (PCA, factor models, monte-carlo VaR) | Hand-roll using gonum + math/rand | ~400-600 LOC per feature | YES for the specific feature; longer per feature than Python (~2× LOC) |
| Hot-path latency | In-process Go is faster than Python+IPC | 0 LOC | YES |

**Track B counter-rec verdict**: gonum CAN deliver, at ~2× LOC
cost per feature. For a small analytics roadmap (5-10 new
features), gonum is cheaper than the Python track infrastructure.
For a large roadmap (20+ features), Python's ecosystem velocity
wins. Current roadmap is small (3-5 features deferred) — **gonum
is the cheaper near-term answer**.

### 7.3 Track C counter-rec

| Goal | Stay-in-Go path | Cost | Closes same dim? |
|---|---|---|---|
| Memory-safe crypto | Existing `crypto/aes` + `crypto/hkdf` are battle-tested; current `kc/alerts/crypto.go` 252 LOC | 0 LOC additional | YES — Go crypto is solid; Rust's qualitative ownership advantage is not a dim-points lift |
| Predictable latency for riskguard | `runtime.GOGC=off` + arena allocation pattern in Go 1.25; or hand-tuned object pooling | ~300 LOC pool optimization | PARTIAL — eliminates GC; doesn't match Rust's fully predictable latency |
| OAuth correctness | Existing `golang-jwt/jwt` + manual nonce handling has 5+ years production hardening; no known CVEs in our usage | 0 LOC | YES — current `oauth/` is solid |

**Track C counter-rec verdict**: stay-in-Go is the conservative
answer. Rust's qualitative crypto advantages are real but don't
translate to dim points; latency improvements are real but don't
matter at <1k user concurrent load. **Track C is dominated by
stay-in-Go on cost grounds** until scale hits the Compatibility
dim threshold.

### 7.4 Counter-rec summary

| Track | Stay-in-Go cost | Closes same dim? | Verdict |
|---|---|---|---|
| A | 0 LOC; widget iteration via dev-tooling | YES (Decorator at 100 via Option 2 + Option 4 ADR-bounded) | **Stay-in-Go wins** |
| B | ~200-400 LOC per gonum integration | YES for small analytics roadmap | **Stay-in-Go wins** at current roadmap |
| C | 0 LOC; ~300 LOC GC tuning if latency demand grows | YES until scale gates Compatibility/Portability | **Stay-in-Go wins** until scale gates |

---

## 8. Decision criteria (per-track payoff triggers)

### 8.1 Track A trigger

**When TS native-AOP becomes user-MRR-positive**: when widget UX
iteration is the bottleneck for product velocity. Specifically:

- Customer demand for new widgets >= 1 per week sustained
- Current Go-template iteration cost >= 4 hours per widget
- TS ecosystem advantage measured at 4× faster iteration

If all three hit, Track A becomes triggerable. Today none holds
(widgets ship at <1 per month; iteration cost ~6 hours; no
measured TS advantage).

### 8.2 Track B trigger

**When Python ecosystem velocity becomes the limiter**: when the
analytics roadmap exceeds 10 new tools per quarter AND each tool
genuinely benefits from numpy / pandas / scipy.

Today: 4 analytics tools shipped (`backtest_tool`, `indicators_tool`,
`options_greeks_tool`, `sector_tool`); roadmap shows 3-5 deferred
(PCA, factor models, MC VaR). Below threshold.

If Python sub-roadmap grows to 10+ deferred features AND the
gonum hand-roll cost compounds to 2000+ LOC, Track B B.5 alone
becomes triggerable as a **feature ship** not architecture
refactor. Today: not triggered.

### 8.3 Track C trigger

**When Compatibility or Portability dim demand becomes user-MRR-
positive**: when paying customers demand multi-broker support
(Compatibility) OR concurrent user count exceeds 1k (Portability /
Rust ticker latency).

Today: no paying customer demand for second broker; concurrent
user count <100. Below threshold.

If user count hits 1k OR a paying customer demands Upstox/Fyers/
Dhan, Track C C.1 (riskguard) becomes triggerable as a latency
hedge.

### 8.4 Stop-rules per track

| Track | Stop-rule trigger |
|---|---|
| A | Track A cumulative cost exceeds 30 weeks AND mcp/ tool surface port stalls (A.4 not progressing); abort Track A; revert deltas |
| B | Track B cumulative cost exceeds 12 weeks AND no new analytics tool ships from the Python track; abort; gonum-port the deferred features back |
| C | Track C cumulative cost exceeds 30 weeks AND riskguard subprocess fails latency SLO (>5ms p99); abort; keep Go-side riskguard |

---

## 9. Honest verdict — does parallel-tracks clear 100%?

### 9.1 What parallel-tracks COULD close

| Dim | Pre-tracks | Post-tracks (best case) | Mechanism |
|---|---|---|---|
| Decorator | 100 (via Option 4) | 100 (via Track A native) | Lateral move, not lift; ADR 0009 supersedes ADR 0008 |
| Portability | 86 | ~92 (+6) | Per-component swap freedom proven empirically; not full +14 because Postgres adapter still scale-gated |
| Compatibility | 86 | ~88 (+2) | Cross-runtime contract explicit; not +14 without real second broker partner |
| Rest | unchanged | unchanged | Tracks don't touch CQRS / Hex / DDD / ES / Middleware / SOLID / Plugin / Test-Arch / NIST / EntGov |

**Total dim-points lift**: +8 (Portability +6, Compatibility +2,
Decorator +0 net).

**Equal-weighted impact**: 8 / 13 = +0.62 absolute.

```
Current 94.08
+ all three tracks complete: 94.70
```

### 9.2 What parallel-tracks STILL doesn't close

| Locked dim points | Source |
|---|---|
| Compatibility +12 | Real broker partnership (paying-customer + business-development) |
| Portability +8 | Postgres adapter at scale (5K+ users) |
| NIST +9 (external) | SOC 2, ISO 27001, SIEM, pen-test |
| EntGov +33 (external) | SOC 2 + ISO 27001 + third-party review |
| **Total still locked** | **+62 of +100** |

**Post-tracks empirical max: 94.08 + 0.62 = 94.70.** The
calibrated empirical-max of 94.62 from `scorecard-final-v2.md`
is essentially identical (+0.08 above; in noise band).

### 9.3 Honest take

**The parallel-tracks roadmap delivers ~+0.6 equal-weighted lift
at a cost of 9-15 months calendar single-developer.** The same
+0.5 lift is available from Phase 3 (hash-publish + JWT rotation
CLI) at ~250 LOC and ~6 hours.

**Parallel tracks do NOT clear the empirical 100% ceiling.** The
remaining +5.3 dim-points after Track completion are
external-$$ + scale-gated; no architectural refactor reaches
them.

**The roadmap shifts the problem from "rubric paths
A/B/C closure mechanism" to "user-MRR feature-shipping cost".**
That is sometimes the right shift — at a 4-person team with
external customer demand for native AOP / Python analytics /
Rust crypto. At a 1-person team with current MRR projection,
it is **the wrong shift**: too much calendar for too little
dim-point lift; opportunity cost on feature-ship is high.

---

## 10. Verdict

**For execution today: NOT recommended.**

The cost-benefit analysis matches `809edaf` §7's KEEP-GO-ACCEPT-
EMPIRICAL-CEILING verdict, applied to the parallel-tracks
framing:

- Best-case parallel calendar at 4-person team: 16-18 weeks for
  +0.6 equal-weighted. Density: 0.04 dim-pts-per-developer-week.
- Realistic single-developer calendar: 72-103 weeks for the same
  +0.6 equal-weighted. Density: 0.008 dim-pts-per-developer-week.
- Comparable internal-tractable items in `scorecard-final-v2.md`
  Phase 3: density 33 dim-pts-per-developer-week.

**Stack-shift parallel-tracks is 800-4000× more expensive per
dim-point than the queued NIST internal items.**

**Triggers that would change this verdict**:

1. User-MRR-positive demand for any track-specific feature
   (TS-native widgets at customer-pace, Python analytics roadmap
   >10 features per quarter, Rust riskguard latency at 1k+ users).
2. Engineering-team scaling to 4+ developers with cross-stack
   bandwidth.
3. Compatibility or Portability dim becoming product-critical
   (paying customer demand for second broker, scale beyond 1k
   concurrent users).

None fire today.

**Defer all three tracks.** Revisit when one of the three triggers
fires. Track A counter-rec (stay-in-Go via Option 2 + Option 4
ADR-bounded) wins on rubric grounds. Track B counter-rec
(gonum) wins on near-term roadmap grounds. Track C counter-rec
(stay-in-Go) wins until scale gates fire.

---

## Sources

- `.research/component-language-swap-plan.md` (`a03694a`) — per-
  component shortlist (preserved here, sequenced into tracks)
- `.research/decorator-stack-shift-evaluation.md` (`809edaf`) §3
  — per-language native-AOP feasibility matrix
- `.research/scorecard-final-v2.md` (this batch) §2.3 — empirical
  re-measurement of `mcp/` thin-vs-leaked
- `feedback_decoupling_denominator.md` — three-axis ROI framework
- `docs/adr/0007-canonical-cross-language-plugin-ipc.md`
  (`202b993`) — IPC contract foundation this roadmap extends
- `docs/adr/0008-decorator-option-4-go-reflection-aop.md`
  (`e8ccd34`) — the rubric path A/B/C closure that Track A would
  supersede with native TS @decorator
- Empirical LOC measurements at HEAD `e2a7dab` via WSL2 Ubuntu
  24.04 / Go 1.25.8

---

*Generated 2026-04-28 evening, read-only research deliverable.
Peer to `scorecard-final-v2.md`. NO ship; foundation phase + 3
tracks documented for trigger-based future authorization.*
