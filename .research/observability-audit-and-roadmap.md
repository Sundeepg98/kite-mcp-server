# Observability Audit + ROI Roadmap

**Date**: 2026-05-02
**HEAD audited**: `b9d9438`
**Charter**: read-only research deliverable per the Phase-1+2 brief.
Identifies the cheapest closure slices for the 78 score the
`b9d9438` `vertical-horizontal-architecture-coverage.md` audit
flagged as the largest single cross-cutting gap. Phase 3 (ship)
runs as separate commits gated on Phase 2 verdict.

**Anchor docs**:
- `.research/vertical-horizontal-architecture-coverage.md` (`b9d9438`) §3.5 — the
  78 score this doc closes against
- `.research/scorecard-final-v3.md` (`1081684`) — current 13-dim
  state; observability folds into NIST DE.CM-1 ("Continuous
  monitoring") + EntGov audit-trail evidence
- `.research/ipc-contract-spec.md` (`4fa5a39`) §6.2 — W3C
  TraceContext design (not yet implemented)
- `MEMORY.md` references to `mcp/observability_tool.go` (server_metrics)
  + `kc/audit/anomaly.go` + `app/metrics/metrics.go`

**Cross-agent state at audit time**: NIST agent + decorator agent
both idle. No conflict expected on `app/`, `kc/audit/`, `mcp/`,
`oauth/middleware.go`.

---

## Phase 1 — Empirical audit per axis

### 1.1 Logging — **score 88**

**Evidence**:
- `main.go:51-57` — `slog.NewTextHandler(os.Stderr)` + `LOG_LEVEL`
  env parser. `parseLogLevel` covers `debug|info|warn|error|""` and
  defaults to `info` (fail-open per code comment).
- `kc/ops/logbuffer.go:101-130` — `TeeHandler` mirrors every record
  to an in-memory 500-entry ring buffer for the `/admin/ops` log
  stream. Handler implements `slog.Handler` correctly (Enabled +
  Handle + WithAttrs + WithGroup).
- `app/requestid.go:50-90` — `requestIDCtxKey` + `withRequestID`
  middleware generates UUIDv7 per request, stores in ctx, threads
  through the handler chain. `LoggerWithRequestID(logger, ctx)`
  attaches the ID to every log line. **Verified at HEAD: zero
  `fmt.Print*` left in non-test code** (grep returned empty).
- `kc/logger/` — 8-file port package wrapping `slog` with
  ctx-aware `Debug/Info/Warn/Error` signatures. Used across `kc/`
  packages; `logport.AsSlog()` un-wraps for legacy callers.

**Gaps**:
- **Format is text, not JSON.** Adequate for human-readable
  console output; limits tooling (Loki / Elasticsearch / Datadog
  log parsing requires regex extraction). Operator-set
  `LOG_FORMAT=json` flip would be ~15 LOC.
- **No log sampling.** Every Debug/Info line flushes. At low
  volume that's fine; at scale it's wasteful. Acceptable at
  current <100-user scale.
- **No structured error context propagation.** Errors include
  request_id but not the full trace context (parent span,
  baggage). Limited by absent tracing layer.

**Cheapest improvement slice**: `LOG_FORMAT=json` env flag
(default text for back-compat) — ~15 LOC + 4 tests in `main.go`
+ `main_test.go`. Density >5 dim-pts/100 LOC IF NIST DE.CM-1 lifts;
likely ~+0 since log format alone doesn't change WHAT is logged.

### 1.2 Metrics — **score 75**

**Evidence**:
- `app/metrics/metrics.go:36-388` — homegrown `Manager` struct with
  `sync.Map` of int64 counters + per-day userSet. `WritePrometheus`
  (line 296) iterates counters and emits Prometheus exposition
  format text.
- `app/metrics/metrics.go:340-356` — `HTTPHandler()` returns
  Content-Type `text/plain; version=0.0.4; charset=utf-8` (correct
  Prometheus content type).
- `app/metrics/metrics.go:359-374` — `AdminHTTPHandler` requires
  the `ADMIN_ENDPOINT_SECRET_PATH` URL prefix; `/admin/<secret>/metrics`
  is the gated production endpoint.
- `mcp/observability_tool.go:23-166` — `server_metrics` MCP tool
  (admin-only) returns runtime stats (heap, goroutines, GC pause,
  DB size) + per-tool call counts + error rates + p50/p95/p99
  latency aggregated from `audit.ToolMetric`. **Critical**: the
  per-tool histograms exist as audit-store-derived data, NOT as
  Prometheus histograms.
- `mcp/common_tracking.go:13-22` — `IncrementDailyMetric` per
  tool call. Confirms metric increment sites exist.

**Gaps**:
- **No histograms.** `WritePrometheus` only emits `_total` counter
  metrics. p50/p95/p99 latency lives in audit store + `server_metrics`
  tool, NOT in Prometheus. Operators using Grafana cannot graph
  per-tool latency without round-tripping the MCP tool.
- **No gauges** (active_sessions, heap_alloc, goroutines all live
  in `server_metrics` tool, NOT Prometheus). Same Grafana-blind-spot
  problem.
- **Cardinality risk surveyed**: per-day counters use `date` label
  (~365/year per metric) + optional `session_type` label (~5).
  Total cardinality ~3-5K per metric per year — acceptable for
  Prometheus's typical 1M-cardinality budget.
- **No client_golang library.** Homegrown counter implementation
  works but limits histogram + summary types that the official
  library provides idiomatically.

**Cheapest improvement slice**: emit per-tool histogram from
existing audit data. ~80-120 LOC in `app/metrics/` + Prometheus
exposition format histogram lines (`_bucket`, `_sum`, `_count`).
Density ~+2 NIST dim-pts / 100 LOC (above 0.4 floor). Implementation
note: bucket boundaries can be hard-coded (10ms, 50ms, 100ms,
500ms, 1s, 5s) since tool latency is well-bounded.

### 1.3 Tracing — **score 30**

**Evidence**:
- **NO** OpenTelemetry / Jaeger / Zipkin imports. `grep go.opentelemetry`
  + `grep otel` against `go.mod` and `go.sum` returns empty.
- `app/requestid.go:30,42` — comments mention "W3C traceparent"
  as future-state, NOT implemented.
- `.research/ipc-contract-spec.md` (`4fa5a39`) §6.2 designs
  W3C TraceContext propagation through `$meta.trace_id` for
  cross-language plugin IPC — design only, no code.
- Single-process traces are partial-recoverable from request_id
  + audit store (every tool call has request_id + correlation_id +
  call_id), but cross-process (riskguard subprocess plugins) loses
  the chain.

**Gaps**:
- **No distributed tracing AT ALL.** This is the headline gap.
- **No span hierarchy.** Even within-process, there's no parent-
  child span tree — only flat audit rows.
- **Cross-process trace propagation absent.** ADR 0007 IPC contract
  doesn't yet propagate trace_id.

**Cheapest improvement slice**: OpenTelemetry SDK + W3C
TraceContext propagation through HTTP middleware. ~150-300 LOC
for SDK init + ctx propagation + 1-2 manual span creation sites
(MCP tool dispatch + broker call). Density ~+3-5 dim-pts NIST /
100 LOC IF an OTLP exporter is also wired (Jaeger/Tempo/Datadog).
Without exporter, the spans are emitted-but-unobserved — score
lift drops to ~+1.

**Realistic ceiling without external-$$**: stdout-exporter-only
spans (each span logged as JSON). Useful for development /
debugging. Production observability requires a backend (Jaeger
Free Cloud, Tempo on R2, Honeycomb 100M-events/mo free tier — ALL
external-$$ above some threshold). At free tier and <100 users,
external-$$ is effectively $0/month for now but tipping point
exists.

### 1.4 Alerting — **score 60**

**Evidence**:
- `kc/audit/anomaly.go:36` — `UserOrderStats(email, days)` returns
  rolling μ + σ for per-user order value baselines. Cached in
  `kc/audit/anomaly_cache.go` (15-min TTL, bounded 10K entries).
- `kc/riskguard/lifecycle.go:172` — `dispatcher.Dispatch(domain.RiskguardRejectionEvent{...})`
  fires on every rejection (anomaly-baseline-breach is one of 9
  rejection causes).
- `mcp/admin_anomaly_tool.go:74-164` — `admin_list_anomaly_flags`
  is **PULL-only** (admin must run the tool to see flags). NO
  PUSH wiring.
- `app/providers/event_dispatcher.go:109` — registered persister
  for `riskguard.rejection_recorded` writes to event store, but
  no notification subscriber.
- `kc/alerts/telegram.go:107-115` — `TelegramNotifier.SendMessage`
  + `SendHTMLMessage` exist; bot infrastructure ready to consume.
- **Missing**: subscriber on `riskguard.rejection_recorded` that
  resolves admin email → chat_id and pushes a notification.

**Gaps**:
- **PULL-only anomaly visibility.** Operator must remember to run
  `admin_list_anomaly_flags`. Real-time alerts on anomaly events
  are absent.
- **No PagerDuty / OpsGenie / Slack push.** Telegram is the natural
  push channel given existing bot infrastructure.
- **No per-anomaly rate limit** (would be needed before push to
  prevent alert fatigue if a misconfigured user trips the same
  flag 100 times in 5 minutes).

**Cheapest improvement slice**: subscribe to `riskguard.rejection_recorded`
event in `app/providers/event_dispatcher.go`, lookup admin's
`telegram_chat_id` via `alertStore.GetTelegramChatID(adminEmail)`,
send via `TelegramNotifier.SendHTMLMessage`. Per-anomaly dedup
via in-memory `sync.Map` keyed by `(email, code)` with 5-minute
TTL. **~80-120 LOC + 4-6 tests**. Density ~+2 NIST dim-pts /
100 LOC (above floor).

### 1.5 Audit trail — **score 96**

**Evidence**: 4-layer comprehensive — already at near-100 per
scorecard v3 §6 (Test Architecture dim measures coverage on this).
Briefly:
- `kc/audit/store.go` (272 LOC) — append-only with hash-chain
  integrity (`prev_hash + canonical_record + secret = hash`)
- `kc/audit/store_worker.go` — async buffered writer; drop-with-
  warning at full buffer
- `kc/audit/summarize.go` (630 LOC) — smart per-tool summaries
  with PII redaction
- `kc/audit/sanitize.go` — token / secret redaction
- `kc/audit/retention.go` — 90-day cleanup goroutine
- `kc/audit/hashpublish.go` — periodic chain-tip publish to R2
  bucket (HMAC-SHA256 signed)

**Gap**: not focus per brief. Score 96 reflects "verified strong;
+4 to 100 is external-$$ SOC 2-grade tamper-evident chain".

### 1.6 Health checks — **score 92**

**Evidence**:
- `app/http.go:507` — `mux.HandleFunc("/healthz", app.handleHealthz)`
- `app/http.go:565-587` — `handleHealthz`:
  - `?probe=deep` → DB SELECT 1 + broker factory presence + WAL
    freshness; intended for periodic deep checks
  - `?format=json` → component-level body (audit, anomaly_cache,
    risk_limits, etc.) with per-component status + dropped_count
    + hit_rate
  - default → flat legacy body (status, uptime, version, tools)
- `app/http.go:597-611` — `healthzComponent` + `healthzReport` +
  `healthzDeepProbeBudget` — typed shapes for component reports.
- 14 tests in `app/healthz_handler_test.go` covering shape +
  degraded transitions + deep-probe timeout.

**Gaps**:
- **No separate `/readyz`.** Readiness is folded into `/healthz?probe=deep`
  via component status. K8s convention prefers separate endpoints
  (liveness = "process alive" → /healthz; readiness = "ready to
  serve traffic" → /readyz). NOT a real gap at current Fly.io
  deployment (Fly.io health probe is single-shape) but would
  matter for K8s deploy.
- **Deep probe budget is single-knob.** No per-component timeout
  override. Adequate at current component count (5-7).

**Cheapest improvement slice**: alias `/readyz` to `/healthz?probe=deep`.
~10 LOC + 1 test. Score lift ~+0 (no rubric line cares; cosmetic
alignment with K8s convention). **Below density floor.**

---

## Phase 2 — ROI ranking (cheapest dim-pts per LOC first)

Score-rubric impact estimated against **NIST CSF 2.0 DE.CM-1 +
EntGov "audit trail of operational events"** — the two dims most
sensitive to observability work. Hexagonal / Test-Arch / SOLID
already at 100 — observability work doesn't move them.

| # | Slice | Axis | LOC | Lift (pts) | Density (pts/100 LOC) | Verdict |
|---|---|---|---|---|---|---|
| 1 | **Real-time anomaly push to Telegram** | Alerting | 80-120 prod + tests | +2 NIST | **2.0** | **SHIP** |
| 2 | **Prometheus per-tool latency histogram** | Metrics | 80-120 prod + tests | +2 NIST | **2.0** | **SHIP** |
| 3 | **OpenTelemetry stdout-exporter spans (no backend)** | Tracing | 250-400 prod + tests | +1 NIST | **0.3** | DEFER — below floor without exporter; trigger = paying-customer SLA OR Track C activation |
| 4 | OpenTelemetry + Tempo/Honeycomb backend wiring | Tracing | 400-600 + ops cost | +3 NIST | n/a | EXTERNAL-$$ — Honeycomb 100M-events/mo free tier covers <100 users but alerting + retention > free tier eventually |
| 5 | `LOG_FORMAT=json` env flag | Logging | 15-25 + tests | +0 (style only) | 0 | DEFER — no rubric line cares; flip when first ops-tooling integration demands it |
| 6 | `/readyz` alias to deep-probe `/healthz` | Health | 10 + 1 test | +0 (cosmetic) | 0 | DEFER — purely K8s-convention cosmetic; Fly.io deployment doesn't care |

**Top 2 slices that clear the 0.4 dim-pts/100 LOC density floor:**
- Slice 1 (anomaly push) — density 2.0 pts/100 LOC
- Slice 2 (Prometheus histogram) — density 2.0 pts/100 LOC

**Combined**: ~200 LOC + tests, **+4 NIST dim-pts** → moves NIST
from 94 → ~96-98. Equal-weighted scorecard impact: +0.3 to +0.4
absolute (94→96 NIST × 1/13 = +0.15, but lift may overflow rubric
methodology's per-row inference noise band).

**Realistic observability-axis ceiling under no-external-$$:**

The §3.5 score in `b9d9438` was 78. Both top-2 slices land:
- Metrics: 75 → ~88 (Prometheus histograms close the largest gap)
- Alerting: 60 → ~85 (push wiring closes PULL-only gap; PagerDuty/
  OpsGenie remain unaddressed but Telegram is the project's
  canonical push channel and is ~equivalent for ops alerting)
- Logging: 88 (unchanged; format flip is below floor)
- Tracing: 30 (unchanged; OTel is real cost, defer per ADR 0010
  trigger-deferral framework)
- Audit: 96 (unchanged)
- Health: 92 (unchanged)

**Weighted observability axis after top-2 ships** =
(88+88+30+85+96+92)/6 = **~80** (was 78 → +2 raw axis-score
under this doc's rubric, NOT directly mapped to 13-dim rubric).

**Honest verdict**: under no-external-$$ constraint, observability
axis caps at ~80-85. The ~15-20 gap to 100 is the tracing axis
which requires either external-$$ exporter OR custom span backend
(another ~600-1000 LOC of greenfield work below the 0.4 floor).
**Not pursuable internally without trigger fire** per ADR 0010.

---

## Phase 3 — Plan: ship slices 1 + 2

Both slices clear the 0.4 floor; both are within scope; neither
conflicts with other in-flight agents.

**Order of ship**: Slice 1 (Telegram anomaly push) first because:
- Smaller scope (~100 LOC)
- Reuses existing Telegram bot infrastructure (no new dep)
- Clean commit boundary (single subscriber + dedup helper)
- Operationally most-valuable: alerts user immediately on flag
  rather than requiring `admin_list_anomaly_flags` poll

**Then** Slice 2 (Prometheus histogram) because:
- Reuses existing audit store data path (no new measurement)
- Single function in `app/metrics/metrics.go`
- Clean test boundary

**Execution constraints**:
- WSL2 narrow-scope test per `.claude/CLAUDE.md`
- `git commit -o -- <paths>` per team-commit-protocol
- Push after each commit
- TDD: tests-first, then minimum code, then refactor

---

## Sources

- `app/metrics/metrics.go` — homegrown Prometheus exposition
- `app/http.go:565-587` — `/healthz` handler
- `app/requestid.go:50-90` — UUIDv7 + ctx threading
- `kc/ops/logbuffer.go:101-130` — TeeHandler streaming
- `kc/audit/anomaly.go` — rolling μ+3σ per-user
- `kc/audit/anomaly_cache.go` — 15-min cache, 10K entries
- `kc/riskguard/lifecycle.go:172` — RiskguardRejectionEvent emission
- `kc/alerts/telegram.go:107-115` — TelegramNotifier surface
- `mcp/admin_anomaly_tool.go` — PULL-only flags surface
- `mcp/observability_tool.go:23-166` — server_metrics MCP tool
- `app/providers/event_dispatcher.go:109` — rejection persister
  registered (foundation for alert subscriber)
- `.research/scorecard-final-v3.md` (`1081684`) — current rubric state
- `.research/ipc-contract-spec.md` (`4fa5a39`) §6.2 — W3C
  TraceContext design (deferred per ADR 0010)
- `.research/vertical-horizontal-architecture-coverage.md` (`b9d9438`) §3.5
  — the 78 score this doc closes against
- `docs/adr/0010-stack-shift-deferral.md` — deferral framework for
  external-$$ items

---

*Generated 2026-05-02, read-only research deliverable. Phase 3
ship commits follow as separate commits.*
