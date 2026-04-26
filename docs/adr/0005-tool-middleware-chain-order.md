# ADR 0005: Per-Tool Middleware Chain Order

**Status**: Accepted (2026-04-26, retrospective — chain order evolved
incrementally; current shape stabilized ~Mar 2026)
**Author**: kite-mcp-server architecture
**Decision drivers**: Pre-trade safety must run before billing-tier
checks; observability (audit) must capture every call regardless of
downstream rejection; SEBI hash-chained audit requires the call
record before any side effect.

---

## Context

The MCP tool-call path in this server is non-trivial. A single
`place_order` invocation must satisfy at least the following before
hitting the Kite API:

- Have a unique correlation ID for log/trace stitching.
- Time out within a known bound (no zombie tool calls).
- Be recorded in the SEBI-mandated audit trail with hash-chained
  predecessor.
- Run plugin before-hooks (e.g. `rolegate` family-mode access checks).
- Be rejected if the global circuit breaker has tripped.
- Pass 9 risk-guard checks (kill switch, value cap, daily count,
  rate-limit, duplicate, idempotency, confirmation, anomaly,
  market-hours).
- Pass per-tool / per-user rate limiting.
- Pass billing-tier gate (free/pro/premium / `ENABLE_TRADING`).
- Be intercepted by paper-trading middleware if user is in paper mode.
- Have its response decorated with a dashboard URL hint.

The order in which these are applied **changes behavior**, not just
performance. A few examples:

- If billing runs **before** audit, free-tier rejections never appear
  in the audit log — making rate-limit abuse / probing invisible.
- If risk-guard runs **after** billing, paying users can blow past
  position caps; billing has no idea about pre-trade safety.
- If circuit-breaker runs **after** risk-guard, every blown-circuit
  request still pays the cost of running 9 risk checks against a
  Kite that's already known-down.
- If paper-trading runs **before** risk-guard, paper users have a
  different safety surface from real users — undesirable, the whole
  point of paper mode is to mimic the real path.

This ADR documents the order chosen, *why* it is that order, and the
alternatives discarded.

## Decision

The middleware chain registered in `app/wire.go:480-631`, in
registration order (each layer wraps the next; first registered is
outermost):

1. **Correlation ID** (`mcp.CorrelationMiddleware`,
   `app/wire.go:480`) — generates a per-call ID for log stitching.
   Outermost so every other layer's logs share the ID.
2. **Timeout** (`mcp.TimeoutMiddleware(30s)`, `app/wire.go:482`) —
   hard ceiling on tool execution. Wraps everything else so a stuck
   risk check or stuck Kite call gets killed.
3. **Audit** (`auditMiddleware`, `app/wire.go:484`) — records the
   intent to call the tool. Runs *before* any rejection so the audit
   trail captures attempts, not just successes. SEBI hash-chained.
4. **Plugin Hooks** (`mcp.HookMiddlewareFor(app.registry)`,
   `app/wire.go:508`) — runs registered before/after hooks. Two
   production consumers wired here: `rolegate` (family-mode access)
   and `telegramnotify` (after-hook DM to family admin).
5. **Circuit Breaker** (`circuitBreaker.Middleware()`,
   `app/wire.go:511`) — fail-fast when Kite is observably down.
   Above risk-guard so that a tripped breaker short-circuits before
   we spend cycles on 9 safety checks.
6. **RiskGuard** (`riskguard.Middleware(riskGuard)`,
   `app/wire.go:513`) — 9 pre-trade checks. Above billing because
   safety is unconditional — even paying premium users must pass kill
   switch, anomaly detector, etc.
7. **Per-tool Rate Limiter** (`toolRateLimiter.Middleware()`,
   `app/wire.go:522`) — per-user per-tool throttle (e.g. 10
   place_order/min). Below RiskGuard so abuse-grade traffic that
   risk-guard would have rejected anyway doesn't burn rate-limit
   budget unfairly.
8. **Billing Tier** (`billing.Middleware(...)`, `app/wire.go:567`,
   conditional on `STRIPE_SECRET_KEY` + non-DevMode) — free/pro/
   premium gating, `ENABLE_TRADING` enforcement. Below safety so a
   paying user is still subject to the same risk-guard surface.
9. **Paper Trading** (`papertrading.Middleware(paperEngine)`,
   `app/wire.go:627`, conditional on user opt-in) — intercepts and
   simulates orders. Below billing+risk so paper mode mirrors the
   real path's checks; differs only at the bottom (simulated fill
   vs Kite call).
10. **Dashboard URL** (`mcp.DashboardURLMiddleware(kcManager)`,
    `app/wire.go:631`) — appends a dashboard hint to responses.
    Innermost wrapper (response-only side effect; cannot affect
    rejection decisions).

The handler the chain wraps then routes through the use-case layer
(per `.claude/CLAUDE.md` Architecture: Tool Handler → Use Case → CQRS
Command/Query → Broker Port → Adapter), keeping middleware concerns
above the domain.

## Alternatives considered and rejected

**A. Fat handlers — every tool runs its own checks inline.**
Original shape pre-Mar 2026. Rejected once we hit 80 tools — the
copy-paste of "check kill switch, check rate limit, check billing"
across every order-placement handler had drifted, and one tool
(`modify_gtt_order`) was found to be missing the kill-switch check.
Centralizing into middleware fixed that and removed ~600 LOC of
duplication.

**B. Run audit *after* business logic (only log successes).**
Rejected on SEBI grounds: NSE/INVG/69255 Annexure I demands every
algo *attempt* be logged, not just successes. Probing/abuse
detection also needs failed-attempt visibility.

**C. Run billing before risk-guard.** Rejected because it inverts
the safety/commercial priority. A paying user with a runaway loop
should still be stopped by RiskGuard. Conversely, a free user
hitting RiskGuard's kill switch should not be told "upgrade to
premium" — they should be told the kill switch is on. Putting
RiskGuard above billing keeps these messages cleanly separated.

**D. Run rate-limiter as the outermost layer (cheap rejection
first).** Considered. Rejected because per-tool rate limiting is
*per-user* and requires the auth/email context that is established
upstream by HTTP middleware. The MCP-tool-call middleware chain
runs after auth has already happened, so "outermost" already gets
the auth context for free. Rate-limit's position below RiskGuard is
chosen so that risk-guard outcomes (idempotency dedup,
duplicate-order block) don't pollute rate-limit counters with
already-rejected requests.

**E. Single monolithic middleware that runs all checks in
configurable order.** Rejected as anti-modular. Each middleware
layer in this chain is independently testable (`riskguard.Middleware`
has 30+ tests; `billing.Middleware` has its own table-driven
matrix). A monolithic version would force every test to mock every
other layer.

**F. Push everything down into the use-case layer.** Rejected because
multiple use cases share the same middleware needs. Audit, for
example, must be uniform across every tool — not "implemented per
use case". Middleware is the right abstraction level for
cross-cutting concerns; use cases are the right level for domain
logic.

## Consequences

**Positive**:
- Adding a new tool gets all 10 layers automatically. No
  copy-paste of safety checks.
- Each layer is independently versioned and tested. RiskGuard's
  9-check matrix lives in `kc/riskguard/internal_checks.go`; auditing
  lives in `kc/audit`; billing tier logic lives in `kc/billing`.
- The order is documented in code comments at every
  `serverOpts = append(...)` line and in `.claude/CLAUDE.md`
  ("Middleware Chain (order matters)"), reducing onboarding
  surprise.
- SEBI auditability: every tool call has a hash-chained audit
  record before any side effect; rejection reasons are recorded
  uniformly.

**Neutral**:
- Per-call latency is the sum of all 10 layers. Measured at p95
  ~12 ms total middleware cost; dominated by audit DB write
  (mitigated by buffered async writer, see `kc/audit`). Acceptable.
- Re-ordering requires a code change, not a config flip. This is
  intentional — order is a correctness property, not a tuning knob.

**Negative**:
- A bug in an outer layer (e.g. correlation ID middleware crashing)
  takes down all tool calls. Mitigation: panic-recovery middleware
  added at HTTP layer (`app/http.go`, commit `26a3154`) catches
  before the MCP layer.
- The chain order is non-obvious to new contributors. This ADR
  exists to capture the rationale; `.claude/CLAUDE.md` cross-refs
  this ADR.

## References

- `app/wire.go:480-631` — full chain registration in order
- `.claude/CLAUDE.md` "Middleware Chain (order matters)" — operator
  shorthand
- `kc/riskguard/guard.go` + `internal_checks.go` — 9 RiskGuard checks
- `kc/audit/` — buffered async audit writer + hash-chained store
- `kc/billing/billing_test.go` — tier-gating matrix
- `mcp/circuitbreaker*.go` — breaker state machine
- `papertrading/middleware.go` — order interception
- Commit `26a3154` — "feat(app): add panic-recovery middleware as
  outermost HTTP layer" (sibling concern at the HTTP layer above
  this MCP-layer chain)
- Commit `ec325ae` — "feat(mcp): add Config-driven middleware chain
  builder"
- Commit `333ca32` — "feat(riskguard): plugin discovery via
  RISKGUARD_PLUGIN_DIR manifest" (extension point for safety layer)
- Commit `a97dc29` — "feat(riskguard): market-hours rejection for
  live orders (T1)" (most-recent addition to the 9-check matrix)
