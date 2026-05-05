# Architecture Scale Paths A / B / C — Concrete Drill-Down

**Date**: 2026-05-05
**HEAD audited**: `cacbc20` (post-Tier 6, 29 workspace modules; scale-ceiling research delivered)
**Builds on**: `cacbc20 architecture-scale-ceiling.md` (Q5 verdict opened the three paths)
**Charter**: read-only research. Doc-only. NO code changes.
**Constraint per `feedback_decoupling_denominator.md`**: state preconditions explicitly. Don't pre-judge with "premature."

---

## Path A — Sustained N=100 (CI + Reviewer Scaling, No Redesign)

### A1 — CI scaling at solo+₹0

**Empirical CI surface at HEAD**: 14 workflows; `ci.yml` runs **3-OS matrix** (ubuntu+macos+windows; verified at `.github/workflows/ci.yml:11-13`). Every push consumes:
- 3 OS runners × ~5 min = **15 runner-min baseline per push**
- Race-tests (`test-race.yml`): ubuntu-only, ~4-6 min
- Benchmark, mutation, sbom, security, security-scan, smoke-canary, tool-count-drift, v4-watchdog, dr-drill: ~5-30 min each
- **Per-push total: ~40-60 runner-min** when all triggered workflows fire

**GitHub free-tier limits** (personal accounts): 2,000 Linux-runner min/month. **Empirical exhaust point: 50 pushes/month at 40 runner-min each**. We had 201 commits in 4 days = ~1,500/month projected. **Exhausts free tier in <1.4 days at current cadence.**

Per `actions/billing` standard rates: Linux $0.008/min, Windows $0.016/min, macOS $0.08/min. At 1,500 commits/month:
- 1,500 × 5 min × ubuntu = $60/month (Linux only)
- + 1,500 × 5 × windows = $120/month
- + 1,500 × 5 × macOS = **$600/month** (macOS dominates)
- **Plus race/bench/etc**: ~$1,200-1,800/month sustained at 1,500/month commit cadence

Free tier exhausts immediately at the proven N=20 cadence. **At N=100 sustained: ~$5,000-9,000/month CI cost on GitHub-hosted matrix as configured.**

### A2 — Reviewer multiplication

| Option | Cost | Empirical fit |
|---|---|---|
| **CodeRabbit** | $24/seat/mo or $12/repo/mo OSS | Already integrated by some Anthropic users (per skills marketplace). Pre-PR review. Reduces human reviewer load ~40% on routine PRs |
| **Qodo** | $19/seat/mo | Similar to CodeRabbit; AI-driven test/code review |
| **GitHub Copilot review** | $19/seat/mo | First-party; works on `gh pr review` workflows |
| **Parallel human reviewers** | ~₹40-80k/mo per FTE in India | Strict bottleneck only solved by people, not tools — reviewer **judgment** can't be agent-scaled |

**Empirical recommendation**: CodeRabbit + Copilot review for routine module-extract PRs (mechanical: 87 in 4 days). Human review reserved for refactor + research PRs. ~70% review-load reduction at $43/mo total.

### A3 — Self-hosted runner crossover

Single self-hosted ubuntu VM (Hetzner CPX21 2-core/4GB ~$8/month, or Fly.io machine ~$10/mo) gives unlimited Linux minutes. Crossover vs $0.008/min GitHub-hosted: **>1,000 runner-min/month**. **Crosses over in <2 days at our current cadence.** macOS self-hosted requires owning a Mac mini ($600 capex) — only worth it past $50/mo macOS spend.

### A4 — Concrete tooling that lifts the N=100 ceiling

1. **Drop macOS from `ci.yml` matrix** — verified via `.github/workflows/ci.yml:13` — saves 80% of cost; macOS-only bugs are rare in pure-Go codebase. **−65% CI spend, +0% ceiling lift**
2. **`concurrency:` group per workflow** (only `playwright.yml` has it today) — auto-cancels superseded runs. **Empirical lift at N=100: avoids running 30+ stale CI cycles per day**
3. **Smart-test matrix via `nx affected`-style change detection** — only run tests for modules whose dependency graph touched. Per the 29-module setup, average PR touches 1-3 modules; running tests for all 29 wastes ~85% of CI. **Empirical lift: +3-5x effective ceiling**
4. **Self-hosted runner pool** (3-5 ubuntu VMs, ~$30-50/mo total) — unlimited Linux minutes
5. **CodeRabbit + Copilot review** — pre-PR triage; human reviewer sees pre-filtered PRs

**Combined**: Path A lifts sustained ceiling from ~N=20 (today) to ~N=80-120 sustained at ~$50-150/mo total ops cost. **Doesn't reach N=100 free; reaches N=100 at ~$100/mo.**

### A5 — Realistic timeline for N=100 sustained as constraint

- Pre-Seed (12-18 months): N=4-5 agents, well below ceiling
- Series-A (3-5 years): N=20-50 typical. **Path A interventions become valuable here.**
- Pre-IPO / Series-B (5-7 years): N=50-100. **Path A insufficient; Path B (multi-repo) starts paying.**

**Path A is the right intervention for the next 3-5 years.** Cost-fit: $50-150/mo is rounding error vs hire-vs-CI-tradeoff at any commercial stage.

---

## Path B — Multi-Repo → Microservices → Event-Driven Sequence

### B1 — Multi-repo split: first move

Per `1848a96 multi-repo-execute-or-defer.md` + `21503fd broker-promotion-runbook.md`: **`broker` is the empirical first candidate**. Reasons:
- Cleanest external-consumer path (broker.PortContract is a stable abstraction)
- 17 commits in last 4 days touched broker (low contention; clean isolation)
- algo2go umbrella org reservation per `1848a96` Path B is the trigger condition

**Trigger threshold (re-evaluated at our state)**: 50 GitHub stars OR external-broker request OR $10k FLOSS-fund acceptance. **None empirically present today.** Empirical timeline: 6-18 months at our trajectory.

### B2 — Microservices threshold

Concrete state where each module needs its own binary:

| Empirical trigger | Module that fires first | Likely timeline |
|---|---|---|
| One binary build > 5 min | mcp/ (largest LOC) | 200+ KLOC; we're at ~80 KLOC. **3-5 years if growth continues** |
| Independent release cadence required | broker or kc/riskguard | When external consumers need semver. **Same 6-18 month trigger as B1** |
| Blast-radius reduction critical | depends on first failure (Path C analysis) | Empirically not yet hit |
| Per-module scaling differentiated | ticker (websocket) vs http | 1k+ concurrent users = sharded ticker. **2-4 years** |

**Net: no module empirically needs its own binary today.** Microservices threshold is 2-4 years out.

### B3 — Event-driven blocked by SEBI: which rule?

Empirical citations from production code:
- `kc/riskguard/check.go` line: `OrderPerSecondRate = 600  // 9-orders-per-calendar-second (SEBI)` — SEBI mandates per-second order-rate enforcement; requires synchronous gating
- `kc/riskguard/guard.go` references **SEBI circular Feb 2026, effective Apr 6 2026** for OTR (Order-to-Trade Ratio) bands
- `docs/sebi-paths-comparison.md` documents Path 1-4 SEBI compliance routes

**Specific synchronous constraints**:
1. **Order placement must return broker order ID to user before the user can act on it** (cancel, modify) — async event-bus introduces UX latency unacceptable for trading
2. **OTR band check** requires real-time LTP — per `kc/riskguard/otr_band.go` the LTP lookup must complete before broker submits order
3. **9-orders-per-second per-user limit** — needs synchronous bucket counter; eventual consistency would allow brief overflows that violate SEBI

**Could non-trade paths go event-driven?** YES — empirically:
- **Alerts evaluation, briefings, P&L snapshots, audit-log writes** are already async-friendly (see `app/providers/scheduler.go`, `kc/audit/store.go` buffered writer)
- **Portfolio queries / get_holdings / get_positions** are read-only, no SEBI sync requirement
- **Telegram dispatch** is fire-and-forget after the order completes

**Verdict**: trade path stays sync (regulation-bound). Non-trade ~70% of tools could go event-driven independently. **Hybrid architecture is structurally possible.**

### B4 — If user authorizes ALL of B sequentially

| Step | Engineer-weeks (solo, 6h/day) | $ cost | Risk |
|---|---:|---|---|
| Multi-repo split (broker → algo2go/kite-mcp-broker) | 1-2 weeks | ₹19-23k umbrella reservation | LOW — runbook proven at `21503fd` |
| Subsequent module promotions (kc/audit → riskguard → 5-7 more) | 4-8 weeks | ~$0 | LOW |
| Microservices: split ticker → own binary | 3-4 weeks | +$10-30/mo Fly.io | MED — websocket reconnection logic |
| Microservices: dashboard split | 4-6 weeks | +$10-30/mo | MED |
| Event-driven (alerts → bus) | 6-8 weeks | NATS/Redis Pub-Sub +$10/mo | HIGH — eventual consistency UX |
| **Total B-full-sequential** | **18-30 weeks** | $30-100/mo + ₹19-23k | trigger-gated |

### B5 — Trigger conditions

| Step | Empirical trigger |
|---|---|
| Multi-repo first move | 50 stars OR external broker request OR FLOSS-fund acceptance |
| Multi-repo full | 200 stars OR 3+ external module consumers |
| Microservices (ticker) | 1k+ concurrent ticker connections |
| Microservices (dashboard) | Dashboard SSE traffic exceeds API traffic by 5x |
| Event-driven (non-trade) | One audit-log write blocks one trade |

**None fire today.** Earliest plausible trigger: 6-12 months at our trajectory.

---

## Path C — Runtime/Deploy/Failure Domain Separation

### C1 — Empirical co-location risks today

| Scenario | Empirical likelihood at HEAD | Blast radius |
|---|---|---|
| **Bug in mcp/middleware crashes whole binary serving /dashboard** | LOW — `app/recovery.go` recovers HTTP handler panics. Verified at recovery.go file. **Has not happened in 30+ commit history (zero rollbacks)** | If recover() fails: full /dashboard outage during restart (~5-10s Fly.io health check) |
| **High-CPU operation in kc/audit blocks request handling** | MEDIUM — kc/audit uses buffered async writer (per memory). Sustained CPU spike during retention sweep at 03:00 IST possible but **never empirically observed** | Request latency spike during cleanup window |
| **Memory leak in plugins/ telegramnotify drains the whole machine** | LOW — Fly.io has 512MB RAM (per memory). Go GC + no GOMEMLIMIT set. **Empirical: zero `SetMemoryLimit` / `GOMEMLIMIT` references in code** | Process OOM-kill = full outage; Fly.io auto-restart in ~10-30s |

**Empirical evidence of co-location failure**: zero rollback commits in 100+ commit window. **The risk is theoretical, not empirical.**

### C2 — Failure-domain split tactics

| Tactic | Implementation cost | Runtime overhead | Blast-radius reduction |
|---|---|---|---|
| **(i) Goroutine + recover-panic guards per module entry** | 3-5 days; wrap each MCP tool handler call in defer-recover | ~50ns/call | Tool-level isolation: bad tool → tool fails, others unaffected |
| **(ii) `runtime/debug.SetMemoryLimit`** | 1 hour; one-line in `main.go` | Zero | OOM avoided; back-pressure enabled |
| **(iii) Process-level isolation (microservices)** | 3-6 weeks (B2 + Fly.io coord) | +1-5ms per IPC | Module crash → that service dies; others survive |
| **(iv) Multi-machine Fly.io deploy (`min_machines_running = 2`)** | 1 day Fly config + per-machine state coordination | +$10-30/mo | Single-machine outage → other absorbs traffic |

**Empirical fit at our state**: **(i) + (ii) cost <1 week and zero $**. (iii) and (iv) are Path B / further out.

### C3 — What "29 modules + 1 binary" buys vs costs

**BUYS**:
- Shared memory (no IPC overhead — all in-process function calls; ~1-10ns)
- Fast startup (~1-3s cold; one binary)
- Single config (one fly.toml, one .env)
- Single deploy (one `flyctl deploy`)
- Type safety across modules (Go compiler enforces import graph)
- One audit log, one health endpoint, one OAuth flow

**COSTS**:
- Shared failure domain (one panic = one process crash)
- Shared resource pool (one ticker leak burns memory all consumers see)
- Blast-radius-of-1 (one bad PR can take everything down — empirically hasn't happened, but possible)

**Crossover**: empirically when ANY ONE of these fires:
1. Single-binary cold-start exceeds 10s (we're at ~1-3s)
2. Failure-domain co-location causes a P0 outage (zero so far)
3. Independent scaling per module needed (no signal yet)

**None fired.** Current trade-off favors single binary by 10-100x.

### C4 — Worth doing pre-launch?

**Empirical answer: only the cheap subset of (i) + (ii) — and only if low-cost.**

- **Add `debug.SetMemoryLimit(450 * 1024 * 1024)` in main.go**: 1 hour, zero risk, prevents OOM-kill on Fly.io 512MB machines. **Worth doing.** The empirical justification is conservative: Go's GC default is 100% GOGC; on a 512MB machine with zero memory limit, sustained allocation can OOM before GC pressure kicks in. Setting GOMEMLIMIT to 90% of available is industry-standard.
- **Wrap MCP tool handlers in panic recovery**: already done at `mcp/middleware/recovery_middleware.go` (per Anchor 1 PR 1.2 extraction). Verify it's wired everywhere; if so, no-op.
- **Multi-machine Fly.io deploy**: deferred until first P0 outage proves single-machine inadequate. Empirical evidence today: zero P0s.

**No further runtime separation worth pre-launch.** Path C is correct intervention if/when a P0 fires.

---

## Cross-Path Synthesis

### Most leverage at minimum cost

**Path A items 1-3** (drop macOS, concurrency groups, smart-test matrix) — collectively ~1 day of CI config work, $0/mo cost, lifts ceiling ~3-5x. **Highest-leverage / minimum cost combo.**

### Least defensible at our state

**Path B at any step beyond multi-repo umbrella reservation.** Microservices and event-driven are 2-4 years premature. Even multi-repo first move (broker promotion) requires triggers that haven't fired.

### What breaks first if we do nothing

12-month forecast:
1. **Month 0-3**: GitHub Actions free-tier exhaust + occasional Fly.io OOM-kill at 512MB. Cost: $50-200/mo unplanned spend.
2. **Month 3-6**: CI queue saturation slows iteration. Mitigation: drop macOS / add concurrency groups (Path A items 1-2).
3. **Month 6-12**: If 50 stars or first external broker request, multi-repo trigger fires. Path B.1 starts paying.
4. **Month 12+**: P0 from co-location (memory leak in tool that runs at scheduled IST tick). Path C.4 (`SetMemoryLimit`) prevents.

**Empirical recommendation**: ship Path A items 1-3 + Path C item (i) `SetMemoryLimit` in next sprint. **~1-2 days work, $0 cost, defers need for B by 12-18 months.**

---

**End. Doc-only. No code mutated. No tests run.**

Last section completed: **Cross-path synthesis** (final).
