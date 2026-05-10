# Phase Pick — Phase 2 (Postgres Adapter Design)

**Picked**: 2026-05-09 IST
**HEAD at pick**: `c6eea80`
**Production**: v252 LIVE; tools=130; 64th consecutive deploy
**Picker**: Axis-C feature execution + 10K-agent capacity architect domain

## Choice

**Phase 2 — Postgres adapter design** (per `.research/10000-agent-blocker-analysis.md` Phase 2).

## Justification

### Why not Phase 1.4 (self-hosted CI runners)

- **Already substantially mitigated** by audit `6ee6520` (commits `1174156` macOS-drop, `f146355` concurrency-groups, smart-test selection). Current CI cost trajectory is bounded for the next ~6-12 months.
- **Operational, not architectural**. Adds ops surface (k8s cluster maintenance, runner registration) without unblocking any code-level work.
- **Trigger has not fired**. Phase 1.4 ROI inflects when CI cost > self-hosted cost; current fleet (Linux + Windows, smart-test on PR) keeps runner-min < 2K/mo. Crossover threshold = ~2-3× current load.
- **Best deferred** until path-a-owner finishes the testutil/plugins/manager refactor sprint (which may further reduce CI cost via tighter test selection).

### Why not Phase 3 (multi-cell runtime)

- **Phase 2 is its prerequisite**. Multi-cell needs partitioned/replicated state OR per-cell SQLite + cross-cell read API. Either path requires the Store-port interface that Phase 2 designs.
- **Largest leap; biggest risk surface**. K8s migration OR Fly multi-app cell is multi-month engineering. Burning the design budget on Phase 3 without Phase 2's interface foundation produces design speculation, not actionable work.
- **Cost-trigger gated**. Phase 3's ROI inflects at sustained 100+ concurrent users — empirical signal not present.

### Why Phase 2 specifically

1. **Smallest first concrete step IS shippable now** (~2-4h). The port interface + Postgres `Store` contract + injection seam at `app/providers/alertdb.go` is in-tree — design doc + interface stub fits the budget.
2. **Empirical seam already exists**. `ProvideAlertDB(cfg AlertDBConfig) (*alerts.DB, error)` Fx provider is the chokepoint. Both `modernc.org/sqlite` and `pgx/v5/stdlib` satisfy `database/sql` — drop-in driver swap is mechanically straightforward.
3. **External repo aligned**. `algo2go/kite-mcp-alerts` (the external module owning persistence) accepts a `database/sql.DB`. Adding a Postgres driver requires zero schema-rewrite if SQL is portable.
4. **Even at zero-user state, design is valuable** — it documents the partition boundary for future-agent onboarding, locks in the per-cell shard contract before Phase 3 needs it, and surfaces the SQL-portability constraint that current SQLite-specific patterns (e.g., `INSERT OR REPLACE`) violate.
5. **Doc-only first commit** preserves tools=130 invariant; chain-agent and path-a-owner unaffected.

## Scope of this dispatch

| Deliverable | Format | Budget |
|---|---|---|
| Phase pick justification | This file (`phase-2-pick.md`) | Done |
| Design doc | `phase-2-postgres-adapter-design.md` | ~2h |
| Smallest first concrete step | Port-interface stub at `app/providers/store_port.go` (compile-clean, no behavior change) | ~1h |
| Recommended next dispatch | Final section of design doc | inline |

**Stop-rule**: ~4h end-to-end; halt + surface at ~6h.
**Out of scope**: actual Postgres `*Store` implementation (lives in `algo2go/kite-mcp-alerts` external repo); SQLite migration script; Postgres CI integration; per-cell shard infrastructure.
