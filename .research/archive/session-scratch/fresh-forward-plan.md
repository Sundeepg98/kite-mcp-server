# Forward Plan: 76% → 90%+ Architecture (Session N+1+)

**Date:** 2026-04-12  
**Current honest score:** 76%  
**Target:** 90%+  
**Scope:** 2–3 sessions (~10–14 hours total)

---

## 1. Ranked Top 10 Actions (Highest ROI First)

| # | Action | Effort (h) | Score impact | Risk | Dependencies |
|---|--------|-----------|-------------|------|---|
| **1** | Migrate Orders domain to QueryBus (GetOrdersQuery + GetOrderHistoryQuery dispatch in 8 tools) | 2.5 | +3–4% (CQRS 80%→85%) | LOW | None — GetPortfolio beachhead proven |
| **2** | Delete 16 dead Provider interfaces in `kc/manager_interfaces.go` | 0.5 | +8–10% (ISP 30%→40%) | LOW | Grep to confirm 0 external refs |
| **3** | Delete 5 empty `kc/ops/handler_*.go` stubs; remove `core` field from each | 0.25 | +1% (code hygiene) | NONE | None |
| **4** | Delete `kc/cqrs/bus.go` + `query_dispatcher.go` + tests; keep DTOs | 1.0 | +2% (honesty: remove dead infrastructure) | LOW | Verify zero instantiations first |
| **5** | Wire `PlaceOrderCommand` through CommandBus at `place_order_usecase.go` entrypoint (first command dispatch) | 3.0 | +3–5% (CQRS 85%→88%+, unlock commands) | MED | Item #1 (OrderQuery pattern must be proven) |
| **6** | Delete or wire 15 unused `*StoreProvider` interfaces from manager (M1–M5 in Phase 2d) | 1.0 | +5–7% (ISP 40%→50%) | LOW | None |
| **7** | Delete test-only aggregates OR wire one (e.g. OrderAggregate → PlaceOrderCommand) | 2–4 | +5–7% (DDD 80%→87%, or −5 if code moves without wiring) | HIGH | Task #5 (need command dispatch first for real wiring) |
| **8** | Add `CountAll() (total, active int)` to AlertStore; optimize `buildOverview` (item F9 + F18 perf audit) | 1.0 | +1% (perf, not arch) | LOW | None |
| **9** | Fix H1 + H2 error handling: fail-closed on audit/riskguard init; expose degraded flag on `/healthz` | 1.5 | +2% (honesty: remove silent failures) | LOW | None |
| **10** | Hoist `strings.ToLower(query)` in search_instruments closure; use `isttz.Location` in riskguard (F7, F12, F13 perf audit items) | 0.5 | +0.5% (perf, minor arch) | NONE | None |

**Total hours (10 items): ~15.75 hours** (fits in 2.5–3 sessions at 4–6h/session realistic pace)

---

## 2. Three-Phase Roadmap

### Phase 1 (Session N+1, ~4 hours) — Quick wins + wiring foundations

**Goal:** +5–6% to ~81%, remove obviously dead code, lay groundwork for CQRS migration.

- **Item #3:** Delete 5 empty ops handlers (0.25h)
- **Item #2:** Delete 16 dead Provider interfaces (0.5h)
- **Item #4:** Delete cqrs bus/dispatcher, keep DTOs (1.0h)
- **Item #9:** Fix H1/H2 error handling (1.5h)
- **Item #10:** One-liner perf fixes (F7, F12, F13) (0.5h)

**Acceptance:** handlers deleted; manager_interfaces.go < 100 LOC; zero imports of `cqrs.New*Bus`; `/healthz` shows `degraded: true` if audit init fails; `strings.ToLower(query)` appears once above Filter closure.

### Phase 2 (Session N+2, ~6 hours) — Core CQRS & ISP architecture wins

**Goal:** +8–10% to ~86–88%, complete Orders migration, reduce dead abstractions.

- **Item #1:** Migrate Orders domain to QueryBus (2.5h)
  - `GetOrdersQuery` + `GetOrderHistoryQuery` in `kc/cqrs/queries.go`
  - Wire dispatch in 8 order tools
  - Verify: `grep "QueryBus().Dispatch.*Order" mcp/*.go` → ≥6 sites
- **Item #6:** Delete remaining StoreProvider interfaces (1.0h)
- **Item #8:** Add AlertStore.CountAll, optimize buildOverview (1.0h)
- **Item #5 start:** Outline CommandBus wiring for PlaceOrderCommand (1.5h)

**Acceptance:** 14+ order-domain dispatch sites wired; ISP interface count < 10; AlertStore.CountAll() called; CQRS score ~85%; ISP score ~48%.

### Phase 3 (Session N+3, ~4–6 hours) — Command-side wiring & DDD completion

**Goal:** +4–6% to ~90%+, wire first command dispatch, resolve aggregate confusion.

- **Item #5 complete:** Wire PlaceOrderCommand through CommandBus end-to-end (2.5h)
- **Item #7:** Delete test-only aggregates OR wire OrderAggregate (2–3h)

**Acceptance:** CQRS >85%; at least one command dispatched; DDD decision made + executed; honest score 90%+.

---

## 3. What NOT To Do (Low ROI / High Risk)

| No-Go | Why | Cost (h) | Payoff | Risk |
|-------|-----|----------|--------|------|
| Full plugin system | 0 production consumers. Accepted at 40%. | 8–12 | +5% | HIGH |
| Full aggregate decomposition | Test-only aggregates are scoped correctly. Wiring 3+ is job enough for next session. | 4–6 | +3% | MED |
| Manager decomposition beyond 25 | 25 is <35 target. Further split is premature. | 3–4 | +1% | MED |
| Delete all ~2,300 LOC dead code at once | Better selective (items #3, #4, #6) so root causes visible. Bulk cleanup obscures architecture gaps. | 2–3 | +2% | LOW risk but poor signal |
| Raise `kc/isttz` coverage 75%→100% | Minor utility package. Test burden outweighs gain. | 1–2 | +0.2% | LOW value |
| Add `get_order_event_history` ES tool | Nice-to-have. Deferred to Session N+4. | 2–3 | +0.5% | LOW priority |
| Full state-based event sourcing | Current EventStore scoped as audit log (correct, live). Full state-ES is months of work. Out of scope. | 12+ | +10% but speculative | HIGH |

---

## 4. Blockers / Prerequisites

**None hard-blocking.** All three Phases can start immediately:

1. **Commit this session's 59 modified files** — must happen before Phase 1 starts. Status: TODO.
2. **Verify zero instantiations of `cqrs.New*Bus`, `cqrs.LoggingMiddleware`, `cqrs.NewQueryDispatcher`** before deleting (Item #4).
3. **Confirm 16 Provider interfaces have zero external callers** (Item #2).

---

## 5. Success Criteria (Per Phase)

### Phase 1 DONE when:
- `kc/ops/handler_*.go` files deleted (5 files gone)
- `manager_interfaces.go` contains only 4 interfaces
- `kc/cqrs/bus.go`, `query_dispatcher.go` deleted; DTOs remain
- `/healthz` returns `degraded: true` if audit init fails in production mode
- Perf fixes landed: F7, F12, F13 lines changed
- `go build ./...` clean, `go test ./...` passes

### Phase 2 DONE when:
- Orders-domain queries exist in `kc/cqrs/queries.go`
- `grep -r "QueryBus().Dispatch.*Order" mcp/*.go kc/usecases/*.go` ≥ 10 hits
- `NewGetOrdersUseCase` called only at bus handler registration
- `AlertStore.CountAll()` exists and called from `buildOverview`
- Manager's Provider interface surface < 5 interfaces
- CQRS score 85%+, ISP score 48%+

### Phase 3 DONE when:
- `PlaceOrderCommand` dispatched via `CommandBus().Dispatch()` from `PlaceOrderUseCase`
- CommandBus handler registered at wire time
- DDD decision executed: aggregates deleted or OrderAggregate wired
- **Weighted average: 90%+**
- `go build ./...` clean, `go test ./...` passes

---

## Honest Effort Estimate

**Realistic pacing (verified from this session):**
- Deep refactors = 2–3h per domain
- Dead-code removal = 0.25–0.5h per batch
- Error-handling fixes = 1–1.5h per HIGH issue
- Testing/verification = ~15% overhead

**Total: 15–18 hours across 3 sessions** (4–6h/session sustainable pace).

---

## Why This Path?

1. **Phase 1 clears debris** — remove dead code, fix silent errors, lay foundations.
2. **Phase 2 proves the pattern** — GetPortfolio is 100% bus-routed; Orders replicates success.
3. **Phase 3 locks the command side** — proves real dispatch happens end-to-end.
4. **Each phase is shippable** — Phases 1 and 2 hit 81% and 86% honestly; Phase 3 closes to 90%+.

**Honesty principle:** every task has a count-based acceptance criterion. No claims without grep/test verification.
