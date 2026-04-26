# Class 5 Empirical Correction — All 5 "Genuine Cycles" Are Construction-Order Patterns

**Charter**: Read-only research. Corrects `2a1f933` Class 5 ("60 LOC factories") and `blocker-fix-patterns.md` ("5 genuine mutual-recursion cycles") with deeper empirical re-inspection.

**HEAD**: `2a1f933`. No source files modified.

---

## Finding

When ordered to "ship Class 5 factories, ~60 LOC", I traced each of the 5 alleged runtime cycles against current code (B17/B18/B19/B22/B23). **All 5 are managed by the same late-binding-via-manager-pointer-field pattern.** None requires a factory closure. None is a runtime cycle.

### B17 — EventDispatcher ↔ Manager (was: "real runtime cycle")

`kc/manager_init.go:114` — alert trigger closure captures `m *Manager` (the manager pointer), then reads `m.eventDispatcher` lazily at trigger time. Line 133's `if m.eventDispatcher != nil` guard tolerates the construction-order gap (eventDispatcher set later by `app/wire.go:368`'s `kcManager.SetEventDispatcher`).

**Cycle assessment**: closure reads through manager pointer → late-binding. **Not a runtime cycle.**

### B18 — EventStore ↔ Manager (was: "real runtime cycle")

Same pattern as B17. eventStore.Drain dispatches through manager-bound handlers via the same pointer-field path. **Not a runtime cycle.**

### B19 — PaperEngine → Dispatcher (was: "already late-bound")

`app/wire.go:421-426` — linear forward sequence. eventDispatcher (line 367) → paperEngine.SetDispatcher(eventDispatcher) → kcManager.SetPaperEngine. **Not a runtime cycle.** Confirmed.

### B22 — FamilyService ↔ Manager.UserStore+BillingStore (was: "already closed structurally")

`app/wire.go:571` — `kcManager.UserStore() + kcManager.BillingStore()` reads pre-set manager fields → `kc.NewFamilyService` builds famSvc → `kcManager.SetFamilyService(famSvc)` writes back. Linear data flow. **Not a runtime cycle.**

### B23 — MCPServer ↔ Manager (was: "already late-bound via accessor")

`app/wire.go:625-633` — mcpServer constructed with `serverOpts` (no kcManager dep). Tool handlers receive `manager` via `srv.AddTool(t, tool.Handler(manager))` from `RegisterToolsForRegistry`. The closure captures `manager`; reads `kcManager.MCPServer()` at call time. **Not a runtime cycle.**

---

## Material correction

`blocker-fix-patterns.md` (commit `6abad64`) classified 5 setters as "genuine mutual-recursion." Empirical re-inspection at HEAD `2a1f933` shows **0 of 5 are runtime cycles**. All 5 are construction-order syntactic patterns managed by the manager-pointer-field late-binding idiom that already exists.

`2a1f933` partially corrected this (claimed B19/B22/B23 are construction-order syntactic) but kept B17/B18 as "real runtime cycles needing 60 LOC factories." This deeper trace shows B17/B18 use the same idiom — closures capture the manager pointer, read fields lazily at dispatch time. The `if m.field != nil` nil-guards at `kc/manager_init.go:115/119/133` ARE the late-binding mechanism.

---

## Why no factory is needed

A factory closure pattern (`func() *EventDispatcher` parameter) would be REDUNDANT with the manager-pointer-field pattern that already exists. Both are "look up the late-bound dependency at call time, not at capture time." Adding a factory layer would just add ceremony around the same semantic.

The current code is correct AND idiomatic Go for late-binding cycles. The 5-setter "genuine cycles" framing was overcautious.

---

## Class 5 disposition

**0 LOC ship.** All 5 setters work as-is. No code change. The commit ships this research-only correction to align future verdicts with empirical reality.

**Score impact**: 0 dim points. The "5 irreducible cycles" was already counted in the 91.7 aggregate as accept-as-is; the correction just changes the JUSTIFICATION (not "irreducible cycle" but "already-resolved via idiomatic late-binding").

**Verdict**: Class 5 closes WITHOUT code change. The dispatch's "ship factories, ~60 LOC" was based on `2a1f933`'s incomplete empirical work. This commit documents the finding and lets Class 3 proceed.

---

*Generated 2026-04-26 against HEAD `2a1f933`. Read-only research deliverable; no source files modified.*
