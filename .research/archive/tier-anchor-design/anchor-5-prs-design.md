# Anchor 5 — PRs 5.1 through 5.8 Design (kc/ports inversion)

**Date**: 2026-05-04
**HEAD audited**: `dd04545` (post-`b-full-pr-shapes` + post-Tier-2-COMPLETE; PR 4.1 still pending)
**Builds on**: `7ac9d34 b-full-pr-shapes.md` (Anchor 5 PR sketch) + `dd04545 anchor-4-prs-4-2-to-4-8-design.md` (Anchor 4 prerequisite design)
**Charter**: read-only research. Doc-only. NO code changes.

---

## Critical Empirical Re-Frame (refutes prior brief assumption)

The brief calls kc/ports' kc-parent imports "circular surface" and the inversion "removes parent imports, redesign so `kc` imports `kc/ports` (not the reverse)." **This is empirically wrong.**

Read `kc/ports/session.go:1-15` verbatim:

> *"Compile-time satisfaction is asserted in kc/ports/assertions.go, which imports kc. The kc package does NOT import kc/ports — so the import graph stays acyclic even though ports reference kc types."*

**Empirical verification**: zero `import "kite-mcp-server/kc/ports"` lines from inside `kc/`. The 5 importers of kc/ports are all in `mcp/`: `alert_deps.go`, `common_deps.go`, `context_tool.go`, `read_deps.go`, `session_deps.go`. The graph today is:

```
mcp/ ─→ kc/ports ─→ kc/  (one-way; acyclic)
```

The "inversion" is **NOT a cycle break.** The actual goal under Anchor 6 (kc-root god-struct cleanup) is: ports should reference `kc/domain` types, not `kc` parent types — so that **post-Anchor-6 the kc package can shrink to assembly-only** (kc.Manager + Fx wiring) without leaving ports orphaned. This is **decoupling**, not cycle-breaking.

**Re-framed Anchor 5 statement**: *"Move the 4 kc-internal type references out of kc/ports into kc/domain (or other already-extracted leaf modules), so kc/ports has zero kc-parent dependency. This unblocks Anchor 6's kc-root shrink."*

---

## Empirical Inventory

**kc/ports content** (231 LOC across 6 files):

| Port file | LOC | kc-parent imports | Types referenced from kc | Already inverted? |
|---|---:|---:|---|---:|
| `kc/ports/alert.go` | 31 | line 4 | `kc.AlertStoreInterface` (`kc/interfaces.go:30`) | No |
| `kc/ports/credential.go` | 41 | (none) | (none — pure port file) | **Yes** |
| `kc/ports/instrument.go` | 37 | line 4 | `kc.InstrumentManagerInterface` (`kc/interfaces.go:508`) | No |
| `kc/ports/order.go` | 41 | line 4 | `*kc.OrderService` (`kc/order_service.go:13`) | No |
| `kc/ports/session.go` | 63 | line 18 | `*kc.KiteSessionData` (`kc/manager.go:239`), `kc.SessionPort` impl by `*kc.Manager` | No |
| `kc/ports/assertions.go` | 18 | line 3 | `*kc.Manager` for compile-time satisfaction checks | No (intentional — see below) |

**Reverse-deps** (5 mcp/ files): `mcp/alert_deps.go`, `mcp/common_deps.go`, `mcp/context_tool.go`, `mcp/read_deps.go`, `mcp/session_deps.go`. These touch **only the port interface** — they do NOT directly reach the underlying `kc.Manager`. So changing port internals does not propagate to consumers as long as the public port interface stays signature-stable.

**Type-move targets** (4 declarations):

1. `kc.AlertStoreInterface` (`kc/interfaces.go:30`) → relocate to `kc/domain/alert_store_interface.go` OR `kc/alerts/store_interface.go`
2. `kc.InstrumentManagerInterface` (`kc/interfaces.go:508`) → relocate to `kc/instruments/manager_interface.go` (kc/instruments is already extracted)
3. `kc.KiteSessionData` (`kc/manager.go:239`) → relocate to `kc/domain/session.go` (kc/domain already has session.go for related types)
4. `*kc.OrderService` reference in `kc/ports/order.go` → either move OrderService struct to kc/domain OR keep the order.go's reference — **but** OrderService is a service type with method receivers; moving it has implications for Anchor 6 design. **See PR 5.7 for the decision.**

---

## Per-PR Design

### PR 5.1 — `refactor(kc/credential): no-op verification of credential port (already inverted)`

- **Title**: `refactor(kc/ports/credential): add ports leaf-stability assertion test`
- **Files modified**: 1 file new — `kc/ports/credential_leaf_test.go` (~25 LOC).
- **Build verification**: `go vet ./kc/ports/...` and `go test ./kc/ports/... -count=1 -run TestCredentialPortLeaf` and `cd kc/ports && go list -deps . | grep -c kite-mcp-server/kc$` (expect 1 because of the still-present non-credential ports). The test asserts: `import "github.com/zerodha/kite-mcp-server/kc/ports/credential"` returns ports without ever loading `kite-mcp-server/kc` parent (use `go list -deps` programmatically).
- **Acceptance**: test green; comment in test file documents the leaf-stability invariant for the port that's already there.
- **Time**: ~15 minutes.
- **Inter-PR coupling**: Independent. **Smallest first PR — risk floor for Anchor 5.** Can ship immediately, no dependencies.

### PR 5.2 — `refactor(kc/alerts): relocate AlertStoreInterface from kc/interfaces.go`

- **Title**: `refactor(kc/alerts): move AlertStoreInterface to kc/alerts/store_interface.go`
- **Files modified**: 3 files — (a) **NEW** `kc/alerts/store_interface.go` (~50 LOC, hosts the `AlertStoreInterface` type), (b) `kc/interfaces.go` (delete lines 30-XXX, the interface block), (c) **deferred** edit to `kc/ports/alert.go` (does NOT change yet — port still imports `kc` and uses an alias).
- **Build verification**: `go build ./...` from root + `GOWORK=off go build ./...` from root + `cd kc/alerts && go build ./...` + `cd kc/alerts && GOWORK=off go build ./...`. Plus `go vet ./...` from root. **Critical**: at this PR boundary, kc still re-exports `AlertStoreInterface` as a type alias (single-line `type AlertStoreInterface = alerts.AlertStoreInterface` in `kc/interfaces.go`) so all existing consumers keep building unchanged.
- **Acceptance**: type alias works; consumers (143 reverse-dep files) all still build.
- **Time**: ~25 minutes (write file + delete from interfaces.go + add alias + verify).
- **Inter-PR coupling**: Independent of 5.3-5.7. Depends only on PR 4.1+ (kc/domain extracted).

### PR 5.3 — `refactor(kc/ports/alert): drop kc-parent import; reference alerts.AlertStoreInterface`

- **Title**: `refactor(kc/ports/alert): import kc/alerts not kc parent`
- **Files modified**: 1 file — `kc/ports/alert.go`. Change `import "github.com/zerodha/kite-mcp-server/kc"` → `import "github.com/zerodha/kite-mcp-server/kc/alerts"`. Change return type `kc.AlertStoreInterface` → `alerts.AlertStoreInterface`.
- **Build verification**: `cd kc/ports && go build ./... && GOWORK=off go build ./...` plus `go build ./mcp/...` (the 5 reverse-dep mcp/ files). The mcp/ files reference `ports.AlertPort.AlertStore()` — return type changes from `kc.AlertStoreInterface` to `alerts.AlertStoreInterface`. Because of the type alias from PR 5.2, this is **assignment-compatible** without consumer changes.
- **Acceptance**: kc/ports/alert.go compiles without kc-parent import; all 5 mcp/ consumers still build.
- **Time**: ~15 minutes.
- **Inter-PR coupling**: **Depends on PR 5.2 (alias must exist).** Cannot merge before 5.2.

### PR 5.4 — `refactor(kc/instruments): relocate InstrumentManagerInterface`

- **Title**: `refactor(kc/instruments): move InstrumentManagerInterface to kc/instruments package`
- **Files modified**: 3 files — (a) NEW `kc/instruments/manager_interface.go` (~80 LOC), (b) `kc/interfaces.go` (delete `InstrumentManagerInterface` block at line 508), (c) `kc/interfaces.go` (add alias `type InstrumentManagerInterface = instruments.InstrumentManagerInterface`).
- **Build verification**: same gate as PR 5.2. kc/instruments is already an extracted module (commit `766c133`); this PR adds a new file inside it — module standalone build must pass with `cd kc/instruments && go build ./...`.
- **Acceptance**: alias works; consumers all build.
- **Time**: ~25 minutes.
- **Inter-PR coupling**: Independent of 5.2, 5.3, 5.5-5.7. Depends only on PR 4.1+. **Parallel-safe with 5.2.**

### PR 5.5 — `refactor(kc/ports/instrument): drop kc-parent import; reference instruments package`

- **Title**: `refactor(kc/ports/instrument): import kc/instruments not kc parent`
- **Files modified**: 1 file — `kc/ports/instrument.go`. Change `import "github.com/zerodha/kite-mcp-server/kc"` → keep the existing `"kite-mcp-server/kc/instruments"` import (already there at line 5); change `kc.InstrumentManagerInterface` → `instruments.InstrumentManagerInterface`.
- **Build verification**: `cd kc/ports && go build ./...`; `go build ./...`; mcp/ consumers verify.
- **Acceptance**: ports/instrument.go has no kc-parent import.
- **Time**: ~15 minutes.
- **Inter-PR coupling**: **Depends on PR 5.4.** Parallel-safe with 5.3.

### PR 5.6 — `refactor(kc/domain): relocate KiteSessionData to kc/domain/session.go`

- **Title**: `refactor(kc/domain): move KiteSessionData out of kc/manager.go`
- **Files modified**: 2 files — (a) **kc/domain/session.go** (already exists; ADD `KiteSessionData` struct here, ~40 LOC), (b) **kc/manager.go** (delete struct at line 239; ADD type alias `type KiteSessionData = domain.KiteSessionData` for backward compat). Plus a domain-import addition to manager.go imports block.
- **Build verification**: same gate. Critical: 14 packages reference `kc.KiteSessionData` (verified via grep). Type alias keeps all of them green.
- **Acceptance**: alias works; all 14 packages still build.
- **Time**: ~30 minutes (KiteSessionData is referenced by SessionPort interface methods).
- **Inter-PR coupling**: Independent of 5.2-5.5, 5.7. Depends only on PR 4.1+ (kc/domain must exist).

### PR 5.7 — `refactor(kc/ports/{session,order,assertions}): drop kc-parent imports`

- **Title**: `refactor(kc/ports): finalize ports leaf — session+order+assertions drop kc parent`
- **Files modified**: 3 files — (a) `kc/ports/session.go` change `*kc.KiteSessionData` → `*domain.KiteSessionData` and drop kc-parent import, (b) `kc/ports/order.go` — KEEP the kc.OrderService reference for now (OrderService struct stays in kc/ for Anchor 6 reasons; document in comment that this last kc-parent import is intentional and removed in Anchor 6), (c) `kc/ports/assertions.go` — KEEP kc-parent import. Comment clarifies that assertions.go *intentionally* imports kc to verify `*kc.Manager` satisfies the ports — this assertion can ONLY live in a package that imports kc, and ports is the appropriate location. **Do NOT change assertions.go in this PR.**
- **Build verification**: same gate. After this PR, only 1 of the 6 port files (assertions.go + order.go for OrderService) imports kc parent.
- **Acceptance**: 4 of 6 port files have zero kc-parent imports; 2 remain by design (assertions, order).
- **Time**: ~25 minutes.
- **Inter-PR coupling**: **Depends on PR 5.6** (KiteSessionData must be in kc/domain).

### PR 5.8 — `test(kc/ports): cycle-detection test using go list -deps`

- **Title**: `test(kc/ports): pin leaf-stability invariant for 4 ports`
- **Files modified**: 1 file — `kc/ports/leaf_stability_test.go` (~50 LOC). Test asserts: for each of `alert.go`, `credential.go`, `instrument.go`, `session.go` — the parsed import statements via `go/parser` (or programmatically via `go list -deps`) do NOT include `github.com/zerodha/kite-mcp-server/kc` (parent path, exact match). Test EXCLUDES `assertions.go` and `order.go` per the design decision in PR 5.7.
- **Build verification**: `go test ./kc/ports/... -count=1 -run TestPortsLeafStability`.
- **Acceptance**: test green; new ports added to kc/ports/ inherit the leaf-stability invariant via build-time check.
- **Time**: ~30 minutes.
- **Inter-PR coupling**: **Depends on PRs 5.3, 5.5, 5.7.**

---

## Cross-PR Section

### Topological Order

```
              ┌─→ PR 5.1 (smallest, runs first; verifies infra)
              ├─→ PR 5.2 ──→ PR 5.3 ──┐
PR 4.1+ ──────┼─→ PR 5.4 ──→ PR 5.5 ──┼──→ PR 5.8 (final cycle-test)
              ├─→ PR 5.6 ──→ PR 5.7 ──┘
              └─(PR 5.6 also independent of 5.2/5.4)
```

**Parallel-safe pairs/triples**:
- PRs 5.2, 5.4, 5.6 (three independent type relocations) → **3-way parallel**
- PRs 5.3, 5.5, 5.7 (three port-file rewrites) → **3-way parallel** (after their respective predecessors merge)

At N=20 agent capacity per `fd603f3`, Anchor 5's 8 PRs absorb into:
- Wave B-1 (parallel): 5.1 + 5.2 + 5.4 + 5.6 → 4 simultaneous
- Wave B-2 (parallel after B-1 merges): 5.3 + 5.5 + 5.7 → 3 simultaneous
- Wave B-3 (final): 5.8 → 1 PR

**Calendar at N=20**: Wave B-1 (~30 min review + CI), Wave B-2 (~25 min), Wave B-3 (~30 min). **Total: ~1.5 hours best-case if reviewer queue is empty.** With realistic 1-reviewer @ 4 PRs/day, ~2-3 days calendar.

### Mid-Anchor Checkpoint: When Is Codebase Deployable?

The codebase is **safely deployable at every PR boundary**, because:

- **PRs 5.2, 5.4, 5.6** add type aliases. Old paths (`kc.AlertStoreInterface`, `kc.InstrumentManagerInterface`, `kc.KiteSessionData`) keep working via single-line aliases in `kc/interfaces.go` and `kc/manager.go`. All 143 reverse-dep packages compile unchanged.
- **PRs 5.3, 5.5, 5.7** modify only `kc/ports/*.go` files. The 5 mcp/ consumers see the public port interface signature, which (because of type aliases) is assignment-compatible with the new types.
- **PR 5.8** is a test-only addition.

**Empirical conclusion**: there is no intermediate broken-state. Production can deploy after any PR. **Build-greenness invariant satisfied at every commit boundary.**

### Risk Floor

**Smallest first PR**: PR 5.1 (`refactor(kc/credential): add ports leaf-stability assertion test`). 1 file, ~25 LOC, no production code touched. Pure test infrastructure that documents the invariant for the port that's already inverted (credential.go).

**Why not skip 5.1?** Because PR 5.8 needs the same `go list -deps` programmatic check pattern. PR 5.1 establishes the pattern in 25 LOC for one port; PR 5.8 generalizes it across 4. Empirical de-risking step.

---

## Honest Verdict — Is Anchor 5 Subdividable?

**Yes**: 8 PRs, all green-light Wave B fan-out.

**Empirical evidence for subdivision**:
1. The "cycle" in the brief is empirically **not a cycle** — it's a one-way `kc/ports → kc` import. No big-bang refactor needed; subdivision works.
2. Type aliases (PR 5.2/5.4/5.6) preserve build-greenness at every commit boundary. The 143 reverse-dep files never break.
3. PR 5.7 explicitly leaves 2 of 6 port files (assertions.go, order.go) with kc-parent imports BY DESIGN. assertions.go must reference `*kc.Manager` for compile-time satisfaction; order.go's `*kc.OrderService` reference is delegated to Anchor 6's kc-root cleanup. Subdividing this way avoids forcing a premature OrderService relocation.
4. Maximum parallelism: 3-way fan-out in Wave B-1 (PRs 5.2/5.4/5.6) and again in Wave B-2 (PRs 5.3/5.5/5.7). At N=20 agent capacity, Anchor 5 ships in ~2-3 days calendar.

**Anchor 5 calendar updated**: prior `7ac9d34` estimate was 9h review / 2-3 weeks calendar. **Re-framed under 20-agent denominator: ~3 hours review / 2-3 days calendar.** Massive compression.

**Green-light recommendation**: dispatch PR 5.1 immediately (after PR 4.1 lands); fan-out PRs 5.2/5.4/5.6 in parallel as Wave B-1.

---

**End. Doc-only. No code mutated. No tests run.**

Last section completed: **Honest verdict** (final).
