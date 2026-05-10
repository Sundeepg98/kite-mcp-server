# Path B-Full Execution Runbook — All 6 Anchor Redesigns

**Date**: 2026-05-04
**HEAD audited**: `a2ad8e0` (Tier-1 leaf 7/24 — kc/isttz extracted)
**Charter**: read-only research. Single doc. NO code changes.
**Override note**: User explicitly authorized full Path B-Full chain. Prior verdict in `7e1700c` called Anchors 1/2/3/6 "ceremony at our scale today"; user overrides — runbook treats all 6 as in-scope. Re-verdict at end re-evaluates without the pre-judging label.

**Empirical baseline at HEAD `a2ad8e0`** (NOT post-Tier-1 baseline — Tier-1 is in flight, 8/24 modules extracted: broker + kc/{audit, billing, i18n, isttz, legaldocs, money, riskguard}):

| Anchor | Files (prod) | LOC | Reverse-deps | New finding |
|---|---:|---:|---:|---|
| 1. mcp/ | 207 | — | self | imports 16 kc/* + `"kite-mcp-server/kc"` parent (80 files) |
| 2. app/ root | 21 (60 incl tests) | — | self | imports `kc` parent (23 files) |
| 2b. app/providers/ | 14 (32 incl tests) | — | app | clean Fx-recipe partition |
| 3. kc/ops | 70 | — | self | imports `kc` parent (10+ files) |
| 4. kc/domain | 17 prod | — | **143** | **Not a clean leaf**: imports broker, kc/isttz, kc/money |
| 5. kc/ports | 6 | — | **5** (all in mcp/) | All 6 import `"kite-mcp-server/kc"` parent (the circular surface) |
| 6. kc-root | 75 | **25,644** | — | `kc.Manager`: **52 methods** (12 pure getters in `manager_accessors.go`); `kc/interfaces.go` 573 LOC |

**Discrepancy with `7e1700c`**: prior plan said kc/domain has zero internal deps. Empirically false: `kc/domain/holding.go`, `order.go`, `position.go`, `profile.go` import `broker`; `money.go` imports `kc/money`; `session.go` imports `kc/isttz`. Three of those (broker, money, isttz) are now own modules — so the deps are at module boundary, not in-tree-cycle. Domain is **module-clean** (only depends on already-extracted modules). Extraction cost rises slightly but doesn't introduce cycles.

---

## Cross-Anchor Topological Order — Confirmed + Refined

```
Anchor 4 (kc/domain) ──┬─→ Anchor 5 (kc/ports invert) ──→ Anchor 6 (kc-root)
                       └─→ Anchor 1 (mcp/ split)
                       └─→ Anchor 3 (kc/ops split)
                            Anchor 2 (app/) ── independent (2nd-binary trigger)
```

**Refinement**: Anchor 4 must finish before 5/6/1/3. Anchor 5 unblocks 6. Anchors 1, 3, 6 can parallelize (3 agents, disjoint files).

**Sequential calendar (1 engineer, 6h/day focused work)**: ~28-36 weeks. **3-agent parallel after Anchors 4+5 close**: ~16-22 weeks. **Solo realistic with normal life intervening**: ~9-14 months.

---

## Anchor 4 — kc/domain extraction (FIRST)

### Pre-conditions checklist
- [x] Tier-1 leaf modules extracted: broker, kc/money, kc/isttz (verified at `a2ad8e0`)
- [x] kc/domain has only module-clean external imports (verified)
- [ ] Architecture agent's Tier-1 batch (8/24) closed and merged

### Step-by-step execution
- **Phase 0** (0.5 day): grep inventory — 17 prod files; 143 reverse-dep files; 14 importing packages (app, app/providers, kc, kc/alerts, kc/audit, kc/billing, kc/cqrs, kc/eventsourcing, kc/ops, kc/papertrading, kc/riskguard, kc/telegram, kc/usecases, mcp). Grep: `grep -lE "kite-mcp-server/kc/domain\b" --include="*.go" -r .`
- **Phase 1** (0.5 day): design. Confirm kc/domain stays at path `github.com/zerodha/kite-mcp-server/kc/domain` (in-tree multi-module). New `kc/domain/go.mod` requires broker + kc/money + kc/isttz with replace directives identical to `kc/audit/go.mod` shape.
- **Phase 2** (1 day): create `kc/domain/go.mod` per the kc/audit template. Add replace lines for broker + kc/money + kc/isttz. Update root `go.mod` to add `replace github.com/zerodha/kite-mcp-server/kc/domain => ./kc/domain`. Update `go.work` use block. Update Dockerfile to pre-stage `COPY kc/domain/go.mod kc/domain/go.sum* kc/domain/`.
- **Phase 3** (0.5 day): test extension. Run `go test ./kc/domain/...` standalone. Confirm 143 reverse-deps still build via `go build ./...` from root.
- **Phase 4** (0.5 day): deploy. `flyctl deploy` and verify tools=111 unchanged + healthz green.
- **Phase 5** (0.5 day): cleanup. Verify no `replace ../broker` style hacks remain in any go.mod; confirm `go work sync` returns clean.

### Risk inventory + rollback
- **Risk**: domain types churning during extract (e.g., new field on `Order` struct adds to all 143 reverse-deps). **Evidence**: 17 prod files cover Alert/Credential/Instrument/Money/Order/Position/Profile/Session/Holding/Family/Quantity — broad surface. **Mitigation**: pause type changes for 7 days during extract; use `git diff kc/domain/` daily to detect drift.
- **Risk**: in-tree replace path resolution fails when GOWORK=off. **Mitigation**: Dockerfile already proves the pattern (kc/audit, kc/billing, kc/riskguard all use it).
- **Rollback per phase**: Phase 2 — `git revert` the go.mod/go.work commit. Phase 4 — `flyctl deploy` previous tag.

### Calendar week estimate
**Total: 3 working days** (0.5 + 0.5 + 1 + 0.5 + 0.5 + cushion).

### Verification matrix
- `go.work` lists `./kc/domain` ✅
- `kc/domain/go.mod` exists with module path `github.com/zerodha/kite-mcp-server/kc/domain` ✅
- Root `go.mod` has `replace ... => ./kc/domain` ✅
- `go test ./kc/domain/...` green ✅
- Tools count `grep -rE "mcp\.NewTool\(" mcp/*.go | grep -vE "_test" | wc -l` = 111 ✅
- Production deploy + tool-count-drift CI green ✅

---

## Anchor 5 — kc/ports inversion (SECOND)

### Pre-conditions checklist
- [ ] Anchor 4 (kc/domain) extracted as own module
- [ ] kc/interfaces.go declarations stable for ≥7 days (no churn during inversion)
- [ ] Architecture agent's Tier-1 batch closed (avoid go.work race)

### Step-by-step execution
- **Phase 0** (0.5 day): inventory. Grep `grep -E "\"github.com/zerodha/kite-mcp-server/kc\"" kc/ports/*.go` — confirms all 6 port files import the parent kc package (the circular surface). Inventory the exact `kc.AlertStoreInterface`/`kc.CredentialStoreInterface`/etc. type references used inside each port file.
- **Phase 1** (2 days): design. The `*Interface` declarations live in `kc/interfaces.go` (573 LOC). Move them to `kc/domain/storeinterfaces.go` (or split per-domain into `kc/domain/alerts.go`, `kc/domain/sessions.go`, etc.). Each port file then imports `kc/domain` instead of `kc` parent. Type signatures stay byte-identical.
- **Phase 2** (3-4 days): incremental refactor, one port per PR. Order: assertions.go → session.go → credential.go → instrument.go → order.go → alert.go (reverse-dependency order). Each PR: (a) move declarations, (b) update kc/ports/X.go import, (c) verify kc/ops/, mcp/, app/ still compile, (d) merge.
- **Phase 3** (1 day): test extension. Add `kc/ports/cycle_detection_test.go` that verifies — via go list `-deps` — the `kite-mcp-server/kc` parent does not appear in any `kc/ports/*.go` import graph.
- **Phase 4** (1 day): deploy. Check tool count + healthz.
- **Phase 5** (1 day): cleanup. Delete the moved declarations from kc/interfaces.go; update Manager method signatures that consumed them.

### Risk inventory + rollback
- **Risk**: interface drift between kc/interfaces.go and kc/ports/* during refactor (already documented in `redundancy-audit.md` F1+F2). **Evidence**: F1 closure was 4 commits; this multi-PR shape is fragile. **Mitigation**: pause F1+F2 cleanup until inversion complete.
- **Risk**: 5 mcp/ files import kc/ports — interface changes break them. **Evidence**: `mcp/alert_deps.go`, `common_deps.go`, `context_tool.go`, `read_deps.go`, `session_deps.go`. **Mitigation**: keep type names identical during the move; only the import path changes.
- **Rollback per phase**: each Phase 2 PR is independently revertable via `git revert <port-pr-sha>`. Cycle-detection test in Phase 3 pins the inverted state.

### Calendar week estimate
**Total: 2-3 weeks** (1 engineer 6h/day; 6 ports × 0.5 day each + design + cleanup buffer).

### Verification matrix
- `grep -E "\"github.com/zerodha/kite-mcp-server/kc\"$" kc/ports/*.go` returns zero matches ✅
- `kc/interfaces.go` shrinks by ~50% LOC (declarations moved) ✅
- `go build ./...` green at every PR boundary ✅
- mcp/'s 5 importers unchanged in their consumption pattern ✅

---

## Anchor 6 — kc-root god-struct (THIRD; longest)

### Pre-conditions checklist
- [ ] Anchors 4 + 5 complete
- [ ] Decision made: **Option Z (Fx absorbs DI)** vs **Option Y (8-10 narrower services)**. Empirical signal favors Z — `app/providers/` already has 14 prod recipes (alertdb/audit/billing/event_dispatcher/family/mcpserver/scheduler/etc.).

### Step-by-step execution (Option Z path)
- **Phase 0** (1 day): inventory. 52 Manager methods at HEAD; 12 pure getters in `manager_accessors.go` are first deletion candidates. `manager.go` 403 LOC; `manager_init.go` 14 methods; `manager_commands_*.go` 8 across 6 domains.
- **Phase 1** (1 week): design. For each of the 12 pure getters: identify the consumer; design its Fx provider in `app/providers/`. Map: TokenStore() → providers/tokenstore.go; CredentialStore() → providers/credstore.go; etc.
- **Phase 2** (4-6 weeks): incremental migration, one method per week. Per method: (a) write Fx provider, (b) update consumer to take dep via Fx, (c) delete Manager method, (d) verify CI green.
- **Phase 3** (1 week): non-getter methods. The 40 non-getter methods need narrower-port treatment (see Anchor 5 pattern).
- **Phase 4** (1 week): deploy + verify across 4-6 production deploys to surface any runtime regression.
- **Phase 5** (1 week): cleanup. `kc/manager.go` shrinks to assembly-only; aim for <100 LOC. `kc/interfaces.go` deletion (already half-empty post-Anchor-5).

### Risk inventory + rollback
- **Risk**: Fx ordering bugs during incremental migration. **Evidence**: app/providers/lifecycle.go already has explicit ordering; new providers must respect it. **Mitigation**: integration tests at every PR; `go.uber.org/goleak` already wired in tests.
- **Risk**: kc/ subpackages instantiating their own Manager dependency (cycle). **Evidence**: 23 files in app/ + 80 in mcp/ + 10 in kc/ops/ import `"kite-mcp-server/kc"` parent. **Mitigation**: post-Anchor-5 these imports should drop to <20 — verify before Anchor 6 starts.
- **Rollback**: each weekly PR is independently revertable. Lifecycle hook ordering can be A/B tested via Fx invoke graph.

### Calendar week estimate
**Total: 8-12 weeks** (highest single anchor; can compress to 6 weeks if 2 engineers parallel-stream different domains).

### Verification matrix
- `grep -cE "^func \(m \*Manager\)" kc/manager*.go` < 10 ✅
- `wc -l kc/manager.go` < 100 ✅
- `kc/interfaces.go` deleted or <50 LOC ✅
- All 25,644 LOC kc-root reduces by ≥40% (target ~15K LOC) ✅
- Production stability: 7+ deploys with no incident ✅

---

## Anchor 1 — mcp/ Y-split (PARALLEL with 3, 6)

### Pre-conditions checklist
- [ ] Anchor 4 complete (mcp/ depends heavily on kc/domain types)
- [ ] mcp/ contributor pain trigger fires (≥3 merge conflicts in a sprint OR 2nd contributor onboarded)

### Step-by-step execution
- **Phase 0** (1 week): inventory. 207 files; 61 *tools*.go; 16 *middleware*.go; 113 tests. Domain clusters: trade (post/exit/gtt/options ~8 files), portfolio (get/account/margin/dividend/sector ~8), analytics (backtest/indicators/peer/concall/fii_dii ~8), alerts (alert/composite/native/trailing ~10), admin (10 admin*.go), middleware (16). Each ~12K LOC including tests.
- **Phase 1** (1 week): design. 6 sub-packages: `mcp/tools-trade`, `mcp/tools-portfolio`, `mcp/tools-analytics`, `mcp/tools-alerts`, `mcp/tools-admin`, `mcp/middleware`. Shared `mcp/common` extracted first. Each becomes own go.mod when contributor pain trigger fires; until then in-tree-only sub-packages.
- **Phase 2** (3-4 weeks): incremental sub-package extraction. Per sub-package: move files, regenerate schema-lock golden table for that domain, verify tool-count-drift CI green.
- **Phase 3** (1 week): test extension. Schema-lock per sub-package.
- **Phase 4** (1 week): deploy 6 times (one per sub-package).
- **Phase 5** (1 week): cleanup. Old monolithic mcp/ files deleted.

### Risk inventory
- **Risk**: schema-lock golden table breakage. **Mitigation**: extract `mcp/common` (response envelope, ToolHandler factory) first; each sub-package regenerates only its own golden file.
- **Risk**: shared helpers create cycles. **Mitigation**: `mcp/common` is sub-package #0; everything imports it but it imports nothing from siblings.

### Calendar week estimate
**Total: 6-8 weeks**.

### Verification matrix
- `mcp/` directory has 6 sub-packages + common ✅
- Each sub-package has own `_test.go` files ✅
- Tool count = 111 unchanged ✅
- tool-count-drift CI green ✅

---

## Anchor 3 — kc/ops Y-split (PARALLEL with 1, 6)

### Pre-conditions checklist
- [ ] Anchor 4 complete
- [ ] Admin surface stable for 60 days (no new admin_*.go added)

### Step-by-step execution
- **Phase 0** (3 days): inventory. 70 files; admin_* vs user-facing (api_alerts, api_handlers, dashboard) split.
- **Phase 1** (3 days): design. `kc/ops/user/` (dashboard + activity + alerts + paper renderers) vs `kc/ops/admin/` (admin_*, billing, registry).
- **Phase 2** (2 weeks): incremental split. Move files, update imports.
- **Phase 3** (3 days): tests pass.
- **Phase 4** (3 days): deploy.
- **Phase 5** (3 days): cleanup.

### Risk inventory
- Shared template helpers; `kc/templates/` becomes shared dep.

### Calendar week estimate
**Total: 3-4 weeks**.

### Verification matrix
- `kc/ops/user/` and `kc/ops/admin/` exist with own go.mod ✅
- Each tested independently ✅

---

## Anchor 2 — app/providers/ extract (LAST or SKIP)

### Pre-conditions checklist
- [ ] Second top-level binary exists OR ≥3 providers reused outside app/
- **Today: neither true.** Concrete trigger: launch CLI tool that needs Fx recipes.

### Step-by-step execution (when trigger fires)
- **Phase 0** (2 days): inventory. 14 prod recipes in app/providers/.
- **Phase 1** (3 days): design. New repo `kite-mcp-fx-recipes` OR in-tree module `app/providers/`.
- **Phase 2** (1 week): mechanical extraction.
- **Phase 3-5** (1 week): tests + deploy + cleanup.

### Calendar week estimate
**Total: 0 weeks today; ~2 weeks when trigger fires.**

### Verification matrix
- 2nd binary uses providers without copy-paste ✅

---

## Calendar with parallelization

| Path | Calendar |
|---|---:|
| **Sequential, 1 engineer @ 6h/day**: 4 → 5 → 6 → 1 → 3 → 2 | **28-36 weeks** (7-9 months) |
| **2-agent parallel** (after 4+5 close): 6 // (1+3) | **20-26 weeks** (5-6 months) |
| **3-agent parallel** (after 4+5 close): 6 // 1 // 3 | **16-22 weeks** (4-5 months) |
| **Solo with normal life intervening** (50% productive time): | **9-14 months** |

**Resourcing reality**: User is solo today. 2-agent and 3-agent rows assume hires that haven't happened. **Actionable today**: solo serial. Plan for 28-36 weeks calendar; Anchors 4+5 deliver in first 4-6 weeks, 6 starts month 2, 1+3 start month 3+ in solo mode (cannot truly parallel without 2nd contributor).

---

## Honest Re-Verdict (User-Authorized Override)

User accepted the cost. Re-evaluating without "ceremony" framing:

- **Anchor 4 (kc/domain)** — 3 days. **Genuinely worth doing now**: unblocks 5, 6, 1, 3 mechanically. Reverse-dep cascade reduces from 4×N to 1×N. Empirically defensible regardless of trigger state.
- **Anchor 5 (kc/ports inversion)** — 2-3 weeks. **Genuinely worth doing now**: closes a real architectural defect (the circular `kc/ports/* → kc parent` import surface). Cycle-detection-test in Phase 3 makes the win permanent.
- **Anchor 6 (kc-root god-struct)** — 8-12 weeks. **Worth doing post-4+5**: not "ceremony" given user authorization. Concrete value: kc.Manager from 52 methods to <10 means future kc/ subpackage extracts (Tier-2/3 of zero-monolith) become 1-replace operations. Each subsequent anchor benefits.
- **Anchor 1 (mcp/ split)** — 6-8 weeks. **Worth doing if user wants 3-agent-parallel future**: today's solo dev sees no merge conflicts in mcp/, so the immediate ROI is 0. Strategic value: when 2nd contributor onboards, mcp/ split prevents the next 6 months of integration friction.
- **Anchor 3 (kc/ops split)** — 3-4 weeks. **Worth doing if separate admin contributor expected**: today's solo dev maintains all of kc/ops. Strategic value: future SSO/auth-pluggable pivot benefits from clean user/admin split.
- **Anchor 2 (app/providers extract)** — 0 weeks today. **Genuinely defer**: 2nd-binary trigger has not fired. User authorizing Path B-Full doesn't change the cost-benefit; nothing to extract for.

**Net** — 5 of 6 are worth executing under user authorization. Anchor 2 stays trigger-gated regardless. Topological order from `7e1700c` confirmed empirically. Solo realistic completion: **9-14 months**; honest calendar.

**Recommended next dispatch (execution, not research)**: kick off Anchor 4 — kc/domain extraction. 3 working days. Architecture agent or fresh execution agent can do it once Tier-1 batch closes.

---

**End of runbook. No code changes. No tests run. Doc-only deliverable. Last anchor section completed: Anchor 2 (with full re-verdict).**
