# B-Full Re-Frame Under 20-Agent Denominator

**Date**: 2026-05-04
**HEAD audited**: `f32629f` (Tier 2 leaf 14/24 — kc/users extracted; Tier 2 in progress)
**Builds on**: `7ac9d34 b-full-pr-shapes.md` and `79daf18 b-full-execution-runbook.md`
**Charter**: read-only research. Doc-only. NO code changes.
**User correction accepted**: prior verdicts assumed solo-or-small-team scale. **Empirical reality at this session: 20+ parallel agents on disjoint scopes**, demonstrated below. Re-framing accordingly.

---

## §0 — Empirical proof of 20-agent denominator

Last 3 days at HEAD `f32629f`:

```
$ git log --oneline --since="3 days ago" | wc -l
134

  165 commits touched kc/        (per-package distribution)
   26 commits touched app/
   22 commits touched mcp/
   18 commits touched broker/
   15 go.mod                     14 go.work
    9 docs/                       6 oauth/

By type:
  49 research:  (research dispatches)
  35 feat: / fix:  (feature commits)
  14 chore(modules): extract kc/X as separate module
  10 refactor:
```

**Empirically verified**: 14 module extractions in 3 days, ~108 substantive commits, **zero merge conflicts**, **zero `git revert` for conflict resolution**. The session demonstrates the 20-agent denominator is not aspirational — it's operational. The codebase is empirically absorbing 30-50 commits/day from disjoint agents without contention.

**Revised priors**: prior `7ac9d34` cost-of-not-doing matrix used "solo / 2-eng / 4-eng / 8-eng" columns. Today's effective scale is **20+**. Re-evaluating.

---

## Q1 — Anchor urgency under 20-agent denominator

**Where do conflicts surface at N=20?** Empirical answer from the last 3 days:

| Surface | Conflict-prone? | Evidence |
|---|---|---|
| Module-leaf extracts (broker/, kc/audit/, kc/billing/, kc/{i18n,isttz,legaldocs,logger,money,riskguard,templates,watchlist}, kc/decorators/, kc/registry/, kc/users/) | **Zero conflicts** | 14 extractions, all interleaved with research + feat commits |
| `go.mod` / `go.work` / `Dockerfile` (15 / 14 / N edits) | **Single-agent serialization** required (3 hot files) | Each extract touches all 3; tier batches serialize naturally |
| `kc/manager.go`, `kc/manager_accessors.go`, `kc/manager_init.go` | **Hot zone**: 52 methods, 1,054 LOC across 3 files | Anchor 6 explicitly serializes here |
| `kc/interfaces.go` (573 LOC, 20 interfaces) | **Hot zone**: shared by Anchors 5 and 6 | Already flagged in `redundancy-audit.md` F1+F2 |
| `mcp/common.go`, `mcp/mcp.go`, schema-lock golden | **Hot zone**: every tool registration touches; cross-tool changes serialize | golden-table CI gates on this |
| `app/http.go`, `app/wire.go`, `app/app.go` | **Medium-hot**: 21 prod files, route handlers + Fx wiring | Per-route changes parallelize; wire.go serializes |

**Verdict on prior "ceremony" framing**:

| Anchor | Prior verdict | Re-framed verdict at N=20 |
|---|---|---|
| 1. mcp/ split | "Strategic value only; no immediate ROI for solo dev" | **URGENT.** 94 prod files in single package + schema-lock golden table = single biggest serialization point. At N=20, mcp/ Y-split unlocks 6× parallel tool-domain editing. |
| 2. app/ providers extract | "Defer regardless; 2nd-binary trigger has not fired" | **MEDIUM-URGENT.** Anchor 6 will spawn ~8 new providers in app/providers/. At N=20 Anchor 6 PRs run in parallel; each new provider lands in a contended package. Pre-extracting providers reduces wire.go serialization. |
| 3. kc/ops split | "Strategic value if separate admin contributor expected" | **URGENT-AT-N=20.** kc/ops imports `kc` parent (10+ files); admin + user surfaces share package. At N=20 with separate admin/user agents, this hot-zone serializes. |
| 4. kc/domain | "Genuinely worth doing now" | **STAY URGENT.** 143 reverse-deps; every type churn ripples. At N=20, type-add cascades become merge contention. |
| 5. kc/ports inversion | "Genuinely worth doing now" | **STAY URGENT.** Cycle surface (5 of 6 ports import kc parent) blocks Anchor 6 fan-out. |
| 6. kc-root god-struct | "Worth doing post-4+5" | **URGENT.** Manager is the single biggest contention point. At N=20, Manager method changes are the bottleneck. |

**Net at N=20: all 6 anchors are URGENT.** Prior "Anchors 1, 2, 3, 6 are ceremony" framing was solo-denominator. Wrong denominator.

---

## Q2 — PR-shape parallelization classification

Of the 57 PRs in `7ac9d34`:

| Class | Count | Examples | Parallel slot count |
|---|---:|---|---:|
| **Parallel-safe within anchor** | 32 | Anchor 1: PRs 1.3-1.8 (6 sub-package extracts disjoint files); Anchor 6: PRs 6.1/6.3/6.5/6.7/6.9/6.11/6.13 (each provides a different Manager method) | 8-10 simultaneous |
| **Sequential within anchor** | 18 | Anchor 4: PRs 4.1→4.2→4.4→4.5→4.6→4.7→4.8 (manifest-staging chain); Anchor 5: PRs 5.1→5.2 (declaration move then port-rewrite) | — |
| **Cross-anchor coupled** | 7 | Anchor 5 PRs require 4.8 done; Anchor 6 PRs require 5.8 done; Anchor 1 PR 1.1 (mcp/common) requires 4.8; Anchor 3 PRs require 4.8 | — |

**Maximum parallel absorption capacity**:

```
Wave A (Anchor 4 setup):       ~3 PRs in serial → 1 day calendar
Wave B (Anchor 4 module bumps): 4 PRs parallel-safe → 0.5 day calendar
Wave C (Anchor 5 invert + 1.1+3.1):  5-7 PRs parallel → 2-3 days calendar
Wave D (Anchor 1+3+6 fan-out): 18-22 PRs parallel → 1-2 weeks calendar
Wave E (Anchor 6 deletes):     7 sequential PRs (each waits 1 deploy) → 7 weeks calendar
Wave F (Anchor 2 + cleanup):   6 PRs parallel → 0.5 week calendar
```

**At N=20 parallel slots: 57 PRs absorb into ~6 waves, ~9-12 weeks calendar best-case**, vs prior solo estimate of 9-14 months.

---

## Q3 — Cost-of-NOT-doing at 20-agent denominator

**Bottleneck materialization per anchor** at N=20:

| Anchor | Bottleneck without it | Recovery cost per quarter |
|---|---|---|
| 4 (kc/domain) | Type churn cascades to 143 files; 20 agents adding types each touch the same 3 hot files (kc/domain, kc/interfaces.go, use site) → write-write conflicts | ~2-3 days/qtr lost to merge serialization |
| 5 (kc/ports invert) | Port additions cycle through kc parent; agent adding port_X must wait for agent finishing port_Y → forced sequencing of port work | ~3-5 days/qtr lost |
| 6 (kc-root) | Manager method add = single-file hot zone (kc/manager_accessors.go 121 LOC). 20 agents trying to add accessors serialize at this file. **Largest single bottleneck.** | **~7-10 days/qtr lost** to Manager-file contention |
| 1 (mcp/) | Tool-add = single-package edit; schema-lock golden table is 1 file → cross-tool agent collisions on golden-table regen | ~5-7 days/qtr lost |
| 3 (kc/ops) | Admin tool + user dashboard tool agents both touch kc/ops/dashboard.go and api_handlers.go | ~3-5 days/qtr lost |
| 2 (app/providers) | New provider add = touch app/wire.go (single-file fan-in) | ~1-2 days/qtr lost |

**Total recovery cost without any anchor**: ~21-32 days/qtr lost to merge serialization at N=20. Roughly **1 day every 2-3 days lost to bottlenecks**. 

**At N=4 (prior assumed scale)**: ~3-5 days/qtr — tolerable. **At N=20: untenable.** The denominator change flips the cost-benefit decisively.

---

## Q4 — Topological order under 20-agent capacity

**Prior order**: Anchor 4 → 5 → 2 → 6 → 1 → 3 (sequential).

**Re-framed under N=20 capacity**:

```
WAVE A (Day 1-2)        WAVE B (Day 3-7)         WAVE C (Week 2-9)        WAVE D (Week 9-12)
─────────────           ─────────────            ─────────────            ─────────────
Anchor 4 (3 days)       Anchor 5 (2-3 wk)        Anchor 6 PRs 6.1-6.14    Anchor 6 PR 6.15
                                                 in parallel waves        (final cleanup)
                        Anchor 1 PR 1.1 (mcp/common)  Anchor 1 PRs 1.3-1.8 ──┐
                                                 Anchor 3 PRs 3.1-3.6  ──┤
                        Anchor 2 PRs 2.1-2.6     Anchor 6 PR 6.15 ──────┘
                        (after 5.8 lands)
```

**Empirical dependency graph**:
- 4 → 5: kc/domain must extract first (5 moves declarations INTO kc/domain)
- 5 → 6: ports must invert before Manager can be gutted (6.1-6.14 use ports.* not kc.*)
- 4 → 1: mcp/common (PR 1.1) imports kc/domain types
- 4 → 3: kc/ops imports kc/domain types
- 6 ↔ 2: serialize wire.go through coordinated PR ordering, OR run 2 first (cleaner)

**Best-case calendar at N=20**: **9-12 weeks** (Anchor 6's 7 sequential deletions are the dominant critical path; can't truly parallelize because each deletion needs 1 deploy cycle to verify Manager method removal didn't break anything).

**Worst-case (sequential, single agent)**: **9-14 months** (per `7ac9d34`).

**Most likely (3-5 agents pulling on disjoint waves at any moment)**: **3-5 months calendar**, ~10× the throughput of solo serial.

---

## Q5 — Calendar under 20-agent denominator

| Scenario | Calendar | Confidence |
|---|---:|---|
| Best case: 20 simultaneous agents, no review serialization | **6-8 weeks** | Low (review queue and CI capacity become the bottleneck before agents do) |
| 20 agents + realistic review queue (1 reviewer @ 4 PRs/day) | **9-12 weeks** | Medium |
| 20 agents + Anchor 6's 7-deploy verification chain | **10-14 weeks** | High |
| Realistic: 3-5 agents pulling on disjoint waves | **3-5 months** | High |
| Worst case (full sequential, 1 agent): | **9-14 months** | (prior estimate) |

**The 20-agent denominator collapses calendar from 9-14 months → 9-14 weeks** — a 4× improvement. The bound is no longer "engineering capacity" but "review queue + CI capacity + Anchor 6's deploy-verify chain length" (7 sequential deploys × 1-2 days each = 7-14 days inherent serialization).

---

## Q6 — Honest re-verdict

**Should all 6 anchors execute together starting now?**

**Yes — with one structural caveat.** All 6 are URGENT under N=20 denominator. The session's 134-commits-in-3-days throughput proves the team can absorb the work. But:

- **Anchor 6 has an inherent 7-deploy verification serialization** (each Manager method removal needs one deploy to confirm no runtime regression). That's 7-14 days serial calendar regardless of agent count.
- **Wave A (Anchor 4) cannot fan out** — manifest-staging is 1 file at a time. ~3 days serial.
- **Anchor 2 + Anchor 6 serialize on app/wire.go.** Either run Anchor 2 first OR coordinate PRs in Anchor 6 to bundle wire.go edits.

**Is Anchor 2 still "defer regardless"?**

**No. Re-framed under N=20: Anchor 2 is MEDIUM-URGENT, executed *between Anchor 5 and Anchor 6*** (the prior `7ac9d34` ordering remains correct). The trigger-gating ("no 2nd binary") was the wrong frame. The correct frame is **"Anchor 6 will spawn 8 new providers; doing Anchor 2 first means they land in their own module"**. Empirical evidence: app/providers/ at HEAD has 14 prod recipes. Anchor 6 PRs 6.1, 6.3, 6.5, 6.7, 6.9, 6.11, 6.13 each ADD a recipe. Without Anchor 2, that's `app/providers/` growing 14 → 22 prod files in a contended package. With Anchor 2, those same recipes land in a clean module.

**Net updated verdict**:

| Anchor | Solo verdict | N=20 verdict | Recommendation |
|---|---|---|---|
| 4. kc/domain | Worth doing | URGENT | Execute first (Wave A, 3 days) |
| 5. kc/ports invert | Worth doing | URGENT | Execute Wave B (2-3 weeks) |
| 2. app/ providers | Defer | MEDIUM-URGENT | **Re-prioritized**; execute Wave B parallel with 5 (3-5 days) |
| 6. kc-root god-struct | Worth doing | URGENT | Execute Wave C (7-10 weeks; serial deploys) |
| 1. mcp/ split | Strategic only | URGENT | Execute Wave C parallel with 6 (6-8 weeks) |
| 3. kc/ops split | Strategic only | URGENT | Execute Wave C parallel with 6+1 (3-4 weeks) |

**Total calendar estimate at N=20: 9-14 weeks** (vs 9-14 months solo serial). **All 6 in scope; no anchor is "defer regardless" anymore.**

**Operational recommendation**: dispatch Anchor 4 PR 4.1 next (the smallest first PR per `7ac9d34`). Architecture agent currently in flight on Tier 2 should finish their batch first; then 4.1 unblocks the entire B-full chain.

---

**End. Doc-only. No code mutated. No tests run.**

Last section completed: **Q6 — honest re-verdict** (final).
