<!-- secret-scan-allow: strategy-research-no-secrets -->
---
title: Bootstrap Decomposition Strategy — consumer-side analysis (REV 2)
as-of: 2026-05-16 (rev 2 — Path A reconciliation pass)
re-verify-by: 2026-06-16
master-heads:
  kite-mcp-server: 22c6eb0 (this doc's prior commit)
  algo2go/kite-mcp-bootstrap: fe5255d (Path A's empirical-mapping doc commit)
scope: READ-ONLY consumer-side + strategy synthesis; NO code changes
companion: `algo2go/kite-mcp-bootstrap/.research/bootstrap-decomp-empirical-mapping.md` (Path A's doc at fe5255d; cited extensively in §3.0)
methodology: compile-and-grep over both repos, per `feedback_compile_and_run_methodology` + `feedback_verify_before_synthesize`
revision-log:
  - rev 1 (commit 22c6eb0): Shape A with 6 repos as initial recommendation; flagged cite-slot for Path A's doc
  - rev 2 (this commit): targeted revision after Path A's empirical doc landed; cycle-empirically-verified; recommendation upgraded to **Shape A\*** (kc/ extraction as Phase 1 prereq); §INPUTS rows 16-23 added for the cycle-probe data
budget-used: ~3.5h cumulative (rev 1: 2.5h; rev 2: 1h)
---

# Bootstrap Decomposition Strategy (REV 2)

**User's framing (verbatim from dispatch)**: *"Bootstrap module (algo2go/kite-mcp-bootstrap) is currently ONE git. Under their standing per-git rule, that means Sprint 5 fan-out (99 tools across 5 disjoint subdirs) can only take ONE agent — ~25h serial vs ~6h parallel. Bootstrap's whole premise was to enable parallel agents; in current form it doesn't. Sprint 5 just exposed this."*

## Headline recommendation (REV 2 — supersedes rev 1)

**Shape A\* — sequenced extraction: app/metrics → kc/ → mcp/common+plugin+middleware → 5 tool sub-gits (parallel).**

Rev 1 of this doc landed Shape A (6 new repos: 5 tool + 1 common-infra) but did NOT address the cycle that arises from extracting any tool subdir while leaving `bootstrap/kc` + `bootstrap/mcp/{common,plugin}` in-place. Path A's empirical mapping doc at `fe5255d` flagged this; my own re-probe (§INPUTS rows 16-23, verified 2026-05-16) confirms the cycle is real:

```
bootstrap (mcp/plugin_aliases.go blank-imports trade-tools)
    → algo2go/kite-mcp-trade-tools
        → bootstrap/mcp/common (imports bootstrap/kc)
            → bootstrap/kc (imports bootstrap/app/metrics)
                → bootstrap   ← CYCLE
```

The cycle break requires extracting kc/ first (which requires extracting app/metrics first, since kc/ imports it). Once kc/ is its own module (`algo2go/kite-mcp-kc`), the tool sub-gits import `kite-mcp-kc` instead of `bootstrap/kc`, and bootstrap's blank-imports flow downward cleanly.

**Revised sequence (Phase 0 through Phase 3)**:
- **Phase 0**: `app/metrics` → `algo2go/kite-mcp-metrics` (~2h, leaf-only, no deps; 513 LOC)
- **Phase 1**: `kc/` → `algo2go/kite-mcp-kc` (~4-6h, prerequisite; 18,011 LOC + 160 import sites to rewrite)
- **Phase 2**: `mcp/{common, plugin, middleware}` → `algo2go/kite-mcp-tools-common` (~3-4h infra hub)
- **Phase 3 fan-out (parallel-safe)**: 5 tool repos × ~1.5h each = ~7h IF dispatched in parallel under per-git rule; ~7h wall-clock with 5 agents

**Revised total**: ~16-20h agent + ~30min user. ~6h more than rev 1 estimated (rev 1 missed the kc/ + metrics prereqs).

Why this isn't fatal to the ROI calculation: rev 1's §3.2 estimated 60-100h benefit over 12 months from 3-5 Sprint-5-style refactors. Even with the revised cost of ~20h, ROI remains 3-5×. **Shape A\* still wins decisively over Shape C (status quo) AND over rev 1's underspecified Shape A.**

Falsifiable claim (revised): if Shape A* is executed at the cost stated above (~16-20h agent + 30min user), then:
1. The cycle does not reassert at any phase gate (`go build ./...` exit 0 after each phase)
2. Sprint 5 Phase B drops from ~30h serial to ≤8h parallel wall-clock when Phase 3 fan-out runs
3. The next mcp-wide refactor benefits identically without re-incurring Phases 0-2

If any of those fails on first execution, Shape A* is falsified and we revert to Shape C status quo.

---

## §INPUTS — load-bearing facts (probed `2026-05-16` at HEAD `d3a01ed`/`8931b33` unless noted)

| # | Claim | Probe | Verified |
|---|---|---|---|
| 1 | Bootstrap repo has 4 go.mod files in 1 git (root + plugins + testutil + app/providers) | `find . -name 'go.mod' \| wc -l` → 4 in bootstrap; 1 in each of 28 other algo2go leaves | 2026-05-16 |
| 2 | Production tool count = 111 (`/healthz total_available`) | Confirmed in Path A's Sprint 5 PREP (`sprint-5-pattern-d2-prep-2026-05-11.md` §1); empirical re-check via `find mcp -name '*.go' -not -name '*_test.go' \| xargs grep -c 'mcp\.NewTool('` = 111 | 2026-05-16 |
| 3 | mcp/ subdir distribution (production tools): root=12, trade=28, alerts=8, admin=18, portfolio=20, paper=8, analytics=8, misc=9, plugin=0 = **111 total** | per-subdir `grep -c` over non-test `.go` files | 2026-05-16 |
| 4 | mcp/* subdirs all import `mcp/common` + `mcp/plugin` (shared infra) | `grep -h '"github.com/algo2go/kite-mcp-bootstrap/mcp/' mcp/<sub>/*.go \| sort -u` per subdir; every subdir except `mcp/common` itself imports both | 2026-05-16 |
| 5 | mcp/middleware imports nothing else in mcp/* | same probe; mcp/middleware has zero internal-mcp imports | 2026-05-16 |
| 6 | mcp/* subdirs all import `github.com/algo2go/kite-mcp-bootstrap/kc` (Manager surface): trade=9 files, portfolio=9, admin=8, analytics=6, alerts=5, paper=5, misc=4, plugin=1, common=10, middleware=0 | `grep -l 'kite-mcp-bootstrap/kc"' mcp/<sub>/*.go \| wc -l` per subdir | 2026-05-16 |
| 7 | Zero mcp/* subdirs import `kc/ops/` | same grep pattern with `/kc/ops` suffix → 0 across all 10 subdirs | 2026-05-16 |
| 8 | Bootstrap LOC: kc=18,011, app=10,424, mcp=24,656, plugins=321, testutil=825 (non-test, per `find ... \| xargs wc -l`) | empirical wc -l per dir | 2026-05-16 |
| 9 | 111 of 116 Tool.Handler implementations have signature `Handler(manager *kc.Manager) server.ToolHandlerFunc`; 5 are pilot stubs or variants | `grep -rhoE '\) Handler\([^)]*\)' mcp/ \| sort \| uniq -c` | 2026-05-16 |
| 10 | Path A's Sprint 5 PREP (commit `7bcb719`) revised effort: 20-40h cumulative, 6h wall-clock with 5-6 parallel agents (Phase B fan-out) | `head -60 .research/research/sprint-5-pattern-d2-prep-2026-05-11.md` + `git log --oneline 8931b33..HEAD` shows Pilot F at `8931b33` landed today | 2026-05-16 |
| 11 | 28 algo2go leaves are each 1 git → 1 go.mod (verified for `kite-mcp-broker` + spot-checked 5 others); their internal subdirs (e.g., `kite-mcp-broker` has 5) are sub-PACKAGES within ONE module, not sub-modules | `find <leaf>/ -name 'go.mod' \| wc -l` = 1 for each | 2026-05-16 |
| 12 | 28 algo2go leaves LOC range: 11 (templates) to 8,284 (usecases). Median ~1,500 LOC | `wc -l` aggregated per leaf | 2026-05-16 |
| 13 | Path A's bootstrap-internal mapping doc (the planned companion) | NOT YET LANDED at write-time — cite-slot reserved. Once it lands, this doc's §3 + §5 should cross-reference its per-component coupling matrix. | N/A (in flight) |
| 14 | kite-mcp-server master = thin shell candidate? In-tree LOC: kc=17,820, app=10,371, mcp=24,358 + plugins/testutil/cmd = 54,504 non-test LOC. Bootstrap-relocation branch is the merge target. | `find kc app mcp plugins testutil cmd -name '*.go' -not -name '*_test.go' \| xargs wc -l` over `D:/Sundeep/projects/kite-mcp-server/` master HEAD `d3a01ed` | 2026-05-16 |
| 15 | Sprint 5 Pilot F (mcp/ root 12 tools) shipped today at bootstrap HEAD `8931b33` | `git log --oneline -1 8931b33` | 2026-05-16 |
| 16 | Path A's empirical-mapping doc landed at bootstrap commit `fe5255d` (2026-05-16 15:41 IST) | `git log --oneline -1 fe5255d` + `ls .research/bootstrap-decomp-empirical-mapping.md` in bootstrap repo | 2026-05-16 |
| 17 | **mcp/common imports bootstrap/kc + bootstrap/kc/ports** (the cycle-pivot) | `grep -h 'bootstrap/kc' mcp/common/*.go \| sort -u` returns both import lines | 2026-05-16 |
| 18 | mcp/common uses 28 distinct `kc.*` symbols; 23 are interfaces, 2 are concrete structs (`*kc.Manager` 29 refs, `*kc.KiteSessionData` 11 refs), 3 are misc types/functions | `grep -rhoE 'kc\.[A-Z][A-Za-z]+' mcp/common/*.go \| sort \| uniq -c` + per-symbol probe `grep -E "^type X interface" kc/*.go` | 2026-05-16 |
| 19 | **Interface-narrowing to remove mcp/common→kc/ dep is NOT cheap**: the 23 interfaces' method signatures return kc-concrete types (`*KiteTokenEntry`, `*KiteCredentialEntry`, `*riskguard.Guard`, etc.). Pure-redeclaration is impossible without ALSO relocating those concrete types. | `grep -B 0 -A 3 'type [A-Z][A-Za-z]+Interface interface' kc/*.go` — confirmed return types are kc-internal | 2026-05-16 |
| 20 | **kc/ imports bootstrap/app/metrics** (5 production files): `kc/config.go`, `kc/manager_struct.go`, `kc/options.go`, `kc/scheduling_service.go`, `kc/ops/handler.go` | `grep -rl 'bootstrap/app/metrics' kc/` + per-file `grep -c 'metrics\.'` | 2026-05-16 |
| 21 | app/metrics is a pure stdlib leaf (513 LOC, 2 files); zero algo2go imports, zero bootstrap-internal imports | `head -10 app/metrics/metrics.go` shows only stdlib imports | 2026-05-16 |
| 22 | **Tool2 interface (the Sprint 5 migration target) takes `*ToolHandlerDeps`, NOT `*kc.Manager`** | `grep -B 2 -A 10 'type Tool2 ' mcp/common/tool.go` confirms signature | 2026-05-16 |
| 23 | **The cycle direction**: `bootstrap/mcp/plugin_aliases.go` blank-imports each tool subdir for init()-registration; if a tool subdir extracts, it imports `bootstrap/{kc,mcp/common,mcp/plugin}` downward AND bootstrap imports it upward = cycle | `grep -n '_ "github\|"github.com/algo2go/kite-mcp-bootstrap/mcp/' mcp/plugin_aliases.go` returns the 7 blank-imports of tool subdirs | 2026-05-16 |
| 24 | 160 files in bootstrap import `bootstrap/kc` (the LOC-rewrite scope for Phase 1) | `grep -rln '"github.com/algo2go/kite-mcp-bootstrap/kc"' --include='*.go' . \| wc -l` | 2026-05-16 |

> **Methodology footnote per `feedback_compile_and_run_methodology`**: tool count grep over `mcp/` returns 132 (test fixtures included); production-only count via `--include='*.go' \| grep -v _test.go` = 111. Path A's Sprint 5 PREP already corrected for this. All numbers in this doc use the non-test grep filter and were re-verified at write-time.

> **Rev 2 falsification note**: rev 1's §3 recommendation (Shape A as 6 simultaneous new repos) is empirically falsified by §INPUTS row 23 — extracting tool subdirs before kc/ creates a cycle that breaks `go build`. Rev 2's Shape A* (phased extraction) is the corrected recommendation.

---

## §1 — The architectural realization

The user's framing identifies a **per-git concurrency rule** that empirically constrains parallel work. Bootstrap's whole premise (per `github-transfer-bootstrap-2026-05-11.md` design audit at commit `13888e1`) was to enable composition-root decomposition. But the SHAPE of that decomposition matters: 1-git-with-4-go.mods does NOT enable 5-agent parallelism on the SAME git surface.

**The 28 algo2go leaves prove the precedent works**: 28 separate gits → 28 independently-editable surfaces → arbitrary N agents can hold N different leaves concurrently. Each leaf has its own commit history, its own go.mod, its own version tag, its own GOPROXY publish lifecycle.

Bootstrap inherited the inverse pattern: ONE git, MANY internal surfaces, ONE concurrent agent at a time. Sprint 5's mcp/ fan-out (5-6 parallel agents per Path A) is the first task that surfaces this asymmetry SHARPLY: under per-git rule, the entire `Phase B` fans into ONE agent serially = ~30h instead of ~6h.

### §1.1 What "per-git rule" actually buys us

The per-git rule (one agent per git at a time) prevents:
- Concurrent-edit conflicts in shared files
- Mid-flight `git rebase` failures
- Lost-work via push races
- Stale-clone bugs across parallel agent contexts

It does NOT prevent multi-agent dispatch when the agents operate on **disjoint gits**. The 28 algo2go leaves demonstrate this works fine (Path A.1-A.27 inauguration shipped each leaf as a separate sub-dispatch on a separate git, dozens of parallel-readable agents in practice).

### §1.2 The empirical asymmetry between bootstrap subdirs and algo2go leaves

| Dimension | algo2go leaf (e.g., kite-mcp-broker) | bootstrap mcp/<sub> (e.g., mcp/trade) |
|---|---|---|
| Git boundary | OWN git | shared bootstrap git |
| go.mod | OWN | shared with bootstrap root |
| Version tag | OWN (`v0.X.Y`) | inherited from bootstrap |
| GOPROXY publish | independent | none (sub-package, not module) |
| Concurrent agent capacity | parallel-safe by construction | serialized by per-git rule |
| Shared-infra dep on `mcp/common` + `mcp/plugin` | n/a | EVERY subdir imports both (verified §INPUTS row 4) |
| Internal sub-packages | 1-5 per leaf (sub-PACKAGES, not sub-modules) | each subdir is a sub-package |
| LOC median | ~1,500 (range 11-8,284) | mcp/<sub> range 702-3,710 LOC; comparable to leaves |

**The size doesn't differ much. The git boundary does.**

---

## §2 — Decomposition shapes compared

For each shape: effort to execute, parallel-readiness gained, deploy complexity delta, type-identity risk, long-term maintainability.

### Shape A — Per-mcp-subdir gits (5 or 7 new gits)

Extract `mcp/trade/`, `mcp/alerts/`, `mcp/admin/`, `mcp/portfolio/`, `mcp/paper/` (and possibly `mcp/analytics/`, `mcp/misc/`) each into its own algo2go repo. The shared `mcp/common` + `mcp/plugin` either stay in bootstrap (becoming a leaf-imported library) OR get their own gits too.

**Effort to execute**:
- 5 new gits × ~1h each for repo creation + go.mod + initial commit + push = 5h
- Per-subdir code-move: `git filter-repo --paths mcp/trade/` × 5 = ~2h (history preserved)
- Bulk import rewrite per repo: `mcp/trade` becomes `algo2go/kite-mcp-tools-trade`; ~50 import lines per repo × 5 = 250 lines rewritten
- Bootstrap go.mod: ADD 5 new require lines + remove the moved subdirs
- Verify: `go build ./...` + `go test ./...` per new repo, then bootstrap, then kite-mcp-server consumer-chain
- **Total: ~10-14h agent + per-repo cleanup loops**

**Parallel-readiness gained**: HIGH — exactly the Sprint 5 fan-out shape. 5-6 agents can work concurrently on disjoint gits.

**Deploy complexity delta**: MODERATE-HIGH
- Bump cascade: tool repo commit → tool repo tag → bootstrap go.mod bump → bootstrap tag → kite-mcp-server go.mod bump → `flyctl deploy`. **5 hops per change**.
- For Sprint 5's 5-agent fan-out: each agent ends with a tag in their repo, then ONE coordinator agent does the bootstrap-side bump (which requires 5 simultaneous go.mod additions or 5 serial bumps).
- Coordinator step is itself a per-git serial — but it's a 5-line edit, not the 6h-per-subdir migration.

**Type-identity risk**: HIGH
- `mcp/common` is the shared base. If it stays in bootstrap, the 5 tool repos all `import "github.com/algo2go/kite-mcp-bootstrap/mcp/common"`. That's BACK to a shared-git coupling — every common-side edit requires bumping bootstrap, which all 5 tool repos then import.
- Alternative: extract `mcp/common` into its OWN repo (kite-mcp-common-tools). Now there are 6 gits, but common is independent.
- Either way, the `*kc.Manager` type identity (which 111 of 116 handlers take) is a CROSS-REPO type. If `kc.Manager` is still in bootstrap, all 5 tool repos depend on bootstrap for their handler signature. Sprint 5's typed-Deps migration MAKES THIS WORSE because `*common.ToolHandlerDeps` becomes the new cross-repo type.

**Long-term maintainability**: MIXED
- Pro: clear per-domain ownership, per-domain release cadence, parallel-agent-friendly
- Con: 5-7 new repos in the algo2go org (already at 29); cognitive overhead of "which repo does THIS tool live in?" goes up
- Con: cross-repo refactors (e.g., add a field to `ToolHandlerDeps`) require coordinating commits across 5+ repos

### Shape B — Per-domain gits (~3 gits)

Bundle related subdirs:
- `algo2go/kite-mcp-tools-trading` = mcp/trade + mcp/portfolio + mcp/analytics
- `algo2go/kite-mcp-tools-ops` = mcp/admin + mcp/alerts + mcp/misc
- `algo2go/kite-mcp-tools-paper` = mcp/paper (+ mcp/plugin if paper needs it dedicated)

Plus `mcp/common` + `mcp/middleware` stay in bootstrap as shared infra.

**Effort to execute**: ~8-10h agent (3 new repos vs 5; less import-rewrite churn but more careful curation of which subdir bundles with which)

**Parallel-readiness gained**: MEDIUM-HIGH — 3 agents on 3 gits is below Sprint 5's stated 5-6, so Phase B fan-out becomes 2-cycle parallel (3 agents wave 1, 3 agents wave 2) instead of full single-wave parallel. Wall-clock estimate ~10-12h vs Shape A's ~6h.

**Deploy complexity delta**: MODERATE — 3 new tags to coordinate per release instead of 5. Bump cascade still 5 hops (the depth is the same; only the breadth changes).

**Type-identity risk**: MEDIUM
- Fewer cross-repo type imports than Shape A
- But "trading bundle" + "ops bundle" + "paper bundle" boundary is somewhat arbitrary; future tool additions need a "where does this go?" decision
- Risk of bundle drift over time (a bundle accretes adjacent tools until it's mini-monolith)

**Long-term maintainability**: BEST OF SHAPE A/B — 3 repos is manageable cognitive load; clear bundle themes prevent "where do I put a new tool?" ambiguity.

### Shape C — Leave bootstrap as-is, accept Sprint 5 serial

Path A's PREP doc already established Sprint 5 IS tractable serially (revised estimate: 20-40h cumulative). Wall-clock at single-agent serial: roughly 6 dispatches × 4-6h each = 24-36h working hours. Across a calendar week with retries + halts: ~3-5 calendar days.

**Effort to execute**: 0h decomp; 20-40h Sprint 5 (single-agent serial)

**Parallel-readiness gained**: ZERO

**Deploy complexity delta**: ZERO — no new repos, no new go.mod hops

**Type-identity risk**: ZERO — `*kc.Manager` stays in bootstrap, all 111 handlers stay co-located, the Tool2 interface migration is one-package-at-a-time

**Long-term maintainability**: status quo
- The bootstrap-as-one-git pattern persists indefinitely
- Any future mcp-wide refactor pays the same serial penalty
- Pattern D.3 (tool relocation INTO owning algo2go leaves, per `god-object-inventory` end-state) is gated on Sprint 5 completion and inherits the same serial constraint

**When this is the right answer**: if Sprint 5 is the LAST mcp-wide refactor for the foreseeable future. If Pattern D.3 (or any other mcp-cross-cutting refactor) is on the roadmap, Shape C defers the problem rather than solving it.

### Shape D — Hybrid: extract ONLY mcp/ as ONE new git (rev 1's INITIAL leaning; rev 2 rejects in §3.0)

Create ONE new repo `algo2go/kite-mcp-tools` containing the ENTIRE `mcp/` tree (subdirs + root files + common + plugin + middleware). Bootstrap retains `kc/`, `app/`, `plugins/`, `testutil/`.

**Effort to execute**:
- Create `algo2go/kite-mcp-tools` repo + clone locally: ~10min
- `git filter-repo --paths mcp/` from bootstrap clone → new repo: ~30min (history preserved)
- Initialize `algo2go/kite-mcp-tools/go.mod` (module = `github.com/algo2go/kite-mcp-tools`, go 1.25.0)
- Bulk sed: every internal import `github.com/algo2go/kite-mcp-bootstrap/mcp/...` → `github.com/algo2go/kite-mcp-tools/...`
- External imports stay: `kc` + `kc/ops` + algo2go leaves still point at their respective gits
- Bootstrap-side: `git rm -r mcp/`, add `require github.com/algo2go/kite-mcp-tools` to bootstrap's go.mod, rewrite any bootstrap-side imports of `mcp/...` (e.g., `app/wire.go` ToolRegistration entry points)
- Verify: `go build ./...` + `go test ./...` in tools repo, then bootstrap, then kite-mcp-server
- **Total: ~6-10h agent + ~30min user-action for repo creation**

**Parallel-readiness gained**: HIGH for mcp-internal work — Sprint 5 Phase B fan-out runs 5-6 parallel agents inside `algo2go/kite-mcp-tools` because every subdir lives in the same git as before, but Path A's per-git-rule binds to "one agent per git" — and ONE git means the 5-6 parallel-agent constraint is unchanged.

**WAIT — this needs re-examination.** If `kite-mcp-tools` is ONE git, then the 5-6-parallel-agent fan-out still binds to ONE git → one agent → same serial penalty.

**Re-evaluation**: Shape D only buys us parallelism if we ALSO accept multi-agent dispatch within `kite-mcp-tools`. Which the per-git rule prohibits.

**Two sub-variants emerge**:

- **Shape D.1**: Extract mcp/ into ONE git; relax per-git rule for "disjoint subdir edits within one git" — agents dispatched onto `mcp/trade/` and `mcp/alerts/` simultaneously inside `kite-mcp-tools` IF they edit no shared files (`mcp/common`, `mcp/plugin`, `mcp/registry.go`).
- **Shape D.2**: Extract mcp/ into ONE git AND ALSO accept Shape C-style serial Sprint 5 (don't gain parallel benefit; just gain the "tools live with tools, infra lives with infra" organizational benefit).

D.1 is essentially Shape A in disguise (relaxing per-git rule with care). D.2 doesn't solve the Sprint 5 problem.

**Implication**: pure Shape D does NOT solve the user's problem. The user's framing assumed "split bootstrap → parallel agents enabled" but the per-git rule is the binding constraint, not the git-count.

---

## §3 — Revising the recommendation in light of §2 finding (rev 1 baseline + rev 2 reconciliation)

**The per-git rule is the binding constraint**. Decomposing bootstrap into N gits only helps if you actually dispatch N agents. So the question reframes:

> **Do we trust ourselves to dispatch parallel agents safely INSIDE a single git when the subdirs are disjoint AND the agents don't touch shared infra?**

Empirical answer from past dispatches (your prior research files):
- `user_team_agents_default.md` flagged 3+ concurrent agents as the threshold for team config
- `user_team_commit_protocol.md` documents per-teammate worktrees as a safety measure
- `feedback_narrow_test_scope_no_stash.md` prohibits `git stash` as cross-agent isolation
- Past sessions (`session_2026-05-04_close-2-architecture-progress.md`) had concurrent-edit friction WITHIN a single git that motivated the per-git rule

**The per-git rule was forged BECAUSE concurrent-edit friction is real in practice, not just in theory.** Decomposing into N gits genuinely changes the calculus: each git's history is independent, push races are impossible across gits, stale-clone bugs are bounded by per-git scope.

So **Shape A is the correct response** — but only IF the per-git rule is the absolute binding constraint AND the parallel-agent benefit is worth the multi-repo overhead.

### §3.0 Path A reconciliation (REV 2 — added 2026-05-16 post-fe5255d)

Rev 1 of §3.1 (immediately following this section) proposed extracting all 6 new repos (5 tool + 1 common-infra) effectively simultaneously. **Path A's empirical-mapping doc at `algo2go/kite-mcp-bootstrap/.research/bootstrap-decomp-empirical-mapping.md` commit `fe5255d` exposed a structural cycle that rev 1 did not address.** My own re-probe (§INPUTS rows 17-23, verified 2026-05-16) confirms the cycle.

#### §3.0.1 The cycle, empirically traced

Path A's finding (their doc §2.5 + §2.3) plus my re-probe yields this dependency graph:

```
bootstrap/mcp/plugin_aliases.go (in package mcp at bootstrap root)
        │
        │  blank-imports each tool subdir
        ▼
bootstrap/mcp/<sub>              ←─── each subdir imports mcp/common + mcp/plugin
                                      and most also import bootstrap/kc
        │
        ▼
bootstrap/mcp/common ────────►  bootstrap/kc  ────►  bootstrap/app/metrics
bootstrap/mcp/plugin ─────────┘                              │
                                                             │
            (stdlib only; no further bootstrap-internal deps)
```

If we extract any tool subdir to a separate git (say `algo2go/kite-mcp-trade-tools`) while leaving `kc/`, `mcp/common`, and `mcp/plugin` in bootstrap:

- The new repo IMPORTS `bootstrap/{kc, mcp/common, mcp/plugin}` (downward)
- bootstrap IMPORTS the new repo via `mcp/plugin_aliases.go` blank-import (upward)
- **That is a Go module cycle. `go build` exit ≠ 0.**

#### §3.0.2 Option 1 (interface narrowing) — empirically infeasible at low cost

Path A's framing left open whether interface-narrowing in `mcp/common` could break the dep on `bootstrap/kc`. I probed this directly. §INPUTS row 18: mcp/common references 28 distinct `kc.*` symbols. §INPUTS row 19: 23 of them are pure interfaces, but their METHOD SIGNATURES return kc-internal concrete types (`*KiteTokenEntry`, `*KiteCredentialEntry`, `*riskguard.Guard`, etc.).

To redeclare these interfaces in `mcp/common` without importing `kc`, we'd need to ALSO relocate the concrete return-type structs (`KiteTokenEntry`, `KiteCredentialEntry`, etc.) — which means inverting type ownership across the kc/common boundary. That's a deeper refactor than just extracting kc/ as a Go module. **Option 1 is rejected as more expensive than Option 2.**

#### §3.0.3 Option 2 (extract kc/) — the path forward

Extracting kc/ as `algo2go/kite-mcp-kc` is mostly mechanical:
- 18,011 LOC moved (§INPUTS row 8)
- 160 import sites rewritten (`bootstrap/kc` → `algo2go/kite-mcp-kc`, §INPUTS row 24)
- BUT: kc/ itself imports `bootstrap/app/metrics` (§INPUTS row 20). So kc/ has its OWN prerequisite: extract `app/metrics` first.

#### §3.0.4 Distinction Path A's doc made explicit, which rev 1 conflated

Path A correctly distinguished:
- **Internal decomp of kc/** (split the god-struct into sub-packages): genuinely blocked per Sprint 2-4 halts. The god-struct can't be cracked without invasive surgery.
- **External promotion of kc/** (move the package AS-IS to its own go.mod): mechanically tractable. `git filter-repo --paths kc/` + `go.mod init` + bulk sed. No god-struct surgery needed.

Rev 1 implicitly conflated these and treated kc/ as undecomposable. Path A's framing fixes this: external promotion is the cheap kind. Rev 2 adopts it.

### §3.1 Revised recommendation: Shape A* — phased extraction

**Recommendation: Shape A\*, executed as 4 phases (Phase 0-2 sequential prereqs, Phase 3 parallel-safe)**:

| Phase | New repo | Contents | Why | Cost | Phase parallelism |
|---|---|---|---|---|---|
| **0** | `algo2go/kite-mcp-metrics` | app/metrics (513 LOC, 2 files) | kc/ imports it; stdlib-only leaf | ~2h | sequential (single agent) |
| **1** | `algo2go/kite-mcp-kc` | bootstrap/kc + kc/ops + kc/ports (18,011 LOC) | mcp/common, mcp/plugin, and tool subdirs all import this; cycle pivot | ~4-6h (160 import sites rewritten across bootstrap) | sequential (single agent; ONE big git change) |
| **2** | `algo2go/kite-mcp-tools-common` | mcp/common + mcp/plugin + mcp/middleware | Shared infra; all 5 tool repos import this | ~3-4h | sequential (single agent; depends on Phase 1) |
| **3a** | `algo2go/kite-mcp-tools-trade` | mcp/trade | 28 tools | ~1.5h | **parallel agent A** |
| **3b** | `algo2go/kite-mcp-tools-portfolio` | mcp/portfolio + mcp/analytics + relevant root tools | 28 + ~10 root tools | ~1.5h | **parallel agent B** |
| **3c** | `algo2go/kite-mcp-tools-ops` | mcp/admin + mcp/misc | 27 tools | ~1.5h | **parallel agent C** |
| **3d** | `algo2go/kite-mcp-tools-alerts` | mcp/alerts | 8 tools | ~1.5h | **parallel agent D** |
| **3e** | `algo2go/kite-mcp-tools-paper` | mcp/paper | 8 tools | ~1.5h | **parallel agent E** |

**Total**: 7 new repos (vs rev 1's 6 — adds metrics + kc/ as Phase 0+1 prereqs).
**Total agent cost**: ~2h + ~6h + ~4h + (~7h parallel wall-clock OR ~7.5h serial) = **~19-21h cumulative, ~13-15h wall-clock with parallel Phase 3**.
**Plus existing 29 algo2go repos = 36 algo2go repos post-decomp**.

The mcp/ ROOT files (12 tools: market_tools, tax_tools, watchlist_tools, ext_apps widget code) need a home. Per rev 1's analysis they distribute by domain into the 5 tool repos. This is unchanged by rev 2.

### §3.2 Revised bump-cascade ROI

**Before Shape A\***: Sprint 5 Phase B fan-out runs serially under per-git rule: 5 agents × ~6h each = ~30h wall-clock IF parallelized but can't be. Practically: ~3-5 calendar days at single-agent pace.

**After Shape A\***: Sprint 5 Phase B fan-out runs in parallel after Phases 0-2 land: 5 agents × ~6h wall-clock = ~6h wall-clock. Plus coordinator phase (~3h sequential) = ~9h end-to-end.

**Time saved per Sprint-5-style refactor**: ~20-25h wall-clock per occurrence (unchanged from rev 1).

**Revised cost paid once**: Shape A\* decomp = ~19-21h agent + ~30min user (vs rev 1's ~10-14h).

**Revised breakeven**: ONE Sprint-5-style refactor still pays back the decomp cost (20h saved vs 20h spent). Margin is tighter than rev 1 claimed.

**Number of expected occurrences** (per `god-object-inventory-2026-05-11.md` end-state vision; unchanged from rev 1):
- Sprint 5 itself (Pattern D.2 typed-Deps migration) — IMMEDIATE benefit
- Pattern D.3 (tool relocation into owning algo2go leaves) — same 5-subdir fan-out
- Future tool-surface refactors (rate-limit changes, observability instrumentation, etc.) — same fan-out shape
- Per-domain release cadence (each tool repo can ship independently)

**Revised total benefit over 12 months**: 3-5 Sprint-5-style refactors × ~20h saved each = 60-100h cumulative. **Net 12-month ROI under rev 2: +40-80h** (subtracts the higher Phase 0-2 cost from rev 1's projection).

### §3.3 The shared-infra coupling answer (unchanged)

The empirical finding (verified §INPUTS row 4): every mcp/<sub> imports `mcp/common` + `mcp/plugin`.

**Resolution**: `algo2go/kite-mcp-tools-common` (Phase 2) is the shared-infra repo. All 5 tool repos import it. Changes to common bump the 5 tool repos through the standard GOPROXY+go-get cycle. Bonus: after Phase 2 lands, `mcp/common`+`mcp/plugin`+`mcp/middleware` can release on their own cadence independent of bootstrap.

This IS a real bump-cascade cost: a `common` change touches 5 downstream repos. But:
- Common changes are RARE (it's stable interface code: NewToolHandler, ArgParser, MarshalResponse, etc.)
- Common changes that are LARGE often warrant the bump cascade anyway (e.g., adding ToolHandlerDeps in Sprint 5 IS a coordinated cross-cutting change)
- The 28 algo2go leaves already accept this pattern: `kite-mcp-domain` is shared infra; changes to it propagate to 7 dependent leaves; we've shipped this many times without trouble

### §3.4 What Path A's doc and this doc agree on (rev 2 reconciliation)

- The cycle is real (Path A §2.5; my §INPUTS row 23)
- kc/ extraction is the cheap prerequisite (NOT internal decomp; AS-IS promotion)
- app/metrics extraction is kc/'s prerequisite (Path A §2.5 reverse-coupling note; my §INPUTS row 20)
- mcp/common + mcp/plugin form one infra bundle (Path A §3; my rev 1 §3.1)
- Sprint 5 Phase B can fan out 5 parallel after Phases 0-2 land

### §3.5 What this doc adds that Path A's doc didn't address

Path A's doc is bootstrap-internal-only (no consumer-side analysis). This doc's contributions:
- Cost analysis from the consumer side (cumulative + per-phase)
- ROI calculation against agent-concurrency denominator (per `feedback_decoupling_denominator.md`)
- Falsifiable claim form (this rev's §headline)
- Explicit comparison vs Shape B (3-bundle) and Shape D (1 git for mcp/) that Path A did not formalize
- Confirmation that 23/28 of mcp/common's kc-symbols are interfaces BUT transitively pull concrete types (rules out cheap Option 1)

---

## §4 — Other monolithic gits hiding

Per dispatch §3 question: "is kite-mcp-server itself a candidate for further decomp? Is kc/ inside bootstrap a candidate?"

### §4.1 kite-mcp-server master

Today's state (`d3a01ed`):
- In-tree LOC: 54,504 non-test
- Sprint 0 bootstrap-relocation branch (`deefac1`) reduces this to 710 LOC if merged
- Post-merge: kite-mcp-server is pure deploy thin-shell; no parallel-amenable surfaces remain

**Verdict**: NOT a decomp candidate. The bootstrap-relocation merge is the pending work; once merged, kite-mcp-server is correctly minimal.

### §4.2 kc/ inside bootstrap

Per §INPUTS row 8: kc/ = 18,011 non-test LOC. Internal structure:
- kc/ root: 58 files / 9,710 LOC
- kc/ops: 48 files / 8,017 LOC (admin + user + shared sub-packages)
- kc/ports: 6 files / 284 LOC

**Is kc/ a parallel-amenable surface?** Looking at the structure:
- kc/manager_*.go family (manager.go, manager_init.go, manager_accessors.go, etc.) — these are the god-struct (per `god-object-inventory-2026-05-11.md`); each agent editing these races every other agent
- kc/{credential_service, session_service, alert_service, order_service, portfolio_service, family_service}.go — these ARE more disjoint; one agent per service feasible
- kc/ops/ — admin + user + shared; possibly decomp-amenable

**Caveats**:
- Path A's god-object-inventory roadmap (Phase 4 slice 10) aims to drain kc.Manager's raw fields once the 5 Tier-1 facades fully encapsulate them. This is single-agent work because facade-decomp is structurally sequential.
- The kc/* services already have a clean Anchor-6-precedent shape for per-service edits, but they don't fan out 5+ wide.

**Verdict (REV 2 UPDATE — supersedes rev 1's "Defer")**:

Rev 1 said "defer kc/ decomp" because rev 1 conflated INTERNAL kc/ decomposition (god-struct split, genuinely blocked) with EXTERNAL kc/ promotion (as-is move to its own go.mod, mechanically cheap).

Per Path A's empirical doc §3 + my §3.0.4 reconciliation: **external kc/ promotion is Phase 1 of Shape A\***. It's a prerequisite (the cycle pivot), not optional. 160 import sites get rewritten; kc/'s internal structure stays unchanged.

So:
- **External kc/ promotion**: IN scope, Phase 1 of Shape A* (~4-6h)
- **Internal kc/ decomposition** (god-struct split): NOT in scope; still deferred per the Sprint 2-4 halts

### §4.3 app/ inside bootstrap

10,424 non-test LOC. Internal structure:
- app/ root: 33 files
- app/providers/: 12 files (workspace member, own go.mod ALREADY)
- app/metrics/: 8 files

**Is app/ a parallel-amenable surface?**
- app/wire.go is the 805-LOC Fx composition root — sequential by design
- app/http.go is the 1,596-LOC HTTP mux — sequential by design (route ordering matters)
- app/adapters split (Sprint 1 Slice 2 at `d43d709`) is DONE — 9 per-domain files now
- app/providers IS already a workspace sub-module (own go.mod)

**Verdict**: app/ is NOT in scope; the wire+http monoliths are intrinsically sequential. Defer.

### §4.4 kite-mcp-server master vs bootstrap-relocation branch

The decision-of-record from prior dispatches (Sprint 0 + algo2go-dependency-state research):
- Bootstrap-relocation branch (`deefac1`) is the staged merge
- Post-merge: kite-mcp-server is 710-LOC thin shell
- User has not yet authorized the merge (per `path-to-100-percent-algo2go-2026-05-11.md` §6 step 1)

Shape A bootstrap decomp can land EITHER:
- Before merge: bootstrap-relocation branch needs rebase OR the decomp happens on bootstrap master, then bootstrap-relocation branch gets the updated bootstrap pointer
- After merge: cleaner; one branch only

**Recommendation: defer Shape A until after Sprint-0 merge lands** to avoid rebase complexity. The cost is at most 1-2 weeks of Sprint 5 serial work (Path A's existing Phase B plan) before Shape A unblocks subsequent refactors.

**Counter-argument**: if Sprint 5 IS the trigger for Shape A and waiting means Sprint 5 ships serially, the breakeven slips by one refactor cycle. User decides.

---

## §5 — Pull-through cascade analysis

Per dispatch §4 question.

### §5.1 Cascade depth, N=5 (Shape A) vs N=1 (Shape C)

**Shape A bump cascade (5 new tool repos + 1 common repo)**:

```
tool repo X: change → commit → tag v0.Y.Z       (level 1)
  ↓
common repo (if cross-cutting):                  (level 1.5)
  ↓
algo2go/kite-mcp-bootstrap go.mod bump            (level 2)
  bootstrap repo: commit → tag v0.M.N
  ↓
kite-mcp-server go.mod bump                       (level 3)
  kite-mcp-server: commit → tag (optional)
  ↓
flyctl deploy                                     (level 4)
```

**4 hops** per change in Shape A.

**Shape C (status quo)**:

```
bootstrap subdir change → commit                  (level 1)
  ↓
kite-mcp-server go.mod bump (via replace OR tag)  (level 2)
  ↓
flyctl deploy                                     (level 3)
```

**3 hops** per change in Shape C. ONE fewer hop than Shape A.

### §5.2 Manageability at N=5 vs N=10

**N=5 (recommended Shape A configuration)**:
- Standard Go monorepo-lite pattern
- 5 tool repos × ~1 tag/month each = ~5 tag-bumps/month on bootstrap
- Bootstrap tags = ~1/month (consolidates 5 tool-repo bumps into one bootstrap release)
- kite-mcp-server tags = ~1/month (consolidates bootstrap bumps into one deploy)
- **Verdict**: tractable. Mirrors the existing 28-algo2go-leaf cadence which we already manage.

**N=10 (hypothetical Shape A.1 with finer-grained decomp)**:
- 10 tool repos = doubles the per-repo coordination overhead
- Bump cadence likely ~2× faster
- Risk of "this tool moves between repos" decisions accelerating
- **Verdict**: NOT recommended. N=5 is the right granularity.

### §5.3 Automation that reduces friction

For Shape A to be sustainable:

1. **Multi-repo tag script**: `scripts/cut-tools-release.sh` — bumps all 5 tool repos in sequence, updates bootstrap go.mod, opens PR. ~50 LOC bash. Modeled on `litestream.yml` or `flyctl deploy` automation.

2. **Cross-repo CI**: GitHub Actions workflow_dispatch in bootstrap that triggers consumer-chain rebuild when any tool-repo tags. Already feasible with `repository_dispatch` events; ~30 LOC YAML.

3. **`go mod tidy` automation in PRs**: Dependabot already monitors algo2go repos. Configure dependabot in bootstrap + kite-mcp-server to auto-PR on tool-repo tags.

4. **Tag convention**: enforce `v0.X.Y` semver in tool repos; bootstrap pins major.minor; auto-PR on patch bumps. Standard Go module hygiene.

5. **Pre-merge gate**: CI on bootstrap PRs requires `go test ./...` + `go build ./...` + ALL 5 tool-repo `go list -m` resolve cleanly. Catches version-skew at PR time, not at deploy time.

None of these are new technology — all are bog-standard Go-monorepo-lite patterns that the existing 28-leaf ecosystem already uses.

### §5.4 The recurring cost of Shape A

**Per-month coordination overhead estimate**:
- ~5 tool-repo PRs/month × ~10min PR review each = ~50min
- ~1 bootstrap-bump PR/month × ~20min review = 20min
- ~1 kite-mcp-server-bump + deploy/month × ~30min = 30min
- **Total recurring: ~100min/month**

vs Shape C: ~30min/month (single bootstrap PR, single deploy)

**Net recurring delta: +70min/month, OR ~14h/year**

Break-even calculation (continued from §3.2): 60-100h benefit / 14h recurring cost = **4-7× ROI over 12 months**.

---

## §6 — Recommendation (one shape, defended) — REV 2

**Recommendation: Shape A\* with 7 new repos (1 metrics + 1 kc + 1 common-infra + 5 tool), executed in 4 phases. Phases 0-2 sequential, Phase 3 parallel-safe.**

(Supersedes rev 1's Shape A; rev 1 was structurally falsified by the cycle exposed in §3.0.1.)

### §6.1 Why Shape A* wins

Empirical justification:
1. **Sprint 5 fan-out is real and recurring**. Path A's PREP doc (verified 2026-05-16, commit `7bcb719`) explicitly designs for 5-6 parallel agents in Phase B. The current per-git rule blocks that. Shape A* unblocks it after Phases 0-2 land.
2. **28 algo2go leaves prove the multi-repo pattern works at scale**. We already coordinate 29 algo2go repos; 36 is the same operating model with +7 repos.
3. **The cascade cost is bounded and automatable**. Per §5.3, standard Go monorepo-lite tooling handles this; no novel infrastructure needed. After Phase 1+2, the cascade depth is 4 hops (tool → common → kc → bootstrap → kite-mcp-server) but each is automatable.
4. **ROI still breaks even on ONE Sprint-5-style refactor** even at the revised ~20h cost. The next 12 months will likely contain 3-5 such refactors.
5. **The mcp/common shared-infra coupling is handled cleanly via the Phase 2 infra repo**, not by collapsing back to a monolith.
6. **kc/ extraction is mechanically tractable** as AS-IS module promotion (Path A §3.0.4 distinction). NOT the same as the genuinely-blocked god-struct internal decomp. This is a key clarification rev 1 missed.

### §6.2 Falsifiable claim (revised)

If Shape A* is executed at the cost stated below:
- ~19-21h agent total (~2h Phase 0 + ~4-6h Phase 1 + ~3-4h Phase 2 + ~7-7.5h Phase 3)
- ~30min user (gh repo create × 7 + auth checks)
- ~16h/year recurring (incrementally higher than rev 1's ~14h due to 1 additional repo to maintain)

Then ALL THREE of these MUST hold:
1. Each phase's `go build ./...` exits 0 BEFORE the next phase starts (the cycle does not reassert at any phase gate)
2. Sprint 5 Phase B drops from ~30h serial wall-clock to ≤8h parallel wall-clock once Phase 3 starts (5+ agents fan-out)
3. The next mcp-wide refactor (Pattern D.3 or any other) benefits identically without re-incurring Phases 0-2

If any one fails on first execution, Shape A* is falsified and we revert to Shape C status quo.

### §6.3 What NOT to do

- **Don't do Shape A (rev 1's unphased version)**: structurally cyclic. Cannot pass `go build`.
- **Don't do Shape B (3-bundle gits)**: arbitrary boundaries, future drift risk, parallel benefit is partial (2-cycle vs single-cycle). Also still needs Phases 0+1 prereqs (kc/ + metrics extraction), so the savings vs A* are marginal.
- **Don't do Shape A.1 with N=10 fine-grained**: coordination overhead exceeds benefit.
- **Don't do internal decomp of kc/**: the god-struct internal split is genuinely blocked per Sprint 2-4 halts. Shape A*'s Phase 1 is AS-IS external promotion only — no internal surgery.
- **Don't do app/ decomp now**: Fx wire + HTTP mux are intrinsically sequential. Defer.
- **Don't do bootstrap-relocation merge AND Shape A\* in same dispatch window**: too many concurrent rebases. Land merge first, then Shape A*.

### §6.4 Decision matrix for user (REVISED)

| Shape | Decomp cost | Parallel benefit | Recurring cost | Net ROI 12mo | Compile-clean? |
|---|---|---|---|---|---|
| **A\* (Phased: metrics + kc + common + 5 tool)** | ~19-21h + 30min user | 5-6 agents on mcp-fan-out (~24h/yr saved) | +16h/yr | **+40-80h/yr** | YES (after each phase gate) |
| A (rev 1's unphased 6 repos) | ~10-14h claimed | Would have been the same | n/a | n/a | **NO — cycle** |
| B (3 bundle repos, also phased) | ~17-19h + 20min user | 3 agents (~12h/yr saved) | +10h/yr | +20-50h/yr | YES (same phasing required) |
| C (status quo) | 0 | 0 | 0 | 0 (baseline) | YES |
| D (mcp/ as 1 git, also phased) | ~14-16h + 20min user | 0 (per-git rule still binds) | +7h/yr | NEGATIVE | YES |
| Hybrid (defer Shape A\* until Sprint 5 ships serially) | 0 now; ~20h later | 0 for Sprint 5; future refactors gain | same as A* | A*'s ROI minus 1 Sprint-5-cycle savings (~+20-60h/yr) | YES |

**The strictly-dominant strategy is Shape A\***. The hybrid (defer A* until after Sprint 5 ships serially) is the conservative alternative — gives up ~20h of Sprint 5 savings but keeps future-refactor savings. Defensible if user prefers risk-averse path through one more Sprint-5-style refactor before paying the decomp cost.

### §6.5 Rev 1 vs Rev 2 delta summary

| Dimension | Rev 1 (commit `22c6eb0`) | Rev 2 (this revision) |
|---|---|---|
| Repo count | 6 (5 tool + 1 common) | 7 (1 metrics + 1 kc + 1 common + 5 tool) — net +1 |
| Decomp cost | ~10-14h + 30min | ~19-21h + 30min — net +6-10h |
| Phasing | Effectively parallel (incorrect) | 4-phase sequential prereq → parallel only at Phase 3 |
| Cycle handling | Not addressed | Phase 0+1 + 2 break the cycle empirically |
| Net 12mo ROI | +60-86h/yr | +40-80h/yr |
| Falsifiable claim | 2 conditions | 3 conditions (added compile-clean phase-gate condition) |
| Compile-clean? | NO (rev 1 was structurally falsified) | YES at each phase gate |
| Distinction internal vs external kc/ decomp | Conflated; called kc/ "not in scope" | Clarified per Path A: external promotion is cheap, internal decomp stays blocked |

---

## §7 — What this doc does NOT recommend (per original dispatch instruction)

Per the rev-1 dispatch: "Don't recommend execution sequencing yet — that comes after the user picks a shape based on both your doc + Path A's doc."

So this doc names **A\*** as the recommendation but does NOT specify:
- WHEN to execute (now vs after Sprint-0 merge vs after Sprint 5 ships)
- WHICH agent dispatches each phase (single coordinator vs multi-agent at Phase 3 only)
- WHO owns each of the 7 new repos for maintenance
- Per-repo naming finalization (the §3.1 names are still provisional)

Those decisions await explicit user authorization. The rev 2 falsification of rev 1's Shape A means the cost numbers have moved (now ~20h, not ~12h); user may want to re-validate the breakeven assumption before committing.

---

## §APPENDIX — Empirical probes used

```bash
# Bootstrap inventory (verified 2026-05-16 at HEAD 8931b33)
find . -name 'go.mod' | wc -l                                          # → 4 (root + 3 workspace)
find mcp -name '*.go' -not -name '*_test.go' | xargs grep -c 'mcp\.NewTool('  # → 111

# Per-subdir tool counts
for d in trade alerts admin portfolio paper analytics misc plugin; do
  find mcp/$d -name '*.go' -not -name '*_test.go' | xargs grep -c 'mcp\.NewTool('
done

# Inter-subdir coupling
for d in trade alerts admin portfolio paper analytics misc; do
  grep -h '"github.com/algo2go/kite-mcp-bootstrap/mcp/' mcp/$d/*.go | sort -u
done   # → every subdir imports mcp/common + mcp/plugin

# 28-leaf precedent (single git, single go.mod)
for d in kite-mcp-*/; do find "$d" -name 'go.mod' | wc -l; done    # → 1 for each except bootstrap

# Path A's revised effort estimate
grep -A 2 'Revised effort estimate' .research/research/sprint-5-pattern-d2-prep-2026-05-11.md
# → "20-40h cumulative... 5-6 parallel agents, ~6h wall-clock"

# Tool registration distribution
grep -rhE 'mcp\.NewTool\("' mcp/ --include='*.go' | grep -v _test.go | wc -l   # → 111 (matches /healthz)
```

---

**END OF DOC (REV 2)** — verified at kite-mcp-server `22c6eb0` + bootstrap `fe5255d`; cycle re-probes 2026-05-16. Companion: Path A's bootstrap-internal mapping doc at `algo2go/kite-mcp-bootstrap/.research/bootstrap-decomp-empirical-mapping.md` commit `fe5255d` (cited extensively in §3.0). Rev 1 (commit `22c6eb0`) is superseded by this revision.
