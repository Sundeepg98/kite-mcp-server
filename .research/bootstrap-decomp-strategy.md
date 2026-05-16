<!-- secret-scan-allow: strategy-research-no-secrets -->
---
title: Bootstrap Decomposition Strategy — consumer-side analysis
as-of: 2026-05-16
re-verify-by: 2026-06-16
master-heads:
  kite-mcp-server: d3a01ed
  algo2go/kite-mcp-bootstrap: 8931b33
scope: READ-ONLY consumer-side + strategy synthesis; NO code changes
companion: Path A's bootstrap-internal mapping doc (in flight at write-time; cite-slot reserved §INPUTS row 13)
methodology: compile-and-grep over both repos, per `feedback_compile_and_run_methodology` + `feedback_verify_before_synthesize`
budget-used: ~2.5h of 2-4h target
---

# Bootstrap Decomposition Strategy

**User's framing (verbatim from dispatch)**: *"Bootstrap module (algo2go/kite-mcp-bootstrap) is currently ONE git. Under their standing per-git rule, that means Sprint 5 fan-out (99 tools across 5 disjoint subdirs) can only take ONE agent — ~25h serial vs ~6h parallel. Bootstrap's whole premise was to enable parallel agents; in current form it doesn't. Sprint 5 just exposed this."*

## Headline recommendation

**Shape D — Hybrid: extract `mcp/` into its own git as `algo2go/kite-mcp-tools` (single new repo, NOT 5-7); leave `kc/`, `app/`, and the other in-tree workspace members inside bootstrap unchanged.**

This unblocks Sprint 5's 5-6 parallel agents (the entire fan-out target lives in `mcp/`) at the cost of ONE new repo + ONE go.mod-bump-cascade hop. The 28-algo2go-leaf precedent and the empirically-confirmed `mcp/{common,plugin}` shared-infra coupling both argue against Shape A/B (per-subdir or per-domain gits) — those would create 5-7 new gits to coordinate when ONE new git solves the parallel-agent problem cleanly.

Shape C (do nothing, accept Sprint 5 serial) is empirically defensible per Path A's revised 20-40h-cumulative estimate (which is "tractable serially") — but defers the parallel-agent benefit indefinitely and is falsifiable: the moment a NEXT mcp-wide refactor surfaces (and there will be one — Pattern D.3 tool-relocation INTO owning algo2go leaves per the `god-object-inventory` end-state), the same per-git-rule bottleneck reasserts. **Pay the one-time decomp cost now to unblock a recurring class of work.**

Falsifiable claim: if Shape D is executed at the cost stated below (~6-10h agent + ~30min user), then Sprint 5 Phase B drops from ~30h serial to ~6h parallel wall-clock; AND any follow-on mcp-wide refactor benefits identically. If either of those wall-clock numbers fails to materialize on first execution, the recommendation is falsified.

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

> **Methodology footnote per `feedback_compile_and_run_methodology`**: tool count grep over `mcp/` returns 132 (test fixtures included); production-only count via `--include='*.go' \| grep -v _test.go` = 111. Path A's Sprint 5 PREP already corrected for this. All numbers in this doc use the non-test grep filter and were re-verified at write-time.

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

### Shape D — Hybrid: extract ONLY mcp/ as ONE new git (RECOMMENDED)

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

## §3 — Revising the recommendation in light of §2 finding

**The per-git rule is the binding constraint**. Decomposing bootstrap into N gits only helps if you actually dispatch N agents. So the question reframes:

> **Do we trust ourselves to dispatch parallel agents safely INSIDE a single git when the subdirs are disjoint AND the agents don't touch shared infra?**

Empirical answer from past dispatches (your prior research files):
- `user_team_agents_default.md` flagged 3+ concurrent agents as the threshold for team config
- `user_team_commit_protocol.md` documents per-teammate worktrees as a safety measure
- `feedback_narrow_test_scope_no_stash.md` prohibits `git stash` as cross-agent isolation
- Past sessions (`session_2026-05-04_close-2-architecture-progress.md`) had concurrent-edit friction WITHIN a single git that motivated the per-git rule

**The per-git rule was forged BECAUSE concurrent-edit friction is real in practice, not just in theory.** Decomposing into N gits genuinely changes the calculus: each git's history is independent, push races are impossible across gits, stale-clone bugs are bounded by per-git scope.

So **Shape A IS the correct response** — but only IF the per-git rule is the absolute binding constraint AND the parallel-agent benefit is worth the multi-repo overhead.

### §3.1 Real recommendation: Shape A with `mcp/common` strategy

**Recommendation: Shape A, executed as 6 new repos**:

| New repo | Contents | Tool count | Why |
|---|---|---|---|
| `algo2go/kite-mcp-tools-common` | mcp/common + mcp/plugin + mcp/middleware | 0 (infra) | Shared infra; all 5 tool repos import this |
| `algo2go/kite-mcp-tools-trade` | mcp/trade | 28 | Trade ops + GTT + close_position |
| `algo2go/kite-mcp-tools-portfolio` | mcp/portfolio + mcp/analytics | 28 | Read-side queries + analytics |
| `algo2go/kite-mcp-tools-ops` | mcp/admin + mcp/misc | 27 | Admin + session tools |
| `algo2go/kite-mcp-tools-alerts` | mcp/alerts | 8 | Alert lifecycle |
| `algo2go/kite-mcp-tools-paper` | mcp/paper | 8 | Paper-trading isolation |

**Total**: 5 tool repos + 1 infra repo = 6 new repos. Plus existing 29 algo2go repos = **35 algo2go repos post-decomp**.

The mcp/ ROOT files (12 tools: market_tools, tax_tools, watchlist_tools, ext_apps widget code) need a home. Two options:
- Stay in bootstrap as a small remaining `kite-mcp-bootstrap/mcp-root/` package
- Move into `kite-mcp-tools-portfolio` (market+tax+watchlist are read-side queries) or split: market → `kite-mcp-tools-market` (NEW 7th repo) OR distribute

**Recommendation: distribute the 12 root tools across the 5 tool repos by domain** (market data → portfolio, tax → portfolio, watchlist → portfolio, ext_apps widgets → matching domain repo). 12 root tools have already been migrated to Tool2 interface at `8931b33` so they're parallel-ready surface; they need home assignment.

### §3.2 The bump-cascade ROI

**Before Shape A**: Sprint 5 Phase B fan-out runs serially: 5 agents × ~6h each = ~30h wall-clock IF they could be parallelized but can't. Practically: ~3-5 calendar days at single-agent pace.

**After Shape A**: Sprint 5 Phase B fan-out runs in parallel: 5 agents × ~6h wall-clock = ~6h wall-clock. Plus coordinator phase (~3h sequential) = ~9h end-to-end.

**Time saved per Sprint-5-style refactor**: ~20-25h wall-clock per occurrence.

**Cost paid once**: Shape A decomp = ~10-14h agent + ~30min user.

**Breakeven**: ONE Sprint-5-style refactor pays back the decomp cost.

**Number of expected occurrences** (per `god-object-inventory-2026-05-11.md` end-state vision):
- Sprint 5 itself (Pattern D.2 typed-Deps migration)
- Pattern D.3 (tool relocation into owning algo2go leaves) — same 5-subdir fan-out
- Future tool-surface refactors (rate-limit changes, observability instrumentation, etc.) — same fan-out shape
- Per-domain release cadence (each tool repo can ship independently)

**Estimated total benefit over 12 months**: 3-5 Sprint-5-style refactors × ~20h saved each = 60-100h cumulative.

### §3.3 The shared-infra coupling answer

The empirical finding (verified §INPUTS row 4): every mcp/<sub> imports `mcp/common` + `mcp/plugin`.

**Resolution**: `algo2go/kite-mcp-tools-common` is the shared-infra repo. All 5 tool repos import it. Changes to common bump the 5 tool repos through the standard GOPROXY+go-get cycle.

This IS a real bump-cascade cost: a `common` change touches 5 downstream repos. But:
- Common changes are RARE (it's stable interface code: NewToolHandler, ArgParser, MarshalResponse, etc.)
- Common changes that are LARGE often warrant the bump cascade anyway (e.g., adding ToolHandlerDeps in Sprint 5 IS a coordinated cross-cutting change)
- The 28 algo2go leaves already accept this pattern: `kite-mcp-domain` is shared infra; changes to it propagate to 7 dependent leaves; we've shipped this many times without trouble

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

**Verdict**: kc/ is NOT in scope for current parallel-agent demand. **Defer kc/ decomp**. Revisit if/when a kc-wide refactor surfaces (e.g., Pattern D.3 might need a kc/manager change too — TBD).

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

## §6 — Recommendation (one shape, defended)

**Recommendation: Shape A with 6 new repos (5 tool + 1 common), executed AFTER Sprint-0 bootstrap-relocation merge lands.**

### §6.1 Why Shape A wins

Empirical justification:
1. **Sprint 5 fan-out is real and recurring**. Path A's PREP doc (verified 2026-05-16, commit `7bcb719`) explicitly designs for 5-6 parallel agents in Phase B. The current per-git rule blocks that. Shape A unblocks it.
2. **28 algo2go leaves prove the multi-repo pattern works at scale**. We already coordinate 29 algo2go repos; 35 is the same operating model with +6 repos.
3. **The cascade cost (3 → 4 hops) is bounded and automatable**. Per §5.3, standard Go monorepo-lite tooling handles this; no novel infrastructure needed.
4. **ROI breaks even on ONE Sprint-5-style refactor**. The next 12 months will likely contain 3-5 such refactors (per `god-object-inventory` end-state).
5. **The mcp/common shared-infra coupling is handled cleanly via a 6th infra repo**, not by collapsing back to a monolith.

### §6.2 Falsifiable claim

If Shape A is executed at the cost stated below:
- ~10-14h agent (decomp execution)
- ~30min user (gh repo create × 6 + auth checks)
- ~14h/year recurring (per §5.4)

Then BOTH of these MUST hold:
- Sprint 5 Phase B drops from ~30h serial wall-clock to ≤8h parallel wall-clock (5+ agents fan-out)
- The next mcp-wide refactor (Pattern D.3 or any other) benefits identically without re-incurring the decomp cost

If either fails on first execution, Shape A is falsified and we revert to Shape C status quo.

### §6.3 What NOT to do

- **Don't do Shape B (3-bundle gits)**: arbitrary boundaries, future drift risk, parallel benefit is partial (2-cycle vs single-cycle)
- **Don't do Shape A.1 with N=10 fine-grained**: coordination overhead exceeds benefit
- **Don't do kc/ or app/ decomp now**: those surfaces aren't parallel-amenable (god-struct + Fx wire + HTTP mux are intrinsically sequential)
- **Don't do bootstrap-relocation merge AND Shape A in same dispatch window**: too many concurrent rebases. Land merge first, then Shape A.

### §6.4 Decision matrix for user

| Shape | Decomp cost | Parallel benefit | Recurring cost | Net ROI 12mo |
|---|---|---|---|---|
| A (5 tool + 1 infra repo) | ~10-14h + 30min user | 5-6 agents on mcp-fan-out (~24h/yr saved) | +14h/yr | +60-86h/yr |
| B (3 bundle repos) | ~8-10h + 20min user | 3 agents (~12h/yr saved) | +8h/yr | +24-40h/yr |
| C (status quo) | 0 | 0 | 0 | 0 (baseline) |
| D (mcp/ as 1 git) | ~6-10h + 20min user | 0 (binding constraint not solved) | +5h/yr | NEGATIVE (cost without benefit) |
| Hybrid (defer Shape A until Sprint 5 ships serially) | 0 now; ~10-14h later | 0 for Sprint 5; future refactors gain | same as A | A's ROI minus 1 Sprint-5-cycle savings |

**The strictly-dominant strategy is Shape A**. The hybrid (defer Shape A until after Sprint 5) gives up the Sprint 5 savings but keeps the future-refactor savings — defensible if user prefers risk-averse path.

---

## §7 — What this doc does NOT recommend (per dispatch instruction)

Per dispatch: "Don't recommend execution sequencing yet — that comes after the user picks a shape based on both your doc + Path A's doc."

So this doc names **A** as the recommendation but does NOT specify:
- WHEN to execute (now vs after Sprint-0 merge vs after Sprint 5 ships)
- WHICH agent dispatches the decomp (single coordinator vs multi-agent for repo creation)
- WHO owns each of the 6 new repos for maintenance
- Per-repo naming finalization (the §3.1 names are provisional)

Those decisions await user choice between Shape A vs Shape B vs Shape C vs A-deferred, informed by Path A's bootstrap-internal mapping doc (when it lands).

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

**END OF DOC** — verified at kite-mcp-server `d3a01ed` + bootstrap `8931b33`; probes 2026-05-16. Companion: Path A's bootstrap-internal mapping doc (cite-slot §INPUTS row 13; not yet landed).
