<!-- secret-scan-allow: audit-research-no-secrets -->
---
title: Sprint 0 PR Mergeability Audit
as-of: 2026-05-16
re-verify-by: 2026-05-23 (1-week shelf life — branch divergence accelerates)
master-heads:
  kite-mcp-server: 280ae67
  algo2go/kite-mcp-bootstrap: 2c741e3
scope: READ-ONLY empirical audit on the Sprint 0 bootstrap-relocation branch; no code changes, no merge executed
methodology: live gh + git probes; trial-merge on scratch branch then aborted; per `feedback_compile_and_run_methodology`
budget-used: ~40min of 30-45min target
---

# Sprint 0 PR Mergeability Audit

**User's question (verbatim from dispatch)**: *"Is that PR still mergeable, or has divergence made it stale?"*

## Headline complexity classification: **"Needs rebase but no conflicts" (~30min)** — with one caveat

Empirical trial-merge succeeded at the git-text level (exit 0, no conflict markers). However, semantic post-merge cleanup is required: **6 of my own integration test files added to master AFTER the branch was cut reference packages the branch deletes**. They must be removed (or relocated to bootstrap) after merge.

**Total effort to ship a mergeable state**:
1. ~5min: open PR via `gh pr create` (no PR exists today)
2. ~5min: merge (clean merge per trial)
3. ~5min: remove 6 orphan test files in mcp/ (or relocate them to bootstrap)
4. ~10min: verify `go build ./...` + `go test -run XXX ./...` clean
5. ~5min: `flyctl deploy` if user authorizes

**Bucket**: between **trivial fast-forward** and **needs rebase with manual conflict resolution**. Best characterized as **"clean merge + one trivial semantic cleanup commit"**.

## §INPUTS — load-bearing facts (probed `2026-05-16`)

| # | Claim | Probe | Verified |
|---|---|---|---|
| 1 | Sprint 0 branch exists at `origin/bootstrap-relocation` on `Sundeepg98/kite-mcp-server` fork; HEAD `deefac1c27e766db0444fa78e4387f22ec3ac999` | `git ls-remote origin` returns the branch | 2026-05-16 |
| 2 | Branch does NOT exist on `zerodha/kite-mcp-server` (upstream) | `git ls-remote upstream \| grep bootstrap` returns empty | 2026-05-16 |
| 3 | Branch tip `deefac1` is 1 commit ahead of my Sprint 0 commit `bc76c76` — the additional commit is a research-doc-only follow-up at `deefac1` | `git log --oneline origin/bootstrap-relocation -3` shows `deefac1 docs(research): dead-code-utilization-analysis-2026-05-11.md` + `bc76c76 relocation: thin shell` + base | 2026-05-16 |
| 4 | **NO GitHub PR exists** for this branch in EITHER `Sundeepg98/kite-mcp-server` OR `zerodha/kite-mcp-server` | `gh pr list --repo Sundeepg98/kite-mcp-server --head bootstrap-relocation --state all` returns empty; same for `zerodha/...` | 2026-05-16 |
| 5 | Branch base (merge-base with master): `b6b4f6a` ("test(e2e): add OAuth full roundtrip mock — closes critical-path E2E gap") | `git merge-base origin/master origin/bootstrap-relocation` | 2026-05-16 |
| 6 | Master is **13 commits ahead** of branch-base; branch is **2 commits ahead** of branch-base | `git rev-list --left-right --count origin/master...origin/bootstrap-relocation` returns `13 2` | 2026-05-16 |
| 7 | ZERO file overlap between master's 13 commits and branch's 2 commits (no modify/modify conflicts in the 3-way diff) | `comm -12 <(git diff --name-only b6b4f6a..origin/master \| sort) <(git diff --name-only b6b4f6a..origin/bootstrap-relocation \| sort)` returns empty | 2026-05-16 |
| 8 | Master-side touches: `.claude-plugin/*`, `.github/*`, `.research/*`, `README.md`, `server.json`, `cmd/dr-decrypt-probe/main_test.go`, `docs/extension-points.md`, `docs/operator-playbook.md`, plus 6 NEW files in `mcp/*_full_chain_test.go` | `git diff --name-only b6b4f6a..origin/master` returns 25 paths | 2026-05-16 |
| 9 | Branch-side touches: 528 paths — deletes ENTIRE `kc/`, `app/` (except `app/providers/`), `mcp/`, `plugins/`, `testutil/` dirs; rewrites `main.go` + `main_test.go` + `go.mod` + `go.work`; adds 1 research doc | `git diff --name-only b6b4f6a..origin/bootstrap-relocation \| wc -l` returns 528 | 2026-05-16 |
| 10 | Trial-merge via `git merge --no-ff --no-commit origin/bootstrap-relocation` from `origin/master`: **exit 0; "Automatic merge went well"; no conflict markers** | scratch branch `trial-sprint-0-merge`, then `merge --abort` | 2026-05-16 |
| 11 | **`go build ./...` on the merged tree: exit 0** (production code compiles cleanly) — pulled `github.com/algo2go/kite-mcp-metrics v0.1.0` from GOPROXY automatically | trial-merge then `go build ./...` | 2026-05-16 |
| 12 | **`go test -run XXX ./...` on the merged tree: FAILS at `mcp/` package** with error `no required module provides package github.com/zerodha/kite-mcp-server/kc` | trial-merge then `go test -run XXX ./...` | 2026-05-16 |
| 13 | The 6 master-added test files (`mcp/*_full_chain_test.go` + `mcp/order_chain_helpers_test.go`) survive the merge but reference deleted `kc/` package; this is an "added on master, deleted-on-branch dir" semantic conflict that git's 3-way merge treats as "add wins" (file kept) without checking semantic validity | `git ls-tree <merge-result> -- mcp/` shows 6 files; `go test -run XXX ./mcp` fails on `kc` import | 2026-05-16 |
| 14 | After removing the 6 orphan test files: `go build ./...` exit 0 AND `go test -run XXX ./...` exit 0 (production-only compile-clean) | trial-merge + `rm mcp/*_full_chain_test.go` + rebuild | 2026-05-16 |
| 15 | The merge resolves `cmd/dr-decrypt-probe/main_test.go` (which master modified at commit `47bd6a3` for Windows fix) to the MASTER blob — not the branch blob — because branch did not touch this file post-base. The Windows fix is preserved. | `git ls-tree <merge-result> -- cmd/dr-decrypt-probe/main_test.go` returns hash `bcbe377` matching origin/master, not branch hash `d4e108d` | 2026-05-16 |
| 16 | Merged go.mod uses cross-repo `replace` directives (`replace github.com/algo2go/kite-mcp-bootstrap => ../algo2go/kite-mcp-bootstrap`) — NOT tagged versions. Bootstrap is at `v0.0.0-00010101000000-...` pseudo-version. | `grep 'kite-mcp-bootstrap' go.mod` on merge result shows replace directive + pseudo-version | 2026-05-16 |
| 17 | Bootstrap has NO tags published; `git tag --list` returns empty | run in `algo2go/kite-mcp-bootstrap` clone | 2026-05-16 |
| 18 | **Bootstrap-side divergence since Sprint 0 branch was cut**: 5 commits on bootstrap master (Sprint 5 PREP `7bcb719`, Tool2 infrastructure `4c823c6`, Pilot F `8931b33`, empirical mapping `fe5255d`, Phase 0 cutover `7ef28c1` + Phase B canary delete `2c741e3`). All consumed AUTOMATICALLY post-merge because go.mod replace points at local filesystem. | `git log --oneline bc76c76..2c741e3` on bootstrap; merged kite-mcp-server's replace directive verified per row 16 | 2026-05-16 |
| 19 | app/metrics on master = identical to bootstrap: 513 non-test LOC, 2 files, 10 import sites (`app/app.go`, `app/providers/manager.go`, `app/wire.go`, `kc/{config,manager_struct,options,scheduling_service,ops/handler}.go`, `kc/manager_construction_test.go`, `kc/manager_lifecycle_test.go`) | `find app/metrics -name '*.go' \| xargs wc -l` + `grep -rln 'github.com/zerodha/kite-mcp-server/app/metrics' --include='*.go' .` | 2026-05-16 |
| 20 | Phase 0 (extract app/metrics) on kite-mcp-server master would be ~75min — same cost as Path A's bootstrap-side Phase 0 (identical surface) | empirical: same LOC, same import site count, same dependency shape | 2026-05-16 |

---

## §1 — Branch location + existence

- Branch: `bootstrap-relocation`
- Owner: `Sundeepg98/kite-mcp-server` (fork; not upstream zerodha)
- Branch tip: `deefac1c27e766db0444fa78e4387f22ec3ac999` (1 commit ahead of session-snapshot reference `bc76c76`)
- Branch composition:
  - `bc76c76` — the Sprint 0 thin-shell relocation commit (my work in the prior session)
  - `deefac1` — a research-doc-only follow-up (`dead-code-utilization-analysis-2026-05-11.md`)
- **No GitHub PR exists** (verified via `gh pr list` on both fork + upstream). The branch was pushed but never opened as a PR.

The session-snapshot reference `bc76c76` was correct — that commit IS on this branch. The branch tip moved one research-doc commit beyond it.

---

## §2 — Branch contents shape

### §2.1 Net diff stats

```
$ git diff --stat b6b4f6a..origin/bootstrap-relocation | tail -3
 528 files changed, 109 insertions(+), 156150 deletions(-)
```

Branch's 2 commits comprise:
- **bc76c76**: ~155K LOC deleted (kc/, app/ except app/providers, mcp/, plugins/, testutil/); main.go rewritten to thin shell; go.mod rewritten to import bootstrap; ~100 lines added
- **deefac1**: +9 LOC (one new research doc)

### §2.2 What kite-mcp-server looks like post-merge (per merged tree)

Survives on master after merge:
- `main.go` (rewritten to thin shell delegating to `bootstrap.Main()`)
- `cmd/{dr-decrypt-probe, event-graph, rotate-key}/` (operational binaries; cmd/ stays intact)
- `examples/riskguard-check-plugin/` (example code; survives)
- `app/providers/` (workspace member — survives because branch only deleted `app/` non-providers files)
- `go.mod`, `go.sum`, `go.work` (rewritten to consume bootstrap via replace directive)
- All `.research/*`, `docs/*`, `scripts/*`, `tests/*`, `skills/*`, `etc/*`, `.github/*` (NOT in the move-out scope)
- Top-level `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE`, `NOTICE`, `PRIVACY.md`, `TERMS.md`, `funding.json`, `flake.{nix,lock}`, etc.

Deleted by merge:
- Entire `kc/` tree (102 files / 17,820 LOC)
- `app/` files EXCEPT `app/providers/` (45 files / 10,371 LOC minus providers subset)
- Entire `mcp/` tree (104 files / 24,358 LOC) — INCLUDING my 5 sibling integration tests added at `d3a01ed`. See §3.4 for the semantic conflict.
- Entire `plugins/` tree (3 files / 321 LOC)
- Entire `testutil/` tree (4 files / 825 LOC)

Net: kite-mcp-server master goes from 54,504 non-test LOC to ~710 non-test LOC (98.7% reduction), matching my prior Sprint-0 surface report.

### §2.3 New main.go (verified at merge result)

```go
package main

import "github.com/algo2go/kite-mcp-bootstrap"

func main() {
    bootstrap.Main(bootstrap.Options{...})
}
```

(Per `bc76c76` commit body; verified post-trial-merge at `main.go` blob.)

### §2.4 New go.mod shape (verified at merge result)

```
require (
    github.com/algo2go/kite-mcp-alerts v0.6.0
    github.com/algo2go/kite-mcp-bootstrap v0.0.0-00010101000000-000000000000
    github.com/algo2go/kite-mcp-bootstrap/app/providers v0.0.0-00010101000000-000000000000
    github.com/stretchr/testify v1.11.1
    modernc.org/sqlite v1.46.1
)

replace (
    github.com/algo2go/kite-mcp-bootstrap => ../algo2go/kite-mcp-bootstrap
    github.com/algo2go/kite-mcp-bootstrap/app/providers => ../algo2go/kite-mcp-bootstrap/app/providers
    github.com/algo2go/kite-mcp-bootstrap/plugins => ../algo2go/kite-mcp-bootstrap/plugins
    github.com/algo2go/kite-mcp-bootstrap/testutil => ../algo2go/kite-mcp-bootstrap/testutil
)
```

**Replace directives use local-filesystem-relative paths** (`../algo2go/kite-mcp-bootstrap`). This means post-merge resolution depends on the user's working-tree layout. See §4 for the Phase 0 implication.

---

## §3 — Master-side divergence (13 commits since branch-base)

### §3.1 Commit list

```
280ae67 docs(research): bootstrap decomposition strategy REV 2 -- Path A reconciliation
22c6eb0 docs(research): bootstrap decomposition strategy — consumer-side synthesis
d3a01ed test(integration): 4 sibling full-chain tests + shared helper (modify/cancel/gtt/close)   ← adds mcp/*_full_chain_test.go
76e42be test(integration): add full chain place_order -> audit -> riskguard -> broker E2E       ← adds mcp/place_order_full_chain_test.go
47bd6a3 fix(dr-decrypt-probe): use runtime-aware path for test exec (.exe on Windows)            ← modifies cmd/dr-decrypt-probe/main_test.go
379c46d docs(readme): add Windows mcp-remote footnote + RFC 8414/9728 standards mention
557344b docs(state): refresh STATE.md with today's deployments + new corpus subdirs
6e72014 chore(repo): prepare for transfer to algo2go org -- patch 8 hard-coded URL refs
f81c91b docs(research): comprehensive decomposition blocker inventory
2b57212 .research: Option B refactor design — expose unexported Manager fields + delete accessors
ef192db .research: path to literal 100% algo2go — residual analysis + transfer mechanics
160ff40 .research: algo2go dependency-state analysis
8910d20 chore: execute 6 of 8 dead-code-utilization recommendations (items 1-4, 6, 8)
```

### §3.2 File overlap with branch (the conflict zone)

**ZERO file overlap**. The intersection of master-touched paths and branch-touched paths is empty per §INPUTS row 7.

Master-side touches:
- 10 of 13 commits: `.research/*`, `.claude-plugin/*`, `.github/*`, `README.md`, `server.json`, `docs/*` — none overlap branch's deletes
- 1 commit (`47bd6a3`): `cmd/dr-decrypt-probe/main_test.go` — branch retains `cmd/`; both blobs differ but only ONE side modified post-base, so 3-way merge cleanly takes master's version
- 2 commits (`76e42be` + `d3a01ed`): ADD 6 new files to `mcp/` — branch deletes all of `mcp/`. **Semantic conflict** (see §3.4)

### §3.3 cmd/dr-decrypt-probe/main_test.go — modify on master, untouched on branch

Master modified it at `47bd6a3` (Windows .exe fix). Branch did NOT touch it post-base. Trial-merge result: **master blob wins** (`bcbe377` vs `d4e108d` branch-base). The Windows fix survives. No conflict.

### §3.4 The semantic conflict: 6 new mcp/ test files vs mcp/ directory deletion

**The issue**: my commits `76e42be` and `d3a01ed` (Sprint 5 Pilot extensibility work) ADDED 6 new files to `mcp/` AFTER the branch was cut:
- `mcp/place_order_full_chain_test.go`
- `mcp/modify_order_full_chain_test.go`
- `mcp/cancel_order_full_chain_test.go`
- `mcp/place_gtt_order_full_chain_test.go`
- `mcp/close_position_full_chain_test.go`
- `mcp/order_chain_helpers_test.go`

The branch DELETES the entire `mcp/` tree (because mcp/ moved to bootstrap).

**Git's 3-way merge behavior**: when a directory is deleted on one side and a file is added under that directory on the other side, git treats it as "add wins" — the new file is kept. Verified empirically (§INPUTS row 13): the 6 files survive in the merged tree.

**The semantic problem**: these surviving files import `github.com/zerodha/kite-mcp-server/kc` (deleted) + `github.com/algo2go/kite-mcp-broker/mock` + other packages that no longer make sense in the thin-shell repo. `go test -run XXX ./...` exits FAIL on the merged tree (§INPUTS row 12) with error:

```
mcp/order_chain_helpers_test.go:47:2: no required module provides
package github.com/zerodha/kite-mcp-server/kc
```

**Resolution**: post-merge, the 6 orphan test files must either be DELETED (their target code now lives in bootstrap) or RELOCATED to `algo2go/kite-mcp-bootstrap/mcp/*_full_chain_test.go` where they would compile against the live in-tree types. After `rm mcp/*_full_chain_test.go` (§INPUTS row 14), both `go build` and `go test -run XXX` exit 0.

---

## §4 — Bootstrap-side divergence + version-pinning

### §4.1 Bootstrap commits since Sprint 0 branch was cut

Bootstrap master moved from where my Sprint 0 work referenced it to current `2c741e3`. The intermediate commits:

```
2c741e3 feat(metrics): canary deletion of in-tree app/metrics; GOPROXY canonical (Phase B)
7ef28c1 feat(metrics): canary cutover to algo2go/kite-mcp-metrics v0.1.0 (Phase A)
fe5255d docs(research): bootstrap decomposition — empirical mapping
8931b33 refactor(mcp): migrate 12 root-mcp tools to Tool2 interface (Pilot F)
4c823c6 feat(mcp/common): add Tool2 interface + registry type-switch (additive Sprint 5 pilot infrastructure)
7bcb719 docs(research): Sprint 5 Pattern D.2 PREP — Tool.Handler migration survey
2b96ef6 refactor(manager-cqrs): split 788-LOC manager_commands_admin.go
9c29415 refactor(manager-init): split 538-LOC manager_init.go into per-concern files
c24bd56 refactor(manager): expose SessionManager field; delete getter (PR B4)
8652c73 refactor(manager): expose SessionSigner field
... (more Sprint 1-3 work)
```

### §4.2 Are any of these "ADDITIONAL changes that need to be re-applied after merge"?

**No**. The Sprint 0 branch's go.mod uses a `replace` directive pointing at `../algo2go/kite-mcp-bootstrap` (local filesystem). This means:
- Post-merge, the user's working tree resolves bootstrap from their LOCAL clone
- Whatever state the local clone is at (currently `2c741e3` = Phase 0 canary-deletion complete) gets pulled in automatically
- **No separate go.mod bump needed** to consume Phase 0 (or any subsequent phase) post-merge

This is by design from my Sprint 0 dispatch: I used local-filesystem replace because bootstrap had no tags published. Bootstrap STILL has no tags (verified §INPUTS row 17). The replace remains the canonical resolution path.

### §4.3 Implication for Phase 0 "production-orphaned" claim

The dispatch claim: *"Phase 0 is production-orphaned until Sprint 0 PR merges."*

**Empirically verified**:
- Master `280ae67` go.mod has zero `kite-mcp-bootstrap` references (§INPUTS row check above)
- Master's `flyctl deploy` would build from in-tree code; never touches Phase 0's `kite-mcp-metrics` extraction
- The only path to producing a deploy that consumes `algo2go/kite-mcp-metrics v0.1.0` is via the Sprint 0 merge (or by doing direct extraction work on master — see §6)

---

## §5 — Merge complexity classification

**Verdict: between "Trivial clean merge" and "Needs rebase with manual conflict resolution"**. Best characterized as:

### **"Clean merge + one semantic cleanup commit" (~30-45min total)**

Empirical justification:
- Git's 3-way merge: **succeeds with exit 0, no conflict markers** (§INPUTS row 10)
- Post-merge `go build ./...`: **exit 0** (§INPUTS row 11)
- Post-merge `go test -run XXX ./...`: **FAILS** at mcp/ (§INPUTS row 12) — the 6 orphan test files
- After `rm mcp/*_full_chain_test.go`: **both pass** (§INPUTS row 14)

### Concrete merge plan (no decisions, just steps)

| Step | Action | Time | Risk |
|---|---|---|---|
| 1 | `gh pr create --base master --head bootstrap-relocation --title "Sprint 0: bootstrap relocation" --body ...` on `Sundeepg98/kite-mcp-server` | 5min | LOW |
| 2 | `git checkout master && git merge --no-ff origin/bootstrap-relocation` | 5min | LOW (clean per trial) |
| 3 | `rm mcp/*_full_chain_test.go mcp/order_chain_helpers_test.go && rmdir mcp` | 1min | LOW (these are orphan tests; their target code moves to bootstrap) |
| 4 | `git commit -am "cleanup(mcp): remove orphan integration tests (target code moved to bootstrap)"` | 2min | LOW |
| 5 | `go build ./... && go test -run XXX ./...` verify both exit 0 | 5min (WSL2) | LOW |
| 6 | `git push origin master` | 1min | LOW |
| 7 | (Optional, separate concern) Relocate the 6 test files to `algo2go/kite-mcp-bootstrap/mcp/*_full_chain_test.go` so the integration test work is not LOST | 15-30min | LOW (additive in bootstrap repo) |
| 8 | (Optional, separate concern) `flyctl deploy` to push the thin shell to production | 5min | MED (first deploy of new shape — should be tested in staging first if possible) |

**Total agent + user time**: ~30min on the critical-path merge; ~45-60min if step 7 (test relocation) is bundled.

---

## §6 — Alternative: "Replicate decomp on kite-mcp-server master directly"

If the user prefers NOT to land Sprint 0 merge and instead replicates Path A's phased extraction directly on kite-mcp-server master:

### §6.1 Phase 0 (extract app/metrics) cost on master

- Same code: 513 LOC, 2 files (§INPUTS row 19)
- Same 10 import sites (§INPUTS row 19)
- Same dependency shape (zero algo2go deps, stdlib-only leaf)
- Same as Path A's bootstrap-side Phase 0 = ~75min per Path A's commit message

### §6.2 Phase 1 (extract kc/) cost on master

- 102 files (matches bootstrap)
- 17,820 non-test LOC (matches bootstrap; verified in prior research at `algo2go-dependency-state-2026-05-11.md`)
- Same import-rewrite scope expected
- ~4-6h per Path A's Phase 1 design (in `bootstrap-decomp-strategy.md` rev 2 §3.1)

### §6.3 The forking risk

If the user goes Path 6 (replicate on master), bootstrap and kite-mcp-server master would have **TWO PARALLEL extractions of app/metrics** that may diverge in trivial ways (commit SHAs, message wording, even tiny code differences from independent sed runs). Reconciling them later would require:
- Decide which extraction is canonical
- Force-push or rebase to align
- ~1-2h of reconciliation work

**vs Sprint 0 merge path**: bootstrap's Phase 0 is automatically consumed via the replace directive; zero reconciliation needed.

### §6.4 Concrete cost comparison (per-decision matrix)

| Path | One-time cost | Reconciliation risk | Future Phase 1 cost on master |
|---|---|---|---|
| Sprint 0 merge + post-cleanup (this audit's recommendation) | ~30-45min | None | 0h (bootstrap's Phase 1 work transparently consumed) |
| Replicate on master directly | ~75min for Phase 0; ~4-6h for Phase 1 | ~1-2h if bootstrap also does Phase 1 | ~4-6h additional |
| Defer Sprint 0 indefinitely | 0min today | None (yet) | Accumulates as bootstrap moves further ahead |

---

## §7 — What this audit does NOT recommend

Per dispatch: *"Don't recommend an answer — just surface findings + complexity classification. The user picks merge vs replicate vs defer based on your audit."*

This doc names the complexity bucket as **"clean merge + one cleanup commit"** but does NOT recommend WHICH path. Three viable paths surfaced:

1. **Merge Sprint 0 PR** (~30-45min total): cleanest path; Phase 0 (and all future phases) consumed automatically via replace directive
2. **Replicate decomp on master directly** (~75min for Phase 0 alone; ~5-7h for Phase 1): independent path; loses bootstrap-already-paid-cost-of-extraction; introduces reconciliation risk
3. **Defer indefinitely**: accumulates orphan-state risk as bootstrap moves further ahead; each additional bootstrap commit increases the "what's pinned vs current" delta

User decides based on:
- Risk appetite for the local-filesystem replace directive in production (the merged go.mod doesn't use tagged versions, it uses a relative path — that's a deployment-architecture choice that needs explicit user authorization)
- Whether to lose or relocate the 6 integration tests
- Whether to consume Path A's Phase 0 + 5 bootstrap-side commits (Pilot F, Sprint 3 manager-cqrs split, etc.) into production immediately or defer

---

## §APPENDIX — Empirical commands used

```bash
# Branch existence + tip
git ls-remote origin | grep bootstrap-relocation        # → deefac1c... refs/heads/bootstrap-relocation
git ls-remote upstream | grep bootstrap-relocation      # → empty
gh pr list --repo Sundeepg98/kite-mcp-server --head bootstrap-relocation --state all  # → empty
gh pr list --repo zerodha/kite-mcp-server --head bootstrap-relocation --state all     # → empty

# Branch base + divergence
git merge-base origin/master origin/bootstrap-relocation     # → b6b4f6a
git rev-list --left-right --count origin/master...origin/bootstrap-relocation  # → 13 2

# File overlap (the conflict zone)
comm -12 \
  <(git diff --name-only b6b4f6a..origin/master | sort) \
  <(git diff --name-only b6b4f6a..origin/bootstrap-relocation | sort)
# → empty (no modify/modify conflicts)

# Trial merge (scratch branch, then abort)
git checkout -b trial-sprint-0-merge origin/master
git merge --no-ff --no-commit origin/bootstrap-relocation     # → exit 0, no conflicts
go build ./...                                                # → exit 0
go test -run XXX ./...                                        # → FAIL at mcp/
rm mcp/*_full_chain_test.go mcp/order_chain_helpers_test.go
go test -run XXX ./...                                        # → exit 0
git merge --abort
git checkout master && git branch -D trial-sprint-0-merge

# Bootstrap-side state
cd ../algo2go/kite-mcp-bootstrap
git log --oneline bc76c76..master | head -10                  # → 5+ commits since Sprint 0 was cut
git tag --list                                                # → empty (no tags published)
```

---

**END OF DOC** — verified at kite-mcp-server `280ae67` + bootstrap `2c741e3`; trial-merge probes 2026-05-16; 1-week shelf life (branch divergence accelerates as additional commits land).
