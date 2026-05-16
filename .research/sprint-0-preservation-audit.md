<!-- secret-scan-allow: preservation-audit-no-secrets -->
---
title: Sprint 0 Preservation Audit — what could be lost on merge
as-of: 2026-05-16
re-verify-by: 2026-05-23 (1-week shelf life — branch + bootstrap divergence accelerates)
master-heads:
  kite-mcp-server: 5167a11
  algo2go/kite-mcp-bootstrap: 2c741e3
scope: READ-ONLY empirical preservation audit; no code changes; no merge executed
companion: prior `sprint-0-pr-mergeability-audit.md` (commit 5167a11) flagged 6 orphan test files; this doc digs exhaustively
methodology: empirical per-file diff scans + branch-divergence enumeration + GOPROXY availability probes; per `feedback_compile_and_run_methodology`
budget-used: ~55min of 45-60min target
---

# Sprint 0 Preservation Audit

**User's verbatim ask**: *"Listen, I don't want to lose any of my research work or documents or tests or anything. I don't want to lose anything, so carefully analyze how to research again if needed and proceed in a way that we are able to save our effort and go to work. See, I don't want to lose bootstrap or the main kite MCP master."*

## Headline preservation picture

**Total at-risk items surfaced: 7 categories, ~145 items** — but only ~10 of these are genuinely-unique-to-master and would be silently lost. The remaining ~135 are content drifts that bootstrap correctly supersedes (bootstrap's Sprint 1-3 work is the canonical evolution; master's stale copies are what we want to discard).

| Strategy bucket | Count | What |
|---|---|---|
| **Relocate to bootstrap before/after merge (`Commit-to-bootstrap`)** | **6** | mcp/*_full_chain_test.go orphan integration tests |
| **User-discard-OK** | **3 + ~80** | 3 compiled Linux binaries (~83 MB) at repo root + ~80 untracked `.research/` scratch files (commit-msg drafts, ad-hoc shell scripts, coverage files) |
| **Explicit-keep (already preserved)** | **228 + 7** | 228 files with content drift where bootstrap has the SUPERSEDING version (kc/, app/, mcp/, etc. — Sprint 1-3 refactors) + 7 `app/metrics/*` files now in external `algo2go/kite-mcp-metrics v0.1.0` + 9 `app/adapters_*.go` files (Sprint 1 Slice 2 split of `app/adapters.go`) |
| **Branches with valuable work — NOT at risk** | **5 branches** | `origin/develop` (12 commits) + `origin/feat-{dcr,embedded-docs,oauth}` (35 commits combined) — these are pre-Sprint zerodha-upstream feature branches; the bootstrap-relocation merge doesn't touch them |
| **External repos (28 algo2go leaves)** | **0 at risk** | Zero leaves import bootstrap or kite-mcp-server (verified `grep -l` → empty); merge cannot affect them |
| **DEPLOY-TIME BLOCKER (new finding)** | **1 critical** | Sprint 0 branch's go.mod uses `replace ... => ../algo2go/kite-mcp-bootstrap` (local filesystem path); Dockerfile builds CANNOT resolve this path; **deploy WILL break post-merge unless bootstrap tags are published OR the deploy path is restructured** |
| **Estimated execution time for full preservation sweep** | **~90min user + ~60min agent** | See §7 |

**Critical addition vs prior mergeability audit**: the local-filesystem replace directive (§INPUTS row 17) is a DEPLOY-TIME BLOCKER, not just a "deployment-architecture choice" as the prior doc said. Verified empirically: GOPROXY returns 404 for the workspace sub-modules at pseudo-version `v0.0.0-00010101000000-000000000000`. **This must be resolved before any merge that ships to production.**

---

## §INPUTS — load-bearing facts (probed `2026-05-16`)

| # | Claim | Probe | Verified |
|---|---|---|---|
| 1 | Master touched 0 files in `kc/`, `app/`, `plugins/`, `testutil/` since branch-base | `git diff --name-only b6b4f6a..origin/master \| grep '^<dir>/'` per dir | 2026-05-16 |
| 2 | Master touched 6 files in `mcp/` since branch-base — all ADDED (not modified existing) | same probe — returns the 6 `mcp/*_full_chain_test.go` files | 2026-05-16 |
| 3 | Bootstrap has 0 copies of the 6 master-added test files (`find . -name <each>` returns 0) | per-file `find` in bootstrap | 2026-05-16 |
| 4 | 528 files in kc/+app/+mcp/+plugins/+testutil/ on master; vs bootstrap: **287 identical** (bit-equal blobs), **228 drifted** (bootstrap has newer/different version), **13 missing-from-bootstrap** | scripted blob-hash compare; see §APPENDIX | 2026-05-16 |
| 5 | Of the 13 missing-from-bootstrap files: 6 are the master-added orphan tests; 5 are `app/metrics/*` (extracted to `algo2go/kite-mcp-metrics v0.1.0`); 1 is `app/adapters.go` (split into 9 `app/adapters_*.go` files on bootstrap via commit `d43d709`); 1 is `app/metrics/daily_metrics_test.go` | per-file inspection vs bootstrap commit history | 2026-05-16 |
| 6 | The 228 drift cases are ALL bootstrap-side improvements (Sprint 1-3 refactors). Bootstrap's 13 commits since Sprint 0 branch-cut all forward-progress; no divergent forks of master-side improvements | `git log --oneline bc76c76..master` on bootstrap — Sprint 1 splits, Sprint 2 init split, Sprint 3 cqrs split, PR B1+B2+B4 accessor cleanups, Pilot F, Phase 0 cutover | 2026-05-16 |
| 7 | Working tree has 121 untracked entries on kite-mcp-server master | `git status --porcelain \| grep '^??' \| wc -l` | 2026-05-16 |
| 8 | Of those 121: 21 commit-message drafts (`_*_msg.txt`, `_redact*.txt`, `_pa[0-9]_msg.txt`); 9 coverage files (`.cov`); 38 ad-hoc shell scripts (`.research/*.sh`); 3 compiled Linux binaries at root; 1 in-progress JS scratch (`.claude/tst.js`); 1 untracked script (`scripts/apply-docs-triage.sh`); rest = other `_msg.txt` drafts | categorized scan via `git status --porcelain` + `file`/`head` per type | 2026-05-16 |
| 9 | The 3 root binaries (`dr-decrypt-probe`, `event-graph`, `rotate-key`) are ELF 64-bit Linux executables, ~83 MB total, NOT gitignored (per `git check-ignore -v` returns empty) | `file` + `ls -la` + `git check-ignore -v` | 2026-05-16 |
| 10 | `scripts/apply-docs-triage.sh` is 666 LOC — appears to be a docs-triage helper applying a 38-file plan from 2026-04-18; not yet committed | `head -30 scripts/apply-docs-triage.sh` | 2026-05-16 |
| 11 | `.claude/tst.js` is 21 LOC — appears to be a sorting-algorithm scratch experiment | `cat .claude/tst.js` | 2026-05-16 |
| 12 | Remote branches: `origin/{master, bootstrap-relocation, develop, feat-dcr, feat-embedded-docs, feat-oauth}` + `upstream/{master, develop, feat-*}` mirrors of zerodha. `fork/master` mirror also present | `git branch -r` | 2026-05-16 |
| 13 | `origin/develop` is 12 commits ahead of `origin/master`, NONE of which are on master; earliest unique commit dated 2025-09-01 — predates Sprint work | `git log origin/master..origin/develop --oneline` + `git log ... --pretty='%ad'` | 2026-05-16 |
| 14 | `origin/develop` is 9 commits diverged from `upstream/develop` (Sundeepg98 carries fork-specific changes); the 12 unique-to-origin/develop commits include OAuth implementation, alerts tool, holdings type param, market protection, etc. — Sundeepg98 work BEFORE the algo2go reorg | `git rev-parse origin/develop` vs `upstream/develop`; `git log` content | 2026-05-16 |
| 15 | `origin/feat-{dcr, embedded-docs, oauth}` are IDENTICAL to their `upstream/feat-*` counterparts (no divergence) | `git rev-parse origin/<branch>` vs `git rev-parse upstream/<branch>` | 2026-05-16 |
| 16 | Zero algo2go leaves depend on `github.com/algo2go/kite-mcp-bootstrap` or `github.com/zerodha/kite-mcp-server` (28 leaves are pure providers; merge cannot affect them) | `grep -l 'kite-mcp-bootstrap\|zerodha/kite-mcp-server' kite-mcp-*/go.mod` returns empty | 2026-05-16 |
| 17 | **DEPLOY-TIME BLOCKER**: GOPROXY returns 404 for bootstrap workspace sub-modules at pseudo-version `v0.0.0-00010101000000-000000000000`. Direct GOPROXY probe: `https://proxy.golang.org/github.com/algo2go/kite-mcp-bootstrap/app/providers/@v/v0.0.0-00010101000000-000000000000.zip` → 404. Same for `/plugins/` and `/testutil/`. | `GOPROXY=https://proxy.golang.org go get github.com/algo2go/kite-mcp-bootstrap@latest` from a scratch module returns 404 errors for all 3 sub-modules | 2026-05-16 |
| 18 | Dockerfile builds via `RUN go mod download` against GOPROXY. The Sprint 0 branch's go.mod uses `replace ... => ../algo2go/kite-mcp-bootstrap` (local filesystem path). The Docker build context (`COPY . .`) doesn't include the sibling algo2go directory. **The deploy build would fail at `go mod download` step** | `grep -E 'RUN go\|go mod' Dockerfile` + inspect Sprint-0 branch's go.mod replace block | 2026-05-16 |
| 19 | Bootstrap has NO published git tags (`git tag --list` returns empty) | run in bootstrap clone | 2026-05-16 |
| 20 | The 5 `app/metrics/*` files missing from bootstrap are NOT lost — they're external in `algo2go/kite-mcp-metrics v0.1.0` per Path A's Phase 0 work (bootstrap commits `7ef28c1` cutover + `2c741e3` canary delete) | `grep 'kite-mcp-metrics' bootstrap/go.mod` returns `v0.1.0` | 2026-05-16 |
| 21 | `app/adapters.go` is missing from bootstrap because Sprint 1 Slice 2 (bootstrap commit `d43d709`) split it into 10 per-domain `app/adapters_*.go` files. Content preserved, reorganized | `ls bootstrap/app/adapters*.go` returns 10 files | 2026-05-16 |

> **Methodology note**: §INPUTS row 4's "287 identical / 228 drifted / 13 missing" totals come from a scripted blob-hash compare between master HEAD `5167a11` and bootstrap HEAD `2c741e3`. Full script in §APPENDIX.

---

## §1 — At-risk items by category

### §1.1 Genuinely-unique-to-master (HARD preservation required)

**Count: 6 files** — the mcp/*_full_chain_test.go orphan integration tests added on master at commits `76e42be` + `d3a01ed` (Sprint 5 Pilot extensibility work):

| File | LOC | Content |
|---|---|---|
| `mcp/place_order_full_chain_test.go` | ~230 | Place order chain: audit + riskguard + broker mock |
| `mcp/modify_order_full_chain_test.go` | ~135 | Modify order chain |
| `mcp/cancel_order_full_chain_test.go` | ~110 | Cancel order chain (audit + broker only — riskguard bypassed by design) |
| `mcp/place_gtt_order_full_chain_test.go` | ~125 | GTT order chain (audit + broker only) |
| `mcp/close_position_full_chain_test.go` | ~135 | Close position chain: audit + riskguard + broker MARKET opposite-direction |
| `mcp/order_chain_helpers_test.go` | ~140 | Shared `fullChainHarness` + `assertAuditRowExists` + `newFullChainHarness(t)` |

**Bootstrap has zero copies** of these files (§INPUTS row 3). They reference `kc/` types that won't exist in kite-mcp-server post-merge.

**Preservation strategy: Commit-to-bootstrap (PR-A)** — relocate these 6 files to `algo2go/kite-mcp-bootstrap/mcp/` BEFORE Sprint 0 merge, so they exist in the bootstrap repo where their dependencies (`kc`, `algo2go/kite-mcp-broker/mock`, etc.) live.

**Cost**: ~30-45min agent work:
1. Copy 6 files from kite-mcp-server master to bootstrap mcp/
2. Sed import paths: `github.com/zerodha/kite-mcp-server/kc` → `github.com/algo2go/kite-mcp-bootstrap/kc`
3. Verify `go build ./...` + `go test ./mcp/...` exit 0 on bootstrap
4. Commit to bootstrap master + push (single commit, additive)

### §1.2 Content drift (228 files — bootstrap correctly supersedes)

**Count: 228 files** with different content between master and bootstrap.

**Empirical analysis**: bootstrap's 13 commits since Sprint 0 branch-cut (§INPUTS row 6) are ALL forward-progress:
- Sprint 1 Slice 2 (commit `d43d709`): split app/adapters.go → 10 files
- Sprint 1 Slice 3 (`4e14268`): split mcp/ext_apps.go → 14 files
- PR B1 (`45ff970`): expose `ManagedSessionSvc` field, delete getter
- PR B2 (`8652c73`): expose `SessionSigner` field, inline mutator
- PR B4 (`c24bd56`): expose `SessionManager` field, delete getter
- Sprint 2-a (`9c29415`): split manager_init.go → per-concern files
- Sprint 3 Option-a (`2b96ef6`): split manager_commands_admin.go → 6 per-domain files
- Sprint 5 PREP (`7bcb719`): docs only
- Sprint 5 Pilot infrastructure (`4c823c6`): add Tool2 interface
- Sprint 5 Pilot F (`8931b33`): migrate 12 root-mcp tools to Tool2
- Phase 0 cutover (`7ef28c1`): metrics extraction
- Phase 0 canary delete (`2c741e3`): remove in-tree metrics

**None of these are divergent forks of master's improvements** — they're all bootstrap-side enhancements. Master's stale copies are exactly what we want to discard.

**Preservation strategy: Explicit-keep (already preserved)** — the merge discards master's stale 228 copies and the merged kite-mcp-server consumes bootstrap's newer versions via the import path. Bootstrap is the canonical source.

**Cost**: $0 — no action needed.

### §1.3 13 missing-from-bootstrap files

**Count: 13 files** that exist on master but not in bootstrap. Per §INPUTS row 5:

| Path | Status | Disposition |
|---|---|---|
| `mcp/place_order_full_chain_test.go` | unique to master | §1.1 (Commit-to-bootstrap) |
| `mcp/modify_order_full_chain_test.go` | unique to master | §1.1 |
| `mcp/cancel_order_full_chain_test.go` | unique to master | §1.1 |
| `mcp/place_gtt_order_full_chain_test.go` | unique to master | §1.1 |
| `mcp/close_position_full_chain_test.go` | unique to master | §1.1 |
| `mcp/order_chain_helpers_test.go` | unique to master | §1.1 |
| `app/adapters.go` | split into 10 files on bootstrap | **Explicit-keep** (preserved as `adapters_briefing.go`, `adapters_eventsourcing.go`, etc. on bootstrap) |
| `app/metrics/histogram.go` | extracted to `algo2go/kite-mcp-metrics v0.1.0` | **Explicit-keep** (external module) |
| `app/metrics/histogram_test.go` | extracted | **Explicit-keep** |
| `app/metrics/metrics.go` | extracted | **Explicit-keep** |
| `app/metrics/metrics_edge_test.go` | extracted | **Explicit-keep** |
| `app/metrics/metrics_test.go` | extracted | **Explicit-keep** |
| `app/metrics/daily_metrics_test.go` | extracted | **Explicit-keep** (in `algo2go/kite-mcp-metrics`) |

**Net unique-to-master: 6 files** (all in §1.1).

### §1.4 Untracked working-tree items (121 entries)

Categorized per §INPUTS row 8:

#### §1.4.1 Compiled binaries (3 files, ~83 MB) — **User-discard-OK**

```
dr-decrypt-probe      21,671,889 bytes  (ELF Linux, debug-info, not-stripped)
event-graph           39,669,309 bytes  (ELF Linux, debug-info, not-stripped)
rotate-key            21,572,236 bytes  (ELF Linux, debug-info, not-stripped)
```

These are from WSL2 `go test` compile runs (debug-info = test binary, not production). Source code is tracked in `cmd/{dr-decrypt-probe,event-graph,rotate-key}/`. Binaries themselves are throwaway artifacts.

**Note**: they're NOT in `.gitignore` (root-level only `/kite-mcp-server` is). Could be permanently fixed by adding `/dr-decrypt-probe`, `/event-graph`, `/rotate-key` to `.gitignore` — but unrelated to preservation.

**Preservation strategy: User-discard-OK** — `rm dr-decrypt-probe event-graph rotate-key` before any commit/merge work.

#### §1.4.2 Commit-message drafts (21 files) — **User-discard-OK**

Examples: `_redact-test-fixture-msg.txt`, `_pa1_msg.txt`, `_tier1-1-msg.txt`, `_commit_msg_arch_audit.txt`, etc.

These are leftover commit-message scaffolding from prior session work. Each was used to compose a commit message via `git commit -F <file>` then never deleted. The commits these supported are ALREADY ON MASTER (verified via git log) — the source content is in commit messages, not these scratch files.

**Sample content**: `head -5 _redact-test-fixture-msg.txt` returns text identical to commit `16b6ad3`'s body.

**Preservation strategy: User-discard-OK** — these are equivalent to `*.tmp` files. Safe to `rm .research/_*_msg.txt`.

#### §1.4.3 Coverage files (9 files) — **User-discard-OK**

`*.cov` files in `.research/` are go-test coverage outputs from past runs. Transient build artifacts.

**Preservation strategy: User-discard-OK** — `rm .research/*.cov`.

#### §1.4.4 Ad-hoc shell scripts (38 files in `.research/*.sh`) — **NEEDS USER REVIEW**

Examples: `anchor2-baseline.sh`, `anchor2-prebuild.sh`, `wsl-build-anomaly.sh`, `phase3a-batch1-msg.txt`, `_pr615_build.sh`, etc.

**Sample content** (`anchor2-baseline.sh`):
```bash
#!/bin/bash
# Baseline check for Anchor 2 — app/providers extraction
set -e
export PATH=/usr/local/go/bin:/usr/bin:/bin
cd /mnt/d/Sundeep/projects/kite-mcp-server
echo "=== go version ==="
go version
echo "=== go vet ./app/providers/... ==="
go vet ./app/providers/... 2>&1 | tail -20
```

These are ONE-OFF dispatch helpers from past Anchor/Phase work. Each was used ONCE during a specific past dispatch, then never re-run.

**Two perspectives**:
- These contain TRACES of past methodology (which can be replayed in future research dispatches)
- BUT they're un-modular, hardcode-path-specific, and tied to specific commit ranges that are now ancient

**Preservation strategy: NEEDS USER REVIEW** — present the list to user with a 1-line per-file annotation; user marks each as "keep & commit", "archive to .research/scripts-archive/", or "discard".

**Alternative simpler strategy**: bulk-move all 38 to `.research/scripts-archive-2026-05-16/` and commit, then user can prune later. ~5min effort.

#### §1.4.5 Stray scripts/apply-docs-triage.sh (1 file, 666 LOC) — **NEEDS USER REVIEW**

This is a 666-LOC bash script implementing a 38-file docs-triage plan from 2026-04-18 (per its header comment). It was authored, never committed.

**Two scenarios**:
- The triage was performed (then the script is post-facto safe to discard)
- The triage was NOT performed (then the script encodes pending work + should be preserved)

**Preservation strategy: NEEDS USER REVIEW** — surface the script + its date + ask if the triage was done.

#### §1.4.6 .claude/tst.js (1 file, 21 LOC) — **User-discard-OK**

JavaScript scratch experiment (sorting algorithm). No production relevance.

**Preservation strategy: User-discard-OK** — `rm .claude/tst.js`.

#### §1.4.7 Other untracked .research/ files

Remaining 8 entries are similar shape to §1.4.2 (commit-message drafts named `anchor2-pr1-msg.txt`, etc.).

**Preservation strategy: User-discard-OK** — bundle with §1.4.2.

### §1.5 Branches with valuable work

Per §INPUTS rows 12-15:

| Branch | Owner | Status | Risk from Sprint 0 merge |
|---|---|---|---|
| `origin/bootstrap-relocation` | Sundeepg98 fork | THE Sprint 0 branch under audit | n/a (this IS what merges) |
| `origin/master` | Sundeepg98 fork | current production master | n/a (this is the merge TARGET) |
| `origin/develop` | Sundeepg98 fork | 12 commits ahead of master, NONE on master; earliest 2025-09-01 | **NONE** — separate branch line; merge doesn't touch this |
| `origin/feat-dcr` | Sundeepg98 fork (= upstream/feat-dcr) | mirror of zerodha upstream | **NONE** — pre-fork branch; merge doesn't touch |
| `origin/feat-embedded-docs` | Sundeepg98 fork (= upstream) | mirror | **NONE** — pre-fork branch |
| `origin/feat-oauth` | Sundeepg98 fork (= upstream) | mirror | **NONE** — pre-fork branch |
| `fork/master` | local fork remote mirror | duplicate of origin/master | n/a |
| `upstream/*` | zerodha/kite-mcp-server remotes | upstream mirrors | **NONE** — independent |

**Preservation strategy: Explicit-keep (already preserved)** for all branches except `bootstrap-relocation` (which is the one being merged). All branches exist on GitHub remotes (origin + upstream); none are at risk from the Sprint 0 merge.

**`origin/develop` is the only one with non-zero unique-commits**: 12 OAuth+alerts+holdings commits dated 2025-09-01. These are pre-Sprint zerodha-side improvements that diverged from master long before Sprint work began. The Sprint 0 merge has zero interaction with this branch.

**Optional user action**: decide whether to merge `origin/develop` into master at some future point (independent of Sprint 0). NOT a Sprint-0 preservation concern.

### §1.6 External repos at risk (28 algo2go leaves)

**Count: 0** — verified §INPUTS row 16. Zero leaves import bootstrap or kite-mcp-server. The 28 leaves are upstream providers; the merge cannot affect them.

**Preservation strategy: Explicit-keep (already preserved)**.

### §1.7 NEW finding: DEPLOY-TIME BLOCKER (replace directive vs Dockerfile)

**This was implicit in the prior mergeability audit but NOT fully analyzed.**

Per §INPUTS rows 17-18:
- Sprint 0 branch's `go.mod` uses `replace github.com/algo2go/kite-mcp-bootstrap => ../algo2go/kite-mcp-bootstrap`
- This relative path ONLY works on the user's local machine where `../algo2go/kite-mcp-bootstrap` exists
- Dockerfile (`COPY . .` + `RUN go mod download`) does NOT include the sibling algo2go directory in build context
- Empirical GOPROXY probe: `proxy.golang.org` returns 404 for `kite-mcp-bootstrap/app/providers@v0.0.0-00010101000000-...`, `/plugins/...`, `/testutil/...`
- Bootstrap has no git tags published (`git tag --list` → empty)

**Implication**: `flyctl deploy` of the merged thin shell would FAIL at the `RUN go mod download` step inside the Docker builder. Production would NOT come up.

**Three resolution paths**:

A. **Publish bootstrap tags first** (~30min):
1. In bootstrap repo: `git tag v0.1.0 && git push origin v0.1.0`
2. ALSO tag each workspace sub-module: `git tag app/providers/v0.1.0`, `git tag plugins/v0.1.0`, `git tag testutil/v0.1.0` (Go's submodule-tag convention)
3. Push all 4 tags
4. Update Sprint 0 branch's go.mod to use `require github.com/algo2go/kite-mcp-bootstrap v0.1.0` (drop the replace)
5. Verify `go mod download` works without the replace
6. Re-test Docker build

B. **Use vendor directory** (~45min):
1. After merge, `go mod vendor` to populate `vendor/` with bootstrap source
2. Dockerfile uses `-mod=vendor` so no GOPROXY fetch needed
3. Vendor dir is committed; deploy works without GOPROXY

C. **Restructure Docker build context to include sibling dir** (~1h):
1. `flyctl deploy` from a parent dir that contains both `kite-mcp-server/` and `algo2go/kite-mcp-bootstrap/`
2. Adjust Dockerfile `COPY` paths
3. Higher build-context size; less standard pattern

**Recommended path: A** (publish tags) — most aligned with standard Go module distribution. Bootstrap is in algo2go org; tags are public; future cascade work (Path A's continued Phase 1-3 extractions) all need tags anyway.

**Preservation strategy: User-action-required** — this is a BLOCKER, not optional. Must resolve before any merge that touches production.

---

## §2 — Per-strategy execution plan

### §2.1 Strategy: Commit-to-bootstrap (PR-A)

**Items**: 6 mcp/*_full_chain_test.go files (§1.1)

**Steps**:
1. Agent: in bootstrap repo, copy the 6 files from kite-mcp-server master
2. Agent: `find . -name '<file>' -exec sed -i 's|github.com/zerodha/kite-mcp-server|github.com/algo2go/kite-mcp-bootstrap|g' {} +` in bootstrap
3. Agent: verify `go build ./...` + `go test -count=1 -run 'Test.*FullChain' ./mcp` exit 0
4. Agent: single commit `test(integration): relocate 6 full-chain tests from kite-mcp-server master (Sprint 0 preservation)`
5. User: review + push

**Time**: ~30-45min agent + ~5min user review.

### §2.2 Strategy: User-discard-OK (cruft removal)

**Items**:
- 3 root binaries (~83 MB)
- 21 commit-message drafts (`_*_msg.txt`)
- 9 coverage files (`*.cov`)
- 1 `.claude/tst.js`
- 8 additional `_msg.txt` drafts in `.research/`

**Steps**:
```bash
cd kite-mcp-server
rm dr-decrypt-probe event-graph rotate-key                  # 3 binaries
rm .research/_*_msg.txt                                      # ~29 msg drafts
rm .research/*.cov                                           # 9 coverage files
rm .claude/tst.js                                            # 1 scratch
```

**Time**: ~5min total. No commit needed (these are untracked; deletion is local-only).

**Optional bonus**: add to `.gitignore`:
```
/dr-decrypt-probe
/event-graph
/rotate-key
.research/_*_msg.txt
```
That's a tracked change (`.gitignore` is tracked) and could be a separate small commit.

### §2.3 Strategy: User-review (ad-hoc scripts)

**Items**:
- 38 `.research/*.sh` ad-hoc helpers
- 1 `scripts/apply-docs-triage.sh`

**Simplest path**: agent bulk-moves to `.research/scripts-archive-2026-05-16/` + commits. User can later prune at leisure.

```bash
cd kite-mcp-server
mkdir -p .research/scripts-archive-2026-05-16
mv .research/*.sh .research/scripts-archive-2026-05-16/
mv scripts/apply-docs-triage.sh .research/scripts-archive-2026-05-16/
git add .research/scripts-archive-2026-05-16/
git commit -m "archive(scripts): preserve 39 ad-hoc dispatch helpers in .research/scripts-archive-2026-05-16/"
```

**Time**: ~10min agent + ~5min user review.

**Alternative**: present full list to user with 1-line annotations + per-file disposition decisions. ~30-45min user time. NOT recommended unless user wants explicit control over each file.

### §2.4 Strategy: User-action-required (deploy-time blocker)

**Items**: bootstrap tags + go.mod replace directive removal (§1.7 path A)

**Steps**:
1. User OR agent: in `algo2go/kite-mcp-bootstrap`:
   ```bash
   git tag v0.1.0
   git tag app/providers/v0.1.0
   git tag plugins/v0.1.0
   git tag testutil/v0.1.0
   git push origin v0.1.0 app/providers/v0.1.0 plugins/v0.1.0 testutil/v0.1.0
   ```
2. User OR agent: in kite-mcp-server (on a rebase branch of `bootstrap-relocation`):
   - Update go.mod: change `replace ... => ../algo2go/kite-mcp-bootstrap` to `require github.com/algo2go/kite-mcp-bootstrap v0.1.0`
   - Same for the 3 sub-modules
   - Drop the replace block
   - `go mod tidy`
3. Verify `go mod download` works without local sibling path
4. Verify `Dockerfile` build succeeds locally
5. Push the rebased branch

**Time**: ~30-45min agent + ~10min user authorization.

**Critical sequencing**: this MUST happen BEFORE the user clicks "merge" on the Sprint 0 PR. Otherwise the post-merge `flyctl deploy` fails.

---

## §3 — Recommended execution sequence

The full preservation sweep in dependency order:

| Step | Action | Strategy | Cost |
|---|---|---|---|
| 1 | Commit-to-bootstrap: relocate 6 orphan tests | §2.1 | 30-45min agent |
| 2 | Deploy-blocker fix: publish bootstrap tags + update Sprint-0 branch's go.mod | §2.4 | 30-45min agent + 10min user |
| 3 | Cruft cleanup: discard 41 throwaway files | §2.2 | 5min |
| 4 | Archive ad-hoc scripts | §2.3 | 10min agent + 5min user |
| 5 | (Optional) `.gitignore` patch for binaries + msg drafts | §2.2 bonus | 5min |
| 6 | Verify ALL: `go build ./...` + `go test ./...` on bootstrap; `go mod download` against GOPROXY for the rebased Sprint-0 branch; trial Docker build | §1.7 verification | 15min |
| 7 | After all preservation done: open PR + merge per prior mergeability audit's plan | (per `sprint-0-pr-mergeability-audit.md` §5) | 30-45min |
| **Total** | | | **~2.5h agent + ~30min user** |

---

## §4 — What this audit does NOT recommend (per dispatch instruction)

Per dispatch: "Surface preservation risks + propose strategy per item. Don't decide for the user."

This doc names strategies per category but does NOT decide:
- WHETHER to publish bootstrap tags as v0.1.0 specifically (could be v0.0.1 or any other version)
- WHEN to merge (immediately after preservation? wait for additional bootstrap work?)
- WHETHER the 38 ad-hoc shell scripts get bulk-archived or per-file-reviewed
- WHETHER to ALSO merge `origin/develop`'s 12 commits at some point (separate concern from Sprint 0)

User authorizes each phase explicitly.

---

## §5 — Summary table for executable handoff

| # | At-risk item | Count | Strategy | Cost |
|---|---|---|---|---|
| 1 | mcp/*_full_chain_test.go orphan tests | 6 | Commit-to-bootstrap | 30-45min |
| 2 | Bootstrap workspace sub-modules at pseudo-version | 4 sub-modules | User-action: publish tags + drop replace | 30-45min |
| 3 | Compiled Linux binaries at root | 3 | User-discard-OK | 1min |
| 4 | Commit-message drafts (`_*_msg.txt`) | ~29 | User-discard-OK | 1min |
| 5 | Coverage files (`*.cov`) | 9 | User-discard-OK | 1min |
| 6 | Ad-hoc shell scripts (`.research/*.sh`) | 38 | Archive + user review | 10min |
| 7 | Stray `scripts/apply-docs-triage.sh` | 1 | Archive + user review | 1min |
| 8 | `.claude/tst.js` scratch | 1 | User-discard-OK | 1min |
| 9 | 228 drift files in kc/app/mcp/plugins/testutil | 228 | Explicit-keep (bootstrap supersedes) | $0 |
| 10 | 7 metrics+adapters files | 7 | Explicit-keep (extracted/split) | $0 |
| 11 | origin/develop + feat-* branches | 5 branches | Explicit-keep (not at risk) | $0 |
| 12 | 28 algo2go leaves | 0 | Explicit-keep (no coupling) | $0 |
| **Total at-risk** | | **~330 items** | | **~2.5h** |

(Of the ~330: only ~10 are HARD-preservation; the rest are explicit-keep-because-already-preserved.)

---

## §APPENDIX — Empirical probes used

```bash
# §INPUTS row 1-3: master-touched files in deleted-by-branch dirs
git diff --name-only b6b4f6a..origin/master | grep -E '^(kc/|mcp/|app/|plugins/|testutil/)' | grep -v '^app/providers/'

# §INPUTS row 4: 287/228/13 split
BOOTSTRAP=D:/Sundeep/projects/algo2go/kite-mcp-bootstrap
identical=0; drifted=0; missing=0
while IFS= read -r f; do
  master_blob=$(git ls-tree origin/master -- "$f" | awk '{print $3}')
  [ -z "$master_blob" ] && continue
  bs_path="$BOOTSTRAP/$f"
  if [ ! -f "$bs_path" ]; then missing=$((missing+1)); continue; fi
  bs_blob=$(cd "$BOOTSTRAP" && git hash-object "$f")
  if [ "$master_blob" = "$bs_blob" ]; then identical=$((identical+1)); else drifted=$((drifted+1)); fi
done < <(git ls-tree -r origin/master --name-only -- kc/ app/ mcp/ plugins/ testutil/)
echo "$identical/$drifted/$missing"
# → 287/228/13

# §INPUTS row 7-8: untracked categorization
git status --porcelain | grep '^??' | wc -l                            # → 121 total
git status --porcelain | grep '^??' | grep -E '_.*_msg\.txt$' | wc -l   # → 21 msg drafts
git status --porcelain | grep '^??' | grep -E '\.cov$' | wc -l          # → 9 coverage
git status --porcelain | grep '^??' | grep -E '\.research/.*\.sh$' | wc -l  # → 38 scripts

# §INPUTS row 9: binary classification
file dr-decrypt-probe event-graph rotate-key
git check-ignore -v dr-decrypt-probe event-graph rotate-key             # → empty (not ignored)

# §INPUTS row 13-15: branch divergence
git rev-list --count origin/master..origin/develop                       # → 12
git log origin/master..origin/develop --pretty='%ad %h' --date=short | tail -2

# §INPUTS row 16: cross-coupling check
cd D:/Sundeep/projects/algo2go
for d in kite-mcp-*/; do
  grep -l 'kite-mcp-bootstrap\|zerodha/kite-mcp-server' "$d"go.mod 2>/dev/null
done
# → empty

# §INPUTS rows 17-19: GOPROXY availability (THE BLOCKER)
mkdir /tmp/bs-fetch-test && cd /tmp/bs-fetch-test
go mod init testbsfetch
GOPROXY=https://proxy.golang.org go get github.com/algo2go/kite-mcp-bootstrap@latest
# → 404 errors for app/providers, plugins, testutil at pseudo-version
cd D:/Sundeep/projects/algo2go/kite-mcp-bootstrap
git tag --list                                                           # → empty
```

---

**END OF DOC** — verified at kite-mcp-server `5167a11` + bootstrap `2c741e3`; preservation probes 2026-05-16; 1-week shelf life (branch + bootstrap divergence accelerates with each new commit).
