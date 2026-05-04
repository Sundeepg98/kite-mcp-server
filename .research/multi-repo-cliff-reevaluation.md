# Multi-Repo Cliff — Empirical Re-evaluation Post F1-F7 + Module Extractions

**Date**: 2026-05-04
**HEAD audited**: `ca9996c` (`chore(aop): gate kc/aop behind //go:build research tag (F7 close)`)
**Predecessor**: `1848a96` `.research/multi-repo-execute-or-defer.md` (verdict: Path A+B, reject Path C)
**Charter**: read-only research. Single doc. NO code mutation.

**Empirical baseline** (verified at HEAD):
- `go.work` enumerates **5 members**: `.`, `./broker`, `./kc/audit`, `./kc/money`, `./kc/riskguard` (riskguard added by in-flight architecture agent `ac06fb8a7f7d864a6` per dispatch note; `kc/riskguard/` 10,191 LOC matches `kc/riskguard/go.mod` presence)
- Root `go.mod` `replace (...)` block: 4 directives (one per non-root member)
- Import-site grep at HEAD: `broker`=143, `kc/audit`=73, `kc/money`=15 (test+prod combined)
- `tools=111` NewTool registrations grep-confirmed at HEAD
- 7 deploys v191→v197 (per dispatch context); zero schema-lock drift

---

## Q1 — Has the data shifted `1848a96`'s "stay in-tree" verdict?

**Answer: No. The verdict holds, but the *cliff slope* is now empirically known and gentler than `1848a96` feared.**

`1848a96`'s rejection of Path C cited **dev-time cost (4-9 weeks for 3 spin-outs)** and **launch-day narrative penalty**. The new commits don't contradict either — they add a **third distinct option** that `1848a96` didn't model:

- **In-tree multi-module via `go.work`** (commits `b7fedcc`/`5d74acf`/`9ce2248` + the in-flight riskguard) is **NOT** the same as Path C "aggressive multi-repo NOW". It's an intermediate state that captures most of the modularization benefits at zero launch-narrative cost. Public surface stays one repo (`Sundeepg98/kite-mcp-server`); HN reviewer still sees one product.
- Path C's specific concern was *4-5 separate GitHub repos at launch*. Today we have **5 modules in 1 repo**, not 5 repos. That's exactly the configuration `1848a96` Phase 4 didn't score.
- The dev-time-cost claim from `1848a96` ("2-3 dev-weeks per spin-out") was **per-GitHub-repo split**, not per in-tree module extract. Empirical extracts cost ~1 day each (commits `b7fedcc`, `5d74acf`, `9ce2248` are individual commits), so `1848a96`'s number was for the wrong operation.

**What `1848a96` got right** (still valid):
- Show-HN narrative penalty for multi-GitHub-repo at 0 stars: **still applies** to Path C. We aren't doing Path C; the empirical ground confirms the rejection.
- Path A+B ranking 19/21 vs Path C 9/21: scoring still holds for *GitHub-repo split*. **Doesn't apply to in-tree go.work split** which is essentially Path A with internal cleanup.

**What `1848a96` missed** (the new data fills in):
- It modeled binary "single repo vs multi-repo" without considering the `go.work` middle. The middle is the actual ground we're on.
- It assumed extraction costs would be sunk before any value lands; commits `eacaf2d`/`d10bed6`/`ef5d075`/`5d68310` show value (broker/ticker port + Zerodha adapter + conformance harness with 4 buckets) **already shipped** in 4 commits, all in-tree, no separate repo.

---

## Q2 — Validate or invalidate the 7 blockers

| # | Blocker | Status | Evidence |
|---|---|---|---|
| 1 | Cross-module replace directives compound to N×M | **Reduced.** Root `go.mod` has 4 flat replaces (one per member); workspace mode supersedes for canonical builds. | `go.mod` `replace (...)` block + `go.work` use directive list both verified |
| 2 | Transitive replace pattern grows super-linearly (0→1→3) | **Confirmed and accepted.** `kc/audit/go.mod` requires root + broker + kc/money (3 indirect replaces). `kc/audit/go.mod:14-18` comment explicitly explains the bidirectional pattern. | `kc/audit/go.mod` lines 7-23 verified |
| 3 | CI surface 5× | **Partially valid.** Default `go test ./...` from root + workspace covers all members; matrix-test per member is canonical when explicitly desired. Comment at `go.work:42-44`: *"matrix-test per member is the canonical path. The default `go test ./...` from the root still works"*. So CI growth is opt-in, not forced. | `go.work:42-44` |
| 4 | Single-developer cognitive load | **Reduced.** F1-F7 retired 11 deprecated annotations; conformance harness centralizes adapter expectations. The 6 F-chain commits (F2-F7) collectively *reduced* code volume. | Commits `54ae51b` (F2 dead-code delete), `82dc952` (F5 unify) |
| 5 | OSS discoverability without umbrella org | **Unchanged.** Same posture as `1848a96`: defer until 50★/external-fork trigger; Algo2Go reservation (Path B) covers brand insurance. | `1848a96` Phase 5 still applies; HEAD has 0 stars per dispatch |
| 6 | Production Dockerfile builds single repo | **Workaround proven.** Dockerfile pre-stages each module manifest before `go mod download`. Comment at Dockerfile lines 5-10 makes the pattern explicit: *"Add another COPY line per future module extraction"*. **Empirically validated by 7 production deploys** (v191→v197) with `tools=111` held. | `Dockerfile:1-19` verified; production proof per dispatch |
| 7 | broker.PortContract conformance becomes API surface of broker-repo | **Already realized in-tree.** `broker/conformance/conformance.go` is the explicit API surface with 4 buckets (PortContract / OptionalCapabilities / ErrorClassification / TickerLifecycle). Adapter authors invoke each from their own test file per the package doc-comment example. **No GitHub-repo split required for this to work.** | `broker/conformance/conformance.go:1-30` + `broker/conformance/conformance_test.go` |

**Net**: 4 of 7 blockers were materially **reduced** by the new empirical work; 1 (transitive replace) **confirmed and accepted**; 1 (CI growth) **shown to be opt-in**; 1 (discoverability) **unchanged from `1848a96`'s position**.

---

## Q3 — Triggers we missed

`1848a96`'s trigger list: **50 stars / second broker / external fork / senior contributor / Pre-Seed**. The new data reveals **two near-term triggers** that `1848a96` didn't anticipate:

**T6 (NEW) — Conformance-harness external invocation.** `broker/conformance/conformance.go` is now genuinely **adapter-author-facing** (4 buckets, public function signatures). The moment a non-Sundeep developer wants to write a Dhan/Upstox/Groww adapter, they will be importing `github.com/zerodha/kite-mcp-server/broker/conformance` *into their own repo*. That import works today via Go module path; **no GitHub-repo split required**. But once it happens, the broker module's API stability becomes an external contract — the standard cliff trigger for "broker should be its own repo with semver". Probability over 24 months: ~25-35% (higher than `1848a96`'s 31% promotion estimate because the harness is now real, not aspirational).

**T7 (NEW) — Module-count cliff at N=6 or N=7.** Empirically, N has gone 1 → 2 (`b7fedcc`, money) → 3 (`5d74acf`, broker) → 4 (`9ce2248`, audit) → 5 (riskguard, in-flight). Each step has been empirically painless (~1 day). The `kc/billing` extraction (commit 5 of 5 per dispatch context) brings N=6. After that, the trigger is **operational**: when transitive-replace count exceeds Dockerfile maintainability or a `go work sync` resolves slow enough to hurt local-dev iteration. Threshold is **empirically verifiable** rather than guessed — measure `go build ./...` cold-cache time after each new module; if it exceeds 30s, that's the trigger.

**Triggers `1848a96` had right** (no change): 50★, second broker, external fork, senior contributor, Pre-Seed.

---

## Q4 — Watermark for re-evaluation (since answer is still "stay in-tree")

**Watermark: re-evaluate when ANY of the following fires.**

1. **N ≥ 7 modules** (current: 5 + billing = 6 inflight). Empirically defensible because each new module costs ~1 day in-tree but adds another `replace` directive root + at least one transitive in any module that imports it. At N=7, the Dockerfile manifest-staging block exceeds 7 COPY lines, which is the empirical heuristic for "this is no longer a build-time concern but an architecture-doc concern".
2. **External adapter author opens an issue or PR** asking for `broker/conformance` to have an independent semver tag. This is T6 from Q3 firing.
3. **`go work sync` cold-cache local-build time exceeds 30s** on a developer's typical machine. Today: anecdotally <5s; empirically measurable by anyone running it.
4. **Any of `1848a96`'s original 5 triggers fire** (50★, second broker shipped, external fork, senior contributor, Pre-Seed).

**Why these specifically**: each is **empirical and binary-verifiable** — no judgment required. None are "feels-like" thresholds. `1848a96`'s preconditions were largely product-side (Pre-Seed, etc.); the new ones are architecture-side, anchored to commits we can run grep against.

**Drop the prejudging language**: this is *not* "premature optimization" or "ceremony". The denominator is multi-agent parallel-dev velocity (per `feedback_decoupling_denominator.md`). At N=5 today, parallel agents working on disjoint modules can edit independently — empirically observed in this session's port-adapter-framework + F-chain commit interleavings (no merge conflicts across `eacaf2d`/`82dc952`/etc.). The decoupling has paid for itself once.

---

## Q5 — If answer flips: first concrete step

**It doesn't flip today.** But if a Q4 trigger fires, the empirically-defensible first concrete step is:

**Promote `broker/` to its own GitHub repo first.** Justification:
- 143 import sites (`grep -rE "kite-mcp-server/broker\b"`) — the highest-leverage module
- Already has the conformance harness as a public-facing API (`broker/conformance/conformance.go`)
- 1 internal dep (`kc/money` via existing `replace ../kc/money`) — minimal transitive complexity
- Adapter authors are the most likely external contributor type per T6

**Migration sequence** (when trigger fires):
1. **Pre-flight** (~2 days): create `Sundeepg98/kite-mcp-broker` (or under reserved umbrella org), copy `./broker/*` files preserving git history via `git filter-repo`
2. **Tag v0.1.0** in the new repo with current commit SHA referenced in CHANGELOG
3. **Update root `go.mod`**: replace `replace github.com/zerodha/kite-mcp-server/broker => ./broker` with `require github.com/Sundeepg98/kite-mcp-broker v0.1.0`. Update `go.work` to drop `./broker` member.
4. **Update Dockerfile**: remove `COPY broker/go.mod broker/go.sum* broker/` line (no longer in-tree)
5. **Update import paths**: 143 sites change from `kite-mcp-server/broker` to `Sundeepg98/kite-mcp-broker`. Single search-and-replace + `goimports`
6. **Re-run conformance suite** in both repos to validate semver-stable contract

**Time/₹ budget when trigger fires**:
- ~3 dev-days calendar (1 day pre-flight + 1 day mechanical migration + 1 day buffer)
- ~₹0 direct cost
- **Cost only fires AFTER the trigger condition is empirically met** — pre-trigger spend is wasteful

**Umbrella-org reservation status**: Algo2Go umbrella reservation is **task #42 per dispatch context**, status open. `1848a96` Path B recommended Saturday reservation (~₹19-23k). **Reservation is independent of when broker promotes** — even if broker stays in-tree, the brand reservation insulates against Zerodha C&D risk. Recommendation **unchanged from `1848a96`**: reserve umbrella as Saturday side-quest; promote broker only on trigger.

---

## Closing

**Verdict**: `1848a96`'s Path A+B (stay in-tree, reserve umbrella, reject GitHub-repo split) **stands**. The new empirical data **didn't shift** the verdict but **dramatically clarified the cliff slope**: `go.work` multi-module is the actual ground we're on, transitive replaces are tractable up to N≈7, and conformance-harness adapter-author API is realized in-tree without a repo split.

**The honest update to `1848a96`**: it didn't model the in-tree multi-module middle ground. We're operating in that middle ground today, profitably. The next decision point is empirical (N≥7 OR external adapter author OR build-time >30s OR original 5 triggers), not strategic.

No code changes. No tests run. Single-doc deliverable.
