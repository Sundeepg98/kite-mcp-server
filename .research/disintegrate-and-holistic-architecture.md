# Disintegrate-AND-Holistic Architecture — pattern, tooling, sequence

**Date**: 2026-05-02
**HEAD audited**: `99b9bdf`
**Charter**: research deliverable — NO ship of code; doc only.
**User framing** (verbatim): *"If algo2go is to combine multiple
products, we need to BE in a position to disintegrate first. Right
now we can't."*

The brief asks for a pattern that simultaneously enables:

1. **Disintegration** — components ship as separate repos / products /
   language stacks;
2. **Holistic development** — agents and humans cross-cut without
   coordination tax.

These are usually treated as a tradeoff. The recommendation below
shows why the user's instinct is right (the current monolithic
`go.mod` IS a meaningful blocker) AND that the fix is much cheaper
than the framing suggests (Bazel-grade tooling is overkill at this
scale).

**Anchor docs (cross-checked, not duplicated)**:
- `.research/multi-product-and-repo-structure.md` (`39577c3`,
  commit Q4+Q5 audit) — verdict "one product + two extractable
  libraries". This doc takes that as input and asks: *what pattern
  enables that extractability without paying for it now?*
- `.research/fork-loc-split-and-tier3-promotion.md` (`d0e999d`) —
  per-component spin-out cost (~2-3 dev-weeks each); 31% promotion
  probability over 24 months.
- `.research/parallel-stack-shift-roadmap.md` (`8361409`) §1 —
  Foundation phase that any cross-language track shares.
- `.research/ipc-contract-spec.md` (`4fa5a39`) — chose JSON-RPC 2.0
  over stdio as the cross-runtime IPC contract; this doc inherits
  that choice.
- `.research/component-language-swap-plan.md` (`a03694a`) — 24-month
  per-component shortlist (widgets→TS, riskguard→Rust, analytics→
  Python).
- `feedback_decoupling_denominator.md` — three-axis ROI framework
  (user-MRR / agent-concurrency / tech-stack-portability). This
  doc evaluates against Axis B (agent-concurrency) and Axis C
  (portability), not Axis A (user-MRR).

---

## Bottom line — three sentences

1. **Adopt Go workspaces (`go.work`) NOW** — set up two modules
   inside the existing repo (`kc/riskguard/` and `kc/audit/` get
   their own `go.mod`; everything else stays in the root module).
   Migration cost: ~3-5 dev-days. No new repos. No CI rework. No
   external visibility change.
2. **Defer Bazel and polyrepo entirely.** At ~64,705 prod LOC, a
   single Go module compiles in under 30 seconds; Bazel's onboarding
   cost (4-8 dev-weeks + ongoing toolchain overhead) and polyrepo's
   cross-repo coordination tax (3-5× calendar per cross-cutting
   change per `multi-product-and-repo-structure.md` §5.2 5C) buy
   nothing the workspace pattern doesn't already deliver.
3. **Trigger-driven escalation.** Workspaces are a *strict superset*
   of the current state — they enable every disintegration path
   (separate repo, language port, sellable library) without
   committing to any of them. Promote a `kc/<x>/` workspace member
   to a separate repo only when one of five concrete external
   triggers fires (per `multi-product-and-repo-structure.md` §5.5).

The single sentence that resolves the user's framing:

> The blocker isn't the monorepo. It's the absence of *module
> boundaries* inside the monorepo. Add `go.work` + per-component
> `go.mod` files, and you ARE in a position to disintegrate — even
> though the disintegration hasn't happened yet.

---

## Phase 1 — Empirical baseline

### 1.1 Top-level LOC + dep map

LOC measured via `find . -name "*.go" -not -name "*_test.go" |
xargs wc -l` at HEAD `99b9bdf`. (No `cloc` available locally;
matches `multi-product-and-repo-structure.md` §3 within ~1%.)

| Component | Prod LOC | Test LOC | Files | Internal `kc/*` deps | External deps |
|---|---:|---:|---:|---|---:|
| `app/` | 9,583 | 21,612 | 37 | 14+ | many |
| `mcp/` | 23,368 | 38,706 | ~80 | 14+ | many |
| `oauth/` | 2,736 | 13,087 | 11 | `kc/users` | 4 |
| `broker/` | 3,315 | 6,610 | 11 | `kc/money`, `kc/domain` | 2 |
| `cmd/` | 310 | 974 | 2 | `kc/alerts` | 1 |
| `plugins/` | 321 | 495 | 3 | `kc/users` | 2 |
| `kc/` (root files) | ~9,103 | (mixed) | 44 | many | many |

### 1.2 Per `kc/<context>` audit

Empirical numbers; reverse-dep counts EXCLUDE worktrees and tests.
Internal deps are non-test imports only. External deps count
unique third-party imports (stdlib excluded).

| Context | Prod LOC | Test LOC | Internal deps (non-test) | Reverse deps (callers) | External deps | Extract score (0-3) |
|---|---:|---:|---|---:|---:|---:|
| `kc/money` | 238 | 539 | (none) | 4 (broker, broker/mock, broker/zerodha, kc/domain) | 0 | **3** |
| `kc/decorators` | 127 | 261 | (none) | 1 (`mcp`) | 0 | **3** |
| `kc/aop` | 1,179 | 1,212 | (none) | 0 | 0 | **3** (but unused) |
| `kc/isttz` | 21 | 27 | (none) | indirect | 0 | **3** |
| `kc/logger` | 273 | 262 | (none) | many | 0 | **3** |
| `kc/ports` | 231 | 0 | (none) | (interface-only) | 0 | **3** |
| `kc/scheduler` | 440 | 889 | `kc/isttz` | 3 (app, app/providers, mcp) | 0 | **3** |
| `kc/instruments` | 801 | 1,953 | `kc/isttz` | 14 | 1 | **3** |
| `kc/watchlist` | 493 | 970 | (none) | 7 | 0 | **3** |
| `kc/users` | 1,214 | 2,733 | `kc/alerts` | 20 | 1 | 2 |
| `kc/registry` | 389 | 1,130 | `kc/alerts` | 8 | 0 | 2 |
| `kc/ticker` | 470 | 2,234 | (none) | 10 | 1 | **3** |
| `kc/domain` | 3,378 | 4,229 | `broker`, `kc/isttz`, `kc/money` | **78** | 2 (testify only) | 2 |
| `kc/cqrs` | 1,480 | 771 | `kc/domain`, `kc/logger` | **100** | 1 | 2 |
| `kc/eventsourcing` | 2,137 | 3,127 | `broker`, `kc/alerts`, `kc/domain` | 17 | 3 | 2 |
| `kc/usecases` | 7,688 | 10,819 | `broker`, `broker/mock`, `kc/alerts`, `kc/audit`, `kc/cqrs`, `kc/domain`, `kc/eventsourcing`, `kc/logger`, `kc/money`, `kc/riskguard`, `kc/ticker`, `kc/users`, `kc/watchlist` | 32 | many | 1 |
| `kc/riskguard` | 3,550 | 6,498 | `kc/alerts`, `kc/domain`, `kc/logger`, `oauth` | 24 | 6 (incl. mcp-go, hashicorp/go-plugin) | 2 |
| `kc/audit` | 3,967 | 6,421 | `kc/alerts`, `kc/domain`, `kc/logger`, `oauth` | 34 | 6 (incl. mcp-go) | 2 |
| `kc/billing` | 1,221 | 4,553 | `kc/alerts`, `kc/domain`, `kc/logger`, `oauth` | 12 | 9 (Stripe SDK) | 2 |
| `kc/alerts` | 3,836 | 11,365 | `broker/zerodha`, `kc/domain`, `kc/isttz`, `kc/logger` | **53** | 9 | 2 |
| `kc/papertrading` | 1,981 | 8,255 | `broker`, `broker/mock`, `kc/alerts`, `kc/domain`, `kc/logger`, `kc/riskguard`, `oauth` | 5 | 5 | 1 |
| `kc/telegram` | 1,860 | 6,135 | `broker`, `broker/zerodha`, `kc/alerts`, `kc/domain`, `kc/instruments`, `kc/papertrading`, `kc/riskguard`, `kc/ticker`, `kc/watchlist` | 3 | 4 | 1 |
| `kc/ops` | 7,026 | 19,583 | `app/metrics`, `broker/zerodha`, `kc`, `kc/alerts`, `kc/audit`, `kc/billing`, `kc/cqrs`, `kc/domain`, `kc/instruments`, `kc/logger`, `kc/papertrading`, `kc/registry`, `kc/riskguard`, `kc/templates`, `kc/ticker`, `kc/users`, `oauth` | 3 | many | **0** (most tangled) |

**Extract score legend**:
- **3** — extractable today as standalone Go module, zero rework.
- **2** — extractable after 1-3 dev-week rework (interface
  abstraction; remove 1-2 intra-`kc/` deps).
- **1** — needs heavy rework (3+ internal deps; broker SDK leaks).
- **0** — inseparable from the host; would need redesign.

### 1.3 Empirical findings

1. **`kc/money`, `kc/decorators`, `kc/isttz`, `kc/logger`,
   `kc/ports` are zero-internal-dep leaves**. They could be
   `go.mod`-promoted today with no code changes. They're not the
   candidates for marketing, but they prove the workspace pattern
   is mechanically zero-friction for a non-trivial subset.
2. **`kc/audit` and `kc/riskguard` are the spin-out candidates per
   `multi-product-and-repo-structure.md` §4** — both have only
   3-4 internal deps (`kc/alerts`, `kc/domain`, `kc/logger`,
   `oauth`) and clean API surfaces. **Counter-finding to flag:**
   both also import `mark3labs/mcp-go` directly (audit's
   `middleware.go` exposes a `ToolHandlerMiddleware`; riskguard's
   guard tests use `gomcp.CallToolRequest`). For a **library**
   spin-out (e.g., `riskguard-go`) the mcp-go coupling needs to
   move to a separate `kc/riskguard/mcpadapter/` package — modest
   refactor, ~2-3 dev-days, NOT a blocker for the workspace move.
3. **`kc/usecases` and `kc/ops` are inseparable** as currently
   structured. ops imports 16 internal `kc/*` packages; usecases
   13. These are aggregator packages by design (the use-case layer
   IS the orchestrator); they belong in the root module forever.
4. **`kc/domain` and `kc/cqrs` are the gravity wells** (78 and 100
   reverse-dep callers respectively). Promoting them to their own
   `go.mod` is high-leverage (every other workspace member
   benefits) but requires careful interface design — they're the
   closest thing to a "platform module" the codebase has.
5. **`kc/aop` has zero callers** — dead code per the empirical
   audit. Either delete or document as reserved-for-future-use.
6. **The fork-LOC split (`fork-loc-split-and-tier3-promotion.md`)
   shows 97% of the codebase is original work** since the
   August-2025 fork. The "kc/* tangle" is entirely our doing,
   which means the fix is also entirely our authority.

### 1.4 Honest limitation

These numbers are import-graph approximate. A genuine "compile
this package standalone" test would require actually creating a
`go.mod` and running `go build`. That's a Phase-1 outcome of the
workspace migration itself — the audit above is a strong-but-not-
definitive predictor.

---

## Phase 2 — Tooling / architecture survey

For each pattern: what it does, fit-for-our-case, migration cost,
ongoing cost, what it enables, what it costs developers /
agents.

### A. Go workspaces (`go.work`) — **RECOMMENDED**

**What it is**: Multi-module monorepo. Go 1.18+. A `go.work` file
at repo root names N `go.mod` modules; `go build` / `go test`
treat them as a unified build graph but each module has its own
dependencies, version, and downstream consumers.

**Mechanism**: Each chosen `kc/<context>/` gets a `go.mod` (e.g.,
`module github.com/zerodha/kite-mcp-server/kc/riskguard`); the
root `go.work` lists all members; consumers in the root module
import via the same import path (no change to import paths). When
external consumers want only one module, they `go get` it as if
it were any other Go library.

**Fit for our case**:
- ✅ Zero import-path changes for existing code. The same import
  `"github.com/zerodha/kite-mcp-server/kc/riskguard"` works
  whether riskguard is a workspace member or a separate repo.
  This is the killer feature.
- ✅ Per-module `go.mod` enables independent versioning and
  external `go get`. A third party can `go get
  github.com/zerodha/kite-mcp-server/kc/riskguard@v1.0.0` even
  while it lives in our monorepo.
- ✅ `gopls` since Go 1.20 handles workspaces natively; agents
  using LSP get the same cross-package navigation they get
  today.
- ✅ `golangci-lint` v1.56+ runs across workspace members.
- ⚠️ `goreleaser` requires per-module config — adds ceremony but
  not blocking.
- ⚠️ Per-module release tags (`kc/riskguard/v1.0.0` instead of
  `v3.5.0`) are non-trivial for downstream consumers to parse.
  Mitigation: documented release matrix in CHANGELOG.

**Migration cost**: **3-5 dev-days for the initial setup** (one
workspace member as a proof of concept), then **~1 dev-day per
additional member**. The initial setup involves:
- Create `go.work` at root.
- Pick 1-2 zero-dep leaves (e.g., `kc/money`, `kc/decorators`)
  as the first members — proves the mechanism, low risk.
- Verify CI green: `go test ./...` from root still works; `go
  test ./...` from inside `kc/money/` works in isolation.
- Update `.github/workflows/ci.yml` to also run per-module
  builds (small change).

**Ongoing cost**: per-module `go.mod` updates split Dependabot's
work. Modest CI growth (~10% wall clock if all members run in
parallel). No semver coordination needed because the root module
imports members via local `replace` directive in `go.work`.

**What it enables**:
- Disintegration: any workspace member can be promoted to its
  own repo with ZERO import-path churn — just publish the
  module at its existing import path and remove from `go.work`.
- Holistic dev: cross-module refactors stay atomic in one PR
  (workspace coordinates the build); agents can edit anywhere.
- Per-language port (per `parallel-stack-shift-roadmap.md`): a
  Rust riskguard would replace the Go module via the IPC
  contract; the workspace member becomes a thin "go-side proxy
  for the Rust subprocess". Module boundary makes the swap
  surgical.
- External library stars: each workspace member has its own
  `pkg.go.dev` page (since 2023). `riskguard-go` accumulates
  stars even before it's a separate repo.

**What it costs developers / agents**:
- Slightly more ceremony when adding a new dep (which `go.mod`
  does it land in?). For agent work, this maps cleanly to
  package boundary already implicit in current code.
- Workspace-aware tools have caught up since 2022; remaining
  edge cases (e.g., `goreleaser`) are documented workarounds.

**Verdict**: ✅ **First-move pattern.** Strict superset of the
current state; no functionality lost; everything that works
today still works.

### B. Bazel + `rules_go` — overkill at this scale

**What it is**: Polyglot build graph. Sandboxed, hermetic,
content-addressable. Each package declares a `BUILD.bazel`; the
build graph spans Go + TS + Python + Rust + protobuf + everything.

**Mechanism**: replace `go build` with `bazel build //...`. Bazel
handles cross-language deps, codegen, remote caching, and remote
execution. `rules_go` gives the Go-specific rules; `gazelle`
auto-generates `BUILD.bazel` from existing Go imports.

**Fit for our case**:
- ✅ True polyglot. If TS/Python/Rust tracks all activate per
  `parallel-stack-shift-roadmap.md`, Bazel's value goes up.
- ✅ Remote caching can shave CI time from minutes to seconds
  for unchanged subgraphs — relevant if 60+ tests grow to
  600+ tests.
- ❌ Onboarding cost: 4-8 dev-weeks for a Go-only team to
  internalize Bazel mental model + per-package `BUILD.bazel`
  maintenance discipline.
- ❌ Per-PR friction: any new file requires `gazelle update`
  which agents must remember. Failure mode: agent edits
  Go file, forgets `BUILD.bazel`, CI fails on Bazel build.
  This is solvable but adds context-window tax.
- ❌ Tooling integration: `gopls`, `goreleaser`, `golangci-lint`,
  `govulncheck` all need Bazel-aware shims (`gopls` has
  `bazel-gopls` plugin; `golangci-lint` works inside `bazel
  test`; `goreleaser` doesn't natively integrate).
- ❌ Debugging: when Bazel decides a target needs rebuilding,
  the reason is opaque without `bazel query` literacy.

**Migration cost**: **4-8 dev-weeks** (Gazelle + initial
`BUILD.bazel` generation + CI plumbing + dev-environment
documentation + first-pass remote cache setup).

**Ongoing cost**: ~10-15% per-PR ceremony (Gazelle re-runs);
~$50-200/month for remote cache hosting (Buildbarn or BuildBuddy)
unless self-hosted; bus-factor risk if only 1-2 devs know
Bazel-fu.

**What it enables**:
- Hermetic builds (provable reproducibility).
- Cross-language graph — when ALL of TS+Python+Rust tracks
  activate.
- Sub-second incremental rebuilds on remote-cache hits.

**What it costs**:
- Agent context-window tax. Every Bazel-aware tool call
  requires 2-3× more context than the equivalent `go build`.
- Bazel error messages are notoriously verbose and
  agent-unfriendly.
- Steep learning curve for human contributors landing on the
  repo for the first time.

**Verdict**: ❌ **Reject for now.** Justified IF AND ONLY IF
3+ language tracks activate AND CI time becomes a constraint
(neither true today). Workspace pattern (A) handles the disint-
egration question without paying Bazel's tax. Revisit when (a)
two language tracks have activated, OR (b) CI wall time exceeds
10 minutes consistently, OR (c) team grows to 4+ FTE.

### C. Pants build — niche, similar tradeoffs to Bazel

**What it is**: Python-first polyglot build (recently added
Go support in `goals/go`). Lighter setup than Bazel; explicitly
tries to be more accessible.

**Fit**: ❌ **Reject.** Strictly worse than Bazel for our case —
Bazel has the Go ecosystem (rules_go is mature; Pants's Go
support is younger), and the migration cost is similar. Pants
shines for Python-monorepo teams; we're a Go-first team adding
optional language tracks. No advantage over Bazel; downsides
include weaker Go ecosystem.

**Verdict**: ❌ **Reject.** Bazel beats Pants in every relevant
axis for our codebase composition.

### D. Polyrepo + git submodules — high cost, low gain

**What it is**: Each component as a separate repo; consumers
include via git submodule (or just `go get` for Go).

**Mechanism**: `kc/riskguard/` becomes
`github.com/Sundeepg98/riskguard-go`; the parent `kite-mcp-server`
repo `go get`s it. (Submodules are mostly relevant for non-Go
artifacts; for Go this is just the standard polyrepo pattern.)

**Fit**: ⚠️ **Defer.** Per `multi-product-and-repo-structure.md`
§5.2 5C, polyrepo migration is **6-12 dev-weeks** total (2-3 per
spin-out × 3-4 candidates) and adds a 3-5× calendar tax to every
cross-component refactor. The empirical 31% probability of
Tier-3 promotion in 24 months (per
`fork-loc-split-and-tier3-promotion.md`) is below the proactive-
spin-out threshold.

**Migration cost**: **2-3 dev-weeks per spin-out**.
**Ongoing cost**: per-repo CI, SBOM, audit, release cadence;
cross-repo PR coordination.

**What it enables**: full disintegration today — repo-level star
counts, independent issue trackers, repo-level FLOSS-fund pitch.

**What it costs**:
- Cross-repo refactors become flag-day operations (PR-A merges
  in repo-X, then publish vN+1, then PR-B in repo-Y bumps to
  vN+1).
- Agent context fragmentation: agents working on cross-cutting
  features must context-switch between repos (Mode-2 conflict
  per `feedback_decoupling_denominator.md` Axis B).
- Discoverability: a user landing on `riskguard-go` doesn't
  naturally find `kite-mcp-server` unless cross-linked.

**Verdict**: ⚠️ **Trigger-driven.** Move `kc/riskguard/` →
`riskguard-go` when external triggers fire (per §5.5 of the
prior doc): 50+ stars on parent, ≥2 inbound questions about
standalone use, ≥5 forks of subdirectory, Rainmatter/FLOSS
pitch needs separable artifact, second broker integration
appears. Until then, workspace member is sufficient.

### E. Polyrepo + meta-repo (`meta-git`, `gita`, Google `repo`)

**What it is**: Multiple repos plus a coordinating "meta-repo" tool
that batches commands across all of them.

**Fit**: ❌ **Reject for our scale.** The meta-repo pattern shines
at 20+ repos (e.g., Google's `repo` for AOSP); at our 1-3 spin-out
target, Pyrgolib's overhead exceeds savings. The honest workflow
is "manually `cd` between two repos" — not worth a tool.

**Verdict**: ❌ **Reject.** Reconsider only if spin-outs exceed
~5 repos, which the trigger model in §5.5 doesn't predict for
24+ months.

### F. Nx / Turborepo — primarily TS, partial Go

**What it is**: Polyglot monorepo build orchestrator with
intelligent caching and dep-graph awareness. Primary user base
is TypeScript; Go support exists via plugins (`@nx-go/nx-go`)
but is community-maintained.

**Fit**: ⚠️ **Defer to Track A.** If/when TypeScript track
activates per `parallel-stack-shift-roadmap.md`, Nx becomes the
natural orchestrator for the TS subdirectories. For pure Go, it
adds tax with no benefit. The natural sequence: workspace pattern
(A) for Go today; layer Nx on TOP of Go workspaces if/when TS
arrives.

**Migration cost (when TS arrives)**: ~1-2 dev-weeks for the
Nx workspace setup + adapting CI.
**Ongoing cost**: Nx daemon + cloud cache (~$0-50/month for
small teams).

**What it enables**: TypeScript-first incremental builds,
affected-only CI runs, dep-graph-aware test selection.

**Verdict**: ⚠️ **Hold for Track A.** Workspace pattern (A) is
neutral — Nx can ride on top later if TS lands.

### G. Monorepo with strict package boundaries enforced by linter

**What it is**: Single Go module + custom architecture lint
(e.g., `go-arch-test`, `archtest`, `import-rules.md` self-
authored linter) that fails CI when forbidden import edges
appear.

**Mechanism**: declare in a config file "kc/audit/ may not
import broker/zerodha"; lint enforces; agents and humans see
fast feedback in PR review.

**Fit**: ✅ **Complementary to (A).** This is what we have today
(implicitly — there's no enforcement, just discipline). Adding
explicit lint rules costs ~2-3 dev-days; the rules then encode
the dep map measured in Phase 1.

**Migration cost**: **2-3 dev-days.**
**Ongoing cost**: rules need maintenance as dep map evolves.

**What it enables**: prevents drift; agents who try to introduce
forbidden cross-context imports get fast CI failure instead of
silent erosion of boundaries.

**Verdict**: ✅ **Companion to workspace pattern (A).** Adopt
both: workspaces give the structural fact; arch-lint gives the
enforcement. Workspaces alone allow accidental tangle-creation
within a module; arch-lint alone allows boundaries to exist
without external visibility.

---

## Phase 3 — Recommended migration sequence

### Move 1 (immediate, ~5-7 dev-days total)

**Set up `go.work` with two zero-dep workspace members.**

1. **Day 1-2**: Add `go.work` at repo root. Pick `kc/money/`
   and `kc/decorators/` as first members (zero internal deps;
   risk-free).
   - Create `kc/money/go.mod` with `module
     github.com/zerodha/kite-mcp-server/kc/money` and minimal
     `go 1.25`.
   - Create `kc/decorators/go.mod` likewise.
   - `go.work` contains:
     ```
     go 1.25
     use (
       .
       ./kc/money
       ./kc/decorators
     )
     ```
2. **Day 3**: Verify `go build ./...` from root works; `go test
   ./...` inside each module works in isolation. Verify `gopls`
   (or `gopls-lsp` plugin) navigates correctly.
3. **Day 4**: Update CI: matrix-build per workspace member +
   the root module. Adjust `.github/workflows/ci.yml` to add
   `working-directory:` per matrix entry.
4. **Day 5**: Document the workspace pattern in `docs/`. Add
   `CONTRIBUTING.md` section explaining "when a new package
   should be its own workspace member" (criterion: zero
   internal deps OR external library candidate).

**Outcome**: working `go.work` with 2 members. The mechanism
proven at near-zero cost. No external visibility change.

### Move 2 (week 2, ~5-7 dev-days)

**Promote `kc/riskguard/` and `kc/audit/` to workspace members.**

These are the spin-out candidates per
`multi-product-and-repo-structure.md` §4.

1. **Day 1-2**: Refactor `kc/riskguard/middleware.go` to move
   the `mcp-go` adapter to `kc/riskguard/mcpadapter/`
   subdirectory (keeps the core `kc/riskguard/` library
   `mcp-go`-free).
2. **Day 3**: Refactor `kc/audit/` similarly — move `mcp-go`
   types out of the library core into `kc/audit/mcpadapter/`.
3. **Day 4-5**: Add `go.mod` for both; update `go.work`.
4. **Day 6-7**: Verify CI green; document.

**Outcome**: 4 workspace members. `kc/riskguard/` and `kc/audit/`
are now genuinely externally consumable as `go get` targets.
External visibility: `pkg.go.dev` indexes them as separate
modules.

### Move 3 (week 3, ~3-5 dev-days)

**Add architecture lint to prevent boundary erosion.**

1. **Day 1**: Pick the linter (`go-arch-test` is the most
   maintained per March 2026 GitHub activity).
2. **Day 2-3**: Encode the dep map from §1.2 as lint rules.
   Run the linter; fix any pre-existing violations (likely
   minor — the empirical map already reflects current
   behavior).
3. **Day 4-5**: Add `arch-lint` step to CI; document.

**Outcome**: future agents and humans get CI failure when they
introduce a forbidden cross-context import. The dep map is now
*enforced*, not aspirational.

### Move 4 (trigger-driven, ~2-3 dev-weeks per event)

**Promote workspace member to separate repo when triggers fire.**

Triggers per `multi-product-and-repo-structure.md` §5.5 (already
the policy):
- 50+ stars on parent repo
- ≥2 inbound questions about standalone use within 30 days
- ≥5 forks of a candidate subdirectory
- Rainmatter / FLOSS-fund pitch requires separable artifact
- Second broker integration appears

Mechanical move (per the prior doc §5.7):
1. Create new repo `Sundeepg98/<x>-go` (or `zerodha/<x>-go`).
2. `git filter-repo` the workspace member's history into the
   new repo.
3. Tag `v0.1.0`.
4. Update `go.work` to remove the member; update root
   `go.mod` to depend on the new repo.
5. Verify CI; release a parent version noting the dep update.

**Cost per spin-out**: ~2-3 dev-weeks. **Recoverable in ~6
months** if the trigger was real (per `fork-loc-split-and-tier3-
promotion.md`).

**Crucial point**: because the workspace member already had its
own `go.mod`, the spin-out is mechanical. No import-path
changes. No code changes. The disintegration is *complete and
trivial* once the structural prerequisite is in place.

### End-state architecture (12-24 months)

| Tier | Pattern | Members |
|---|---|---|
| Core monorepo (root `go.mod`) | `app/`, `mcp/`, `oauth/`, `broker/`, `cmd/`, `kc/usecases/`, `kc/ops/`, `kc/cqrs/`, `kc/eventsourcing/`, `kc/domain/`, `kc/alerts/`, `kc/billing/`, `kc/papertrading/`, `kc/telegram/`, `kc/instruments/`, `kc/users/`, `kc/registry/`, `kc/ticker/`, `kc/watchlist/`, `kc/scheduler/`, `kc/logger/`, `kc/ports/` | 22 packages, ~58k LOC |
| Workspace members (own `go.mod`, in tree) | `kc/money/`, `kc/decorators/`, `kc/isttz/` | leaves promoted for cleanliness; ~400 LOC |
| Workspace members → potentially separate repo | `kc/audit/`, `kc/riskguard/` | spin-out candidates; ~7,500 LOC |
| Separate repos (after triggers fire) | `riskguard-go` (and/or `tool-call-audit-go`) | 0-2 repos |
| TS / Python / Rust ports (per `parallel-stack-shift-roadmap.md`) | Track A widgets-TS, Track B analytics-Python, Track C riskguard-Rust | 0-3 sibling subdirs OR separate repos |

The end-state is **strictly workspace + selective spin-out**, not
polyrepo and not Bazel.

### How this enables the parallel-stack-shift roadmap

`parallel-stack-shift-roadmap.md` describes a Foundation phase
(JSON-RPC 2.0 IPC contract per `ipc-contract-spec.md`) followed
by per-language tracks. The workspace pattern (A) is *the*
prerequisite that makes track activation surgical:

- **Track A (TS widgets)**: replace `kc/templates/` HTML with a
  TypeScript build artifact that compiles to the same HTML.
  Workspace member `kc/templates-ts/` (own `package.json`) sits
  next to the existing Go members. CI builds TS; outputs land
  in a Go-side embedded FS. Zero coordination tax.
- **Track B (Python analytics)**: spawn a Python subprocess via
  the IPC contract; the workspace member `kc/analytics-py/`
  contains the Python code with its own `pyproject.toml`. The
  Go side imports a thin `kc/analytics/proxy/` package.
- **Track C (Rust riskguard)**: replace `kc/riskguard/` workspace
  member's *implementation* with a Rust subprocess; the Go-side
  `kc/riskguard/` becomes a proxy speaking the IPC contract.
  Module boundary stays the same; consumers don't notice.

The point: **module boundaries via `go.work` are the precondition
for language swaps**. Without them, the swap touches the entire
import graph; with them, it's surgical.

---

## Phase 4 — Honest verdict

### Is the current monolithic Go module actually a blocker?

**Yes, at the structural level. No, at the immediate-functionality
level.**

- **Yes**: there is no module boundary inside `kc/`. Every package
  is in the same `go.mod`; every CI run touches every package;
  external consumers cannot `go get` a sub-package as if it were
  its own library; per-package versioning is not possible. The
  user's framing — "we cannot disintegrate" — is **literally
  correct** at the build-graph level.
- **No**: nothing currently *requires* disintegration. The product
  ships, tests pass, agents coordinate. The blocker is latent,
  not active.

### Is the user's concern addressable WITHOUT a heavy migration?

**Yes — Go workspaces (`go.work`) is the answer.**

The concern "we cannot disintegrate" is a *capability* concern
("we lack the option") not a *requirement* concern ("we need to
disintegrate today"). The cheapest way to acquire the capability
is the workspace pattern, which requires:

- ~5-7 dev-days for the initial setup (2 leaf members).
- ~5-7 dev-days for the candidate members (`kc/riskguard/`,
  `kc/audit/`).
- ~3-5 dev-days for arch-lint enforcement.
- **Total: 13-19 dev-days** (~3 weeks single-developer; ~1 week
  with 2-3 agents in parallel).

Compared to the alternatives:
- Polyrepo migration: 6-12 dev-weeks for ~3 spin-outs.
- Bazel migration: 4-8 dev-weeks plus ongoing tax.
- Status quo: 0 work but capability remains absent.

The workspace pattern is **strictly cheaper than polyrepo or
Bazel**, AND **strictly more capable than status quo**. It is
also a **monotonic improvement** — every step preserves all
current capabilities and adds new ones.

### Does it require Bazel-grade tooling?

**No.** Bazel's value materializes when the language graph is
already polyglot AND the build is CI-time-bound. Neither is true
today. If both become true (per `parallel-stack-shift-roadmap.md`
Foundation activation + 3 tracks live), revisit Bazel; until then,
the workspace pattern is sufficient.

### What's the first move?

**Set up `go.work` with `kc/money/` and `kc/decorators/` as
the first two members. Verify CI green. Document. Stop.**

That single move (~5 dev-days) is the highest-leverage architectural
change available to this codebase. Everything downstream — risk-
guard library, audit-trail library, Rust port, TS widgets, FLOSS-
fund pitch with separable artifacts — becomes mechanically
straightforward once the workspace mechanism is proven.

### One residual honest caveat

The repo has hundreds of committed build artifacts at root
(`*.exe`, `*.cov`, `*.out`, `app_*.html`) per the empirical
listing in §1.4 of `kite-launch-blockers-apr18.md` (referenced in
MEMORY.md). Cleaning those is **not** part of the workspace move
but should land as a sibling housekeeping commit before launch.
The workspace pattern doesn't depend on it; the launch readiness
does.

---

## Summary table

| Pattern | Migration cost | Ongoing cost | Disintegration | Holistic dev | Verdict |
|---|---|---|---|---|---|
| Status quo monolith | 0 | low | ❌ no | ✅ atomic | current |
| **Go workspaces (A)** | **3-5 days** | **low** | **✅ via promote** | **✅ atomic** | **✅ ADOPT** |
| Bazel (B) | 4-8 weeks | medium-high | ✅ polyglot | ⚠️ Bazel tax | ❌ defer |
| Pants (C) | 4-8 weeks | medium | ⚠️ partial | ⚠️ Pants tax | ❌ reject |
| Polyrepo + submodules (D) | 6-12 weeks | high | ✅ full | ❌ flag-day | ⚠️ trigger-driven |
| Meta-repo (E) | 1-2 weeks | medium | ✅ partial | ❌ N-repo tax | ❌ reject (scale) |
| Nx / Turborepo (F) | 1-2 weeks (post-TS) | low-medium | ⚠️ TS-first | ✅ ok | ⚠️ defer to Track A |
| Arch-lint (G) | 2-3 days | low | n/a | ✅ enforces | ✅ adopt as companion |

**Recommended stack**: A + G. Migrate when triggers fire to D for
specific spin-outs. Layer F on top if Track A activates. Skip B,
C, E entirely.

---

## Sources

- `.research/multi-product-and-repo-structure.md` (`39577c3`) —
  Q4+Q5 evaluation; this doc inherits the verdict.
- `.research/fork-loc-split-and-tier3-promotion.md` (`d0e999d`) —
  per-component spin-out costs; 31% promotion probability.
- `.research/parallel-stack-shift-roadmap.md` (`8361409`) —
  Foundation phase; per-language track scope.
- `.research/ipc-contract-spec.md` (`4fa5a39`) — JSON-RPC 2.0 IPC
  pattern that workspace boundary makes natural to layer on.
- `.research/component-language-swap-plan.md` (`a03694a`) — 24-
  month per-component shortlist.
- `feedback_decoupling_denominator.md` — three-axis ROI framework.
- `docs/adr/0007-canonical-cross-language-plugin-ipc.md` — existing
  cross-language pattern that workspace promotion enables more
  cleanly.
- Empirical LOC + dep audit at HEAD `99b9bdf` via Git Bash on
  Windows (`find . -name "*.go" | xargs wc -l` + `grep -roE`
  import-graph extraction). Cross-checked against
  `multi-product-and-repo-structure.md` §1.2 LOC numbers within
  ~1%.

---

*Generated 2026-05-02, read-only research deliverable. NO ship of
code. Doc commits to `.research/disintegrate-and-holistic-archi-
tecture.md`; root recommendation: adopt `go.work` (~5-7 dev-days).*
