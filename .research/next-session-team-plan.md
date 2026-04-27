# Next-Session Team-Config Plan

Status: research only. Read this BEFORE the next Claude Code team session
starts. Set up the team config from the roster below at session-start —
do NOT migrate mid-flight (per `user_team_agents_default.md`, the cost
of mid-flight migration exceeds the benefit).

## Preamble

This session shipped 36+ commits via ad-hoc `Agent()` + `SendMessage`
coordination across many parallel scopes (Money VO Slices 1+2, ES order
aggregate pilot, decoupling investments, etc.). The ad-hoc approach
worked because file-scope discipline + path-form `git commit -o --` +
no worktrees + `git pull` (plain merge, never rebase) prevented the
concurrent-edit pathologies catalogued in
`feedback_team_commit_protocol.md`.

The next session should formalize this into a **Claude Code team config**
because:
- 3+ concurrent agents on a shared codebase is the team-default trigger
  per `user_team_agents_default.md`
- Persistent task queue + TeammateIdle hook beats ad-hoc dispatch
- Per-teammate file-scope locks become enforceable rather than advisory
- Empirical evidence from this session: the 36-commit run validated that
  shared-tree + `commit -o` works at 9-agent peak parallelism

**Decision: shared tree + `commit -o`, NO worktrees** — per the user's
explicit "merge issues later dump" directive. Worktrees relocate merge
conflicts but introduce setup overhead and disk cost; with the proven
file-scope discipline, shared tree is the lower-friction path.

## Team roster

Twelve teammates organized into four waves. Each teammate has an
explicit file-scope lock (only they may touch listed paths) so the
shared-tree protocol stays safe.

### Wave A — disjoint-package execution (parallel, ~hours wall time)

#### `money-vo-slice3`
- **Scope**: Slice 3 of the Money VO sweep — `UserTracker.DailyPlacedValue`
  + position/PnL Money conversion
- **File-scope lock**:
  - `kc/riskguard/guard.go` (UserTracker struct, RecordOrder)
  - `kc/riskguard/types.go` (UserStatus.DailyPlacedValue if extracted)
  - `kc/usecases/portfolio_*.go`
  - `mcp/portfolio_*.go`
  - `kc/telegram/briefing_*.go`
  - All matching `*_test.go` siblings
- **Dependency**: none — disjoint from Slices 4-5
- **Estimated LOC**: ~400-700 (per Slice 1 cascade size)

#### `money-vo-slice4`
- **Scope**: Slice 4 — `kc/billing/` tier amounts Money conversion
- **File-scope lock**:
  - `kc/billing/billing.go` (tier price fields, MRR computation)
  - `kc/billing/checkout.go`
  - `kc/billing/store.go` (if SQL persistence touches money)
  - All matching `*_test.go`
  - Admin dashboard tier display files (if any cross over)
- **Dependency**: PRECONDITION — confirm no in-flight billing-related
  work on master before starting. Run `git log --oneline -20 kc/billing/`
  to check.
- **Estimated LOC**: ~300-500

#### `money-vo-slice5`
- **Scope**: Slice 5 — `kc/papertrading/` cash field Money conversion
- **File-scope lock**:
  - `kc/papertrading/portfolio.go` (Cash field)
  - `kc/papertrading/engine.go` (deposit/withdraw/PnL)
  - `kc/papertrading/store.go` (SQL persistence — REAL stays REAL,
    rebuild Money on Scan)
  - `kc/papertrading/monitor.go` (LIMIT-fill background)
  - All matching `*_test.go`
- **Dependency**: none — fully self-contained package, no external clients
- **Estimated LOC**: ~250-400

#### `dual-emit-cleanup`
- **Scope**: `position.converted` event cleanup. Audit any remaining
  legacy "appendAuxEvent + typed event" dual-emit paths and remove the
  legacy half (typed-event subscribers already drive persistence).
- **File-scope lock**:
  - `kc/eventsourcing/order_aggregate.go`
  - `kc/eventsourcing/projection.go`
  - `app/wire.go` ONLY for the persister-subscription wiring (limited;
    coordinate explicitly with main agent if any other change is needed)
  - All matching `*_test.go`
- **Dependency**: none
- **Estimated LOC**: ~50-100

### Wave B — coverage agents (parallel after Wave A or alongside if file-scope-disjoint)

#### `app-coverage`
- **Scope**: HTTP integration tests for `app/` — currently the lowest-
  covered package per the most recent coverage audit
- **File-scope lock**:
  - `app/*_test.go` (read-only on `app/*.go` — no production edits)
  - May touch `testutil/` to add HTTP fixture helpers
- **Dependency**: none
- **Estimated LOC**: ~800-1500 (test code only)

#### `kc-root-coverage`
- **Scope**: Manager boot + lifecycle tests at `kc/` package root
- **File-scope lock**:
  - `kc/manager_*_test.go` and `kc/service_test.go`
  - `kc/manager_reconstitution_test.go`, etc.
  - May touch `testutil/kcfixture/` for boot fixtures
- **Dependency**: none — pure test additions, no production touch
- **Estimated LOC**: ~1000+

#### `eventsourcing-coverage`
- **Scope**: Deserialize fast-paths + outbox goroutine coverage
- **File-scope lock**:
  - `kc/eventsourcing/*_test.go`
  - `kc/eventsourcing/outbox_test.go`
- **Dependency**: prefer to land AFTER `dual-emit-cleanup` so the
  test surface reflects the cleaned event topology
- **Estimated LOC**: ~600-900

### Wave C — Playwright + UX agents (Playwright infra is the gate)

#### `playwright-infra` (gate)
- **Scope**: Playwright + `package.json` + baseline scaffolding. NO
  individual widget/page tests yet — just the framework.
- **File-scope lock**:
  - `package.json` (new)
  - `playwright.config.ts` (new)
  - `e2e/` directory tree (new — base fixtures, helpers)
  - `.gitignore` updates for `node_modules/`, `playwright-report/`,
    `test-results/`
- **Dependency**: none — strict GATE. Must commit first; downstream
  agents block on this.
- **Estimated LOC**: ~200-400 (config + fixtures only)

#### `widget-visual-regression`
- **Scope**: 17 widget snapshot tests
- **File-scope lock**:
  - `e2e/widgets/*.spec.ts`
  - Reference snapshot images under `e2e/__snapshots__/`
- **Dependency**: BLOCKED until `playwright-infra` lands its commit
- **Estimated LOC**: ~600-1000

#### `dashboard-e2e`
- **Scope**: 8 SSR pages e2e flows
- **File-scope lock**:
  - `e2e/dashboard/*.spec.ts`
  - `e2e/auth/*.spec.ts`
- **Dependency**: BLOCKED until `playwright-infra` lands
- **Estimated LOC**: ~800-1200

#### `a11y-audit`
- **Scope**: `@axe-core/playwright` integration + per-page a11y assertions
- **File-scope lock**:
  - `e2e/a11y/*.spec.ts`
  - `package.json` adjustments only for `@axe-core/playwright` dep
    (coordinate with `playwright-infra` if it hasn't shipped the dep)
- **Dependency**: BLOCKED until `playwright-infra` lands
- **Estimated LOC**: ~300-500

#### `mobile-og-misc`
- **Scope**: mobile responsive audit (Playwright viewport tests) + OG
  image asset generation
- **File-scope lock**:
  - `e2e/mobile/*.spec.ts`
  - `kc/templates/og-image.png` (new asset)
  - `kc/templates/landing.html` ONLY for `<meta property="og:image">`
    addition (coordinate with main agent on the single-line edit)
- **Dependency**: BLOCKED until `playwright-infra` lands; otherwise
  independent
- **Estimated LOC**: ~200-400

### Wave D — serial multi-week refactor (single agent, multi-week)

#### `resolver-refactor → wire-fx → logger-sweep` (chain)
- **Scope**: deep architectural refactors that touch wide surfaces.
  Each must complete fully before the next starts.
- **Owner**: a single dedicated long-running agent across multiple
  sessions (NOT a Wave A-C parallel slot)
- **Dependency**: serial. resolver-refactor must commit before wire-fx
  starts; wire-fx must commit before logger-sweep starts.
- **Why serial**: each touches `app/wire.go` and many cross-package
  files. Parallel attempts would produce daily merge conflicts.
- **Estimated wall time**: separate sprint, several weeks each

### Wave E — outside agent scope

Items that need budget/external action and cannot be agent-executed:
- SEBI RA filing (₹1.1-1.8L Y1, see `kite-cost-estimates.md`)
- Pvt Ltd registration (₹55-85k)
- Domain rename to Algo2Go (₹9-22k)
- Fintech lawyer consultation (₹15-35k consult)
- Rainmatter warm intro
- These are tracked in `feedback_cheapest_compliance_action.md` and
  related research docs; they belong in a human-execution checklist,
  not the agent team config.

## Wave decomposition + dependency edges

```
Wave A (parallel):
  money-vo-slice3 ─┐
  money-vo-slice4 ─┼─ all disjoint, all start at session T0
  money-vo-slice5 ─┤
  dual-emit-cleanup ┘

Wave B (parallel, can overlap with A if file-scope-disjoint):
  app-coverage           — pure test additions, T0-safe
  kc-root-coverage       — pure test additions, T0-safe
  eventsourcing-coverage — prefer T1 (after dual-emit-cleanup)

Wave C:
  playwright-infra       — GATE, must land first
    ├─ widget-visual-regression
    ├─ dashboard-e2e
    ├─ a11y-audit
    └─ mobile-og-misc

Wave D (serial, multi-week, single dedicated agent):
  resolver-refactor → wire-fx → logger-sweep

Wave E: human-only, out of agent scope
```

## File-scope-locks summary

The 36-commit empirical evidence from this session: file-scope
discipline + `commit -o` worked with up to 9 concurrent agents. No
contamination commits, no soft-reset incidents. The locks below
encode that discipline into the team config rather than relying on
each brief to repeat it.

| Teammate | Read-only on | Read-write on |
|----------|--------------|---------------|
| money-vo-slice3 | rest | `kc/riskguard/guard.go`, `kc/usecases/portfolio_*.go`, `mcp/portfolio_*.go`, `kc/telegram/briefing_*.go`, matching tests |
| money-vo-slice4 | rest | `kc/billing/**`, billing-touching admin tests |
| money-vo-slice5 | rest | `kc/papertrading/**` |
| dual-emit-cleanup | rest | `kc/eventsourcing/**`, narrow `app/wire.go` persister-wiring lines |
| app-coverage | `app/*.go` | `app/*_test.go`, `testutil/**` |
| kc-root-coverage | `kc/manager*.go`, `kc/service.go` | matching `_test.go`, `testutil/kcfixture/**` |
| eventsourcing-coverage | `kc/eventsourcing/*.go` | `kc/eventsourcing/*_test.go` |
| playwright-infra | rest | `package.json`, `playwright.config.ts`, `e2e/**` (fixtures only) |
| widget-visual-regression | rest | `e2e/widgets/**`, `e2e/__snapshots__/widgets/**` |
| dashboard-e2e | rest | `e2e/dashboard/**`, `e2e/auth/**` |
| a11y-audit | rest | `e2e/a11y/**` |
| mobile-og-misc | rest | `e2e/mobile/**`, `kc/templates/og-image.png`, single-line landing.html OG meta |

## Standing rules every brief in next session must include

These are the lessons of THIS session, encoded as boilerplate:

1. **WSL2 testing** — run `wsl -d Ubuntu -u root bash -c "cd
   /mnt/d/Sundeep/projects/kite-mcp-server && /usr/local/go/bin/go test
   ./... -count=1"` for full-suite verification. Per
   `feedback_wsl_for_go_test.md` and the project CLAUDE.md "Go Testing —
   USE WSL2" section. Windows-side `go test` has 50-70% pass-rate due to
   SAC + tooling friction.

2. **Commit protocol** — `git commit -o -- <paths> -m "..."` only.
   NEVER `git add -A`. NEVER `git pull --rebase`. If push rejects, do a
   plain `git pull` (merge), then push again. Per
   `feedback_team_commit_protocol.md`.

3. **No worktrees** — shared tree only. The session decided this
   explicitly.

4. **TDD** — red→green discipline. Write failing test first, run it,
   confirm RED, then implement, confirm GREEN. Per
   `D:/Sundeep/projects/kite-mcp-server/.claude/CLAUDE.md`.

5. **Domain events ordering** — append new events to the END of
   `kc/domain/events.go` (currently 1387 lines). Inserting in the
   middle creates massive merge surfaces with concurrent agents.

6. **`app/wire.go` is high-collision** — don't touch unless absolutely
   needed. Coordinate with main agent before any edit. The 2026-04
   resolver-refactor / wire-fx work is a multi-week serial sprint
   precisely because this file is a pinch point.

7. **Co-Authored-By trailer** required on every commit:
   ```
   Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
   ```

8. **Brief restates rules** — agents only see the brief, not the chat
   history. Every dispatch must restate "wire don't delete", file-scope
   lock, and the commit protocol verbatim. Per
   `feedback_reinforce_rules_in_briefs.md`.

## Dependency edges + sequencing notes

- **Slice 4 (billing) precondition**: confirm no in-flight billing
  changes before dispatch. Worth one `git log --oneline -10 kc/billing/`
  check at the orchestrator.
- **Playwright infra is a HARD gate** for Wave C agents. They MUST NOT
  start until `playwright-infra` has committed `package.json`. Best
  approach: dispatch `playwright-infra` solo at T0; dispatch the four
  Wave-C dependents only after the gate-commit lands.
- **Wave D is multi-week serial** — `resolver-refactor` blocks
  `wire-fx` blocks `logger-sweep`. None of these run in parallel with
  each other. They CAN run in parallel with Wave B coverage agents
  (different file scopes) but absolutely never with each other.
- **eventsourcing-coverage** prefers to land AFTER `dual-emit-cleanup`
  so its tests reflect the cleaned event topology. Not a hard block —
  it could run on the pre-cleanup topology and then be updated, but
  the saved rework makes T1 dispatch cheaper.

## Honest expectation

| Wave | Wall time | Score impact |
|------|-----------|--------------|
| A | ~few hours with 4 parallel agents | DDD +1 to +1.5 (slices 3-5 complete the Money sweep), ES tidy +0.3 |
| B | ~1 day overlapping with A | Coverage +1 to +2 (raises overall package coverage from ~80% to ~88%) |
| C | ~1-2 days after playwright-infra gate | UX/E2E/A11y +1.5 to +2.5 (currently zero E2E coverage) |
| D | separate multi-week sprint | Architecture +2 to +3 (resolver/wire/logger are the highest-leverage decoupling investments still pending) |
| E | human execution | regulatory + monetization gating, not measured on the score rubric |

**Equal-weighted score projection:**
- After Wave A+B+C: ~92.5-93.5 (from current ~91.5)
- After Wave D: ~95-96
- After Wave E (regulator-gated): scoring rubric maxes out around ~97-98
  given the inherent ceiling on solo-developer pre-revenue posture

## How to instantiate this plan

1. **Settings** — verify `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS: "1"` is
   set in `~/.claude/settings.json` env block.

2. **Team config** — create
   `~/.claude/teams/kite-mcp-money-sweep/config.json` with the 12-roster
   from this doc. Encode file-scope locks per-teammate.

3. **Hooks** — verify TeammateIdle + TaskCompleted hooks are present at
   `~/.claude/hooks/agent-teams/`. Per
   `user_team_agents_default.md`, hookify can't handle these events;
   write directly.

4. **Task files** — populate `~/.claude/tasks/kite-mcp-money-sweep/`
   with one task file per teammate. Include the standing rules
   verbatim in each task file.

5. **Dispatch sequence at T0**:
   - All Wave A agents simultaneously
   - `playwright-infra` simultaneously (it's the gate)
   - `app-coverage`, `kc-root-coverage` simultaneously (Wave B safe-T0
     subset)

6. **Dispatch at T1** (after Wave A drains + `playwright-infra` lands):
   - `eventsourcing-coverage`
   - `widget-visual-regression`, `dashboard-e2e`, `a11y-audit`,
     `mobile-og-misc`

7. **Dispatch at T2** (after Wave A+B+C drain):
   - Wave D first link (`resolver-refactor`) in a fresh long-running
     session

## Empirical evidence from this session

The team-config plan above is extrapolated from the 36+ commits
landed this session via ad-hoc coordination. Specific data points
that informed the design:

- **9-agent parallel peak**: held without contamination once the
  `commit -o` discipline was in place from turn 1
- **Money VO Slices 1+2 (this session)**: 22 + 25 file changes each,
  zero merge conflicts, both shipped clean. Demonstrates that ~25
  file-scope is a safe single-commit boundary.
- **ES order pilot (concurrent)**: ran in parallel with both Money
  slices on `kc/usecases/gtt_usecases.go` + `kc/domain/events_edge_test.go`.
  Zero collision because file-scope lock was respected.
- **Pre-existing race in `kc/riskguard/market_hours.go:28`** discovered
  during Slice 1 verification — flagged as out-of-scope. A team session
  could spawn a one-off `race-fix-market-hours` agent in Wave A if the
  bandwidth allows; not in the core 12-roster.

## Cross-references

- `user_team_agents_default.md` — when to default to teams (≥3
  concurrent agents triggers it)
- `feedback_team_commit_protocol.md` — shared-tree path-form rules
- `user_agent_orchestration_rule.md` — main agent orchestrates only;
  team agents preserve this contract
- `user_agent_domain_map_rule.md` — team config IS the domain map; no
  separate tracking
- `feedback_research_then_work_cadence.md` — 3-4 parallel agents per
  batch on non-overlapping scopes; the wave structure here scales that
  to 12 because file-scope locks are explicit
- `.research/agent-concurrency-decoupling-plan.md` — the underlying
  Investment A-K rationale that the resolver/wire/logger Wave D series
  comes from
- `.research/money-vo-sweep-roadmap.md` — Slices 3-5 detail (this doc
  references them; the sweep doc is the source of truth)
