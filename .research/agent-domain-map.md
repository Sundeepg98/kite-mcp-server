# Agent → Domain Map

**Purpose**: live, authoritative mapping of named-agent roles to canonical
domains for the kite-mcp-server repository. Per
`user_agent_domain_map_rule.md`: the orchestrator MUST maintain this map
from session start and route follow-ups to the agent whose prior context
matches the domain — not to whoever is idle.

**Companion**:
- `.claude/team/config.yaml` — operational team config (slots, modes, perms)
- `scripts/agent-worktree-init.sh` — per-agent isolated working tree
- `scripts/agent-worktree-cleanup.sh` — tear-down

**Last updated**: 2026-05-09 IST (session resume)
**HEAD at update**: `52204eb`
**Production**: v1.3.0 LIVE (binary literal; doesn't auto-bump per deploy); tools=111 (production-registered = master-built; raw `grep mcp.NewTool(` returns 130 which includes 19 test fixtures — per `production-master-gap-report.md` §1.5); Fly.io machine version 273 (84+ consecutive deploys, v228 → v273+). Last empirical verification 2026-05-11 via `curl /healthz`.

---

## Canonical Roles

The following five roles cover the empirical work-axes of the project as
of 2026-05-09. Add new roles only when a recurring work-axis has emerged
across 2+ sessions; transient one-off work uses the closest existing role.

### `chain` — Deploy / release pipeline

- **Domain**: `flyctl deploy`, version increments, smoke tests, rollback
  decisions, `Dockerfile` deploy-axis edits, `fly.toml` config, deploy
  scripts (`scripts/deploy.sh`, `scripts/smoke-test.sh`).
- **Owns exclusively**: deploy axis only — never business logic.
- **Forbidden paths**: `kc/**/*.go`, `mcp/**/*.go`, `broker/**/*.go`,
  `.research/**`.
- **Cross-session resume**: route deploy questions, version-bump triggers,
  rollback alarms here. Re-ping with deploy state pasted (current version,
  smoke status, machine count).
- **Recent context** (cross-session): owned v189 → v273+ deploy streak (machine version 273 at last empirical check 2026-05-11; was v228 at 2026-05-09 doc-write time).
- **WSL2 use**: minimal — `flyctl` is binary-launched from Windows.
- **Last touched**: v229 deploy in flight per session-resume note.

### `audit` — Feature TDD

- **Domain**: feature increments under TDD discipline. Axis C work:
  audit-log search, scanner phases, payoff-viz, options strategies, etc.
  Edits `mcp/`, `kc/usecases/`, `kc/audit/`, `kc/templates/`. Adds tests
  FIRST per `CLAUDE.md` TDD policy.
- **Owns exclusively**: feature work in `mcp/` + `kc/usecases/` +
  `kc/audit/` + `kc/templates/`.
- **Forbidden paths**: `fly.toml`, `Dockerfile`, `go.work`, `go.mod`.
- **Cross-session resume**: route feature-shipment questions here. Re-ping
  with feature scope + test-failure dump if WSL2 red.
- **Recent context**: shipped audit-log search (3 commits), scanner
  Phases 1-3 (3 commits), payoff-viz Option (c) + Phase (a) refactor
  (4 commits), in this and prior session.
- **WSL2 use**: ALL `go test` / `go build` runs in WSL2.

### `path-a-owner` — Module promotion to algo2go

- **Domain**: Path A workflow — promote in-tree modules to
  `github.com/algo2go` GitHub org repos. Touches `go.work` + `go.mod` +
  `Dockerfile` during cutover. Phase B canary deletion. Repository
  creation on github.com/algo2go.
- **Owns exclusively**: `go.work`, `go.mod`, `Dockerfile` during a
  promotion. Other agents must defer their edits to these files until
  the promotion completes.
- **Cross-session resume**: route module-promotion questions here. Re-ping
  with current module name + Path A step (1 promote / 2 cutover / 3 canary
  delete).
- **Recent context**: completed broker, kc/money, kc/decorators promotions
  (3 algo2go external modules). 27 in-tree modules remain. Path A.4 in
  flight (kc/i18n or kc/legaldocs per session-resume note).
- **WSL2 use**: ALL Go ops in WSL2.

### `playwright` — Visual verification

- **Domain**: visual verification — dashboard rendering, widget UX, OAuth
  flow screenshots, kite.zerodha.com login flow recordings. Touches
  `kc/templates/*.html`, `tests/playwright/`.
- **Owns exclusively**: visual-test fixtures.
- **Forbidden paths**: `fly.toml`, `Dockerfile`, `go.work`, `go.mod`,
  `broker/**`.
- **Cross-session resume**: route UI-verification questions here. Re-ping
  with screenshot URL or test-spec content.
- **Recent context**: not heavily used in recent sessions; reserved slot.
- **WSL2 use**: minimal — Playwright is Node-based.

### `capacity-architect` — Research / capacity-planning docs

- **Domain**: doc-only research and capacity-planning analysis. Writes to
  `.research/` ONLY. NEVER mutates code. Doc-only commits.
- **Owns exclusively**: `.research/**`.
- **Forbidden paths**: `**/*.go`, `go.work`, `go.mod`, `fly.toml`,
  `Dockerfile`, `scripts/**`.
- **Cross-session resume**: route capacity-planning, blocker-analysis,
  scale-out questions here. Re-ping with target N (e.g., 1K-agent,
  10K-agent) + budget hours.
- **Recent context**: shipped `1000-agent-capacity-plan.md` +
  `10000-agent-blocker-analysis.md` in this session (commit `52204eb`).
- **WSL2 use**: only for tool-count verification (`grep -rE
  'mcp\.NewTool\("' mcp/`).
- **Tool count invariant**: MUST verify count is unchanged after each
  research commit. Doc-only invariant.

---

## Disjoint-Scope Conventions for Parallel Dispatch

When dispatching 3+ agents in parallel:

1. **Read this map BEFORE dispatch.** Confirm no two agents will edit
   the same files. The role-level forbidden_paths in
   `.claude/team/config.yaml` are the enforcement boundary.

2. **Same-axis conflicts**: if two agents both belong to `audit`, give
   them disjoint package scopes (e.g., one on `mcp/scanner_*`, one on
   `mcp/payoff_*`). Verify in the brief that file overlap is zero.

3. **Path A is exclusive**: `go.work`, `go.mod`, `Dockerfile` during a
   promotion. Other agents wait. If they must edit other parts of these
   files (e.g., `Dockerfile` non-deploy axis), serialize via SendMessage
   ack from `path-a-owner`.

4. **Doc-only is always disjoint** from code work — `capacity-architect`
   can run in parallel with any other role.

5. **Worktree per agent**: when 3+ concurrent agents will land commits in
   the same minute, use `scripts/agent-worktree-init.sh <role> <task>`.
   Each agent's worktree is a separate checkout + branch; merge to master
   serially per `user_team_commit_protocol.md`.

---

## Cross-Session Resume Rules

Per `user_agent_context_size_rule.md`: every agent has 1M context same as
orchestrator. Reuse via SendMessage with bigger task batches. Spawn fresh
ONLY for genuine concurrency on disjoint scopes.

To resume an agent across sessions:

1. **Reach for THIS file first** — it's the authoritative agent → domain
   map. UUIDs may have rotated (memory-snapshot files captured them at
   end of prior sessions; see `MEMORY.md` agent-team-snapshot entries).

2. **By role, not UUID**: at session start, dispatch `audit` /
   `chain` / `path-a-owner` / `playwright` / `capacity-architect` agents
   with their canonical domain restated. New UUIDs are fine; the role +
   domain is the stable axis.

3. **Re-ping vs spawn-fresh**:
   - **Re-ping** (SendMessage to existing agent): when the new task is in
     the same domain as their prior context.
   - **Spawn fresh**: only when (a) prior agent died (Explore agents die
     on completion per `feedback_agent_lifecycle.md`), OR (b) the new
     task is genuinely concurrent with their current task on disjoint
     scope.

4. **Snapshot at session close**: dump live UUIDs + role + last-task
   into `MEMORY.md session_<date>_agent_team_snapshot.md`. Next-session
   orchestrator reads this on startup.

---

## Hard Rules Carried by All Agents

(Mirrors `.claude/team/config.yaml` `rules:` block; restated here for
quick reference.)

1. **WSL2 mandatory** for `go test` / `go build` (Windows-native is
   SAC-flaky 50-70% per `feedback_wsl_for_go_test.md`).
2. **`git commit -o -- <paths>`** per PR; NEVER `git add -A`. Forbidden
   git commands: `git stash`, `git pull --rebase`, `git rebase`,
   `git commit --amend`, `git commit --no-verify`.
3. **Push to origin/master** per commit when WSL2 green (per
   `user_agents_push_after_wsl_green.md`).
4. **tools=111 invariant** (production-registered count via compile-and-run): refactor work shouldn't change tool count; feature work MAY change it but must record in commit message. **NOT 130** — that's a raw `grep mcp.NewTool(` over `mcp/` which over-counts test fixtures by 19. Methodology rule pinned at `STATE.md` §5.6 + §11.
5. **Don't deploy yourself**: `chain` agent owns deploys exclusively.
6. **Disjoint scope**: check this file before dispatch.

---

## What's Already Done (don't re-do)

To prevent re-execution of already-shipped work, the following are
empirically complete as of HEAD `52204eb`:

| Item | Commit | Description |
|---|---|---|
| Drop macOS from CI matrix | `1174156` | Path A item 1 per audit `6ee6520`. Saves 65% CI cost. |
| Concurrency groups in CI | `f146355` | Path A item 2 per audit `6ee6520`. Cancels in-flight runs on rapid commits. |
| Smart-test selection (PR diff) | (already in `ci.yml`) | Path A item 3. PR runs only affected packages. |
| Algo2go org Path A — broker | `7f71ccf`+`bef0b31` | External `github.com/algo2go/kite-mcp-broker` v0.1.0 |
| Algo2go org Path A — kc/money | `b92173b`+`bef0b31` | External `github.com/algo2go/kite-mcp-money` v0.1.0 |
| Algo2go org Path A — kc/decorators | `7f71ccf` (decorators) + `c19bca9` | External v0.1.0 |
| 1K-agent capacity plan | `52204eb` | `.research/1000-agent-capacity-plan.md` |
| 10K-agent blocker analysis | `52204eb` | `.research/10000-agent-blocker-analysis.md` |

**Empirical conclusion**: any future "Phase 1.1 = drop macOS from CI" work
items in dispatch briefs are already done; verify via this table before
re-execution.

---

## Open Sequence (next-session pickup)

Per `.research/10000-agent-blocker-analysis.md` Phase 0+:

- **Phase 0.2** (THIS COMMIT): team-config stub at `.claude/team/config.yaml`
- **Phase 0.3** (THIS COMMIT): worktree scripts at `scripts/agent-worktree-{init,cleanup}.sh`
- **Phase 0.4** (THIS COMMIT): this file
- **Phase 1.x** (Phase 1.1 ALREADY DONE per above): Phase 1.4 self-hosted
  CI runners (when CI cost trigger fires) is the next CI scaling step.
- **Phase A.4** (path-a-owner agent in flight): kc/i18n or kc/legaldocs
  promotion per session-resume note.
- **Phase 2** (deferred): Postgres adapter alongside SQLite via existing
  `SQLDB` interface in `kc/alerts/db.go`. Trigger: 1000+ concurrent users.
- **Phase 3+**: deferred until user-count signal.

---

**End of map. Update on every dispatch that adds a role, retires a role,
or changes the canonical domain of an existing role.**
