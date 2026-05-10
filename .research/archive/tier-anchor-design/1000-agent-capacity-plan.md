# 1000-Agent Capacity Plan — Phased Roadmap

**Date**: 2026-05-06
**HEAD**: `9b6209b` (Path A FULLY CLOSED for broker + kc/money — both external on algo2go GitHub org; 28 in-tree workspace modules remain)
**Builds on**: `cacbc20 architecture-scale-ceiling.md`, `6ee6520 architecture-scale-paths-A-B-C.md`, `725ac32 abc-100pct-complete-paths.md`, `21503fd broker-promotion-runbook.md`
**Charter**: doc-only research. NO code changes during plan-document commit. **Phases below are roadmap; execution follows in subsequent dispatches.**

---

## Empirical Baseline at HEAD `9b6209b`

| Dimension | State |
|---|---|
| Workspace modules | **28 in-tree** (all `kite-mcp-server/*` namespace) + 2 external (`algo2go/kite-mcp-broker` v0.1.0 + `algo2go/kite-mcp-money` v0.1.0) |
| External repos | 2 algo2go repos with semver tags + GOPROXY-fetched. Path A pattern PROVEN. |
| Production deploys | 40 consecutive (v189 → v228), tools=111 invariant held throughout |
| Single-binary deploy | Yes (Fly.io BOM region, `min_machines_running = 1`) |
| Single-repo CI | 14 workflows in `.github/workflows/` |
| Sub-packages within modules | 12 (mcp/{admin,alerts,analytics,common,middleware,misc,paper,plugin,portfolio,trade}; kc/ops/{admin,shared,user}) — folder-organized, NOT separate go.mods |
| Empirical proven concurrency | 3-5 disjoint-scope agents simultaneously (this session: ~12 commits this dispatch alone, no merge conflicts) |
| Per-user IP whitelist | SEBI April-2026 mandate; static egress IP `209.71.68.157` BOM region |
| SEBI synchronicity | `kc/riskguard/check.go` enforces `OrderPerSecondRate = 600` (9/sec) — synchronous trade path required |

**Strategic position**: Path A pattern (algo2go promotion) is empirically validated. Phase 0 below extends it. Phases 1-3 are progressive infrastructure scaling. Phase 4 is engineering-blocked at solo per ABC research.

---

## Phase 0 — Foundation (~2-4 weeks engineering at 5-agent pace)

**Goal**: Multi-repo skeleton complete. Per-agent worktree pattern documented. Team-config setup for sustained 5-10 concurrent agents.

### 0.1 — Promote remaining 28 in-tree modules to algo2go (~3-5 days at 5-agent pace)

| Sub-step | Cost | Smallest first step |
|---|---|---|
| Promote `kc/sectors` (canonical NSE/BSE leaf, zero internal deps) | 2-4h | Use existing broker-promotion-runbook.md mechanics; tag v0.1.0 |
| Promote `kc/isttz`, `kc/i18n`, `kc/legaldocs`, `kc/aop`, `testutil` (zero-dep leaves) | 2-4h each, 5 mods × 3h = ~15h | Batch as 5 parallel agent dispatches; disjoint go.mod targets |
| Promote `kc/audit`, `kc/cqrs`, `kc/decorators`, `kc/eventsourcing`, `kc/logger`, `kc/scheduler` (1-internal-dep modules) | 3-4h each, 6 mods × 4h = ~24h | After leaves; sequential per module due to go.work serialization |
| Promote `kc/alerts`, `kc/billing`, `kc/instruments`, `kc/registry`, `kc/users`, `kc/watchlist` (2+ internal deps) | 4-6h each, 6 mods × 5h = ~30h | After 1-dep batch |
| Promote `kc/domain`, `kc/papertrading`, `kc/riskguard`, `kc/templates`, `kc/ticker`, `kc/usecases`, `kc/telegram`, `oauth`, `plugins`, `app/providers` (heavier fan-in) | 6-8h each, 10 mods × 7h = ~70h | Last batch; some require Phase B canary deletion proven for kc/money pattern |

**Total Phase 0.1**: ~140 agent-hours. At 5-agent pace ~28 hours wall clock = ~4 working days. At 1-agent pace ~3.5 weeks.

**ROI rationale**:
- **At zero-user state**: low. Each promotion is mechanical work that doesn't ship user-visible features. The promotion itself takes the agent off feature work.
- **At-scale (post-50-stars or first external contributor)**: high. External consumers can `go get algo2go/kite-mcp-X@vY.Z.W` without forking the whole monorepo. Multi-repo CI splits scale linearly with module count.
- **Net**: do this in background while feature work proceeds in parallel. The 70h heavier-fan-in batch should defer until after feature shipping reaches a stable point (post-Show-HN).

**Smallest first step**: promote `kc/sectors` as the next agent dispatch. Mirrors `kc/money` mechanics exactly (zero internal deps, has go.mod + go.sum, standalone-buildable). Estimate: 2-3 hours including v0.1.0 tag + canary deletion.

**Hard dependencies**: Path A owner finishes their current promotion (whatever module they picked); avoid concurrent go.work + Dockerfile edits.

**Honest blocker**: each promotion serializes through `go.work` + root `go.mod` + `Dockerfile` edits. Can't truly parallelize across modules without merge conflicts on these 3 hot files. Fix is Phase 0.4 below.

### 0.2 — Team-config setup at session start (~4 hours)

Per `MEMORY.md` user rule: "set up Claude Code team config at session start (not mid-flight) when 3+ agents will work on a shared codebase."

**Contents**:
- `.claude/team/config.yaml` declaring named agents with domain ownership (e.g., axis-c-feature, path-a-promoter, observability)
- Pre-defined dispatch templates per domain (so orchestrator doesn't re-derive briefs each session)
- Hooks for TeammateIdle + TaskCompleted (Python; pattern from `~/.claude/hooks/agent-teams/`)
- Documented "main agent = orchestrator only" rule

**ROI**: prevents the empirical concurrent-edit friction observed in prior sessions (delete/revert/WIP-breaks-build cycles per `feedback_team_agents_default.md`).

**Smallest first step**: stub `.claude/team/config.yaml` with 3 named agents (axis-c, path-a, observability) and disjoint domain prefixes. ~30 min.

### 0.3 — Worktree-per-agent pattern automation (~1 day)

Per `MEMORY.md` `user_team_commit_protocol.md`: for scale + safety-first, use per-teammate git worktrees.

**Contents**:
- Script `scripts/agent-worktree-init.sh <agent-name>` creating `D:\Sundeep\projects\kite-mcp-server-{agent}` worktrees
- Each agent works in isolated worktree, pushes to shared origin/master, no shared working-tree race
- Documentation for orchestrator on which agent owns which worktree

**ROI**: eliminates the working-tree race condition empirically observed when 2+ agents edit go.mod / Dockerfile / go.work simultaneously.

**Honest constraint**: per `MEMORY.md` `feedback_no_stash_anywhere.md`, no `git stash` in any clone. Worktrees enforce isolation cleanly.

**Smallest first step**: write `scripts/agent-worktree-init.sh` skeleton + verify it works for 2 named agents. ~1-2 hours.

### 0.4 — Concurrent-edit conventions across multi-repo (~4 hours)

**Contents**:
- Documentation: which files are "hot" (go.work, root go.mod, Dockerfile, Dockerfile.selfhost) — single-agent serialization required
- Pattern: agents touching hot files coordinate through orchestrator messages (not concurrent dispatches)
- Pattern: agents working on disjoint module sub-trees (mcp/portfolio vs kc/audit) can dispatch concurrently
- Recipe: how to ship a hot-file change without blocking other agents (file with `_o` path-form `git commit -o` per CLAUDE.md)

**ROI**: doc-only deliverable that captures empirical lessons from this session. Prevents re-derivation by future agents.

**Smallest first step**: append to existing `.research/agent-domain-map.md` (if exists, else create). ~30 min.

---

## Phase 1 — CI Sharding (~1-2 weeks engineering)

**Goal**: CI cost + latency bounded as commit cadence grows from ~30/day to ~150/day. PR-to-green-CI latency stays under 5 min for fast lane.

### 1.1 — Drop macOS from `ci.yml` matrix (~30 min)

Empirical: $600/mo macOS spend at 1500 commits/month. macOS-specific bugs in pure-Go codebase are rare. **−65% CI spend immediately.**

### 1.2 — Add `concurrency:` group per workflow (~2 hours)

Today only `playwright.yml` has it. Add to `ci.yml`, `test-race.yml`, `benchmark.yml`, etc. Auto-cancels superseded runs. **Saves ~30 stale CI cycles/day at N=20.**

### 1.3 — Smart-test matrix (~1-2 days)

`nx affected`-style change detection: only test modules whose dependency graph touched. Average PR touches 1-3 of 28 modules; running all 28 wastes ~85% of CI. **3-5x effective ceiling lift.**

Implementation: shell script in `scripts/ci-affected-modules.sh` reads PR diff, computes dependency graph via `go list -deps`, outputs matrix entries. Workflow uses GitHub Actions matrix strategy from script output.

### 1.4 — Self-hosted runner pool (~1-2 days)

3-5 Hetzner CPX21 2-core/4GB VMs at ~$8/mo each = ~$30-50/mo. Unlimited Linux minutes. Crossover vs GitHub-hosted: ~$1,000-2,000/mo at sustained N=20.

### 1.5 — Per-PR fast lane vs full-suite weekly (~4 hours)

`ci.yml` (fast lane): build + vet + affected-package tests, target <3 min runtime.
`ci-full.yml` (weekly cron): everything else (race, mutation, sbom, security, dr-drill, benchmark). Target <60 min runtime, accepts overnight runs.

### 1.6 — Per-repo independent CI for algo2go/* modules (~1-2 days)

Each algo2go repo gets its own `.github/workflows/ci.yml` (clone parent's pattern, scope to that module). Releases tagged independently. **Removes monorepo CI as bottleneck for module-isolated changes.**

**Phase 1 total cost**: ~5-8 engineer-days. **At 5-agent pace: ~1-2 working days wall clock** (each step is mostly disjoint).

**Hard dependencies**: 1.6 depends on Phase 0.1 module promotions. 1.1-1.5 are independent.

**ROI rationale**:
- **At zero-user state**: high. Lifts effective concurrency ceiling from 20-25 to 100+ at the cost of 1-2 weeks engineering. Cost recovery via reduced GitHub Actions spend.
- **At-scale**: very high. CI sharding is the structural enabler for N=100+ sustained.
- **Net**: positive immediately. Recommend execute after Phase 0.

**Smallest first step**: 1.1 (drop macOS) — single line change in `.github/workflows/ci.yml`. ~30 min total.

---

## Phase 2 — Multi-Repo Orchestration (~2-4 weeks engineering)

**Goal**: 28+ algo2go repos releasable independently with semver discipline; cross-repo dependency upgrades automated.

### 2.1 — Semantic versioning + changelog automation (~3-5 days)

- Each algo2go repo uses `release-please` GitHub Action OR `goreleaser`
- Conventional commits enforced (already in use empirically; codify in CONTRIBUTING.md per repo)
- Auto-generate CHANGELOG.md per repo on tag

### 2.2 — Cross-repo dependency management (~3-5 days)

- Dependabot for algo2go/* repos cross-pinning each other
- Renovate-style policies: auto-merge patch + minor bumps for internal deps; manual for major
- `go mod tidy` + `go work sync` automation in CI

### 2.3 — Umbrella-repo pattern for cross-cutting features (~3-5 days)

For features spanning multiple algo2go modules (e.g., new SEBI compliance check that touches kc/audit + kc/riskguard + kc/usecases):
- Issue tracker in `kite-mcp-server` repo (umbrella)
- Sub-issues in algo2go/* repos
- Release-train tooling: Phase A ships in algo2go/X@vY+1, Phase B in algo2go/Z@vW+1, kite-mcp-server bumps both deps in single PR

### 2.4 — Release-train tooling (~3-5 days)

Script `scripts/release-train.sh`:
- Reads umbrella issue's sub-issue tags
- Cuts releases in topological order
- Bumps consumer go.mod
- Posts release notes back to umbrella issue

**Phase 2 total cost**: ~12-20 engineer-days. **At 3-agent pace: ~4-7 working days wall clock.**

**Hard dependencies**: Phase 0.1 (28 module promotions) AND Phase 1 (CI sharding) both done first.

**ROI rationale**:
- **At zero-user state**: low. Adds operational discipline for changes that are already mechanically straightforward.
- **At-scale (1-3 external contributors)**: high. Without semver + changelog automation, breaking changes propagate silently.
- **Net**: defer until first external consumer or first cross-repo breaking change. Phase 1 is required first.

**Smallest first step**: 2.1 step on `algo2go/kite-mcp-broker` (single repo, already has 1 release tag at v0.1.0). Add release-please workflow. ~2-4 hours.

---

## Phase 3 — Distributed Dev Infrastructure (~1-2 months engineering)

**Goal**: Multi-tenant CI cluster + cross-agent coordination + observability for sustained N=100+ concurrent agents.

### 3.1 — Self-hosted CI cluster (Kubernetes-grade) (~2-3 weeks)

- 5-10 self-hosted runner VMs orchestrated via `actions-runner-controller` on lightweight K8s (k3s or Talos)
- Shared cache layer (`actions/cache` backed by S3 or Cloudflare R2)
- Auto-scaling based on queue depth

### 3.2 — Event bus for cross-agent coordination (~1-2 weeks)

- NATS JetStream (lightweight, single-binary, embeddable) OR Redpanda (Kafka-compatible)
- Use cases: agent A finishes module-promotion, publishes `module.promoted` event; agent B (deps-bumper) consumes
- Avoids polling-based coordination (which doesn't scale to N=100)

### 3.3 — Distributed lock service (etcd or similar) (~1 week)

- Scope ownership: agent A acquires lock on `go.work` for 5 minutes during edit; agent B blocks on the same lock
- Replaces orchestrator-mediated serialization (which becomes the bottleneck at N=100)

### 3.4 — Observability stack (~1-2 weeks)

- Prometheus scraping CI runner metrics + Fly.io app metrics
- Grafana dashboards: PR-to-merge latency, CI cost/PR, deploy frequency, rollback rate
- Distributed tracing for cross-repo workflows (Jaeger or Tempo)

**Phase 3 total cost**: ~4-8 engineer-weeks. **At 2-agent pace: ~3-4 weeks wall clock.**

**Hard dependencies**: Phases 0-2 done. AND empirical evidence that N=50+ sustained is being attempted (otherwise this is premature complexity).

**ROI rationale**:
- **At zero-user state**: NEGATIVE. Adds significant ops complexity (K8s cluster, event bus, lock service) for capacity nobody is using.
- **At-scale (sustained N=50-100)**: positive but expensive. Each component requires SRE-level operations skill to maintain.
- **Net**: defer until empirical N=50+ sustained. Most teams should hire DevOps before doing this.

**Smallest first step**: 3.4.a — add Prometheus `node_exporter` to existing Fly.io machine + a single Grafana Cloud free dashboard. ~2-4 hours. Provides observability baseline before scaling. Other Phase 3 steps explicitly deferred.

---

## Phase 4 — Cell-Based Runtime (~3-6 months, ENGINEERING-BLOCKED on trade path)

**Goal**: Per-tenant/per-region cells; ~70% decomposition (read paths cell-isolatable; trade path forced monolith).

### 4.1 — Trade path stays monolith (regulatory)

`kc/riskguard/check.go` enforces `OrderPerSecondRate = 600` per SEBI April 2026. The 9-orders-per-second per-user limit requires synchronous bucket counter; eventual consistency would allow brief overflows that violate SEBI. **Trade path cannot decompose.**

Per ABC research at `725ac32`: **maximum decomposition ~70%** (non-trade tools: alerts, briefings, P&L snapshots, audit-log writes, Telegram dispatch, portfolio queries). Cell-based blocked structurally for trade.

### 4.2 — Per-cell read-path deployments (~6-10 weeks engineering)

- Each cell handles N tenants on its own Fly.io machine
- Cell-router shards by user-email-hash (consistent hashing)
- Per-cell SQLite via Litestream replicated to Cloudflare R2

### 4.3 — Per-user IP whitelisting workflow (~2-3 weeks engineering)

SEBI April-2026 mandates each user whitelist the operator's static egress IP in their Kite developer console. Multi-cell distribution multiplies this: each cell has a different egress IP; each user must whitelist EACH cell IP in their dev console.

**Two paths**:
- **(a) Manual user UI**: dashboard page showing "These are our cell IPs: A, B, C. Add ALL of them to your Kite dev console." High user-friction.
- **(b) Kite dev-console automation**: scrape/automate the whitelist API. Brittle (Kite's UI may not have a stable API).

**Honest blocker**: until SEBI relaxes per-user IP whitelist to per-operator (no per-user requirement) OR until Kite exposes a programmatic whitelist API, multi-cell distribution at our scale is **engineering-blocked at solo**. Multi-region therefore stays single-region (BOM) until regulation changes.

### 4.4 — Service mesh (~3-4 weeks engineering)

- Linkerd or Istio for inter-cell mTLS
- Per-cell observability + tracing
- Cell failure → automatic re-route to healthy cell

**Phase 4 total cost (effective)**: ~3-6 months engineering for the ~70% decomposable surface. Trade path stays monolith forever.

**Hard dependencies**: Phases 0-3 done. AND user count >100 (otherwise the operational cost dwarfs the value).

**ROI rationale**:
- **At zero-user state**: massively negative. Adds 3-6 months of ops overhead for capacity nobody is using.
- **At-scale (1000+ concurrent users)**: positive ONLY for read-path scalability. Trade path latency stays bounded by single-machine latency anyway.
- **Net**: defer until concrete user-count trigger fires. Even at 1000 agents, this is overkill — N=1000 agents is a developer-concurrency target, not a user-concurrency target. They're different denominators.

**Smallest first step**: do not start. Defer until empirical user-count signal warrants. The plan documents this phase only for completeness — it's the formal answer to "what does 10,000-agent capacity look like" but it's not a phase to start at our state.

---

## Cross-Phase Synthesis

### Phase ordering recommendation (prioritized)

| Order | Phase | Cost | Why |
|---|---|---|---|
| 1 | Phase 0.2 (team-config) + 0.3 (worktrees) + 0.4 (conventions) | ~2 days | Unblocks safe 5-10-agent concurrency immediately |
| 2 | Phase 0.1 (module promotions, batch by tier) | ~3 weeks | Validates Path A pattern at scale; mechanical |
| 3 | Phase 1 (CI sharding) | ~1 week | Cost containment + ceiling lift |
| 4 | Phase 2.1 (release-please on existing 2 repos) | ~4 hours | Cheapest discipline checkpoint |
| 5 | Phase 3.4.a (Prometheus baseline only) | ~4 hours | Observability before scale |
| 6+ | Defer until trigger fires | — | Phase 2.2-2.4, Phase 3.1-3.3, Phase 4.* are pre-trigger |

### Hard constraints carried throughout

1. **SEBI synchronicity** (`kc/riskguard/check.go` `OrderPerSecondRate = 600`): trade path CANNOT decompose. Maximum 70% decomposition per ABC research.
2. **Per-user IP whitelist**: blocks multi-cell distribution until regulation changes.
3. **tools=111 invariant**: every refactor verified via `grep -rE 'mcp\.NewTool\("' mcp/`.
4. **WSL2 mandatory** for `go test`/`go build` (per `feedback_wsl_for_go_test.md`).
5. **No git stash, rebase, worktrees-as-stash, --no-verify** (per `MEMORY.md`).

### N-agent capacity crossover points

| N | What's needed |
|---|---|
| **N=5-10** | Phase 0.2-0.4 (proven pattern, this session) |
| **N=20-30** | Phase 0.1 (module promotions reduce hot-file contention) |
| **N=50-100** | Phase 1 (CI sharding) |
| **N=100-300** | Phase 2 (multi-repo orchestration) |
| **N=300-1000** | Phase 3 (distributed dev infrastructure) |
| **N=1000+** | Phase 4 partial (~70% read-path; trade stays monolith) |

### Honest acknowledgments

- **At our zero-user state, N=1000-agent capacity is not the binding constraint.** N=5-10 sustained is the real near-term denominator. Phases 0-1 cover that comfortably.
- **The plan above assumes empirical triggers fire; do not pre-execute Phases 3-4.**
- **Phase 4 cell-based architecture is forever capped at ~70%** by SEBI synchronicity. The remaining 30% (trade path) lives in monolith perpetually unless regulation changes.
- **Solo execution timeline**: ~6-8 months for Phases 0-3 cumulative. With current 5-agent pace observed this session, ~5-7 weeks calendar.

---

## Recommended Next Concrete Steps

### Phase 0 next concrete step (post-current-Path-A-promotion)

Path A owner is in flight on their next module promotion. After it lands, the Phase 0 attack vector is **0.2 + 0.3 + 0.4 in single dispatch** (~4 hours total) — these are doc-only or scripts, no go.work / Dockerfile contention with Path A:

1. **Phase 0.2 — team-config setup** (~30 min): stub `.claude/team/config.yaml` with 3-5 named agents
2. **Phase 0.3 — worktree script** (~1-2 hours): write `scripts/agent-worktree-init.sh`
3. **Phase 0.4 — conventions doc** (~30 min): append to `.research/agent-domain-map.md`

These three unblock sustained 5-10-agent concurrency before resuming Phase 0.1 module promotions in series.

### Recommended next dispatch

**Agent**: 1000-agent-capacity-architect (this domain) — same agent, next dispatch
**Scope**: Phase 0.2 (team-config) + 0.3 (worktree script) + 0.4 (conventions doc) — 3 disjoint files, single commit, ~4 hours
**Disjoint from Path A**: yes. Path A owner edits `go.work`/`go.mod`/`Dockerfile`; this dispatch edits `.claude/team/`, `scripts/`, `.research/`.
**Dependencies**: Path A's current module promotion lands first (avoid go.work race during their commit window).

### Alternative: chain into more module promotions

If Path A owner is consistently dispatched for the heavier-fan-in modules and doesn't get to leaves, queue **promote `kc/sectors`** as the next agent dispatch. Mirrors `kc/money` pattern exactly, ~2-3 hours including v0.1.0 tag + canary deletion. Lower-risk than waiting for Path A owner to pick it up.

**My recommendation**: Phase 0.2-0.4 first (unblocks all subsequent agent-team scaling); then queue `kc/sectors` promotion as the third concurrent agent.

---

**End of plan. Doc-only. No code mutated. tools=111 invariant verified at HEAD `9b6209b` (40-deploy streak). Stop-rule budget: ~3 hours. Plan can iterate.**
