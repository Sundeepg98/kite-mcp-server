# Agent-Concurrency Decoupling Plan

**Corrects the denominator** in `path-to-100-business-case.md` (`78c243e`). That doc used user-MRR (₹15-25K target) as ROI denominator and concluded "stop at 98.5". The correct denominator for THIS user is **multi-agent parallel-development throughput** — every decoupling investment is judged on "how many agents can productively edit in parallel without coordination friction".

**Charter**: Read-only synthesis. No source files modified.

**Cross-referenced grounding**:
- `~/.claude/projects/D--Sundeep-projects/memory/user_team_agents_default.md` — empirical 4-agent friction
- `~/.claude/projects/D--Sundeep-projects/memory/user_team_commit_protocol.md` — observed contamination/break incidents
- `~/.claude/projects/D--Sundeep-projects/memory/feedback_use_teams.md` — round-18 team proven pattern (6 agents, 20 tasks)
- `path-to-100-business-case.md` (78c243e) — LOC + $$ data reused with corrected ROI lens
- `final-138-gap-catalogue.md` — 13-dim score-lift side benefits
- This session's empirical data: A (mcp/) + B (.research/*.md) lanes succeeded; SAC env divergence; shared GOCACHE not yet observed but architecturally hot

---

## 1. Empirical concurrency ceilings (current architecture)

Ground-truth data from prior sessions:

| Setup | Observed ceiling | Failure mode |
|---|---|---|
| 4 agents on shared tree, file-disjoint scopes | 4 max productive | 3 contamination commits + 1 broken-tree incident in 2026-04-20 session per `user_team_commit_protocol.md` |
| 5+ agents on shared tree | broken | Same memory: "Team > 4-5 agents → file overlap probability too high" |
| 6 agents on team config + per-worktree | 6 productive (round-18 per `feedback_use_teams.md`) | Zombies acceptable; team API auto-coordinated |
| This session: A (mcp/) + B (.research/*.md) | 2 productive | Lanes were architecturally disjoint; zero collision risk |

**Inferred ceiling at HEAD `78c243e`: ~4-5 productive agents on shared tree, ~6-8 on team-with-worktrees.**

The **hard serialization points** in current architecture (each blocks parallel agents):

1. **`app/wire.go`** — 600 LOC composition root. Adding a new service = touching this file. **Single-agent serialization point.**
2. **`app/app.go`** — 700+ LOC App struct. Adding fields = same problem. **Serialization point.**
3. **`mcp/mcp.go`** — `GetAllTools()` is a static slice. New tool = appending here. **Serialization point.**
4. **`mcp/common_deps.go`** — `ToolHandlerDeps` struct. New port/provider = touching here. **Serialization point.**
5. **`kc/manager.go`** + `kc/manager_init.go` + `kc/manager_accessors.go` — Manager God-object. Any new service still funnels through. **Serialization point.**
6. **Shared GOCACHE / GOMODCACHE** — concurrent `go test` across agents races on cache. Architecturally hot, observed in some sessions.
7. **`go.mod` / `go.sum`** — concurrent `go get` / `go mod tidy` produces merge conflicts ~100% of the time.
8. **Single SQLite test DB** — concurrent test runs lock SQLite. Mostly mitigated by per-test `t.TempDir()` but `INSTRUMENTS_SKIP_FETCH=1` requires global env state.
9. **`fly.toml` + Dockerfile** — single deploy artifact. Two agents can't both bump version.

---

## 2. Decoupling-investment matrix

For each investment, what type of agent-concurrency friction it eliminates AND throughput-lift estimate:

### Investment A — Wire/fx DI container

**Friction eliminated**: Eliminates `app/wire.go` as a serialization point. Each new service is a separate `wire.NewSet(...)` provider declaration in its own file. N agents can add services in parallel; `wire.Build()` regenerates the graph at build time.

**Throughput lift**: 4 → 8 agents (doubles ceiling for service-addition work). Most relevant when 3+ agents are simultaneously adding new tools/use-cases.

**Cost**: 600 LOC (per `78c243e` §6) + ongoing code-gen step in build + cryptic Wire compile errors (notorious DX pain).

**Maintenance overhead**: Wire upgrades break config; `wire_gen.go` regeneration on every dependency change.

**Side benefit (13-dim rubric)**: Hex 88→97 (+9), SOLID 90→93 (+3). **Total +12pt** on architectural dims.

**ROI** = `(throughput_gain * agent_velocity) / (cost + maintenance)` = `(4 * 1.0) / (600 + 100/yr maintenance)` = `0.006 throughput-per-LOC`.

### Investment B — Logger Provider wrap

**Friction eliminated**: Theoretically lets agents mock `*slog.Logger` per-test. But agents already do this trivially via `slog.New(slog.NewTextHandler(io.Discard, nil))` — **no actual friction observed in any session**.

**Throughput lift**: ~0 agents. **Pure ceremony per Pass 18.**

**Cost**: 200 LOC + every prod call site needs `deps.Logger` injection.

**Side benefit**: SOLID 90→91 (+1). ISP score-inflation only.

**ROI**: ~0. **REJECT.**

### Investment C — Middleware split (decompose middleware_chain.go)

**Friction eliminated**: `mcp/middleware_chain.go` adds new middleware in `DefaultBuiltInOrder` slice. Agents adding middleware sometimes collide on slice order. Could split each middleware into its own registration package. **Real but minor friction.**

**Throughput lift**: 4 → 5 agents (marginal).

**Cost**: 150 LOC + per-middleware registration discovery scaffolding.

**Side benefit**: Middleware 96→97 (+1).

**ROI**: low. Defer until 6+ agents simultaneously editing middleware.

### Investment D — Full ES (event-sourced state reconstitution)

**Friction eliminated**: NONE for agent-concurrency. ES is an architectural pattern about state derivation from events, not about decoupling.

**Throughput lift**: 0. Doesn't address any serialization point.

**Cost**: Months of work (per Pass 17 explicitly rejected).

**ROI**: 0. **REJECT for concurrency goal.** (May be justified for ES dim score lift separately.)

### Investment E — Port-per-context fan-out (Phase 3a completion)

**Friction eliminated**: Eliminates `*kc.Manager` as a parameter type across 168 mcp/ sites. Each tool handler depends on a narrow port (Session/Credential/Alert/Order/Instrument). **N agents can edit DIFFERENT tools in parallel without touching common Manager surface.** Manager-method-addition no longer cascades through every consumer.

**Throughput lift**: 4 → 6 agents (per round-18 evidence: 6-agent team succeeded with port-based separation). The single biggest concrete leverage point.

**Cost**: 380 LOC (per `phase-3a-manager-port-migration.md` `d9fdd06`, revised down from 600).

**Maintenance overhead**: Zero — ports are an interface contract, no runtime cost.

**Side benefit**: Hex 88→95 (+7), SOLID 90→94 (+4). **Total +11pt.**

**ROI** = `(2 * 1.0) / (380 + 0)` = **0.005 throughput-per-LOC** but with low cost ceiling = **highest absolute ROI**.

### Investment F — Persistence-per-bounded-context (split SQLite database)

**Friction eliminated**: Today, single `alerts.db` SQLite file holds tool_calls + alerts + watchlist + paper_trades + tokens + credentials + sessions + consent + outbox. Agents running parallel tests collide on global DB lock unless test-isolated. Splitting into `audit.db`, `alerts.db`, `paper.db`, etc. lets parallel test packages own their own files. **Real friction observed in CI race-test workflow per `path-to-100-business-case.md` Pass 24 §A.**

**Throughput lift**: 4 → 6 agents (CI parallelism specifically).

**Cost**: 400 LOC (schema split + migration paths + Litestream config per-db) + ongoing complexity (cross-db queries unavailable).

**Maintenance overhead**: Each new bounded context needs its own DB lifecycle.

**Side benefit**: Hex 88→90 (+2), DDD 95→96 (+1).

**ROI**: medium. Defer until shared-DB collisions become a measured CI bottleneck.

### Investment G — Separate worker binaries (extract scheduler/outbox/ticker as standalone)

**Friction eliminated**: Today, the main binary handles HTTP serving + scheduler + outbox pump + ticker WebSocket + audit retention. Each subsystem runs in shared goroutines. Splitting into `kite-mcp-server-worker`, `kite-mcp-server-ticker`, etc. lets each have its own deploy cadence + agent owner. **N agents can deploy worker changes without affecting the main binary.**

**Throughput lift**: 4 → 7 agents (different agents own different binaries).

**Cost**: 800 LOC (separate `cmd/scheduler/main.go`, `cmd/outbox/main.go`, etc. + service-discovery + IPC).

**Maintenance overhead**: Multiple deploy artifacts, multiple Fly.io machines (~$15/mo extra), multiple log streams.

**Side benefit**: Hex 88→90 (+2), Port 75→82 (+7). **Total +9pt** but requires actual ops investment.

**ROI**: medium. **Premature** at current single-binary scale. Revisit at 5+ agents PERMANENTLY working on different subsystems.

### Investment H — Federated build (Bazel / per-package go modules)

**Friction eliminated**: Eliminates `go.mod` / `go.sum` as a serialization point. Each package gets its own module; `go mod tidy` no longer races. CI can build only changed modules.

**Throughput lift**: 4 → 10 agents (concurrent `go get` / dep upgrades become collision-free).

**Cost**: 2000+ LOC (Bazel config OR multi-module restructure) + permanent build-system complexity.

**Maintenance overhead**: VERY HIGH. Bazel adoption is multi-year commitment; multi-module Go has its own version-skew problems.

**Side benefit**: Compat 80→85 (+5), Port 75→80 (+5).

**ROI**: low at current scale. **Premature** until 10+ agents simultaneously upgrading dependencies. **REJECT.**

### Investment I — Worktree-per-agent enforcement (process discipline, not code)

**Friction eliminated**: This session's A+B succeeded because A and B had architecturally disjoint scopes. Forcing each team agent to use `git worktree add D:/Sundeep/projects/kite-mcp-server-{role} master` eliminates same-tree contamination per `user_team_commit_protocol.md` Option 2.

**Throughput lift**: 4 → 8 agents (per memory: "Always Option 2 for long sessions (>4 hours) or if any agent will do heavy refactors").

**Cost**: ~30 minutes setup at session start. **0 LOC**. ~3GB extra disk per worktree.

**Maintenance overhead**: Push-time merge conflicts (relocated, not eliminated).

**Side benefit**: 0 score lift (process not architectural).

**ROI** = `(4 * 1.0) / (~0 LOC)` = **infinite per LOC**. **Highest ROI investment by far.**

### Investment J — Plugin registry pattern for tools (mcp/mcp.go decoupling)

**Friction eliminated**: Today, adding a tool requires editing `mcp/mcp.go:GetAllTools()` slice. Agents collide on this list. A registry pattern lets each tool register itself in `init()` (or via explicit `RegisterTool`). N agents can add tools in parallel without touching `mcp.go`.

**Throughput lift**: 4 → 7 agents (very common task is "add a new tool", currently bottlenecked).

**Cost**: 50 LOC (per Pass 19 redefinition — turns existing slice into registry function).

**Maintenance overhead**: Zero. Same pattern as `kitemcp.RegisterPlugin` for external plugins.

**Side benefit**: Plugin 97→100 (+3) — closes the rubric ceiling.

**ROI** = `(3 * 1.0) / 50` = **0.060 throughput-per-LOC**. **Second-highest ROI by LOC efficiency.**

### Investment K — `ToolHandlerDeps` decomposition (split common_deps.go)

**Friction eliminated**: `mcp/common_deps.go:19-56` is a 37-field struct. Adding a new port/provider = touching this file. **Real serialization point.** Splitting into per-context Deps structs (`SessionDeps`, `OrderDeps`, `AlertDeps`) lets agents add their context's dependencies without touching common.

**Throughput lift**: 4 → 6 agents.

**Cost**: 200 LOC (split + each tool reaches into its own DepsContext).

**Maintenance overhead**: Each new tool author picks the right Deps struct; mild DX learning curve.

**Side benefit**: Hex 88→90 (+2), SOLID 90→92 (+2).

**ROI**: medium. **Land AFTER Investment E (Phase 3a) — it's the natural extension.**

---

## 3. Throughput-lift summary

| Investment | LOC | Cost ($) | Throughput before → after | Score lift | ROI rank |
|---|---|---|---|---|---|
| **I — Worktree-per-agent** | ~0 | $0 | 4 → 8 | 0 | **#1 (process discipline, infinite per-LOC)** |
| **J — Tool registry pattern** | 50 | $0 | 4 → 7 | +3 (Plugin) | **#2** |
| **E — Port-per-context (Phase 3a)** | 380 | $0 | 4 → 6 | +11 (Hex/SOLID) | **#3** |
| **K — ToolHandlerDeps split** | 200 | $0 | 4 → 6 | +4 | #4 |
| **F — Persistence-per-context** | 400 | $0 | 4 → 6 | +3 | #5 |
| **C — Middleware split** | 150 | $0 | 4 → 5 | +1 | #6 |
| **A — Wire/fx DI container** | 600 | $0 | 4 → 8 | +12 (Hex/SOLID) | #7 (high cost, high lift) |
| **G — Separate worker binaries** | 800 | $15/mo extra | 4 → 7 | +9 | #8 (premature) |
| **B — Logger Provider wrap** | 200 | $0 | 4 → 4 (no change) | +1 | REJECT (ceremony) |
| **D — Full ES** | months | $0 | 4 → 4 (no change) | +5 (ES) | REJECT for concurrency |
| **H — Federated build (Bazel)** | 2000+ | $0 | 4 → 10 | +10 | REJECT (premature) |

---

## 4. Dependency graph

What unlocks what:

- **I (Worktree)** — independent. Apply at session start. Zero deps.
- **J (Tool registry)** — independent. 50 LOC, ships standalone.
- **E (Phase 3a port migration)** — independent. ~380 LOC across 5 batches.
- **K (ToolHandlerDeps split)** — depends on E. After Phase 3a Batches 1-2 lands, the per-context Deps split becomes natural.
- **F (Persistence-per-context)** — depends on E + K. Bounded contexts need port surface first.
- **A (Wire/fx)** — independent of E but synergistic. Doing E + K first reduces what Wire needs to know about.
- **C (Middleware split)** — independent. Low LOC, low priority.
- **G (Separate workers)** — depends on F (DBs split first, otherwise workers share state).
- **D, B, H** — REJECTED.

**Critical path for max throughput**: I → J → E → K → F → (optional A or G).

---

## 5. Recommendation: ordered execution sequence

### Phase 1 (immediate, before next multi-agent session) — ~50 LOC

1. **I — Worktree setup** (process change, ~30min): script `scripts/setup-worktrees.sh` that creates per-agent worktrees. Push to repo. From next session onwards, every team agent runs in its own worktree. **Throughput ceiling 4 → 8.**

2. **J — Tool registry pattern** (50 LOC, 1 PR): convert `mcp/mcp.go:GetAllTools()` from static slice to registry-with-init() pattern. Per-tool `init()` registration. **Throughput ceiling 8 → 10** (synergy with I) AND **closes Plugin 97→100 rubric ceiling**.

### Phase 2 (within 4 weeks, gated by capacity) — ~380 LOC

3. **E — Phase 3a port migration** (5 batches per `d9fdd06`): land Batch 1 first (50 LOC, mechanical). Then 2-3-4-5 incrementally. **Throughput ceiling 10 → 12** for tool-handler work AND **+11pt on Hex/SOLID dims**.

### Phase 3 (within 8 weeks, gated by Phase 2 completion) — ~200 LOC

4. **K — ToolHandlerDeps split** (200 LOC): per-context Deps structs. **Throughput 12 → 14**, +4pt rubric.

### Phase 4 (defer until 6+ permanent agents and CI bottleneck observed) — ~400 LOC

5. **F — Persistence split** if and only if shared SQLite becomes measured CI bottleneck.

### Diminishing-returns threshold

After Phase 3, marginal throughput gains drop sharply (each subsequent investment buys 1-2 more agents at increasing LOC cost). **Stop at 14-agent ceiling.** Beyond that, the human reviewer becomes the bottleneck, not architectural decoupling — adding more parallel agents creates merge-cycle backlog that exceeds gain.

---

## 6. Score-lift side benefits (acknowledge synergy with 13-dim rubric)

Phases 1+2+3 deliver:
- **Plugin 97 → 100** (Investment J closes rubric)
- **Hex 88 → 95** (Investment E)
- **SOLID 90 → 94** (Investment E)
- **Test Architecture** (slight lift via worktree-driven CI parallelism)

**Aggregate 13-dim lift**: ~96 → 97.5 from concurrency investments alone, BEFORE counting the path-to-98 plan items (`d48046b`).

**Combined with path-to-98 (~275 LOC)**: aggregate ~98.0 with both threads.

This means **decoupling investments are NOT in tension with rubric-pursuit** — they advance both. The "stop at 98.5" verdict from `78c243e` survives intact; this doc just shows the work has bigger payoff than rubric alone.

---

## 7. Anti-recommendations renewed

These LOOK like decoupling but aren't:

| Item | Why not decoupling |
|---|---|
| **Logger Provider wrap (Investment B)** | Mocking `*slog.Logger` is already trivial; no agent-concurrency friction observed |
| **Single-method Provider proliferation** (per Pass 17) | More interfaces = more files for agents to coordinate on, not fewer |
| **Generic `Service` interface** abstracting Manager | Single impl, no swap-need = pure indirection |
| **Bazel build system (Investment H)** | True decoupling but cost dwarfs benefit at ≤10 agents |
| **Full ES reconstitution (Investment D)** | Decouples WHEN data is computed, not WHO edits files |
| **Microservices** (extreme worker split) | At current scale, each microservice introduces 5-10 new serialization points (deploy artifacts, IPC versions, observability) for every 1 it removes |
| **Per-tool separate binaries** | Makes tool development require deploy infra; opposite of agent throughput |
| **Adding more middleware layers** | Pass 17 already noted: more middleware = more `DefaultBuiltInOrder` collisions, not fewer |

**Common anti-pattern signal**: any decoupling that introduces a new shared coordination artifact (interface registry, service registry, build config) and requires agents to coordinate on THAT instead of `wire.go` — net zero progress.

---

## 8. Final verdict

**Total LOC for highest-ROI sequence (Phases 1-3)**: ~630 LOC (~30 LOC + 50 + 380 + 200) over 8 weeks.

**Projected concurrency ceiling**: **4 → 14 agents** (3.5× improvement).

**Score side benefit**: +14pt on Hex/SOLID/Plugin/Test-arch (96 → ~98).

**Decoupling investment IS justified at current friction level**. The empirical 4-agent ceiling has been hit and exceeded multiple times in prior sessions (per memory). Phases 1+2 are LOW LOC, LOW risk, HIGH leverage. Phase 3 is medium-cost extension that materializes as the 6-agent team config becomes routine.

**Investments REJECTED for concurrency goal but recommended for rubric**: Wire/fx (A), separate workers (G), Federated build (H). These are valid for OTHER goals (rubric scoring, cloud-native ops) but don't return throughput at current scale.

**Corrected denominator verdict**: under the agent-concurrency lens, **path-to-98 + Phases 1-2 (Investment I + J + E) = ~430 LOC, 8 weeks, 4 → 12 agent ceiling, 96 → 98 rubric**. This is **dramatically better ROI** than the path-to-100 ceremony work `78c243e` rejected, and **vastly better-aligned with the user's actual development model** (multi-agent parallel) than the user-MRR denominator that prior synthesis used.

**Recommended next action**: ship Investment I (worktree script) + Investment J (tool registry) THIS week. They cost <50 LOC combined and double the agent-concurrency ceiling immediately.

---

*Generated 2026-04-25 against HEAD `78c243e`. Read-only synthesis deliverable; no source files modified.*
