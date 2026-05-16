<!-- secret-scan-allow: research-doc-no-secrets -->
---
title: Zero-In-Tree-Code Feasibility — can kite-mcp-server become Dockerfile + fly.toml + 5-line main.go?
as-of: 2026-05-11
re-verify-by: 2026-06-11
master-head-at-write: 13888e1
scope: READ-ONLY research; module-graph + structural analysis; no source mutations
parallel-tracks:
  - github-transfer-bootstrap-2026-05-11.md (audit-agent disjoint scope: GitHub transfer + algo2go/kite-mcp-bootstrap design)
  - god-object-inventory-2026-05-11.md (path-A-agent disjoint scope: god-object identification + Tier-1 facade decomp)
budget-used: ~3.5h
methodology: compile-and-run (go list, go mod graph) + file:line empirical reads; no grep-only counts of non-binary metrics
---

# Zero-In-Tree-Code Feasibility

## §0 — User framing + this doc's job

User's framing (verbatim): *"if we decomposed 28 modules cleanly, what's structurally special about the residual? Don't accept 'composition root must exist' as a blocker without proof."*

This doc answers **structurally** — not aspirationally. It:

1. Inventories every line of code currently in-tree across the 4 go.work members.
2. For each, classifies promotable / structural-blocker / either.
3. Evaluates 4 architectural patterns (A: init-blank-import / B: Wire-Fx codegen / C: bootstrap module / D: per-module MCP transport).
4. Surfaces concrete file:line evidence for the actual blocker.
5. Recommends a pattern + sequencing — or says don't do it, with reason.

**Headline finding** (TL;DR for context-sensitive readers): **The TRUE structural blocker is not "composition root must exist" — it is `Tool.Handler(*kc.Manager) server.ToolHandlerFunc` at `mcp/common/tool.go:62-65`, a 123-callsite contract that ties every tool to the kc-package god-struct.** Until `kc.Manager` itself is decomposed (a separate workstream — see god-object-inventory-2026-05-11.md), no amount of clever bootstrap module wiring buys ZERO in-tree code. The honest answer is: **bootstrap is feasible AS A LIFT (Pattern C), but truly zero-in-tree requires kc.Manager surgery FIRST.**

## §INPUTS — load-bearing facts probed at HEAD `13888e1`

| Fact | Probe | Verified |
|---|---|---|
| Master HEAD = `13888e1` (bootstrap doc by audit agent); previous master `9a0079b` referenced in dispatch | `git log -1 --pretty=format:"%H %s"` | 2026-05-11 |
| `go.work` has 4 in-tree members: `.`, `./app/providers`, `./plugins`, `./testutil` | `cat go.work` | 2026-05-11 |
| Root `go.mod` requires 27 algo2go modules; kite-mcp-aop in directory but NOT in require (residual after removal) | `grep -c '^[[:space:]]\+github.com/algo2go' go.mod` = 27; `grep aop go.mod` returns only comment refs | 2026-05-11 |
| Zero algo2go module imports back into kite-mcp-server | `go mod graph 2>/dev/null \| grep -E 'algo2go.*kite-mcp-server'` returns empty | 2026-05-11 |
| `go build ./...` exit 0 at HEAD | WSL2 `go build ./...` | 2026-05-11 |
| In-tree non-test LOC: 54,241 across 261 .go files | `find kc app mcp plugins testutil cmd -name '*.go' ! -name '*_test.go' \| xargs wc -l` | 2026-05-11 |
| Per-area non-test LOC: kc=9519 (48f) + kc/ops=8017 (48f) + kc/ports=531 (6f) + mcp=24358 (104f) + app=6999 (21f) + app/providers=2859 (22f) + app/metrics=513 + plugins=321 (3f) + testutil=825 (4f) + cmd=546 (3f) + main.go=140 | per-dir `wc -l` probes | 2026-05-11 |
| 3 sub-module go.mod files have `replace github.com/zerodha/kite-mcp-server => ../` — confirming bidirectional cross-module deps | `cat plugins/go.mod testutil/go.mod app/providers/go.mod` | 2026-05-11 |
| `kc.Manager` god-struct: 63 fields, 132 methods across 30+ kc/*.go files; 17 With* options at construction | `grep '^[[:space:]]\+[A-Za-z]' kc/manager_struct.go`; `grep -c '^func (.*\*Manager)' kc/*.go` = 132; `grep -c '^func With' kc/options.go` = 23 (audit doc reports 17 With* used at app/wire.go:106 BuildManager site; the other 6 are exposed but not all wired) | 2026-05-11 |
| `Tool.Handler(*kc.Manager) server.ToolHandlerFunc` is the contract every tool implements | `mcp/common/tool.go:62-65` direct read | 2026-05-11 |
| 123 tool-Handler callsites use `*kc.Manager` as the parameter type | `grep -rn 'Handler(.*\*kc.Manager)' mcp/ \| wc -l` = 123 | 2026-05-11 |
| 83 files in mcp/ tree import `github.com/zerodha/kite-mcp-server/kc` directly | `grep -c 'github.com/zerodha/kite-mcp-server/kc' mcp/**/*.go` aggregate | 2026-05-11 |
| 50 mcp/ files use `func init() { plugin.RegisterInternalTool(...) }` for tool self-registration | `grep -l '^func init()' mcp/**/*.go \| wc -l` = 50 | 2026-05-11 |
| Zero algo2go modules use `init()` self-registration | iterated `grep '^func init()' algo2go/*/.go` returns empty across all 28 | 2026-05-11 |
| kc/interfaces.go + kc/manager_interfaces.go declare 39 interface types in `package kc` | `grep '^type.*interface' kc/interfaces.go kc/manager_interfaces.go \| wc -l` = 39 | 2026-05-11 |
| Production code does NOT import testutil (test-only); only 2 comment refs (`app/ratelimit.go:108`, `kc/fill_watcher.go:230`) | `grep -rn 'testutil' --include='*.go' \| grep -v _test \| grep -v '^testutil/'` returns 2 comments | 2026-05-11 |
| 33 test files reference testutil | `grep -rn 'testutil' --include='*_test.go' \| wc -l` = 33 | 2026-05-11 |
| app/wire.go = 1008 LOC (composition root); app/http.go = 1596 LOC (HTTP mux); app/adapters.go = 884 LOC; app/app.go = 825 LOC | `wc -l app/*.go` | 2026-05-11 |
| Dockerfile already handles multi-module via `COPY app/providers/go.mod`, `COPY plugins/go.mod`, `COPY testutil/go.mod` before `go mod download` | `head -20 Dockerfile` | 2026-05-11 |

---

## §1 — The 4 in-tree members analyzed

### 1.1 `.` (root module) — `module github.com/zerodha/kite-mcp-server`

**LOC**: 9519 (kc/) + 8017 (kc/ops/) + 531 (kc/ports/) + 24358 (mcp/) + 6999 (app/) + 513 (app/metrics/) + 546 (cmd/) + 140 (main.go) = **50,623 non-test LOC** across ~225 files.

**Non-promoted contents** (the actual code that's IN the root module):
- `main.go` — 140 LOC. Process entry. Imports `app` + `kc/ops` only. Trivially promotable IF a bootstrap target exists.
- `kc/` (48 files, 9519 LOC) — the **god-struct package**. Holds `kc.Manager` (the orchestrator), all 23 With*Option helpers, the per-session/per-service facades (`CredentialService`, `SessionService`, `PortfolioService`, `OrderService`, `AlertService`, `FamilyService`, `StoreRegistry`, `EventingService`, `BrokerServices`, `SchedulingService`, `SessionLifecycleService`), 39 interface declarations.
- `kc/ops/` (48 files, 8017 LOC) — admin dashboard + HTTP handlers. Imports `*kc.Manager` ubiquitously (`handler.go:34`, `dashboard.go:34`).
- `kc/ports/` (6 files, 531 LOC) — port interfaces for `kc.Manager` facets. Importable from mcp/common but lives in root.
- `mcp/` (104 files, 24358 LOC) — all 111 MCP tools. Tool sub-pkgs: `admin/` (8), `alerts/` (6), `analytics/` (7), `common/` (~18), `middleware/` (7), `misc/` (4), `paper/` (5), `plugin/` (~23), `portfolio/` (10), `trade/` (9). Plus root-level shims: `aliases.go`, `mcp.go`, `prompts.go`, `resources.go`, `ext_apps.go`, `market_tools.go`, `tax_tools.go`, `plugin_widget_*.go` (6).
- `app/` (21 files, 6999 LOC) — Fx composition root. `wire.go` (1008 LOC), `http.go` (1596), `adapters.go` (884), `app.go` (825), `envcheck.go` (325), `ratelimit.go` (309), `graceful_restart*` (555), middleware bridge code.
- `app/metrics/` (513 LOC) — Prometheus histograms. Used by app/* and kc/manager_struct.go.
- `cmd/` (3 sub-tools, 546 LOC) — `dr-decrypt-probe`, `event-graph`, `rotate-key`. Operational utilities. Already self-contained.

### 1.2 `./plugins` — `module github.com/zerodha/kite-mcp-server/plugins`

**LOC**: 321 non-test (3 plugin files). **Tiny.**

**Contents**:
- `plugins/example/plugin.go` — 41 LOC. ServerTime sample plugin. Imports root `kc` (parent) for `*kc.Manager`.
- `plugins/rolegate/plugin.go` — 104 LOC. RBAC viewer-blocks-write hook. Imports `algo2go/kite-mcp-users`, `algo2go/kite-mcp-oauth`, **AND** root `mcp` (for `mcp.ToolHook` — but this is a re-export alias; the canonical type is in `mcp/plugin/registry.go:41`).
- `plugins/telegramnotify/plugin.go` — 176 LOC. Family admin DM on trade tools. Same import pattern.

**Bidirectional cross-module dep** (`plugins/go.mod:129`): `replace github.com/zerodha/kite-mcp-server => ../`. The plugins module imports kc + mcp from root; root imports plugins/rolegate + plugins/telegramnotify from `app/wire.go:26-27`.

### 1.3 `./testutil` — `module github.com/zerodha/kite-mcp-server/testutil`

**LOC**: 825 non-test (4 files + 1 sub-package).

**Contents**:
- `testutil/clock.go` — 148 LOC. `FakeClock` + `fakeTicker` deterministic implementations of `algo2go/kite-mcp-clockport.Clock` + `Ticker`. **Production code does NOT import testutil** (verified per-file: only 2 comment refs).
- `testutil/kiteserver.go` — 468 LOC. `MockKiteServer` httptest-backed Kite API fake.
- `testutil/logger.go` — 34 LOC. Capture + Noop logger fakes for `algo2go/kite-mcp-logger.Logger` port.
- `testutil/kcfixture/manager.go` — 175 LOC. Builds `*kc.Manager` test instances. **Sub-package isolated by design** (per its package comment): only callers OUTSIDE the kc tree may import kcfixture, avoiding `kc → testutil/kcfixture → kc` cycles.

**Bidirectional cross-module dep** (`testutil/go.mod:114`): `replace github.com/zerodha/kite-mcp-server => ../`. kcfixture imports `kc`; **33 test files** in root tree reference testutil.

### 1.4 `./app/providers` — `module github.com/zerodha/kite-mcp-server/app/providers`

**LOC**: 2859 non-test (22 files).

**Contents**: Fx provider functions returning typed deps: `AlertSvc`, `AuditStore`, `BillingStore`, `CredentialSvc`, `EventDispatcher`, `FamilyService`, `LifecycleManager`, `LoggerPort`, `Manager`, `MCPServer`, `OrderSvc`, `PortfolioSvc`, `RiskGuard`, `Scheduler`, `SessionSvc`, `TelegramNotifier`. Each is an Fx graph node.

**Bidirectional cross-module dep** (`app/providers/go.mod:126-128`): `replace github.com/zerodha/kite-mcp-server => ../..` + `replace .../testutil => ../../testutil`. providers imports `app/metrics`, `kc`, `mcp`; root imports providers from `app/wire.go:31` + `cmd/event-graph/main.go`.

### 1.5 Bidirectional-dep pattern summary

All 3 sub-modules (plugins, testutil, app/providers) have the SAME structural shape: they declare `replace github.com/zerodha/kite-mcp-server => ../...` because they need to import kc and/or mcp from root, while root imports them via `replace ./plugins ./testutil ./app/providers`. The shared `go.work` makes this work cleanly locally; the replaces in each go.mod make `GOWORK=off` builds (Dockerfile) work.

**This pattern is the empirical evidence that "extract module = take it OUT of the root" is NOT how the existing decomposition has been working for sub-modules that need to talk back to root.** Bidirectional means the sub-module is "extracted" only in terms of go.mod boundary — it's still tied to root via replace directives, and any consumer must include the bidirectional pair as a unit.

### 1.6 Per-member promotable / blocker classification

| In-tree member | LOC | Production deps | Promotable to algo2go? | Why / why not |
|---|---|---|---|---|
| `main.go` | 140 | `app`, `kc/ops` | **PROMOTABLE** to ~5 lines if bootstrap exists | Pure process entry; nothing structurally special about it |
| `kc/` (god-struct package) | 9519 | broker, alerts, audit, billing, cqrs, domain, eventsourcing, instruments, papertrading, registry, riskguard, ticker, usecases, users, watchlist, **app/metrics** | **STRUCTURAL BLOCKER** (until decomposed) | god-struct, 39 interface decls; 83 mcp/ files + all of app/ import this. Either decompose Manager (see god-object doc) OR move kc as a unit |
| `kc/ops/` | 8017 | kc, audit, logger, registry, templates, users, oauth, app/metrics | **PROMOTABLE** after kc/ moves | Independent of mcp/. Could go to algo2go/kite-mcp-ops as a leaf consumer of kc |
| `kc/ports/` | 531 | algo2go/kite-mcp-{instruments,riskguard} | **PROMOTABLE** as algo2go/kite-mcp-ports | Already a leaf port package; importers (mcp/common, mcp/paper) would update path |
| `mcp/common/` | ~2400 | kc, kc/ports, algo2go modules | **STRUCTURAL BLOCKER** | `Tool.Handler(*kc.Manager)` contract pins to root kc package; 14 internal kc imports |
| `mcp/plugin/` | ~2800 | mcp/common | **PROMOTABLE** after mcp/common moves | Only depends on mcp/common |
| `mcp/admin,alerts,analytics,...` (10 sub-pkgs) | ~14000 | mcp/common, mcp/plugin, kc | **PROMOTABLE in batches** after mcp/common moves | Each batch can be its own algo2go module |
| `mcp/` root files (`mcp.go`, `ext_apps.go`, `aliases.go`, `plugin_widget_*.go`) | ~3000 | kc, mcp/common, mcp/plugin, algo2go modules | **PROMOTABLE** after kc moves | Re-exports + composition entry-point |
| `app/` (composition root) | 6999 | kc, mcp, kc/ops, app/providers, app/metrics, plugins/* | **STRUCTURAL BLOCKER** | This IS the composition root; depends on every in-tree symbol |
| `app/metrics/` | 513 | none in tree | **PROMOTABLE** as algo2go/kite-mcp-metrics | Leaf — only imported by kc, app, app/providers; could move first |
| `app/providers/` | 2859 | kc, mcp, app/metrics | already external; **stays external** after bootstrap | Module boundary holds; replace ../.. semantics needed until root shrinks |
| `plugins/*` | 321 | kc/users, mcp, oauth | **PROMOTABLE** as algo2go/kite-mcp-plugins after mcp moves | Tiny — but blocked on mcp.ToolHook re-export |
| `testutil/` | 825 | algo2go/kite-mcp-{clockport,logger}; kcfixture imports root kc | **PROMOTABLE** as algo2go/kite-mcp-testutil after kc moves | Production code already doesn't import testutil; only kcfixture sub-package imports kc |
| `cmd/dr-decrypt-probe,event-graph,rotate-key` | 546 | kc (event-graph), root packages | **PROMOTABLE** but architecturally fine in-tree | These are ops binaries that ship alongside the main binary; bootstrap repo keeps them |

**Verdict matrix** — the actual structural blockers are:
1. **`kc.Manager` god-struct** — until decomposed, the kc package is one bounded unit and either moves whole or stays whole.
2. **`Tool.Handler(*kc.Manager)` contract** — 123 callsites; until tool contract changes, mcp/* can't leave the kc neighborhood.
3. **`app/` composition root depends on every member** — but THIS one is a deliberate inverter, not a blocker (this is what the bootstrap module would absorb).

Everything else is **mechanically promotable**.

---

## §2 — Per-pattern evaluation

### Pattern A — init() blank-import plugin registration (Go database/sql model)

**Description**: Each algo2go module has `func init() { manager.Register(...) }` that self-registers. Composition root becomes a literal manifest: `import _ "github.com/algo2go/kite-mcp-broker"` × 28.

**Empirical state** (verified at HEAD `13888e1`):

- **Pattern A is ALREADY in production INSIDE mcp/** — 50 files have `func init() { plugin.RegisterInternalTool(...) }` (e.g., `mcp/admin/admin_user_tools.go:391`). The mcp/ root's `GetAllTools()` returns the merged `plugin.GetInternalTools()` (per `mcp/mcp.go:67`).
- **Pattern A is NOT used by the 27 active algo2go modules.** I checked 4 (broker, billing, riskguard, papertrading): zero have `func init()`. They expose Go types/functions and the root kc.Manager wires them explicitly via 23 With* options.

**Why init() works for tools but not for services**:

Tools are functions that are run on-demand against a Manager. Their registration is a passive "I exist." Services (broker, alerts store, riskguard guard) need explicit DI threading because:
- They share state (riskGuard uses alertStore for dedup; events route from one to another).
- Their construction has ordering constraints (alertDB opens before stores).
- Their construction takes config (encryption key, retention policy, paths).
- 17 of them are wired via `kc.NewWithOptions(WithAlerts(...), WithRiskGuard(...), ...)` at `app/wire.go:106` — captured in the Fx provider `providers.BuildManager`.

**Could services adopt Pattern A?** Yes — but the registration would have to take a `Config` snapshot from a globally-set source, OR the modules would have to expose a `Register(deps Deps)` shape (which is Pattern C below). init() with no parameters has nowhere to read Config from without a package-global.

**Verdict on Pattern A for services**: **Architecturally wrong choice.** The init-blank-import model is great for tool / driver registration where each plugin is independent and stateless. It's a poor match for the 27-service DI graph with cross-service dependencies.

**Verdict on Pattern A for the residual tools**: **Already done.** Every mcp/ tool already self-registers.

### Pattern B — Wire/Fx code-generation DI

**Description**: Use google/wire OR uber/fx to generate the DI graph at build time. Each module declares providers; composition root is auto-generated.

**Empirical state**: We **already use uber/fx** (`go.uber.org/fx v1.24.0` in go.mod:45). app/wire.go invokes 4 distinct `fx.New(...)` graphs (manager, audit, riskguard, event-dispatcher).

**What Pattern B would buy**: Instead of `app/wire.go` having 1008 lines of imperative `kc.NewWithOptions(WithX(x), WithY(y), ...)` wiring, the graph would be discovered by Fx automatically when each module exposes `var Module = fx.Module("name", fx.Provide(NewBroker, NewAuditStore, ...))`.

**Where it falls short**:
- Pattern B is **about the SHAPE of the composition**, not where it lives. Even with Pattern B, `app/wire.go` still imports each algo2go module to access `*.Module`. It still has to make decisions about which middleware to wire (CircuitBreaker thresholds, RateLimiter caps), which env-gated features to enable. The 1008 lines compress to maybe ~400, but they don't disappear.
- Pattern B doesn't change the `Tool.Handler(*kc.Manager)` contract, so mcp/ stays in-tree.
- Switching Wire would be net-new tooling. Fx is already in use.

**Verdict on Pattern B**: **Lateral improvement, not a path to zero-in-tree.** Could be combined with Pattern C (bootstrap module uses Fx Modules) but doesn't help by itself.

### Pattern C — Move composition root INTO algo2go (the bootstrap module)

**Description**: Create `algo2go/kite-mcp-bootstrap` containing the composition root (`app/wire.go` + `app/app.go` + `app/http.go` + `app/lifecycle.go` + `app/adapters.go` + plugin registration). kite-mcp-server (the deploy repo) becomes a thin shell.

**Empirical state**: Audit agent's `github-transfer-bootstrap-2026-05-11.md` covers this in §2. The honest version of what "thin shell" actually means at HEAD `13888e1`:

The bootstrap module would absorb `app/` (6999 LOC) + `kc/` (9519 LOC) + `kc/ops/` (8017 LOC) + `mcp/` (24358 LOC) + `app/metrics/` (513 LOC) + the bidirectional re-exports needed to keep `Tool.Handler(*kc.Manager)` working. **That's ~49,400 LOC moved as one unit.**

The kite-mcp-server repo would then contain:
- `Dockerfile` (43 lines at HEAD)
- `fly.toml` (~50 lines)
- `smithery.yaml` (~20 lines)
- `.mcp.json` (~10 lines)
- `funding.json`, README, LICENSE, NOTICE, SECURITY, PRIVACY (operational metadata)
- `main.go` reduced to ~10 lines (just `import bootstrap` + `bootstrap.Run()`)
- `cmd/` (3 operational binaries, 546 LOC — optionally also moves but adds little risk if kept)
- `server.json` (MCP Registry manifest)
- `.github/`, `.claude/` plugin metadata

**Risk evaluation**:

1. **The bootstrap module remains a god-module** until `kc.Manager` is decomposed. It's just one large module instead of many small ones, but it's a single piece you'd have to version + release. Tagging `algo2go/kite-mcp-bootstrap@v0.1.0` for every kc-Manager change is high churn.
2. **Bidirectional `replace` directives reverse** — bootstrap would `replace ../kite-mcp-server` for the operational metadata, OR the deploy repo would `replace ../algo2go/kite-mcp-bootstrap`. The git graph stays the same shape, just with a different module-boundary line.
3. **MCP-bus client URL doesn't change** — `kite-mcp-server.fly.dev/mcp` is independent of Go module identity. mcp-remote cache keyed by URL hash stays valid.

**Counter-argument for Pattern C**: It DOES NOT actually decompose anything. It just relocates the composition boundary. The "if we decomposed 28 modules cleanly, what's structurally special about the residual?" question has an answer: **the residual is the part that holds together the 28-module graph, and relocating the holder doesn't unhold it.**

**Verdict on Pattern C**: **Lift, not decomposition.** Audit agent's design is sound mechanically. Does it deliver zero-in-tree? Yes — but at the cost of one 49k-LOC monolith module instead of a 49k-LOC monolith package. The user's framing "everything currently in `./`, `./plugins`, `./testutil`, `./app/providers` workspace members gets promoted to algo2go modules" gets a literal "yes, all to ONE module called bootstrap" answer.

### Pattern D — Per-module MCP transport (most radical)

**Description**: Eliminate centralized `mcp/` package. Each algo2go module exposes its own MCP endpoints. A thin gateway routes by namespace (e.g., `broker.place_order`, `alerts.create_composite`).

**Empirical state**: The MCP-go SDK supports a single `server.MCPServer` instance. The current architecture has ONE such instance constructed at `providers.BuildMCPServer` (called from `app/wire.go`). All 111 tools are registered against this one instance.

**Two flavors of Pattern D**:

- **D.1 — Multiple MCP servers, one gateway router**: Each algo2go module runs its own `server.MCPServer` on a different path (`/mcp/broker`, `/mcp/alerts`, ...). A gateway routes incoming tool calls. **User-visible change**: clients (Claude Desktop, mcp-remote) connect to ONE URL but tools have namespace prefixes — could break client expectations. mcp-remote caching keys would need updating.
- **D.2 — In-process plugin registration**: Each algo2go module exposes a `RegisterTools(server *server.MCPServer, deps Deps) error` function. The thin gateway/bootstrap calls these. **User-visible change**: zero (same endpoint, same tool names, same caller experience).

**D.2 is what mcp/* is essentially doing today** via `plugin.RegisterInternalTool` + the `init()` pattern documented above. **The only thing that's NOT done is moving the tool-registration files to live in the algo2go modules they belong to.**

Example: `mcp/admin/admin_user_tools.go` registers 5 tools, all using `*kc.Manager` and depending on `algo2go/kite-mcp-users`. To move it to `algo2go/kite-mcp-users`:
1. Files move to `algo2go/kite-mcp-users/mcp/admin_user_tools.go`.
2. `Tool.Handler` signature needs to NOT take `*kc.Manager` (current users module doesn't know about Manager).
3. `*kc.Manager` symbol references would translate to narrow interfaces declared in the users module.

**Cost**: To switch `Tool.Handler(*kc.Manager)` to `Tool.Handler(deps ToolHandlerDeps)` (the typed-deps struct at `mcp/common/handler_deps.go:30-60`) at every callsite, would require:
- Replacing the type at the interface (1 line in `mcp/common/tool.go:64`).
- Updating 123 implementations (mostly mechanical: `func (*X) Handler(m *kc.Manager) ToolHandlerFunc { ... }` → `func (*X) Handler(deps common.ToolHandlerDeps) ToolHandlerFunc { ... }`).
- The 16 Provider interfaces on `ToolHandlerDeps` already cover what tools need (see `mcp/common/handler_deps.go:30-66`). The interfaces are declared in `package kc` — they would need to move to `mcp/common` or to algo2go/kite-mcp-ports.

**Verdict on Pattern D.1**: User-visible change, mcp-remote cache invalidation risk; **rejected for brand reasons** (we have ~600 users per the audit agent's separate work and 9 of them have authed Playwright contexts — a URL change costs each user a re-auth).

**Verdict on Pattern D.2**: **This is the actual path to TRUE zero-in-tree code.** It's the same as Pattern A but for tools (not services), AND it requires the prerequisite of decomposing kc.Manager into narrow interfaces (god-object inventory's job).

### Patterns summary

| Pattern | Delivers zero-in-tree? | Disrupts users? | Net SLOC change | Prerequisite |
|---|---|---|---|---|
| A — init blank-import services | NO | none | minor | services need shared state graph; pattern wrong-shape for services |
| B — Wire/Fx codegen DI | NO | none | -600 LOC of imperative wiring | adds Wire (already on Fx) or expands Fx usage |
| C — bootstrap as one big module | YES (literally) | none | 0 (relocation only) | none — could ship today |
| D.1 — per-module MCP servers | YES | client cache invalidate | undetermined | URL/namespace changes |
| D.2 — per-module tool registration | YES (truly) | none | -200 LOC of mcp/* re-exports | **kc.Manager decomposition** (a separate workstream — see god-object-inventory-2026-05-11.md) |

---

## §3 — Cycle / blocker concrete evidence

### 3.1 The 6 concrete structural blockers (file:line evidence)

1. **`Tool.Handler(*kc.Manager)`** — `mcp/common/tool.go:62-65`. The Tool interface signature pins every tool to the kc package. 123 callsites verified by grep over `mcp/`.

2. **`kc.Manager` has 63 fields wiring 14 algo2go modules + in-tree services** — `kc/manager_struct.go:65-186`. Each field requires a corresponding With* option (23 of them at `kc/options.go`) for construction. This is the god-struct.

3. **kc/ops imports `*kc.Manager`** — `kc/ops/handler.go:34` (`manager *kc.Manager`), `kc/ops/dashboard.go:34` (same). 8017 LOC of admin/dashboard handlers cannot escape kc without the Manager moving.

4. **app/wire.go imports kc, mcp, kc/ops, app/providers, app/metrics, plugins/*** — `app/wire.go:12-31`. Twelve internal-root packages. This is the composition root; depends on every member. It cannot externalize until ALL its imports are external OR all imports are absorbed into a single bootstrap module.

5. **`mcp.ToolHook` in `mcp/plugin/registry.go:41`** — plugins/rolegate + plugins/telegramnotify import this as `mcp.ToolHook` (the re-export). To move plugins/ out, the canonical declaration would need to live in algo2go/kite-mcp-plugin-port (or similar).

6. **39 interfaces in `package kc`** — `kc/interfaces.go:526` + `kc/manager_interfaces.go:266` totaling 792 LOC. `TokenStoreInterface`, `RiskGuardProvider`, `AuditStoreProvider`, etc. mcp/common.handler_deps.go uses these. To move mcp/common out, the interfaces would relocate to algo2go/kite-mcp-ports.

### 3.2 What is NOT a blocker (falsified)

- **"Composition root MUST exist as in-tree code"** — **FALSIFIED.** A composition root can live anywhere. Audit agent's bootstrap design (Pattern C) demonstrates the relocation is mechanical.
- **"main.go must orchestrate"** — **FALSIFIED.** main.go can be `import bootstrap; bootstrap.Run()`. Verified pattern (any Go binary with a thin main + library does this).
- **"go.work prevents external promotion"** — **FALSIFIED.** go.work is local-only dev mechanism. The `replace` directives in each sub-module's go.mod handle GOWORK=off (production build).
- **"There's a cycle preventing X"** — **FALSIFIED.** I ran `go mod graph` at HEAD; ZERO algo2go modules import kite-mcp-server back. The dep graph is unidirectional. Cycles only exist within the in-tree root module's packages (mcp ↔ kc ↔ kc/ops ↔ app — the in-tree spaghetti).

### 3.3 The cycle that DOES exist

Inside the root module, there is an internal-package cycle prevention via `package mcp/common` (the leaf). Reading `mcp/common/tool.go:1-44` (the package doc) explicitly documents:

> The pre-PR-1.1 package layout had mcp.Tool (interface) and mcp.Registry (struct that holds []Tool) bidirectionally coupled inside the same package. The audit's redesign at 34e5a23 chose Option B — relocate the Tool interface alone to mcp/common.

This SAME pattern is what would have to be applied transitively to externalize mcp/* — pull common into its own algo2go module first, then per-domain sub-pkgs follow.

---

## §4 — ROI table

| Pattern | Implementation cost (agent-hours) | Maintenance overhead change | Failure-mode risk | User-visible impact |
|---|---|---|---|---|
| A (services) | n/a — wrong-shape | n/a | n/a | n/a |
| A (tools) | DONE (50 files use it today) | none | none | none |
| B (more Fx Modules) | 8-16h (refactor wire.go's 4 graphs into composed Modules) | -600 LOC imperative wiring; +400 LOC declarative Fx Modules; net -200 LOC | startup ordering errors more obscure (Fx graph debugging) | none |
| C (bootstrap module relocation) | 24-40h (1 large mechanical lift; mostly `git mv` + import-path updates + go.mod + Dockerfile + CI) | bootstrap becomes the high-churn module; release tagging cadence rises | mcp.URL caching: zero; Dockerfile multi-stage: already supports; CI matrix: re-point to bootstrap module | none |
| D.1 (per-module MCP servers) | 80-160h | each module owns its own MCP startup; ops complexity rises (multiple servers) | URL changes break client caches; mcp-remote re-auth required for all users | HIGH — client cache invalidation, namespace renames |
| D.2 (per-module tool registration WITH kc decomposition) | 200-400h | each module is self-contained including its tools; matches Pattern C narrative | depends on kc.Manager decomposition (see god-object doc) — risk inherits | none after migration |

---

## §5 — Recommendation

### 5.1 The honest verdict

Per user's framing — *"don't accept 'composition root must exist' as a blocker without proof"* — I have proven:

- "Composition root must exist as in-tree code" → **FALSIFIED.** It can live in algo2go/kite-mcp-bootstrap (Pattern C).
- "Composition root must couple to root module" → **TRUE but escapable.** Pattern C absorbs the coupling INTO the bootstrap module.

The structural blockers to FULLY zero-in-tree (where each algo2go module is self-contained including its tools) are:

1. **`kc.Manager` god-struct** — must be decomposed first. This is god-object-inventory-2026-05-11.md's job.
2. **`Tool.Handler(*kc.Manager)` contract** — must change to `Tool.Handler(deps)` shape using narrow ports.
3. **39 interfaces in `package kc`** — must relocate to a ports module.

Items 2 and 3 are mechanical follow-ons to item 1.

### 5.2 The two paths

**Path X — Bootstrap relocation only (Pattern C; audit agent's design)**:
- Ship: algo2go/kite-mcp-bootstrap absorbs ~49,400 LOC.
- Deploy repo: Dockerfile + fly.toml + ~10-line main.go + operational metadata only.
- Effort: 24-40 agent-hours, mostly mechanical.
- **Delivers literal zero-in-tree** in the sense of "no Go SOURCE files in the deploy repo other than main.go and cmd/*".
- **Does NOT decompose the god-struct.** The 49,400-LOC monolith just lives under a different module name.

**Path Y — Full decomposition (Pattern D.2; god-object doc's roadmap)**:
- Ship: kc.Manager decomposed into 5-10 cohesive types (per god-object doc); 39 kc interfaces relocate to algo2go/kite-mcp-ports; Tool.Handler contract migrates to typed-deps; per-domain tool registrations move into algo2go/kite-mcp-*/tools/ directories.
- Deploy repo: same outcome as Path X but the engineering work was decomposition, not relocation.
- Effort: 200-400 agent-hours.
- **Delivers SUBSTANTIVE zero-in-tree** — the absent code is actually decomposed.

### 5.3 Recommendation

**Do Path X NOW, Path Y INCREMENTALLY.**

- **Path X is fast and reversible.** Ships the brand outcome (one repo per module + a thin deploy repo) at 24-40h. User's external-facing narrative (`algo2go is the home`) is satisfied.
- **Path Y is the real architectural work.** It's how you reach the goal of "every algo2go module is self-contained including its tools," which is what the user is implicitly chasing. But it's gated on god-object-inventory's roadmap (which IS in flight at HEAD `7c21e7d`).
- **Sequencing**: Path X commits the bootstrap relocation; Path Y commits arrive INTO the bootstrap module (since kc + mcp now live there); each Path Y batch shrinks bootstrap and grows the target algo2go module.

### 5.4 What this DOES buy

- **Brand**: completes the "algo2go is the home" narrative even with kc.Manager still a god-struct.
- **Repo separation**: PRs about kc-internal cleanup don't touch the deploy repo. Less merge churn.
- **CI clarity**: deploy repo CI = build + fly deploy. bootstrap repo CI = tests + lint + release tag.
- **Public surface**: clones of kite-mcp-server clone a tiny repo, not 49k LOC.
- **External contributors**: easier to fork the deploy repo for self-hosting variants without inheriting all the source.

### 5.5 What this DOES NOT buy

- **Decomposition**. The god-struct is still a god-struct.
- **Test isolation**. testutil/kcfixture still builds the whole Manager.
- **Cycle freedom**. The in-package mcp ↔ kc ↔ ops cycles are the same, just inside bootstrap.
- **Pattern-A self-registration of services**. Wrong shape; services still need DI threading.

---

## §6 — What this BUYS us (the honest case)

1. **Brand completion** — algo2go org owns every Go source file. Sundeepg98/kite-mcp-server (after transfer to algo2go/kite-mcp-server per audit doc) is a thin deploy shell with operational metadata.
2. **Smaller deploy repo** — clones become fast; CI checkouts are tiny.
3. **Independent module versioning** — bootstrap is a Go module; consumers can pin its version. Lets us cut a "stable" bootstrap while iterating internally.
4. **Tighter blast radius for the deploy repo** — security audits of the deploy repo see only Dockerfile + fly.toml + metadata. Source-level audit happens at the bootstrap module.
5. **Demonstrates "decomposition as standard practice"** — the very repo that orchestrates 28 algo2go modules is itself externalized. The architecture story is internally consistent.
6. **Forecloses one-time launch panic** — if a critical issue requires reverting a kc change, the revert lands in bootstrap, the deploy repo's Dockerfile bumps the bootstrap pin, fly deploys. Cleaner than `git revert` against a sprawling repo.

---

## §7 — What it COSTS us (the honest counter-case)

1. **Two-step PRs become common** — any change touching kc + Dockerfile needs a bootstrap PR + a deploy-repo PR. Adds tag-and-bump ceremony.
2. **Bootstrap becomes the new "god module"** — consolidation, not decomposition. A future audit will identify bootstrap as the new top-of-the-list complexity site.
3. **Version skew risk** — if bootstrap@v0.5 ships and deploy repo pins bootstrap@v0.4, we now have to test the cross-product. Mitigated by always pinning latest at deploy time.
4. **Replace directives reverse but DON'T disappear** — `replace github.com/algo2go/kite-mcp-bootstrap => ../kite-mcp-bootstrap` for local dev. The pain pattern of bidirectional cross-module deps simply moves to the new boundary.
5. **Repo discoverability** — new contributors see the deploy repo first, find ~10 files, ask "where's the source?". Documentation tax to point to bootstrap.
6. **Implicit pressure to put more in bootstrap** — every time a new feature is hard to slot into an existing algo2go module, the path of least resistance is "add it to bootstrap." Counterbalances the decomposition narrative.
7. **CI matrix grows** — currently 4 workspace members tested. Adding bootstrap as a 5th external module with its own tests + lint + release means another GitHub Actions matrix dimension.
8. **MCP Registry manifest** — `name: io.github.Sundeepg98/kite-mcp-server` (per server.json) presumes the source repo. If the deploy repo becomes the canonical source-AND-deploy-repo (post-rename to algo2go/kite-mcp-server), the registry pointer goes to a metadata-only repo. Could confuse registry consumers expecting source.
9. **Most importantly: kc.Manager still rules everything**. The user's framing assumes 28-module decomposition implies the residual is small. Empirically the residual is ~49,400 LOC (90% of the codebase). Pattern C re-labels it. Path Y actually shrinks it.

---

## §8 — Hard rules compliance

- READ-ONLY ✓ (no source mutated, only research file authored)
- WSL2 for `go build ./...`, `go list -m all`, `go mod graph` ✓
- compile-and-run for binary metrics (`go build`; `./kite-mcp-server --version`) — NOT raw grep ✓ (kc.Manager method count cross-referenced)
- Verified cited SHAs (`9a0079b`, `13888e1`, `7c21e7d`) with `git log -1` ✓
- Cited file:line spot-checks (`mcp/common/tool.go:62-65`, `kc/manager_struct.go:65-186`, `kc/ops/handler.go:34`, `app/wire.go:12-31`, `mcp/plugin/registry.go:41`) all read from disk ✓
- as-of frontmatter present ✓
- Single commit + push planned ✓
- Surface IF structural blocker found that fundamentally prevents zero-in-tree → **YES, flagged in §0 headline finding**: `Tool.Handler(*kc.Manager)` contract is the load-bearing blocker for TRUE zero-in-tree (Path Y). Pattern C (audit agent's bootstrap) is feasible without touching this contract; Pattern D.2 needs it changed.

---

## §9 — Cross-cutting awareness

- **`209.71.68.157` IP stale issue**: Not encountered in this scope. (Confirming negative — searched for IP in research files via grep; only appears in MEMORY.md context.)
- **Sundeepg98 → algo2go transfer**: Covered by audit agent's `github-transfer-bootstrap-2026-05-11.md`. My research is the prerequisite analysis (what's possible to externalize); their doc is the procedure (how to transfer + what to call the new module).
- **God-object decomposition**: Covered by path-A agent's `god-object-inventory-2026-05-11.md`. My §5.3 recommendation explicitly calls Path Y "the god-object doc's roadmap." The two are complementary.

---

## §10 — One-sentence summary

**Pattern C (bootstrap module relocation) ships zero-in-tree as a lift in ~30h and satisfies the brand goal; Pattern D.2 (per-module tool registration) ships zero-in-tree as actual decomposition in ~300h and depends on kc.Manager decomposition; the user's question "what's structurally special about the residual" has empirical answer: `Tool.Handler(*kc.Manager)` at `mcp/common/tool.go:64` + the 39 kc-package interfaces — these together pin the in-tree code, not "composition root must exist."**
