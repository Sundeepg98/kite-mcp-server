# ABC 100% Complete Paths — Path B + Microservices + Feature Parity

**Date**: 2026-05-05
**HEAD audited**: `cd8d88e` (post-lint cleanup; v221 LIVE; tools=111; 29 modules)
**Builds on**: `21503fd broker-promotion-runbook.md` (Path B mechanics), `cacbc20 architecture-scale-ceiling.md` (microservices threshold), `6ee6520 architecture-scale-paths-A-B-C.md` (per-axis empirical fit), `2999c12 feature-completeness-audit.md` (feature gaps)
**Charter**: read-only research. Doc-only. NO code changes. No execution.
**User clarification**: research ALL THREE axes' complete-to-100% paths. Defer execution decisions.

---

## Axis A — Path B 100% (broker repo + cutover + verification)

**Definition of 100%**: `algo2go/kite-mcp-broker` exists as standalone GitHub repo, semver-tagged v0.1.0+, kite-mcp-server consumer cuts over to upstream module path, production verifies tools=111 unchanged, both repos co-evolve via dependabot/manual sync.

### A.1 — Pre-flight (dependencies on USER + manual steps)

| Step | Owner | Cost | Time |
|---|---|---|---|
| User creates `algo2go` GitHub org via web UI | USER (web UI only — `gh api orgs/algo2go` returned 404 per prior research) | $0 (free GitHub tier) | ~30 sec |
| User reserves `algo2go.com` domain (optional but cohesive) | USER | ~₹500/yr Namecheap | ~5 min |
| Agent installs `git filter-repo` | AGENT (`pip install git-filter-repo` per `21503fd`) | $0 | ~5 min |

**Pre-flight blocker**: only USER can create the GitHub org. Once created, all subsequent steps agent-executable.

### A.2 — Execution PRs (~10 PRs at agent pace)

Per `21503fd broker-promotion-runbook.md`, sections 2-7 already specify the migration. Drilling to per-PR breakdown:

| PR | Title | Files | Hours |
|---|---|---|---|
| A.2.1 | `gh repo create algo2go/kite-mcp-broker` + branch protection + CODEOWNERS + LICENSE/MIT + .gitignore | (in algo2go org, not consumer repo) | 0.5 |
| A.2.2 | `git filter-repo --subdirectory-filter broker/` against fresh clone; preserves 41 broker-touching commits + tag-rename | new repo bootstrap | 1 |
| A.2.3 | Push `algo2go/kite-mcp-broker:main`; tag `v0.1.0`; `gh release create` | new repo | 0.5 |
| A.2.4 | Phase A transition in kite-mcp-server: change `replace ./broker` → `require github.com/algo2go/kite-mcp-broker v0.1.0` + keep `replace github.com/algo2go/kite-mcp-broker => ./broker` for canary | root `go.mod`, `go.work` (drop ./broker), `Dockerfile` (remove broker COPY) | 1 |
| A.2.5 | Rewrite 143 import lines across 126 files: `find . -name '*.go' \| xargs sed -i 's#kite-mcp-server/broker#algo2go/kite-mcp-broker#g'` + `goimports -w .` | 126 .go files | 1.5 |
| A.2.6 | Verify build: workspace + GOWORK=off + Dockerfile sim + tests + tool-count drift CI | (verification only) | 1 |
| A.2.7 | Production deploy v222+ + 1-hour smoke observation | (deploy-only) | 1.5 |
| A.2.8 | (Phase B, after 1-month canary): delete `./broker/` directory + remove `replace` from go.mod; require-only state | root `go.mod`, delete broker dir | 1 |
| A.2.9 | First upstream-repo iteration (e.g. cherry-pick from kite-mcp-server's broker/ commits → algo2go/kite-mcp-broker) | algo2go repo | 2 |
| A.2.10 | Establish CI parity in algo2go/kite-mcp-broker (clone parent's `ci.yml` + `test-race.yml` + `security.yml`, adapt to broker-only scope) | algo2go repo | 2 |

**Total agent-pace**: ~12 working hours = 1.5-2 working days. Prior `21503fd` estimate said 3 days; agent compression realistic.

### A.3 — Risks + mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| External consumer adopts old `kite-mcp-server/broker` path | LOW (zero today) | Keep `replace` for 1-month canary; deprecation warning in old paths |
| broker.PortContract semver instability | MEDIUM | v0.x explicitly unstable per `21503fd` §8; v1.0 only after first external adapter ships |
| algo2go org-name conflict (existing GitHub org takes name) | LOW | Verify `gh api orgs/algo2go` returns 404 before user creates |
| Calendar slip if filter-repo not installed | LOW | Fallback to `git subtree split` per `21503fd` §2 |

### A.4 — Empirical preconditions (per `feedback_decoupling_denominator.md`)

- **Trigger-fired** state: 50★ OR external adapter request OR FLOSS-fund acceptance. **None present today**. Inaugurating now is **pre-trigger / aspirational**.
- **Cost-of-doing-now vs cost-when-trigger-fires**: same engineering cost (~12h). The marginal cost is **maintenance burden** during the inaugurated-but-unused period: ~30 min/week to keep algo2go/kite-mcp-broker in sync with parent. At 6-12 months pre-trigger → ~12-24h sunk maintenance.
- **Honest verdict**: pre-inauguration costs ~24-36h total (12h initial + 12-24h maintenance). Trigger-fired inauguration costs ~12h. **Pre-inauguration burns ~24h for no concrete value, but provides Pre-Seed pitch optionality + brand defensibility against squatters.**

### A.5 — Calendar at 3 scales

| Scale | Total time |
|---|---|
| Solo+₹0 (today) | ~2 working days agent-pace + ~30 min user web UI |
| Pre-Seed (₹19-23k brand reservation budget) | Same; brand reservation runs in parallel |
| Series-A (designer + ops hire) | Same; algo2go.com landing page becomes a deliverable |

---

## Axis B — Microservices 100% (29 services + API contracts + cells)

**Definition of 100%**: each of 29 modules deploys as independent binary, communicates via gRPC/HTTP contracts, scales horizontally per-service, supports cell-based tenancy.

### B.1 — Per audit `cacbc20` Q1: 2-4 years out at our trajectory

Empirical floor: needs **300+ sustained agent-N** before microservices threshold fires. Today: N=20-30. Gap: 10-15x.

### B.2 — Concrete milestones (sequential)

**Milestone B.M1 — First binary split** (~4-8 weeks):
- Pick **ticker** as first split candidate (rationale: websocket workload differs structurally from HTTP-RPC; horizontal scaling by user-count is naturally per-binary)
- Define gRPC contract: `kc/ticker/proto/ticker.proto` with `Subscribe(SymbolSet) stream Tick`, `Unsubscribe(SymbolSet)`
- Deploy `kite-mcp-ticker` as separate Fly.io app: ~$10-30/mo
- kite-mcp-server consumer: gRPC client to ticker service
- Migration mechanic: feature-flag old in-process ticker vs new RPC; canary 10% traffic
- **Cost**: 4 engineer-weeks at solo + ₹0; ~$30/mo Fly.io

**Milestone B.M2 — Dashboard split** (~6-8 weeks):
- Dashboard SSE traffic separate from API traffic
- Standalone `kite-mcp-dashboard` binary serving `/dashboard/*` routes
- Shared SQLite DB via Litestream replica (or move to Postgres)
- **Cost**: 6 engineer-weeks + Postgres migration if SQLite contention surfaces

**Milestone B.M3 — Trade-path NOT split** (regulatory floor):
- SEBI's `OrderPerSecondRate = 600` (9 orders/sec per `kc/riskguard/check.go`) requires **synchronous** rate-limit gating
- OTR band check (SEBI Apr 2026 mandate) requires real-time LTP
- Synchronous order-confirmation UX intolerant of network-RPC latency
- **Trade tools stay in monolith binary perpetually** — regulatory floor

**Milestone B.M4 — Event-driven non-trade paths** (~12 weeks):
- Alerts evaluation → Kafka/NATS topic
- Briefings, P&L snapshots, audit-log writes → buffered events
- Telegram dispatch → fire-and-forget queue
- **Cost**: 12 engineer-weeks + $50-100/mo NATS/Redis Pub-Sub

**Milestone B.M5 — Cell-based tenancy** (~24+ weeks):
- Each Fly.io machine handles N tenants
- Cell-router shards by user-email-hash
- Per-cell independent scaling
- **Blocker**: per-user OAuth + static egress IP per `fly.toml`. Multi-cell requires per-cell IP whitelist coordination per user × cell — NOT structurally feasible until SEBI relaxes per-broker-app IP whitelist mandate
- **Verdict**: cell-based is **structurally blocked** by SEBI April 2026 IP mandate

### B.3 — Irreducible floor

**Trade path remains in monolith forever.** Per `kc/riskguard/check.go`, SEBI synchronicity is regulation-grounded, not a code choice. **Maximum decomposition: ~70% of tool surface (non-trade) goes microservices/event-driven; 30% (trade) stays sync monolith.**

### B.4 — Total calendar at 3 scales

| Scale | Calendar | Cost |
|---|---|---|
| Solo+₹0 | **NOT achievable** — 60+ engineer-weeks; user has 1 person | $0 dev + $50-100/mo ops indefinitely |
| Pre-Seed (1-2 hires) | ~12-18 months (2-engineer parallel) | ~₹40-50L (2 engineers × 18mo) + ~$100-200/mo ops |
| Series-A (5-engineer team) | ~6-8 months | ~₹2-3 Cr (5 engineers × 8mo) + ~$500/mo ops |

**Verdict at solo+₹0**: Axis B is **engineering-effort-blocked**. Can ship M1 (ticker) at solo pace if user authorizes 4-8 weeks of focused work; M2-M4 require team.

---

## Axis C — Feature 100% (parity with Streak / Trendlyne / Multibagg)

**Definition of 100%**: feature parity on the 4 HIGH-MEDIUM gaps from `2999c12 feature-completeness-audit.md` plus depth additions for visual differentiation.

### C.1 — Empirical gaps from `2999c12`

| # | Gap | Audit severity | Empirical state at HEAD |
|---|---|---|---|
| 1 | Visual scanner/screener UI | HIGH | `peer_compare` + `sector_exposure` MCP tools exist; no UI surface |
| 2 | Mobile responsive dashboard | HIGH | Landing responsive; dashboard pages desktop-first |
| 3 | Real-time chart + indicators | MEDIUM | `chart_app.html` widget exists, read-only |
| 4 | Options payoff visualizer | MEDIUM | `options_payoff_builder` MCP tool exists, no graphical UI |
| 5 | Pattern-based alerts | MEDIUM | `technical_indicators` + `set_alert` separate; no pattern composition |
| 6 | Multi-broker support | HIGH (strategy-level) | Only Zerodha; broker port ready for adapters |
| 7 | Admin audit-log search UI | MEDIUM | Data via `kc/ops/api_activity.go`; no UI form |

### C.2 — Per-feature execution plan

**Feature C.F1 — Visual scanner UI** (~1 week solo):
- Route: `/dashboard/scanner`
- Filter form (sector, market cap, P/E, volume) → backend uses existing tools
- Sortable results table
- Save-screen-as-watchlist integration
- **Designer required**: NO (existing dashboard-base.css covers)

**Feature C.F2 — Mobile responsive dashboard** (~1 week, incremental per page):
- Add `@media (max-width: 768px)` blocks across 7 dashboard pages
- Hamburger menu for nav-tabs
- Touch-friendly form inputs
- **Designer required**: NO (mechanical responsive work)

**Feature C.F3 — Real-time chart with indicators** (~3-4 weeks):
- Integrate Lightweight Charts (TradingView's free OSS library, 60KB)
- Overlays: SMA/EMA/RSI/MACD/Bollinger using existing `technical_indicators` tool
- Drawing tools: defer to post-launch
- **Designer required**: PARTIAL (icon set, palette tuning)

**Feature C.F4 — Options payoff visualizer** (~3 days):
- SVG-based payoff curve renderer in `options_chain_app` widget
- Driven by existing `options_payoff_builder` MCP tool data
- **Designer required**: NO

**Feature C.F5 — Pattern-based alerts** (~1 week):
- New MCP tool `pattern_alert(pattern_name, symbols)`
- Pattern library: golden-cross, RSI-divergence, volume-spike-with-price-move
- Reuse `set_alert` infra for delivery
- **Designer required**: NO

**Feature C.F6 — Multi-broker support** (~1 week per broker, 3-5 brokers):
- broker port already in place; need adapters for Upstox, Dhan, AngelOne, ICICIdirect, Groww
- Per `21503fd`, broker.PortContract conformance harness already published
- **Designer required**: NO; broker-logo set in landing
- **Empirical blocker**: each broker needs separate developer-app credentials + IP whitelist coordination

**Feature C.F7 — Admin audit-log search UI** (~1-2 days):
- Search form on `/admin/ops/audit` route
- Filters: user-email, tool-name, date-range, error-type
- Backend already exists at `kc/ops/api_activity.go`
- **Designer required**: NO

### C.3 — Total feature-100% calendar

| Sub-axis | Solo time | Designer hire (₹2-3L/mo retainer per `69d1e3a`) |
|---|---|---|
| C.F1-C.F2-C.F4-C.F5-C.F7 (no-designer items) | ~3-4 weeks | $0 |
| C.F3 (real-time chart, partial designer) | ~3-4 weeks solo + 1 week designer | ₹50k-1L design |
| C.F6 (multi-broker, 3 adapters minimum) | ~3-4 weeks solo per broker | $0 dev + per-broker developer-app fees (₹500/mo each via Zerodha-Connect; varies by broker) |
| **Total feature-100% solo** | **~12-16 weeks** | **₹50k-1L design + ~₹6-12k/yr per additional broker app** |

### C.4 — Per-scale calendar

| Scale | Calendar |
|---|---|
| Solo+₹0 | ~12-16 weeks for ~80% (drop C.F3 chart designer) |
| Pre-Seed (₹2-3L designer retainer) | ~10-12 weeks for full 100% |
| Series-A (designer + 2 frontend hires) | ~6-8 weeks for full 100% + visual polish past Streak/Trendlyne tier |

---

## Cross-Axis 100% Synthesis

### A + B + C literal-100% at three scales

**Solo+₹0 budget**:
- A: ~2 days agent-pace
- B: NOT achievable (M1 ticker only ~4-8 weeks; M2-M4 blocked)
- C: ~12-16 weeks for 80%; full 100% blocked on designer
- **Total achievable**: A + C-80% in ~13-17 weeks. B beyond M1 is engineering-blocked.

**Pre-Seed (~₹50L over 12mo)**:
- A: 2 days agent + 1 month brand reservation
- B: Reach M1 + M2 (ticker + dashboard split); ~16 weeks combined
- C: Full 100% in ~12 weeks
- **Total**: A + B (M1+M2) + C-full in ~6-8 months
- Cost: ~₹50L (2 engineers + 1 designer × 8mo) + $100-150/mo ops

**Series-A (~₹3-5 Cr over 12mo)**:
- A: shipped immediately
- B: Reach M1+M2+M4 (event-driven non-trade); M3 trade stays mono per SEBI; M5 cells blocked by SEBI IP mandate
- C: Full 100% with visual polish past Streak/Trendlyne in ~8 weeks
- **Total**: A + B (~70% decomposition) + C-premium in ~6-8 months
- Cost: ~₹3-5 Cr (5-engineer team + designer + ops + multi-broker app fees)

### Honest verdict on "literal 100%"

- **Axis A** can reach 100% at any scale (small enough for solo).
- **Axis B can NEVER reach 100%** at our context — SEBI regulation forces trade path to stay sync monolith. Realistic maximum: ~70% decomposition. Cell-based tenancy structurally blocked by per-user IP whitelist.
- **Axis C can reach 100%** at Pre-Seed scale; ~80% achievable solo without designer. Full 100% requires designer hire.

**Empirical recommendation order** (highest leverage, lowest cost first):
1. **Axis A pre-inauguration** — 2 agent-days + USER 30sec web UI. Optionality value high; one-time cost.
2. **Axis C selective**: F7 (audit-log search, 1-2 days) + F1 (scanner, 1 week) + F4 (payoff viz, 3 days) → ~2 weeks; covers most "competitor parity" gaps without designer.
3. **Axis C remaining**: F2 mobile (1 week) + F5 patterns (1 week).
4. **Axis B M1 ticker split** ONLY when sustained N>50 agent or 1k+ ticker users — **trigger-gated, not authorized today**.
5. **Axis B M2+** : engineering-blocked at solo.
6. **Axis A maintenance** : 30 min/week ongoing.

**Aggregate solo budget for highest-ROI 80%**: ~6-8 weeks total (A + C-selective + C-mobile + C-patterns). Skip C.F3 chart-designer + C.F6 multi-broker until business case fires.

---

**End. Doc-only. No code mutated. No tests run.**

Last section completed: **Cross-axis 100% synthesis** (final).
