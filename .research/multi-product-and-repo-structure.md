# Multi-Product Inventory + Repo-Structure Evaluation

**Date**: 2026-04-28 night
**HEAD audited**: `1081684`
**Charter**: research deliverable, NO ship. Two questions:

- **Q4** — Is our product only `kite-mcp-server`, or is it multiple products?
- **Q5** — How should the repository be functional?

**Anchor docs**:
- `.research/fork-loc-split-and-tier3-promotion.md` (`d0e999d`)
  Part 2 — Tier-3 promotion-trigger matrix; this doc inherits its
  per-component cost estimates and 31% promotion probability for
  the trigger thresholds in §6.
- `.research/parallel-stack-shift-roadmap.md` (`8361409`) §1 —
  Foundation phase; cross-references where Q4/Q5 decisions fan
  into the IPC contract.
- `.research/scorecard-final-v2.md` (`8361409`) §2.3 — empirical
  measurement that `mcp/` is NOT thin transport (62% of tools
  have leaked business logic). Critical for "monorepo with cmd/X"
  vs "polyrepo split" math.
- `.research/ipc-contract-spec.md` (`4fa5a39`) — drafted IPC
  spec; informs Q5 polyrepo evaluation (cross-repo IPC
  coordination cost).
- `feedback_decoupling_denominator.md` — three-axis ROI; this
  doc adds release-boundary considerations as a fourth axis
  facet within Axis B (agent-concurrency) and Axis C
  (portability).
- `README.md` (top-level) — claims "ships ~80 tools spanning
  portfolio analysis, market data, options Greeks, backtesting,
  alerts, paper trading, and order placement, plus MCP Apps
  widgets". This is the canonical product story today; Q4
  asks whether it's accurate.
- README is the ground truth for what's currently named a
  "product".

**Empirical scope**: 76 tracked docs, 8 ADRs, 25,584 LOC `kc/*`,
23,368 LOC `mcp/`, 9,392 LOC `app/`, 2,736 LOC `oauth/`, 3,315
LOC `broker/`, 310 LOC `cmd/`, 0 LOC compiled-Go in `skills/`.

---

## Q4 — Single product or multi-product?

### 4.1 Empirical inventory of candidates

For each candidate the brief lists: what it is, current location,
LOC + dependency footprint, standalone-product viability, audience,
monetization angle.

#### 4.1.1 kite-mcp-server core (the MCP server itself)

- **What**: Self-hosted Go server speaking Model Context Protocol
  v1, bridging MCP clients to Zerodha Kite Connect. ~80 tools
  spanning portfolio, market data, options Greeks, backtesting,
  alerts, paper trading, order placement.
- **Location**: root + `mcp/`, `app/`, `oauth/`, `broker/`,
  `kc/*`, `cmd/`. Single Go binary.
- **LOC + deps**:
  - `mcp/` 23,368 prod / 38,706 test
  - `app/` 9,392 prod / 21,384 test
  - `oauth/` 2,736 prod / 13,087 test
  - `broker/` 3,315 prod / 6,610 test
  - `kc/` 25,584 prod (top-level + sub-packages) / 51,517 test
  - `cmd/` 310 prod / 974 test
  - **Total prod: ~64,705 LOC**; tests: ~132,278 LOC
  - Hard deps: `gokiteconnect/v4` (broker SDK), `mcp-go`
    (transport), `golang-jwt`, `stripe-go`, `modernc.org/sqlite`,
    `go.uber.org/fx` (DI), `hashicorp/go-plugin` (RPC), Telegram
    bot SDK.
- **Standalone viability**: This IS the standalone product. Already
  shipping in three deployment modes (hosted Fly.io, local
  Docker, native Go binary).
- **Audience**: Indian retail / power-user Zerodha account
  holders who want AI-assisted trading; secondary audience is
  developers building on top of MCP.
- **Monetization**: free + open source today. Realistic-MRR
  projection (per `kite-mrr-reality.md` referenced in MEMORY.md):
  ₹15-25k/month at 12 months via support contracts, hosted
  premium, or Stripe-tier gating (the billing infrastructure
  already exists in `kc/billing/`).

#### 4.1.2 kite-trading skill plugin

- **What**: Five-command Claude Code plugin (morning, eod, price,
  quick, trade) + one trading-advisor skill. Turns the MCP
  server's 80 tools into an opinionated trading copilot via
  pre-built prompts.
- **Location**: `~/.claude/plugins/local/kite-trading/` (NOT in
  this repo — user's private plugin directory). 7 files: 1
  `plugin.json` (9 LOC), 5 command markdown (44-140 LOC each,
  total 426 LOC), 1 `SKILL.md` (124 LOC). **Total: 559 LOC of
  markdown + JSON; zero Go.**
- **Deps**: requires `kite-mcp-server` MCP server connection
  configured in the host (Claude Code / Claude Desktop). No
  package-level Go deps; pure prompt content.
- **Standalone viability**: NOT standalone — purely a prompting
  layer over the MCP server. Useless without it.
- **Audience**: Claude Code / Claude Desktop users with a Kite
  account who want the trading-copilot framing without crafting
  prompts manually.
- **Monetization**: free; this is distribution / discoverability,
  not a profit center. Could go in
  `anthropics/claude-plugins-official` marketplace once 50+ stars
  on the parent repo establish credibility.

#### 4.1.3 8 Claude Skills wrapper (skills/ folder)

- **What**: 8 in-repo `SKILL.md` files (alert-playbook,
  backtest-interpretation, eod-review, morning-brief,
  options-sanity-check, sector-rotation, tax-harvest,
  trade-check) + 1 README. Static markdown that teaches Claude
  how to reason about Indian-market trading workflows on top
  of MCP server tools. Skills are static — they do NOT execute
  code.
- **Location**: `skills/` (this repo, commit `60e552c`). 9 files
  total, 917 LOC of markdown.
- **Deps**: zero Go. Each `SKILL.md` references MCP tool names
  (e.g. `historical_price_analyzer`, `sector_exposure`); requires
  the kite-mcp-server MCP connection configured.
- **Standalone viability**: standalone-installable as
  `~/.claude/skills/*` independent of the kite-trading plugin.
  Some overlap with the plugin (the plugin's commands are more
  opinionated; skills are more reactive — Claude loads them
  when the user mentions a relevant phrase). They're
  complementary, not competing.
- **Audience**: same as 4.1.2 — Claude Code / Desktop users with
  Kite accounts. No need to install the plugin for these to
  work; skills auto-discover from `~/.claude/skills/`.
- **Monetization**: free; same distribution rationale as 4.1.2.
  The README at `skills/README.md` already pitches this as
  "Skills are the reasoning layer; the kite-mcp-server is the
  execution layer."

#### 4.1.4 MCP Apps widgets

- **What**: 4+ inline widgets that render inside the chat UI of
  MCP Apps-aware hosts (claude.ai, Claude Desktop, ChatGPT
  Connectors). Includes portfolio, activity timeline, orders,
  alerts, watchlist, order_form, admin overview/registry/users/
  metrics, chart_app — actually 14+ HTML widgets in
  `kc/templates/`. Widgets ride on the `ui://` MCP resource
  capability via AppBridge JS.
- **Location**: `kc/templates/*.html` (14,754 LOC of HTML+JS) +
  `mcp/ext_apps.go` (996 LOC) + `mcp/plugin_widgets.go` (108
  LOC) + `mcp/plugin_widgets_pack.go` (138 LOC).
- **Deps**: tightly coupled to the MCP server's `ext_apps.go`
  widget-data plumbing; widgets are served as MCP resources
  alongside tool calls. Cannot ship without the MCP server.
- **Standalone viability**: NOT standalone — they ARE the MCP
  server's UI surface. Widgets without a server is just
  static HTML in a folder.
- **Audience**: same as 4.1.1 (the server's own users). Not a
  separate audience.
- **Monetization**: bundled with the server. Could be a tier
  differentiator (e.g. "Pro tier unlocks the admin dashboard
  widgets") via existing `kc/billing/` middleware.

#### 4.1.5 Dashboard SaaS (`/dashboard`, `/dashboard/activity`, `/admin/ops`)

- **What**: Server-side rendered HTML dashboard with portfolio,
  activity timeline (90-day audit trail), admin operations
  (registry, users, alerts, sessions, tickers, MFA enrollment).
  SSO via cookie set during MCP OAuth callback.
- **Location**: `kc/ops/` (~16.5k LOC incl tests per
  MEMORY.md), `kc/templates/admin_*.html` + `activity.html` +
  `dashboard.html`, `app/http.go` routing.
- **Deps**: same as 4.1.1 — share the same `kcManager`, audit
  store, billing store, user store. Goes through the same
  OAuth bridge. **Tightly coupled to the server's persistence
  layer.**
- **Standalone viability**: NOT standalone in the practical
  sense. Could in principle be split into a separate "admin
  console" service that talks to the server via HTTP, but the
  current SSR pattern shares process memory with the server
  (e.g. `kcManager.UserStoreConcrete()` access on the admin
  pages). A split would require either (a) replicating the
  data layer for the admin service or (b) a thin
  HTTP-as-admin-API layer. ~6-8 dev-weeks.
- **Audience**: same end-users as 4.1.1 plus optional admin
  operators (single-user admin in the typical local-self-host
  case, multi-user admin in the hosted Fly.io case).
- **Monetization**: same tier ladder as 4.1.1. Already gated by
  ADMIN_EMAILS env var for admin pages.

#### 4.1.6 Telegram trading bot (`kc/telegram/`)

- **What**: Long-poll Telegram bot accepting commands (/buy /sell
  /quick /setalert /pnl), inline keyboard confirmations, daily
  P&L briefings (3:35 PM IST), morning briefings (9 AM IST).
- **Location**: `kc/telegram/`. 1,860 prod LOC / 6,135 test LOC.
- **Deps** (NON-test only): `broker/zerodha`, `kc/alerts`,
  `kc/instruments`, `kc/riskguard`, `kc/watchlist` — five
  internal `kc/*` deps. **Deeply tangled with the server's
  domain layer.** The bot's `KiteManager` interface in
  `bot.go` exposes 20+ methods covering tokens, quotes, order
  placement, riskguard checks, watchlist mutations.
- **Standalone viability**: NOT standalone in any meaningful
  near-term sense. Splitting it would require either
  (a) extracting all five internal deps into a shared library
  (effectively the polyrepo question Q5 asks), or (b) the bot
  speaking to the server via HTTP/MCP wire (which is roughly
  the trajectory if Track A from `parallel-stack-shift-roadmap.md`
  ever activates). Per `d0e999d` Tier-3 promotion analysis,
  Telegram is **Low promotion likelihood (~5-15%)** — its
  abstraction layers are already idiomatic Go.
- **Audience**: same as 4.1.1 — users who already trade via the
  MCP server and want a mobile / always-on UI.
- **Monetization**: bundled with the server (free + opt-in via
  `TELEGRAM_BOT_TOKEN`). Premium tier could enable richer
  features (custom briefing templates, multi-account routing).

#### 4.1.7 Paper trading sandbox (`kc/papertrading/`)

- **What**: Virtual ₹1 crore portfolio, simulated orders against
  real Kite quotes, background LIMIT fill monitor, opt-in via
  user toggle. Same audit / riskguard / billing chain as live
  trading; only the broker call is intercepted.
- **Location**: `kc/papertrading/`. 1,981 prod LOC / 8,255 test
  LOC.
- **Deps** (non-test): `kc/alerts`, `kc/domain`, `kc/logger`,
  `oauth/`. **Three internal kc/* deps + oauth.** The `oauth/`
  dep is for user-context resolution in the middleware
  (`middleware.go`); the kc/alerts dep is for SQLite
  persistence of paper-portfolio state.
- **Standalone viability**: SEPARABLE with effort. The engine +
  store are domain-pure (no broker SDK); the middleware
  intercepting orders requires the MCP server's chain. As a
  standalone "paper trading library" usable by other Kite
  developers: ~3 dev-weeks to extract (replace `oauth/` dep
  with an interface, extract `kc/alerts` dep behind a `Store`
  interface, document the host integration contract).
- **Audience**: educational. New traders, strategy developers,
  anyone who wants to test before live trading. Could appeal
  to non-Kite users if generalised to any broker (the engine
  itself is broker-agnostic; only the LTP feed is Kite-shaped).
- **Monetization**: free in this server; standalone library
  could be MIT/Apache for FLOSS-fund eligibility. No realistic
  paid version.

#### 4.1.8 Backtest engine

- **What**: 4 built-in strategies (SMA crossover, RSI reversal,
  breakout, mean reversion), Sharpe ratio, max drawdown, win
  rate, average trade. Operates on Kite historical data.
- **Location**: **`mcp/backtest_tool.go` (581 LOC)** — NOT a
  separate `kc/backtest/` package as the brief framed. The
  brief's framing was wrong; correcting empirically.
- **Deps**: `broker` (for `Broker` type), `kc` (for
  `*kc.Manager`), `kc/cqrs` (for the CQRS bus). **Three
  internal package deps**, plus the MCP server framework
  (`mcp.NewTool`, `server.ToolHandlerFunc`).
- **Standalone viability**: NOT standalone today. The strategy
  rules (~300 LOC of pure-Go logic) ARE separable; the MCP-tool
  wrapper around them is not. Extracting a `kc/backtest/`
  package would be ~2-3 dev-weeks (move strategy code, define
  a `BacktestRunner` interface that takes OHLC + strategy +
  capital, leave the MCP wrapper in `mcp/`). Worth doing IF a
  standalone-product play emerges.
- **Audience**: same as 4.1.1 (educational, "what would have
  happened if I'd run this strategy?"). Not a separate
  audience.
- **Monetization**: bundled with the server. Premium tier could
  unlock more strategies or longer history windows.

#### 4.1.9 Riskguard middleware (`kc/riskguard/`)

- **What**: 9 pre-trade safety checks — kill switch, value cap
  (₹50k default), quantity limit, daily order count (20/day),
  rate limit (10/min), duplicate detection (30s window), daily
  cumulative value cap (₹2L), auto-freeze circuit breaker,
  market-hours rejection. Pluggable via subprocess RPC (per
  ADR 0007).
- **Location**: `kc/riskguard/`. 3,550 prod LOC / 6,498 test LOC.
- **Deps** (non-test): `kc/alerts` (DB-backed limits +
  persistence), `kc/domain` (Money + Order types),
  `kc/logger`. **Two internal kc/* deps + logger.**
- **Standalone viability**: HIGHEST among the candidates.
  Already designed as a domain-clean module: no `gokiteconnect`
  imports; no `mcp/` imports; no `app/` imports; no `broker/`
  imports. The `kc/alerts.DB` dep is for limit persistence
  (could be replaced with an in-memory or any-database
  interface). **As a standalone Go library `riskguard-go`:
  ~2-3 dev-weeks to extract** — replace `kc/alerts` dep with
  a `LimitStore` interface, replace `kc/domain.Money` with
  arbitrary monetary types or alias, document the integration
  contract. The subprocess plugin pattern (`checkrpc/`) is
  already cross-language-ready per ADR 0007.
- **Audience**: any Indian-broker developer building on Kite
  Connect or any other broker SDK who wants to ship pre-trade
  safety without rewriting it. Realistic external adoption:
  10-50 stars on GitHub, 0-3 forks, occasional issues. Same
  shape as `prometheus/client_golang`-style infrastructure
  libraries.
- **Monetization**: open-source library, MIT license. No paid
  version makes sense — the value is the curated set of 9
  checks + tests + battle-testing in production. Indirect
  monetization: stars / brand for the parent project, FLOSS-
  fund eligibility, Rainmatter-pitch credibility.

#### 4.1.10 AI activity audit trail (`kc/audit/`)

- **What**: Every MCP tool call logged to SQLite `tool_calls`
  table. Buffered async writer. Smart per-tool summaries. PII
  redaction. 90-day retention cleanup. CSV/JSON export. Hash-
  chained for tamper-evidence (HMAC-SHA256). Litestream-backed
  for replication. Optional external publication to S3 (R2)
  for tamper-evidence anchor (per the "default-on" upgrade
  shipped in `e3bfba3`).
- **Location**: `kc/audit/`. 3,851 prod LOC / 6,278 test LOC.
- **Deps** (non-test): `kc/alerts` (DB-backed storage),
  `kc/domain`, `kc/logger`. **Two internal kc/* deps +
  logger.** Same shape as `kc/riskguard/` — domain-clean.
- **Standalone viability**: HIGH. Same level as `kc/riskguard/`.
  As a standalone Go library `tool-call-audit-go`: ~3-4
  dev-weeks to extract — generalize from "tool_calls" to
  arbitrary RPC method names, replace `kc/alerts.DB` with a
  `Store` interface, document the hash-chain + R2 publish
  pattern, ship as a generic AI-tool-call audit observability
  library.
- **Audience**: any AI agent / MCP server author who needs
  audit-trail observability. Broader audience than riskguard —
  AI agent observability is a hot topic in 2026; standalone
  library could see 100-500 stars if positioned correctly.
  Compete-adjacent to OpenTelemetry's `gen-ai` semantic
  conventions but at the audit/tamper-evidence layer rather
  than tracing.
- **Monetization**: open-source library, MIT license. Indirect
  monetization through brand / Rainmatter pitch / FLOSS-fund.
  A hosted "audit-as-a-service" SaaS is conceivable but
  outside current scope.

#### 4.1.11 Litestream-backed SQLite layer (`etc/litestream.yml` + storage)

- **What**: SQLite WAL → Cloudflare R2 bucket (kite-mcp-backup).
  10s sync cadence. Auto-restore on container restart. $0/month
  cost.
- **Location**: `etc/litestream.yml` (config only); the
  consumers are `kc/credential_store.go`, `kc/token_store.go`,
  `kc/users/`, `kc/billing/`, `kc/alerts/` (the SQLite tables).
- **Deps**: external `litestream` binary; not Go-internal.
- **Standalone viability**: this is **infrastructure**, not a
  product candidate. Litestream itself is already an
  upstream open-source project. Our `etc/litestream.yml` is
  a 30-line config file pointing at our R2 bucket. NO product
  here.
- **Audience**: ourselves (the server's persistence layer).
- **Monetization**: not applicable.

### 4.2 Cluster analysis — separable vs tightly-coupled

Mapping the candidates against three axes — domain-cleanness,
internal-dep-graph depth, and external-audience scope:

| Candidate | Domain-clean | Internal deps | External audience | Standalone? |
|---|---|---|---|---|
| 4.1.1 kite-mcp-server core | n/a (the host) | n/a | retail traders | YES (already shipping) |
| 4.1.2 trading plugin | yes (markdown) | requires server | Claude Code users | NO (prompts only) |
| 4.1.3 8 skills | yes (markdown) | requires server | Claude Code users | NO (prompts only) |
| 4.1.4 widgets | no (HTML deeply server-bound) | requires server | server's own users | NO |
| 4.1.5 dashboard | no (SSR shares process) | requires server | server's own users | NO without rewrite |
| 4.1.6 telegram bot | no (5 internal deps) | broker/zerodha + 4 kc/* | server's own users | NO without rewrite |
| 4.1.7 paper trading | partial (3 deps + oauth) | kc/alerts, kc/domain, kc/logger, oauth/ | educational | LIBRARY-VIABLE in 3 dev-weeks |
| 4.1.8 backtest engine | partial (3 deps) | broker, kc, kc/cqrs | educational | LIBRARY-VIABLE in 2-3 dev-weeks |
| 4.1.9 **riskguard** | YES (no SDK leaks) | kc/alerts, kc/domain, kc/logger | broker-API developers | **LIBRARY-VIABLE in 2-3 dev-weeks** |
| 4.1.10 **audit trail** | YES (no SDK leaks) | kc/alerts, kc/domain, kc/logger | AI agent developers | **LIBRARY-VIABLE in 3-4 dev-weeks** |
| 4.1.11 litestream layer | n/a (config) | external binary | ourselves | NO (infra, not product) |

**Three genuine standalone-product candidates emerge**:

1. **`kite-mcp-server` itself** — the core product. Already a
   product. Single binary, MIT license, GitHub star magnet.
2. **`riskguard-go` library** — extracted version of
   `kc/riskguard/`. Genuinely separable (no SDK leaks); 2-3
   dev-week extraction; broker-API developer audience.
3. **`tool-call-audit-go` library** — extracted version of
   `kc/audit/`. Genuinely separable; 3-4 dev-week extraction;
   AI agent developer audience (broader than riskguard).

**Two soft candidates** (paper trading, backtest engine) — both
are extractable with ~2-3 dev-weeks of work but the audience is
narrow (educational use, not infrastructure). Keep them in the
monorepo unless a specific external developer asks for them.

**The skills + plugin are NOT standalone products** — they are
prompts. They distribute as part of the kite-mcp-server "product
experience" but live outside the Go binary.

**The widgets + dashboard + telegram bot are NOT standalone
products** — they are surfaces of the server. They distribute
WITH the server, gate via tier (`kc/billing/`).

### 4.3 Verdict on Q4

**The product is `kite-mcp-server`. There are also TWO genuinely
standalone library spin-out candidates (`riskguard-go`,
`tool-call-audit-go`) that share the same fate the
`hashicorp/go-plugin` pattern carved out in ADR 0007 — extracted
modules that BOTH the parent project AND third-party users
depend on.**

Everything else is "the kite-mcp-server experience" — different
packaging, different audience, but always the same compiled-Go
artifact at the core. Skills + plugin are distribution mechanisms;
widgets + dashboard + telegram are server surfaces; backtest +
paper-trading + litestream are server features.

The README's framing ("ships ~80 tools spanning portfolio
analysis, market data, options Greeks, backtesting, alerts, paper
trading, and order placement") is **accurate for the user-facing
story**. The **architectural reality** is one product, with two
defensibly-extractable libraries when external demand arrives.

### 4.4 Honest framing for Rainmatter / FLOSS-fund pitch

If asked "is this multi-product?", the honest answer:

> "It's one product (`kite-mcp-server`) with two genuinely
> separable Go libraries inside it (`riskguard-go`,
> `tool-call-audit-go`). The libraries are domain-clean, no
> broker-SDK leaks, ~3-4 dev-weeks each to extract once
> external demand justifies the monorepo split. The remaining
> surfaces (widgets, dashboard, Telegram, paper trading,
> skills, plugin) are different views and packagings of the
> same underlying server. We chose not to manufacture
> multi-product framing where it doesn't exist."

This is the answer that survives a `feedback_decoupling_denominator.md`-
style ROI audit. Manufacturing more products to look like a
"product family" would inflate the maintenance burden against
zero marginal user-MRR.

---

## Q5 — How should the repository be functional?

### 5.1 Five evaluated options

| Option | Brief description |
|---|---|
| 5A. Status quo monorepo | Single repo, single binary via cmd/, multiple bounded contexts in kc/* |
| 5B. Monorepo with multiple binaries | Single repo, multiple `cmd/X` (cmd/server, cmd/cli, cmd/backtest, cmd/skills) — single deliverable group, single go.mod |
| 5C. Polyrepo | Separate repo per product (kite-mcp-server, kite-trading-plugin, kite-skills, kite-riskguard-go-lib) |
| 5D. Workspace-based monorepo | Go workspaces (go.work) — separate go.mod per product, shared lockstep release |
| 5E. Hybrid | Core in monorepo, externally-consumed libraries spun out (e.g. riskguard-go-lib as standalone, rest in monorepo) |

### 5.2 Per-option evaluation

#### 5A. Status quo monorepo — current state

- **Pros**:
  - Single CI pipeline; one `.github/workflows/ci.yml`. Currently
    runs in ~2 min for `go build` + `go vet` + `go test -race
    ./...` (per README badge "7000+ tests").
  - Cross-package refactors are atomic — touching
    `kc/riskguard/` and `mcp/order_tools.go` is a single PR.
  - Single dep-update cadence — Dependabot updates one go.mod;
    one round of CI.
  - One source of truth for the version (semver / git tag).
  - One README, one LICENSE, one SECURITY.md — discoverability
    is unified.
  - One issue tracker, one PR queue.
- **Cons**:
  - Standalone-library consumers (e.g., a third-party developer
    who wants ONLY `kc/riskguard/`) must `go get
    github.com/.../kite-mcp-server` and pull the entire 64,705
    LOC tree. Go's package versioning works but the perceived
    weight is high.
  - A non-Go consumer (e.g., a Rust developer who wants to use
    the riskguard subprocess plugin) doesn't care about the
    repo size, but does care about the documentation overhead
    of finding the riskguard contract within a server-focused
    repo.
  - Test runtime grows linearly with code size; if `kc/audit/`
    or `kc/riskguard/` grows independently, every PR pays the
    full test cost. (Mitigation: per-package `-run` is
    available, but CI runs full.)
- **Migration cost**: 0 (this is the current state).
- **Operational debt**: minimal. One repo to govern.
- **Contribution-friendliness**: HIGH for the kite-mcp-server
  user audience. MEDIUM for standalone-library consumers (they
  don't see "this is the riskguard project" in the README).
- **AI-coordinator throughput**: HIGH. Single-repo means single
  agent context covers everything; cross-package work is
  trivially atomic.

#### 5B. Monorepo with multiple binaries

- **Pros over 5A**:
  - Multiple deliverables (e.g. `cmd/server` for the MCP
    server, `cmd/rotate-key` for the rotation CLI, future
    `cmd/backtest-cli` for offline backtests) without splitting
    repos.
  - Already partly the case — `cmd/rotate-key/` (168 LOC) and
    `cmd/event-graph/` (under cmd/) exist.
  - Each binary has its own `main.go` but shares all `kc/*`
    packages, single go.mod, single CI.
- **Cons over 5A**:
  - None worth listing. This is just an extension of 5A's
    existing pattern. Adding more `cmd/X` directories is free.
- **Migration cost**: ~0 incremental over 5A. Adding a new
  `cmd/X` directory is a normal feature commit.
- **Operational debt**: same as 5A.
- **Contribution-friendliness**: same as 5A. The README would
  need a paragraph explaining "the server is `cmd/server`; the
  rotation CLI is `cmd/rotate-key`; etc."
- **AI-coordinator throughput**: same as 5A.

**Verdict**: 5B is **already partially in place**. The two
existing `cmd/*` binaries (rotate-key, event-graph) are already
this pattern. Adopting 5B fully just means continuing this
convention as new binaries warrant — no migration step.

#### 5C. Polyrepo

- **Pros**:
  - Each repo has its own README focused on its specific
    audience. `riskguard-go` README is for Indian-broker
    developers; `kite-mcp-server` README is for retail
    traders; `kite-trading-plugin` README is for Claude Code
    users.
  - Independent versioning. `riskguard-go v1.2.0` doesn't
    require bumping `kite-mcp-server v3.5.0`.
  - Independent CI scope. PRs to `riskguard-go` only run
    riskguard tests.
  - Better star-magnet attribution. `riskguard-go` getting 50
    stars looks like a 50-star library; the same code inside
    `kite-mcp-server` is invisible to the GitHub ranking
    algorithm.
- **Cons**:
  - Cross-repo refactors become flag-day operations. Adding a
    new field to `riskguard.OrderCheckRequest` requires PR in
    `riskguard-go`, release of `riskguard-go vN+1`, PR in
    `kite-mcp-server` updating to vN+1, release of
    `kite-mcp-server vM+1`. ~3-5x calendar cost vs single
    monorepo PR.
  - Multiple CI pipelines, multiple Dependabot configs,
    multiple release cadences. Per-repo SBOM, per-repo audit.
  - The IPC contract spec (`.research/ipc-contract-spec.md`,
    `4fa5a39`) becomes a cross-repo coordination doc rather
    than an in-tree doc. Schema changes require version
    coordination across N repos.
  - Loses the atomicity of monorepo refactors. If hex agent
    and risk agent are working on overlapping abstractions,
    they can no longer land sibling PRs in one merge.
  - Discoverability fragments. A user landing on
    `riskguard-go` doesn't naturally find `kite-mcp-server`
    unless cross-linked.
- **Migration cost**: HIGH. Splitting `kc/riskguard/` to its
  own repo:
  - Extract package + tests (~10k LOC)
  - Set up new go.mod, new CI, new README (~50 LOC config)
  - Update kite-mcp-server to import from the new repo
    instead of internal package (~20 import-path changes,
    might need a new go.mod replace directive during
    transition)
  - Coordinate the release (kite-mcp-server can't merge
    until riskguard-go vN is published)
  - Per `d0e999d` cost estimate: ~2-3 dev-weeks for the
    split + ~1 dev-week ongoing per cross-repo schema change.
  - Repeat for each polyrepo split.
- **Operational debt**: HIGH. ~Nx the per-repo overhead of 5A.
- **Contribution-friendliness**: HIGH for the per-product
  audience; LOW for the cross-cutting contributor (e.g. a
  developer who wants to fix a bug spanning riskguard +
  server).
- **AI-coordinator throughput**: LOW. Per
  `feedback_decoupling_denominator.md` Axis B framework, every
  cross-repo coordination is a "Mode-2 conflict file" at the
  repo boundary. Agents must context-switch between repos;
  cross-repo PRs need version coordination.

#### 5D. Workspace-based monorepo (Go workspaces, go.work)

- **Pros over 5C**:
  - Single repo (one place for issues, one README index, one
    LICENSE).
  - Each module has its own go.mod, allowing independent
    versioning AND atomic cross-module refactors via
    `go.work` replace directives.
  - Go workspaces have been stable since Go 1.18 (March 2022)
    and are now well-tooled.
  - go.work makes local development atomic; release versioning
    is per-module via independent git tags.
- **Pros over 5A**:
  - Each extracted library (e.g. `riskguard-go`) has its own
    go.mod, makes it discoverable as a separate Go module
    via pkg.go.dev (e.g.
    `github.com/.../kite-mcp-server/riskguard-go`).
  - Per-module test scope (`go test ./...` in the module dir
    runs only that module's tests).
- **Cons**:
  - Not all Go tooling handles workspaces well. `gopls` does
    (since Go 1.20); `golangci-lint` does (since v1.56);
    Dependabot does (since 2023); but `goreleaser` requires
    per-module config; `pkg.go.dev` indexing of nested modules
    is more recent (still some quirks).
  - go.work itself isn't checked in by convention (it's
    `go.work` not `go.work.sum`); the workspace setup is per-
    contributor. Mitigation: check it in; common modern
    practice.
  - Refactoring across modules now requires updating the
    "downstream" module's go.mod to reference a new tag of
    the "upstream" module, OR using a replace directive that
    must be removed before release. More ceremony than 5A.
  - Per-module release cadences add semver coordination —
    same problem as 5C but with single-repo PRs.
- **Migration cost**: MEDIUM. Splitting `kc/riskguard/` to its
  own go.mod within the monorepo:
  - Create `riskguard-go/` subdir (or in-place `kc/riskguard/`
    + `go.mod`)
  - Move tests / fixtures
  - Set up `go.work` at repo root referencing both modules
  - Update kite-mcp-server's go.mod to depend on the new
    module via replace directive
  - Update CI to run tests per-module
  - Per-module release tags (`riskguard-go/v1.0.0`,
    `kite-mcp-server/v3.5.0`)
  - ~1 dev-week per module split (cheaper than 5C because
    no separate repo provisioning, no separate README from
    scratch).
- **Operational debt**: MEDIUM. One repo, multiple modules.
  Dependabot can be configured per-module-go.mod. SBOM is
  per-module-aware via cyclonedx-gomod or similar.
- **Contribution-friendliness**: HIGH for both the
  cross-cutting contributor (atomic monorepo PRs) AND the
  per-module audience (each module has its own README + go.mod
  + version).
- **AI-coordinator throughput**: HIGH. Single repo means single
  agent context; per-module isolation means agents can scope
  their work without cross-cutting test runs.

#### 5E. Hybrid — core monorepo + spin-outs

- **Pros**:
  - Best of 5A and 5C. The core stays a monorepo (high
    AI-coordinator throughput, atomic refactors); the spin-outs
    (`riskguard-go`, `tool-call-audit-go`) are independent
    repos for star-magnet attribution.
  - Each spin-out is a SMALL repo (~5-10k LOC) — manageable
    per-repo overhead is low.
  - Trigger-driven: only spin out a library when external
    demand justifies (e.g., 50+ stars on the parent project,
    one external user filing an issue against the candidate).
- **Cons**:
  - Adds the cross-repo IPC coordination cost of 5C, but
    bounded to the spin-outs. ~1-3 spin-outs is manageable;
    >5 starts to look like 5C.
  - The spin-out repo has to maintain a separate README, CI,
    SBOM, audit, release cadence — more operational debt
    than 5D.
- **Migration cost**: PER-SPIN-OUT. 2-3 dev-weeks per spin-out
  (per `d0e999d` cost estimates for `kc/riskguard/` extraction).
- **Operational debt**: MEDIUM. Bounded to the number of
  spin-outs.
- **Contribution-friendliness**: HIGH for the per-spin-out
  audience (focused repo), HIGH for the core (still
  monorepo).
- **AI-coordinator throughput**: HIGH for the core; LOW for
  cross-spin-out work, but spin-out work is rare by design.

### 5.3 Comparison matrix

| Axis | 5A monorepo | 5B mono+cmd | 5C polyrepo | 5D workspace | 5E hybrid |
|---|---|---|---|---|---|
| Migration cost (dev-weeks) | 0 | 0 | 6-12 | 2-4 | 2-3 per spin-out |
| Operational debt (yearly) | Low | Low | High | Medium | Medium |
| Cross-cutting refactor cost | Low | Low | High | Low | Low (in-core) |
| Standalone-library discoverability | Low | Low | High | High | High |
| AI-coordinator throughput (Axis B) | High | High | Low | High | High (core), Low (spin-outs) |
| Contribution-friendliness (cross-cutting) | High | High | Low | High | High |
| Contribution-friendliness (per-product) | Medium | Medium | High | High | High |
| FLOSS-fund / Rainmatter pitch fit | OK | OK | Best | Better | Better |
| Versioning ceremony | None | None | High | Medium | Medium (per spin-out) |

### 5.4 Recommendation

**Adopt 5B (monorepo with multiple binaries) as the immediate
default; trigger-driven path to 5E (hybrid) when external demand
justifies a spin-out.**

Rationale:

1. **The current state is already 5B.** `cmd/rotate-key/` and
   `cmd/event-graph/` exist; adding more `cmd/X` directories as
   standalone-binary needs emerge is the path of least
   resistance. No migration cost; no semver complication.

2. **Skip 5C (polyrepo) entirely.** The 6-12 dev-week migration
   cost dwarfs any user-MRR benefit at current scale. Per
   `d0e999d` Tier-3 promotion analysis, P(≥2 components require
   independent release in 24mo) ≈ 31%. Below the "ship it now"
   threshold; above the "completely defer" threshold. The 5E
   hybrid captures this without going polyrepo.

3. **5D (workspaces) is the right answer if the spin-out
   inflection point hits.** Workspaces give us per-module
   versioning + atomic cross-module refactors. Migration cost
   (~2-4 dev-weeks for the workspace setup) is recoverable
   when ANY spin-out happens. Defer until trigger fires.

4. **5E (hybrid) is the strict superset of 5B + targeted
   spin-outs.** When a specific library has external demand
   (the 4.2 standalone candidates: `riskguard-go`,
   `tool-call-audit-go`), spin it out as 5E, leaving everything
   else in 5B. The workspaces machinery from 5D becomes the
   tool that lets 5E coexist with 5B (the core stays monorepo;
   spin-out lives in its own go.mod via go.work or as a
   separate repo).

### 5.5 Trigger conditions for the 5B → 5E spin-out

Concrete signals that justify spinning out a library:

| Trigger | Action |
|---|---|
| **Parent repo crosses 50 GitHub stars** | Spin out the most-starred library candidate per GitHub Insights traffic (likely `riskguard-go` first). Rationale: 50 stars is the credibility floor for a sub-library to attract independent contributors. |
| **External developer files an issue against a candidate** (e.g. "can I use kc/riskguard standalone?") | Acknowledge the question; if a second similar question lands within 30 days, spin out. Rationale: 2 inbound demands = real audience. |
| **One candidate library accumulates >5 GitHub forks specifically of that subdirectory** | Spin out — the forks are evidence of standalone use. |
| **Rainmatter / FLOSS-fund pitch requires a separable artifact** for grant eligibility (per `kite-floss-fund.md` referenced in MEMORY.md) | Spin out the most pitch-relevant candidate. Riskguard is the strongest fit because "Indian retail safety rails as open source library" is grant-grade framing. |
| **A second broker integration appears** (Compatibility dim per scorecard) | Spin out `riskguard-go` first because the abstraction would now serve N brokers. |

If NONE of these triggers fires within 12 months, **stay at 5B
indefinitely**. The empirical 31% probability of Tier-3 promotion
in 24mo (per `d0e999d`) is below the threshold for proactive
spin-out.

### 5.6 Cross-reference with parallel-stack-shift-roadmap.md

Q5 is **orthogonal** to the language-track stack-shift question
that `parallel-stack-shift-roadmap.md` covers. Per the brief:
"This question is orthogonal — it's about ORGANIZATION/RELEASE
BOUNDARIES, not language choice. Don't conflate."

Honoring that:

- The Q5 spin-out trigger is **release-boundary-driven**, not
  language-driven. A `riskguard-go` spin-out is still a Go
  library; a Track C Rust riskguard would be a different
  library (`riskguard-rs`) that imports the Go contract via
  IPC.
- 5E hybrid does NOT require any track to activate. It serves
  the "external Go developer wants to import riskguard
  standalone" demand independent of any language-track shift.
- Conversely, no track activation requires Q5 to change. Track
  A (TS) could be a separate repo OR a `cmd/server-ts/`
  subdirectory; that's a Track A decision, not a Q5
  prerequisite.

### 5.7 Migration roadmap (if/when 5E triggers fire)

For each candidate spin-out, the roadmap is symmetric. Using
`riskguard-go` as the worked example:

**Phase 1 — pre-spin-out preparation (~3 dev-days)**:

1. Extract `kc/alerts.DB` dep from `kc/riskguard/` behind a
   `LimitStore` interface defined in `kc/riskguard/store.go`.
2. Either alias `kc/domain.Money` to a riskguard-internal
   `Money` type OR keep `kc/domain` as a transitive dep
   (cheap; 33 LOC).
3. Add a `kc/riskguard/README.md` that documents the
   integration contract (already partially documented in
   `kc/riskguard/checkrpc/README.md`).
4. Add tests proving the package builds standalone (no
   reverse imports from `mcp/` or `app/`). Already true today
   per the empirical audit in §4.1.9.

**Phase 2 — repo split (~5-7 dev-days)**:

1. Create new repo `Sundeepg98/riskguard-go` (or
   `zerodha/riskguard-go` if the Rainmatter framing
   materialises).
2. Copy `kc/riskguard/*` to the new repo's root.
3. Set up `go.mod` declaring `github.com/Sundeepg98/riskguard-go`.
4. Set up `.github/workflows/ci.yml` mirroring the parent's
   `go vet + test -race + golangci-lint + govulncheck` shape.
5. Add LICENSE (MIT, matching parent), SECURITY.md (lighter
   version), CHANGELOG.md.
6. Tag `v0.1.0` (initial release).

**Phase 3 — parent repo update (~2-3 dev-days)**:

1. Update kite-mcp-server's go.mod to depend on
   `github.com/Sundeepg98/riskguard-go v0.1.0`.
2. Replace internal imports `kc/riskguard` →
   `github.com/Sundeepg98/riskguard-go`.
3. Delete `kc/riskguard/` from kite-mcp-server.
4. Verify CI green.
5. Tag a kite-mcp-server release noting the dep update.

**Phase 4 — ongoing coordination**:

- Schema changes to `riskguard-go` follow the IPC contract
  spec (`.research/ipc-contract-spec.md`, `4fa5a39`)
  evolution rules.
- Per-month dep update cycle (kite-mcp-server bumps to latest
  riskguard-go).
- Quarterly release cycle (riskguard-go semver bump).

**Total per spin-out: ~2-3 dev-weeks** (matches `d0e999d`
cost estimate). Recoverable within ~6 months if the
star/fork trigger is real.

---

## Summary

### Q4 verdict

**One product (`kite-mcp-server`); two genuinely-extractable
standalone Go libraries (`riskguard-go`, `tool-call-audit-go`)
when external demand justifies the split. Everything else is a
surface, packaging, or distribution mechanism of the same
product.**

The skills + plugin are markdown distribution layers; widgets +
dashboard + telegram + paper trading + backtest + litestream are
server features in different surfaces. Calling them "products"
inflates maintenance burden against zero marginal user-MRR.

### Q5 verdict

**Stay at 5B (monorepo with multiple binaries — already the
current state). Trigger-driven path to 5E (hybrid: core monorepo
+ targeted spin-outs) when external demand justifies a specific
library spin-out.**

Concrete triggers per §5.5:
- 50+ GitHub stars on parent
- ≥2 inbound questions about standalone use within 30 days
- ≥5 forks specifically of a candidate subdirectory
- Rainmatter / FLOSS-fund pitch requires separable artifact
- Second broker integration emerges

If NONE fires within 12 months, stay at 5B indefinitely. The
empirical 31% probability of Tier-3 promotion in 24mo (per
`d0e999d`) is below the threshold for proactive spin-out.

### Honest opacity

1. The spin-out cost estimates (~2-3 dev-weeks) inherit
   `d0e999d`'s per-component analysis. They could be off by
   ±50%; the relative ranking among options would not
   change at that range.
2. The 31% promotion probability uses a multiplicative
   independence assumption per `d0e999d` §2.5; correlated
   triggers could move this either direction.
3. The `kc/audit/` standalone-library audience claim ("AI agent
   developer audience, broader than riskguard, 100-500 stars
   range") is informed speculation not market research. A
   conservative reading is "uncertain audience size; ship if a
   specific consumer asks."
4. Skills + plugin are intentionally framed as "not separate
   products". A future framing where they ARE the lead-in
   product (with the MCP server as a backend) is conceivable
   if Claude Code marketplace gating becomes a real
   distribution channel; that's a re-framing, not a fact gap
   in this audit.
5. Q5 evaluation pre-supposes a single-developer-team or small-
   team baseline. At a 4+-person team, polyrepo (5C) becomes
   more tractable; the 5E hybrid recommendation is
   single-team-optimal.
6. **Stack-shift orthogonality** per the brief: this doc does
   NOT propose any language-track decisions. The 5E hybrid is
   pure organization/release-boundary work. Track A/B/C
   activations remain governed by `parallel-stack-shift-
   roadmap.md`.

---

## Sources

- `README.md` — top-level project framing; the "product story" Q4
  audits.
- `.research/fork-loc-split-and-tier3-promotion.md` (`d0e999d`)
  Part 2 — Tier-3 promotion-trigger matrix; per-component cost
  estimates.
- `.research/parallel-stack-shift-roadmap.md` (`8361409`) §1 +
  §3 + §4 + §5 — Foundation phase + per-track scope.
- `.research/scorecard-final-v2.md` (`8361409`) §2.3 — empirical
  measurement that `mcp/` is NOT thin transport.
- `.research/ipc-contract-spec.md` (`4fa5a39`) — drafted IPC
  contract; informs cross-repo coordination cost.
- `feedback_decoupling_denominator.md` — three-axis ROI
  framework.
- `docs/adr/0007-canonical-cross-language-plugin-ipc.md`
  (`202b993`) — the existing pattern that `riskguard-go` would
  inherit if spun out.
- `kc/riskguard/checkrpc/README.md` — the integration contract
  doc that would accompany a `riskguard-go` spin-out.
- Empirical LOC measurements at HEAD `1081684` via WSL2 Ubuntu
  24.04.
- Per-package import-graph audit at HEAD `1081684`:
  - `kc/riskguard/` non-test deps: `kc/alerts`, `kc/domain`,
    `kc/logger`. ZERO `gokiteconnect`. ZERO `mcp/` reverse
    imports.
  - `kc/audit/` non-test deps: `kc/alerts`, `kc/domain`,
    `kc/logger`. ZERO `gokiteconnect`. ZERO `mcp/` reverse
    imports.
  - `kc/papertrading/` non-test deps: `kc/alerts`, `kc/domain`,
    `kc/logger`, `oauth/`. Tightly coupled.
  - `kc/telegram/` non-test deps: `broker/zerodha`, `kc/alerts`,
    `kc/instruments`, `kc/riskguard`, `kc/watchlist`. Deeply
    tangled.
- `~/.claude/plugins/local/kite-trading/.claude-plugin/plugin.json`
  — 9 LOC; the trading plugin's full manifest is 559 LOC of
  markdown.
- `skills/README.md` — 70 LOC; positions skills as "the reasoning
  layer" complementary to the MCP server.

---

*Generated 2026-04-28 night, read-only research deliverable. NO
ship. Q4 verdict: one product + two extractable libraries. Q5
verdict: stay at monorepo-with-multiple-binaries (5B); hybrid (5E)
when external triggers fire.*
