# Algo2Go Umbrella — Product Portfolio Strategy

**Date**: 2026-05-02
**HEAD audited**: `99b9bdf` (canonical product-definition.md just landed)
**Charter**: research deliverable, **NO code changes**. Single doc.

**Anchor docs (memory + repo)**:
- `~/.claude/projects/D--Sundeep-projects/memory/kite-algo2go-rename.md` — domain `algo2go.com` AVAILABLE, GitHub `algo2go` org AVAILABLE, npm/PyPI free; TM Class 36+42 clear; ₹9-22k filing; backup name `Tradarc`.
- `.research/multi-product-and-repo-structure.md` (`39577c3`) — Q4 verdict: **one product with two genuinely-extractable libraries** (`riskguard-go`, `tool-call-audit-go`). Q5 verdict: stay 5B (monorepo + cmd/ binaries); 5E (hybrid spin-out) on trigger.
- `.research/fork-loc-split-and-tier3-promotion.md` (`d0e999d`) — 8 Tier-3 components; aggregate 24mo promotion probability **31% for ≥1**, 12% for ≥3. ~8 expected dev-weeks total.
- `.research/parallel-stack-shift-roadmap.md` (`8361409`) — three language tracks (TS / Python / Rust); Foundation phase 4-5 weeks; verdict: **defer all three** (none of the user-MRR / team-scale / portability triggers fire today).
- `docs/product-definition.md` (`99b9bdf`) — canonical product framing: **kite-mcp-server is the single user-facing product**, ~80 tools, 3 install paths (hosted read-only, self-host full, client-config snippet), differentiated against the official 22-tool Zerodha MCP.
- `MEMORY.md` snippets: `kite-mrr-reality.md` (₹15-25k MRR at 12mo; empanelment after 50 paid subs); `kite-landmines.md`; `kite-launch-blockers-apr18.md`; `kite-zerodha-no-marketplace.md`; `kite-competitors-corrected.md` (Multibagg real threat, Dhanarthi fake).

**Cross-link**: `.research/disintegrate-and-holistic-architecture.md` (being written in parallel by another agent) — that doc covers the architectural shape the portfolio needs; this doc covers the product strategy that depends on it.

---

## TL;DR (≤120 words, lead with verdict)

**Verdict: Do NOT commit to the Algo2Go umbrella today. Reserve the brand by registering the domain + GitHub org + filing the TM (₹9-22k, 1 weekend) — but ship the next 6-12 months under `kite-mcp-server`.** Switch to Algo2Go only when ONE of three triggers fires: (1) Zerodha sends a TM cease-and-desist, (2) we hit ≥50 paid subs (the empanelment-gate threshold per `kite-mrr-reality.md`), or (3) a SECOND broker (Upstox/Dhan) actually ships and pays its way.

**Wedge product when we do switch: `algo2go-mcp` (the current core, renamed).** Not a portfolio launch. The umbrella unlocks future `algo2go-*` packaging only after the wedge has traction; manufacturing 8 sub-products before the lead has 50 stars dilutes attention against zero marginal MRR.

---

## Phase 1 — Grounding (read, no findings yet)

Foundation reads complete. Stationary facts:

- **Renaming is cheap to RESERVE** (~₹1k domain + ~₹0 GitHub + ~₹9-22k TM filing) but **expensive to EXECUTE** (Fly.io app rename, mcp-remote cache invalidation across users, README/blog/launch material rewrite, MCP-Registry server.json update, awesome-mcp-servers re-listing, Smithery re-publish, social handle migration). Memory's "₹9-22k filing" is the MOQ; the operational tail is 2-3 weeks of cleanup.
- **The product today is ONE Go binary** (`kite-mcp-server`, monorepo, single fly.io app). All "candidate products" below are surfaces, packaging, or extractable libraries — not separate market-shipped products yet.
- **Realistic MRR ceiling is ₹15-25k at 12 months** per `kite-mrr-reality.md`. At that cap, multi-product portfolio orchestration is over-engineered.

---

## Phase 2 — Algo2Go product portfolio inventory

For each candidate: name, value prop, audience, stack, standalone-or-umbrella, monetization, **honest-shipping likelihood within 24 months**.

### 2.1 Currently in the codebase

#### P1. `algo2go-mcp` (the headline) — **SHIP-READY TODAY**

- **Value prop**: MCP server that turns Claude / ChatGPT / Cursor into a power-user trading copilot for Zerodha Kite — ~80 tools, riskguard, paper trading, options Greeks, backtesting, Telegram alerts.
- **Audience**: Active Indian retail Zerodha traders who already pay ₹500/month for a Kite Connect dev app and want their AI to *do things* on their account.
- **Stack**: Go 1.25 (single binary, MIT). Stays Go indefinitely per `parallel-stack-shift-roadmap.md` verdict.
- **Standalone or umbrella?**: This IS the product. Standalone today; would be the umbrella's flagship.
- **Monetization**: Free + open source. Future optional paid hosted-trading tier post-empanelment (50+ paid users gate). Current realistic MRR ceiling ₹15-25k at 12mo.
- **24mo ship likelihood**: 100% — already shipped at `kite-mcp-server.fly.dev/mcp`.

#### P2. `algo2go-riskguard` (extract from `kc/riskguard/`) — **TRIGGER-GATED**

- **Value prop**: Drop-in pre-trade safety library for any Indian-broker integration (Kite, Upstox, Dhan, Angel). 9 checks: kill switch, value/qty/count caps, rate limit, duplicate detection, idempotency, anomaly detection, off-hours block, auto-freeze.
- **Audience**: ANY Indian broker SDK consumer (not just Algo2Go users). Realistic external adoption: 10-50 GitHub stars, 0-3 forks, occasional issues — `prometheus/client_golang`-shape infrastructure library.
- **Stack**: Go (current), with `kc/riskguard/checkrpc/` already cross-language ready per ADR 0007. Could later have `riskguard-rs` Rust binding via subprocess plugin.
- **Standalone or umbrella?**: Standalone Go module under the Algo2Go GitHub org. Importable separately; also vendored into `algo2go-mcp`.
- **Monetization**: MIT-licensed library. Indirect monetization via FLOSS-fund eligibility, Rainmatter-pitch credibility, brand for the umbrella.
- **24mo ship likelihood**: 25-30% (matches `multi-product-and-repo-structure.md` Q4.2 spin-out triggers — needs 50+ stars on parent OR external dev demand OR FLOSS-fund forcing event). Extract cost: ~2-3 dev-weeks once trigger fires.

#### P3. `algo2go-audit` (extract from `kc/audit/`) — **TRIGGER-GATED**

- **Value prop**: Tamper-evident audit trail for AI tool calls. SQLite + AES-256-GCM PII fields + hash-chain integrity (HMAC-SHA256) + 90-day retention + CSV/JSON export + optional R2-published Merkle anchor.
- **Audience**: ANY AI agent / MCP server author needing audit observability. Broader than riskguard — AI agent observability is a 2026 hot topic; standalone library could see **100-500 stars** if positioned as "OpenTelemetry gen-ai semantic conventions, but at the audit/tamper-evidence layer."
- **Stack**: Go (current). Hash-chain core could later swap to Rust per Tier-3 promotion §2.7 (15% probability).
- **Standalone or umbrella?**: Standalone Go module under the Algo2Go org. Reusable across non-trading domains.
- **Monetization**: MIT library. Indirect via FLOSS-fund / Rainmatter credibility / brand for the umbrella.
- **24mo ship likelihood**: 15-20%. Extract cost: ~3-4 dev-weeks. Larger audience than riskguard but no specific forcing trigger today.

#### P4. `algo2go-paper` (extract from `kc/papertrading/`) — **TRIGGER-GATED, LOW LIKELIHOOD**

- **Value prop**: Virtual ₹1cr portfolio simulator. Same audit/riskguard/billing chain as live trading; only the broker call is intercepted. Background LIMIT fill monitor against real-quote feed.
- **Audience**: Educational — new traders, strategy developers, anyone testing before live. Could appeal beyond Kite if generalised (engine is broker-agnostic; only the LTP feed is Kite-shaped today).
- **Stack**: Go. 1,981 prod LOC + 8,255 test LOC.
- **Standalone or umbrella?**: Separable in ~3 dev-weeks (replace `oauth/` dep with interface, replace `kc/alerts` dep behind `Store` interface). Library viability medium.
- **Monetization**: Free (educational). MIT library. No realistic paid version.
- **24mo ship likelihood**: <10% as standalone. Educational audience is narrow; remains a server feature.

#### P5. `algo2go-backtest` (extract from `mcp/backtest_tool.go` + strategy core) — **TRIGGER-GATED, LOW LIKELIHOOD**

- **Value prop**: Strategy backtester — 4 built-in strategies (SMA crossover, RSI reversal, breakout, mean reversion), Sharpe ratio, max drawdown, win rate. Operates on Kite historical data.
- **Audience**: Educational + power-traders. Same as paper trading.
- **Stack**: Go today; **Track B Python target** if a 10+ analytics roadmap forms (Per `parallel-stack-shift-roadmap.md` §3 — pandas-ta + scipy + vectorbt would 4× the per-feature velocity over hand-rolled Go).
- **Standalone or umbrella?**: 2-3 dev-weeks to extract `kc/backtest/` package (the 581 LOC tool wraps the strategy code). Bundled today.
- **Monetization**: Bundled / free. No realistic paid version unless we tier strategies.
- **24mo ship likelihood**: <15% as standalone. Likely remains an `algo2go-mcp` feature; Python rewrite IF the analytics roadmap explodes (currently only 3-5 features deferred).

#### P6. `algo2go-greeks` (extract from `mcp/options_greeks_tool.go`) — **NICHE LIBRARY**

- **Value prop**: Black-Scholes options analytics — delta, gamma, theta, vega, IV — plus 8 multi-leg strategy builders (covered call, iron condor, bull/bear spreads, etc.).
- **Audience**: Indian options traders (NIFTY/BANKNIFTY active subset of Zerodha users). Niche but engaged.
- **Stack**: Go (current 825 LOC). Python wrapper around scipy + quantlib could be 300 LOC; same Track B logic as P5.
- **Standalone or umbrella?**: Tightly coupled to MCP plumbing today; could extract domain logic as `algo2go-greeks-go` library (~1.5 dev-weeks).
- **Monetization**: Bundled / library. Could be Pro-tier exclusive in `algo2go-mcp`.
- **24mo ship likelihood**: <10%. Audience is engaged but small; library has limited external pull.

#### P7. `algo2go-telegram` (extract from `kc/telegram/`) — **WILL NOT EXTRACT**

- **Value prop**: Telegram trading bot — `/buy /sell /quick /setalert /pnl`, inline keyboard confirmation, morning + EOD briefings with weekend skip + dedup.
- **Audience**: Mobile-first / always-on Algo2Go users.
- **Stack**: Go today; **Track A TypeScript target** if rich UI / TWA mini-apps demanded. Per Tier-3 promotion §2.1, 15% promotion probability — needs vernacular i18n SLA OR TWA migration as forcing function.
- **Standalone or umbrella?**: NOT separable in any meaningful near-term sense. Per `multi-product-and-repo-structure.md` §4.1.6, Telegram has 5 internal `kc/*` deps (broker/zerodha + alerts + instruments + riskguard + watchlist). Splitting it = polyrepo refactor on the whole stack.
- **Monetization**: Bundled.
- **24mo ship likelihood**: <5% as standalone. Stays a server surface forever unless TWA forces TS rewrite.

#### P8. `algo2go-skills` (the skills/ folder + plugin) — **DISTRIBUTION LAYER, NOT A PRODUCT**

- **Value prop**: Markdown skills (8 in-repo SKILLs covering alert-playbook, backtest-interpretation, eod-review, morning-brief, options-sanity-check, sector-rotation, tax-harvest, trade-check) + 5-command plugin (`/morning`, `/eod`, `/price`, `/quick`, `/trade`).
- **Audience**: Claude Code / Claude Desktop users. Useless without `algo2go-mcp` as backend.
- **Stack**: Markdown + JSON (zero Go).
- **Standalone or umbrella?**: NOT a product. Distribution / discoverability layer.
- **Monetization**: Free. Acts as conversion funnel into `algo2go-mcp`.
- **24mo ship likelihood**: 100% — already shipped. Renaming under Algo2Go is the trivial part of the rebrand.

### 2.2 Plausible future products under same brand

#### P9. `algo2go-multi-broker` (Upstox / Dhan / Angel beyond Zerodha) — **SCALE-GATED**

- **Value prop**: Multi-broker order routing. Per `docs/multi-broker-plan.md`, Upstox adapter is **5-6 dev-weeks, ~3,200 LOC** (architecture is 8/10 ready: `Manager.brokerFactory` field already declared but unused; broker port interface clean).
- **Audience**: Cross-broker users (Zerodha + Upstox; Zerodha + Dhan). Realistically a small slice.
- **Stack**: Go (the broker port stays Go).
- **Standalone or umbrella?**: New `broker/upstox/` package inside the same monorepo. Same binary, additional adapter. NOT a separate product, just a capability.
- **Monetization**: Could be Pro-tier "multi-broker" gate.
- **24mo ship likelihood**: 20-30%. Forcing function: paying customer with both Zerodha + Upstox accounts demanding parity. Per `kite-mrr-reality.md`, this is plausible at 20-30 paid subs (subset of ₹15-25k MRR cohort).

#### P10. `algo2go-dashboard` (split from monolith) — **DO NOT SPLIT**

- **Value prop**: Standalone web UI for portfolio / activity / orders / alerts.
- **Audience**: Same as `algo2go-mcp` users.
- **Stack**: Go SSR today (~16.5k LOC in `kc/ops/`). Could be React/TS standalone.
- **Standalone or umbrella?**: Per `multi-product-and-repo-structure.md` §4.1.5, splitting requires either (a) data-layer replication or (b) HTTP-as-admin-API thin layer — ~6-8 dev-weeks. **Not justified at current scale.**
- **Monetization**: Bundled.
- **24mo ship likelihood**: <10% as standalone. Remains a server surface.

#### P11. `algo2go-strategies` (a strategy marketplace / library) — **POSSIBLE, NOT URGENT**

- **Value prop**: Curated strategy library. Currently 4 built-in; could grow to 20-50 community-contributed strategies + ratings + parameter discovery.
- **Audience**: Power traders, semi-algo retail.
- **Stack**: Go today; would need a strategy schema (YAML/JSON) + sandbox runner. Could be Python-track if pandas-ta dominates.
- **Standalone or umbrella?**: Could become its own GitHub repo `algo2go-strategies` purely as YAML/JSON corpus + reference Go runner.
- **Monetization**: Free / community-curated. Marketplace fee for premium strategies is plausible but adds SEBI investment-advisor compliance overhead — likely NOT a path for us per `kite-mrr-reality.md` cost cap.
- **24mo ship likelihood**: 10-15%. Would need community traction first (50+ stars on parent).

#### P12. `algo2go-research` (FII/DII/concall analysis tools) — **POSSIBLE, BUNDLED**

- **Value prop**: Macro / fundamentals layer — `analyze_concall`, `get_fii_dii_flow`, `peer_compare` (already shipped); plausible additions: `sector_rotation_analysis`, `macro_calendar`, `gst_filing_calendar` (for SEBI-RA-track).
- **Audience**: Same as `algo2go-mcp` core.
- **Stack**: Go today; LLM-coordinator pattern (per `kite-new-tools-apr17.md`) — these tools delegate analysis to the host LLM via WebFetch hints rather than embedding heavy NLP locally.
- **Standalone or umbrella?**: Bundled. Their value is composability with the rest of the toolset.
- **Monetization**: Bundled.
- **24mo ship likelihood**: 60-70% to grow this surface (3 → 8-10 tools); 0% as separate product.

#### P13. `algo2go-cli` (standalone CLI for traders without MCP host) — **POSSIBLE WEDGE EXTENSION**

- **Value prop**: `algo2go portfolio`, `algo2go backtest sma --symbol INFY`, `algo2go alert add RELIANCE 2%` — direct CLI without needing a Claude / ChatGPT host. Same `kc/usecases/` core, different transport.
- **Audience**: Terminal-first power users; CI/CD integrators (e.g., schedule a backtest in GitHub Actions).
- **Stack**: Go (`cmd/algo2go-cli/`). New binary, same monorepo, same go.mod.
- **Standalone or umbrella?**: 5B already supports this — `cmd/event-graph/` and `cmd/rotate-key/` exist; adding `cmd/algo2go-cli/` is a normal feature commit. ~3-4 dev-weeks for a usable subset (top 20 tools as flags).
- **Monetization**: Free.
- **24mo ship likelihood**: 30-40%. Cheap to ship; expands TAM beyond MCP-host users; doubles as a developer-experience surface for `algo2go-mcp`.

### 2.3 Synthesis — what's actually a "product"?

| # | Candidate | Standalone product? | 24mo ship likelihood | Cost to extract |
|---|---|---|---|---|
| P1 | `algo2go-mcp` | YES (the flagship) | 100% (already shipping) | 0 |
| P2 | `algo2go-riskguard` | YES (library) | 25-30% | 2-3 dev-weeks |
| P3 | `algo2go-audit` | YES (library) | 15-20% | 3-4 dev-weeks |
| P13 | `algo2go-cli` | YES (binary, same monorepo) | 30-40% | 3-4 dev-weeks |
| P9 | `algo2go-multi-broker` | NO (capability inside flagship) | 20-30% | 5-6 dev-weeks |
| P12 | `algo2go-research` | NO (capability inside flagship) | 60-70% (more tools) | iterative |
| P4 | `algo2go-paper` | weak (educational) | <10% standalone | 3 dev-weeks |
| P5 | `algo2go-backtest` | weak (educational) | <15% standalone | 2-3 dev-weeks |
| P6 | `algo2go-greeks` | weak (niche) | <10% standalone | 1.5 dev-weeks |
| P7 | `algo2go-telegram` | NO (deeply tangled) | <5% standalone | not feasible |
| P8 | `algo2go-skills` | distribution-only | 100% (already shipping) | 0 |
| P10 | `algo2go-dashboard` | NO (server surface) | <10% standalone | 6-8 dev-weeks |
| P11 | `algo2go-strategies` | maybe | 10-15% | unknown |

**Honest portfolio reality**: 1 flagship + 2 distribution layers + at most 3-4 future spin-out libraries (P2, P3, P13). That's the empirical ceiling. The other 8 candidates are surfaces / capabilities / weak audiences.

---

## Phase 3 — Sequencing & launch order (24-month roadmap)

The wedge is `algo2go-mcp`. Everything else rides the wedge OR has a self-justifying standalone audience.

### Month 0 (today, May 2026)

**SHIP NOTHING UNDER ALGO2GO**. Reserve the brand only:

1. **Register `algo2go.com`** (Namecheap / GoDaddy, ~₹1k/year). Enable WHOIS privacy. Park to a placeholder.
2. **Create `algo2go` GitHub org**. Empty for now; later seat for repo migration.
3. **File TM Class 36 (financial) + Class 42 (software)** via Vakilsearch / LegalWiz, ₹18-22k. 12-18 month TM examination; usage allowed immediately as `Algo2Go™`.
4. **Reserve npm + PyPI** namespace `algo2go` (publish 1 LOC stub or block-list package). ~30 min.

**Total Month 0 cost: ~₹20-23k + 1 weekend.**

**No public rebrand. Continue shipping under `kite-mcp-server`.** Per `docs/product-definition.md`, the canonical product story has just been written under the current name — DO NOT churn the launch material.

### Month 0-3: focus on the wedge under existing brand

Per `kite-launch-blockers-apr18.md` and `docs/product-definition.md`, the immediate priority is:

- Clean repo (`.research/` → private repo, build artifacts purge per Section 2 of product-definition.md)
- Ship Show HN post (draft already in `docs/launch/`)
- Public landing iteration
- MCP Registry publish, Smithery publish, awesome-mcp-servers PRs
- Get to 50 GitHub stars (current target per `kite-rainmatter-warm-intro.md`)

**Trigger to evaluate at month 3**: did Show HN convert, did stars cross 50, did anyone in Zerodha legal notice us?

### Month 3-6: trigger-driven decision point

Three branches, conditional on what happened in months 0-3:

#### Branch A (most likely, 50% probability): "modest traction"

- 20-50 stars, 5-15 paid hosted users, no Zerodha legal pressure
- **Action**: stay `kite-mcp-server`. Ship `cmd/kite-cli/` (P13) under existing name as a new install path. Telegraph "we're working on broker abstraction" in roadmap doc.
- Algo2Go domain stays parked.

#### Branch B (25% probability): "Zerodha sends C&D or invites us in"

- TM cease-and-desist letter, OR Rainmatter / Z-Connect editorial outreach with rebrand request
- **Action**: execute the rebrand sprint. ~3 weeks calendar:
  - Week 1: rename repo to `algo2go/algo2go` (or `Sundeepg98/algo2go`), update go.mod path, redirect from old GitHub URL (auto-redirect works)
  - Week 2: rename Fly.io app `kite-mcp-server` → `algo2go`, set up `algo2go.com` → `algo2go.fly.dev` reverse proxy with announce-redirect from old `kite-mcp-server.fly.dev/mcp` for 6 months
  - Week 3: rewrite README, landing page, MCP Registry server.json, social handles, awesome-mcp-servers PR

#### Branch C (25% probability): "real takeoff"

- 100+ stars, 30+ paid users, multi-broker demand from a real customer
- **Action**: rebrand AND ship `algo2go-multi-broker` (Upstox adapter) as the lead reason. The rebrand has narrative cover ("we generalised; new name reflects it"). 5-6 week multi-broker sprint per `docs/multi-broker-plan.md` overlaps with the 3-week rebrand sprint.

### Month 6-12 (assuming a rebrand triggered)

**Once `algo2go-mcp` is the canonical name with traction, follow-up products ride the audience:**

- **Month 7-8**: extract `algo2go-riskguard` to its own repo (`algo2go/riskguard-go`). 2-3 dev-weeks. Trigger: 50+ parent stars OR 2 inbound questions about standalone use within 30 days. Ship as MIT library; pitch in FLOSS-fund proposal as separable artifact.
- **Month 9-10**: ship `algo2go-cli` (P13) if not already done. 3-4 dev-weeks. Same monorepo, new `cmd/`. Cheap; high distribution leverage (CI/CD users + terminal devs who'd never install an MCP host).
- **Month 11-12**: extract `algo2go-audit` to its own repo (`algo2go/tool-call-audit-go`). 3-4 dev-weeks. Trigger: ANY external AI-agent-builder asks about standalone use OR FLOSS-fund grant requires it. Larger audience than riskguard but slower-burn.

### Month 12-18

- **Multi-broker (P9)** if a paying customer with Upstox + Zerodha exists. 5-6 dev-weeks per multi-broker-plan.md.
- **`algo2go-research` expansion (P12)** — grow from 3 → 8-10 tools. Iterative; not a discrete release.
- **`algo2go-strategies` (P11)** — IF community contributions start arriving (10+ external PRs proposing new strategies in the parent repo); spin out as YAML/JSON corpus repo.

### Month 18-24

- **Track B Python rewrite of `algo2go-backtest` + `algo2go-greeks`** IF analytics roadmap exceeds 10 deferred features (per parallel-stack-shift-roadmap.md trigger). Foundation phase 4-5 weeks + Track B 11-14 weeks.
- **Track A TS rewrite of widgets** IF widget UX iteration becomes the bottleneck. Probability low.
- **Hosted full-trading paid tier** post-empanelment — only if 50+ paid users on read-only tier per `kite-mrr-reality.md`.

### Sequence summary table

| Month | Trigger | Ships | Brand |
|---|---|---|---|
| 0 | (always) | brand reservation + TM filing | both |
| 0-3 | (always) | Show HN, MCP Registry publish, repo cleanup | kite-mcp-server |
| 3-6 | C&D OR 100+ stars | rebrand to algo2go-mcp | algo2go (new) |
| 7-8 | 50+ stars OR 2 inbound | algo2go-riskguard library | algo2go |
| 9-10 | (always at this stage) | algo2go-cli | algo2go |
| 11-12 | external AI-agent demand | algo2go-audit library | algo2go |
| 12-18 | paying multi-broker user | algo2go-multi-broker capability | algo2go |
| 18-24 | analytics roadmap >10 features | Track B Python ports | algo2go (multi-stack) |

---

## Phase 4 — Cross-product synergies the umbrella unlocks

Things that ONLY make sense once Algo2Go is an umbrella, not a single product:

### 4.1 Single sign-on across `algo2go-*` services

Today, each future service would re-implement OAuth. Under the umbrella, `algo2go.com/auth` becomes the canonical OAuth issuer:

- One `OAUTH_JWT_SECRET` issues tokens valid for `algo2go-mcp`, `algo2go-cli`, `algo2go-dashboard` (if ever split).
- User logs in once at `algo2go.com`, gets token, uses across surfaces.
- Per-product scopes: `mcp:read`, `mcp:trade`, `cli:any`, `riskguard:check`.

This is real value at 3+ services; zero value at 1 service. Reinforces "don't switch until ≥2 products are real."

### 4.2 Shared audit trail across products

Today's `kc/audit/` covers MCP tool calls. Under the umbrella, it'd cover:

- `algo2go-mcp` tool calls (today)
- `algo2go-cli` command invocations
- `algo2go-telegram` bot commands
- Inbound webhook events to `algo2go-multi-broker`

Single pane of glass: "What did agent X do across all surfaces today?" Compliance value (SEBI/SEBI-RA audit trail) + UX value (one /dashboard/activity covers everything).

### 4.3 Cross-product analytics

`algo2go-dashboard` could display:

- Risk usage (from algo2go-riskguard subprocess)
- Position state (from algo2go-mcp)
- Active alerts (from algo2go-mcp)
- Backtest history (from algo2go-backtest if extracted)
- CLI command frequency (from algo2go-cli)

Combined risk+position+alert pane is unique-to-umbrella; impossible without shared identity + shared storage.

### 4.4 Bundle pricing for multiple products

When multiple paid tiers exist:

- Free: read-only on hosted `algo2go-mcp`
- Pro (₹500/month): full hosted-trading + backtesting + multi-broker
- Pro+ (₹1500/month): + algo2go-strategies marketplace + priority support

Today there's nothing to bundle. Future-state ROI scales linearly with paid tier count.

### 4.5 Unified developer platform

`algo2go.com/developers` could expose:

- `algo2go-riskguard` (Go library docs)
- `algo2go-audit` (Go library docs)
- `algo2go-mcp` (MCP server docs + tool catalog)
- `algo2go-cli` (man pages)
- IPC contract spec from ADR 0007 (cross-language plugin protocol)
- API key generation per developer

This positions Algo2Go as not just "a product" but "an Indian-trading developer platform" — closer to Stripe's positioning than to a single SaaS.

**Honest take on synergies**: 4.1-4.3 are the real value. 4.4 is theoretical (₹15-25k MRR cap doesn't justify multi-tier complexity). 4.5 is aspirational (the FLOSS-fund / Rainmatter narrative; not a product strategy by itself).

---

## Phase 5 — Technical preconditions

Cross-link: `.research/disintegrate-and-holistic-architecture.md` is the architectural blueprint being drafted in parallel; this section names the **product-strategy-side** preconditions that depend on it.

### 5.1 Required for ANY umbrella to feel coherent

| Precondition | Current state | Cost if not met |
|---|---|---|
| Shared identity model (single user store across products) | EXISTS — `kc/users/` is broker-agnostic | 0 |
| Shared audit log surface (any product can append) | EXISTS — `kc/audit/` is generic ToolCall ⇄ generic event | 0 |
| Shared OAuth token issuer | EXISTS — `oauth/` issues JWT consumed by MCP + dashboard | 0 |
| Shared SQLite + Litestream backup | EXISTS — `etc/litestream.yml` covers all `*.db` files | 0 |
| **Per-product wire contracts** (MCP for `-mcp`, JSON-RPC for `-riskguard` subprocess, CLI flags for `-cli`) | PARTIAL — MCP done; JSON-RPC IPC drafted in ADR 0007 + ADR 0009; CLI absent | ~1 week per missing surface |
| **IPC contract spec** for cross-language calls | DRAFTED — ADR 0007 + `.research/ipc-contract-spec.md` | 0 (already paid) |

### 5.2 Required for `algo2go-riskguard` library spin-out (P2)

| Precondition | State | Cost |
|---|---|---|
| `kc/riskguard/` no SDK leaks | TRUE — empirically verified in `multi-product-and-repo-structure.md` §4.1.9 (zero `gokiteconnect` imports, zero `mcp/` reverse imports) | 0 |
| `LimitStore` interface (replaces `kc/alerts.DB` dep) | NOT YET — extract task | 3 dev-days |
| `kc/domain.Money` either aliased or imported transitively | aliased trivially or 33 LOC dep | 1 dev-day |
| Standalone `README.md` + `LICENSE` + `SECURITY.md` | NOT YET | 1 dev-day |
| Tests prove standalone build | TRUE today (no reverse imports) | 0 |

**Total: ~5 dev-days of pre-extraction work + 5-7 dev-days repo-split work + 2-3 dev-days parent-update = ~2-3 dev-weeks total.**

### 5.3 Required for `algo2go-audit` library spin-out (P3)

Same shape as 5.2; `kc/audit/` is symmetrically clean (`multi-product-and-repo-structure.md` §4.1.10). ~3-4 dev-weeks total.

### 5.4 Required for `algo2go-cli` (P13)

| Precondition | State | Cost |
|---|---|---|
| `kc/usecases/` is the canonical command/query surface (CLI calls usecases, not MCP transport) | TRUE — Clean Architecture per `.claude/CLAUDE.md` | 0 |
| Cobra or kong-style CLI framework | NOT IN deps | add 1 dep |
| Per-command flag definitions for top 20 tools | NOT YET | 2-3 dev-weeks |
| Auth: cli reads `OAUTH_JWT_SECRET` from `~/.algo2go/credentials` (analogous to `~/.kube/config`) | NOT YET | 2 dev-days |
| CI artifact: pre-built binaries for darwin/linux/windows | reuses existing goreleaser | 1 dev-day |

**Total: ~3-4 dev-weeks.**

### 5.5 Required for `algo2go-multi-broker` (P9)

Per `docs/multi-broker-plan.md`: **5-6 dev-weeks, ~3,200 LOC**. `Manager.brokerFactory` field already declared (unused) at `kc/manager.go` line 32 — wiring is a known TODO.

### 5.6 Architecture risks named (cross-link to disintegrate doc)

The companion agent's disintegrate-and-holistic-architecture.md will detail how to reach this. Strategy-side risks worth flagging:

1. **`kc/manager.go` is a god-object** (~600 LOC trimmed to 402 over the fork's lifetime; still central). Multi-product strategy depends on `Manager` being decomposable into per-aggregate services. Per-product extraction is bottlenecked by this.
2. **`kc/templates/` widgets are HTML-templated server-side** — bundling them into a separate `algo2go-dashboard` repo (P10) requires either a Go SSR fork or a JS/TS rewrite (Track A). This is why P10 is "do not split."
3. **Cross-product event bus**: `kc/eventsourcing/` exists but isn't used as the cross-product comm channel. If 4.2 (shared audit) is the umbrella's killer feature, the event bus needs hardening.

---

## Phase 6 — Honest verdict

### 6.1 Is Algo2Go umbrella worth the rebrand cost?

**Reservation cost (Month 0): ₹20-23k + 1 weekend. WORTH IT.** This is insurance:

- If Zerodha sends a C&D, we have the brand ready (no scramble).
- If we choose to rebrand on offense (Rainmatter intro, fundraise, multi-broker), we have the brand ready.
- The TM filing window is 12-18 months; starting now means we have ®registered status by the time it'd matter (mid-2027).
- `algo2go.com` could be claimed by a squatter at any time — a ₹1k/year insurance policy is trivial.

**Execution cost (Month 3-6 IF rebrand triggers): 2-3 weeks calendar.** Justified ONLY when one of the three triggers fires:

1. Zerodha legal action
2. ≥50 paid users (empanelment-gate threshold)
3. Multi-broker actually shipping

**NOT justified prematurely** — per `feedback_decoupling_denominator.md` style ROI logic, rebranding before a forcing event consumes 2-3 weeks of calendar that could ship features. The current `kite-mcp-server` brand is fine for ≤50 paid users; it's literally accurate (it is a Kite MCP server today).

### 6.2 What's the BIG risk?

**Diluting kite-mcp-server's brand BEFORE it has traction.** Concrete risks:

- **Search SEO**: changing the GitHub repo URL invalidates external backlinks (HN posts, Reddit comments, awesome-mcp-servers entries, MCP Registry server.json). GitHub auto-redirects but search engines de-rank during the transition.
- **mcp-remote cache thrash**: existing users have `~/.mcp-auth/mcp-remote-{version}/` keyed to `kite-mcp-server.fly.dev/mcp`. URL change forces re-OAuth across the entire user base — friction event.
- **Show-HN narrative restart**: if we Show-HN as `kite-mcp-server` then rename in 6 months, we burn HN goodwill. HN doesn't allow re-posts of renamed projects within 12 months without flagged-as-spam risk.
- **Premature umbrella signaling** — listing `algo2go-mcp`, `algo2go-riskguard`, `algo2go-audit`, `algo2go-cli` on a website when only the first is real makes the project look vaporware. Per `feedback_decoupling_denominator.md` Axis A logic, manufacturing multi-product framing inflates maintenance perception against zero marginal MRR.

### 6.3 Secondary risks

- **Trademark filing rejected** — Class 36/42 are clean per memory but TM examination can throw curveballs. Mitigation: file with `Tradarc` as backup (per memory) so we have a fallback if Algo2Go gets contested.
- **Domain squatter** — `algo2go.com` is available today; squatters monitor expiring/likely-target domains. Register IMMEDIATELY (Month 0 step 1).
- **Multi-product dilution of attention** — the strategist trap. Per `kite-competitors-corrected.md`, our edge over competitors (Multibagg, Dhanarthi-style fakes) is depth. Spreading thin across 4 sub-products weakens the moat.

### 6.4 What's the right TIME to switch?

**The trigger-driven framework:**

| Trigger | Probability (24mo) | Action |
|---|---|---|
| Zerodha C&D letter | ~10-15% (per `kite-landmines.md`) | rebrand within 30 days |
| ≥50 paid hosted users | ~20-30% (per `kite-mrr-reality.md`) | rebrand within 60 days as part of empanelment ramp |
| Multi-broker (Upstox/Dhan) actually ships | ~20-30% (per `docs/multi-broker-plan.md` triggers) | rebrand simultaneous with multi-broker launch |
| Rainmatter / fundraise triggers | ~10% (per `kite-rainmatter-warm-intro.md`) | rebrand on Rainmatter request |
| ANY of the above fires | ~45-55% combined (independence assumption — likely correlated) | rebrand on first fire |

**Aggregate**: ~50% probability of a trigger firing within 24 months. Below "ship now" threshold; above "completely ignore" threshold. **Reservation now (₹20-23k) is the dominated strategy.**

### 6.5 What's the MINIMUM action today?

Three concrete tasks for the user this weekend:

1. **Buy `algo2go.com`** (Namecheap, ~₹1k/year, 5 minutes).
2. **Create `algo2go` GitHub org** (free, 2 minutes; just claim the namespace).
3. **File TM Class 36 + 42 via Vakilsearch / LegalWiz** (₹18-22k, ~30 minutes online; can be done on a Sunday).

**Optional but recommended**:

4. Reserve `@algo2go` on Twitter / X, Bluesky, Mastodon (5 minutes each).
5. Reserve `algo2go` on PyPI (1-LOC stub `algo2go==0.0.0` with a redirect-readme; 10 minutes).
6. Reserve `algo2go` on npm (same shape; 10 minutes).

**Total weekend cost: ~₹22k + 1.5 hours.** Ship date for actual rebrand: when triggered, not before.

---

## 7. Decision matrix (one-page reference)

| Decision | Recommendation | Rationale |
|---|---|---|
| Buy `algo2go.com` today? | **YES** | ₹1k insurance against squatter |
| Create `algo2go` GitHub org today? | **YES** | Free, prevents conflict |
| File TM Class 36+42 today? | **YES** | 12-18mo examination; start now |
| Rebrand REPO today (`kite-mcp-server` → `algo2go-mcp`)? | **NO** | Triggered only by C&D OR 50 paid OR multi-broker |
| Rebrand fly.io app today? | **NO** | URL change = mcp-remote cache thrash |
| Rewrite README + landing today? | **NO** | Just landed canonical product-definition.md |
| Migrate Show HN narrative? | **NO** | Ship under existing brand first |
| Extract `riskguard-go` library this quarter? | **NO** | Wait for 50+ stars OR external demand |
| Extract `tool-call-audit-go` library this quarter? | **NO** | Same trigger framework |
| Ship `cmd/cli/` this quarter? | **MAYBE** | Cheap (3-4 dev-weeks); high distribution leverage |
| Ship Upstox adapter this quarter? | **NO** | Wait for paying multi-broker user |
| Build `algo2go.com` website this quarter? | **NO** | Park to placeholder until rebrand triggered |

---

## 8. Honest caveats / opacity

1. **The 50% combined trigger probability** assumes weak independence between Zerodha-C&D / paid-users / multi-broker. They could correlate ("Zerodha sends C&D BECAUSE we hit 50 paid users"); the practical conclusion (reserve now, execute on trigger) is robust to correlation.

2. **₹20-23k TM filing is govt + agent fees only**. Add ~₹5-10k if examination throws objections requiring a response. Total worst-case ~₹35k.

3. **Rebrand 2-3 week estimate** is the sprint cost; ongoing tail (mcp-remote re-auth user emails, HN/Reddit comment cleanup, awesome-mcp-servers PR re-merge) is another 2-3 weeks intermittent over 3-6 months.

4. **Multi-product synergies (Phase 4)** are theoretical until ≥2 products are real. SSO (4.1) at 1-product = no value. Bundle pricing (4.4) at 1-product = no value. The synergy story is a 12-24mo payoff, not a Month-0 justification.

5. **`Tradarc` backup name** (per memory) is the right fallback if Algo2Go TM gets contested. Reserve `tradarc.com` defensively (~₹1k) if budget allows.

6. **Per `kite-zerodha-no-marketplace.md`** — Zerodha doesn't have a public app marketplace. Rebrand doesn't unlock a distribution channel; it only escapes a TM risk. The umbrella's strategic value is brand-portability for non-Kite brokers, NOT Zerodha-marketplace listing.

7. **Per `feedback_decoupling_denominator.md`** Axis A logic — every dev-week spent on rebrand is a dev-week NOT spent on features. At ₹15-25k MRR ceiling per `kite-mrr-reality.md`, the opportunity cost matters. Reservation cost (~1 weekend) is acceptable; full-rebrand-without-trigger cost (2-3 weeks) is NOT.

---

## Sources

- `~/.claude/projects/D--Sundeep-projects/memory/kite-algo2go-rename.md` — TM availability, filing cost
- `.research/multi-product-and-repo-structure.md` (`39577c3`) — Q4 (one product + 2 libraries) + Q5 (5B → 5E hybrid)
- `.research/fork-loc-split-and-tier3-promotion.md` (`d0e999d`) — Tier-3 promotion probabilities, 8 dev-weeks expected
- `.research/parallel-stack-shift-roadmap.md` (`8361409`) — three-language tracks, defer-all verdict
- `docs/product-definition.md` (`99b9bdf`) — canonical kite-mcp-server product framing
- `docs/multi-broker-plan.md` — Upstox spec (5-6 dev-weeks, ~3,200 LOC)
- `MEMORY.md` references: `kite-mrr-reality.md`, `kite-landmines.md`, `kite-launch-blockers-apr18.md`, `kite-zerodha-no-marketplace.md`, `kite-competitors-corrected.md`, `kite-rainmatter-warm-intro.md`
- Empirical state at HEAD `99b9bdf` (kc/, mcp/, oauth/, broker/, cmd/, skills/, .claude-plugin/ verified via WSL2/Windows-direct path reads)

---

*Generated 2026-05-02, read-only research deliverable. NO ship of code. Reservation actions (domain/GitHub/TM) are the only Month-0 recommendation; rebrand execution is trigger-gated.*
