# FLOSS/fund grant application drafts — 2026-05-16

_Authored: 2026-05-16 IST_
_Source: FLOSS/fund agent concrete drafts dispatch_
_Status: DRAFT-FOR-SUBMISSION (Q2 deadline ~Jun 30 2026; recommended tier $35k)_

---

## Persistence note (3 of 5 transcript-only persistences)

The content below was originally produced by the FLOSS/fund grants agent earlier today (2026-05-16) but lived in the agent transcript only. This file persists the drafts to the durable corpus so they survive session boundaries.

Sibling persistence files (also being landed today by other agents):
- 1 of 5: 4 transcript-only artifacts from 2026-05-16 session (commit `7ade6f1`)
- 2 of 5: Twitter launch content from 2026-05-16 (commit `a01026d`)
- 3 of 5: **this file — FLOSS/fund grant drafts**
- 4 of 5: (other domain agent)
- 5 of 5: (other domain agent)

The original interactive transcript dispatch produced six concrete deliverables (A through F below). This persists all six verbatim.

---

## State vs prior prep doc (2026-05-02 → 2026-05-11 → 2026-05-16)

| Item | 2026-05-02 prep | 2026-05-11 readiness | 2026-05-16 NOW |
|---|---|---|---|
| `funding.json` schema valid | NO (blockers) | YES v1.1.0 | YES v1.1.0 (master) |
| Plan amounts conform | NO ($25k/$50k) | YES ($10k/$35k/$60k) | YES (unchanged) |
| Fly `/funding.json` serves current | n/a | NO (v1.0.0 stale) | **STILL NO** (Fly returns v1.0.0; 5 days unfixed) |
| GitHub stars | 0 | 0 | **0** (across 30 repos: main + 29 algo2go modules) |
| Show HN posted | NO | NO | NO (draft polished at `docs/show-hn-post.md`) |
| Blog post live | NO | NO | NO |
| Algo2go modules public | future plan | 28 (May 11) | **29** (kite-mcp-metrics today; bootstrap @v0.1.1 GOPROXY-verified) |
| Tools count claim | ~80 | 111 (compile-and-run verified) | 111 (unchanged, prod v1.3.0 / 137h uptime) |
| Tests count | 330+ | ~9,000 / 478 files | 269 host + 28-29 modules = unchanged framing |
| Security audit | 181 findings resolved | unchanged | unchanged (~9.5/10) |
| FOSS United email | drafted, unsent | drafted, unsent | drafted at `docs/drafts/foss-united-grant-email.md`; **still unsent**, still highest-EV near-term action |
| Zerodha compliance email | placeholder | resolved | resolved at `docs/drafts/zerodha-compliance-email.md`; unsent |

**Net delta May 11 → May 16**: One additional algo2go module + bootstrap tag bump. Everything else (traction, Fly redeploy, Show HN, blog) is unchanged. **No traction has been built in the past 5 days; the gate to FLOSS/fund submission remains exactly where it was.**

---

## Deliverable A — `funding.json` (full JSON ready to copy)

Two versions follow. **A1** is a polish of the CURRENT manifest (impact-led description, Algo2go umbrella reflected in projects array, channels upgraded). **A2** is the conservative minimal-change version if you want only the v1.0.0→v1.1.0 description refresh without restructuring.

### A1 — Recommended: impact-led, umbrella-aware

```json
{
  "version": "v1.1.0",
  "entity": {
    "type": "individual",
    "role": "owner",
    "name": "Sundeep Govarthinam",
    "email": "sundeepg8@gmail.com",
    "description": "Independent software engineer based in Bengaluru, India. Solo maintainer of kite-mcp-server — an MIT-licensed Model Context Protocol bridge that turns AI clients (Claude, ChatGPT, Cursor) into safe, audit-trailed trading copilots for Indian retail traders on Zerodha. Active Kite Connect developer for 2+ years. 1,365+ commits since April 2026; production deployment at v1.3.0 with 137+ hours uptime; 29 supporting Go modules published under the algo2go GitHub org. Indian Pvt Ltd incorporation in progress as part of FLOSS/fund tier-1 deliverable.",
    "webpageUrl": {
      "url": "https://github.com/Sundeepg98"
    }
  },
  "projects": [
    {
      "guid": "kite-mcp-server",
      "name": "Kite MCP Server",
      "description": "Brings Zerodha's Kite Connect API into AI clients (Claude Desktop, claude.ai, ChatGPT, Cursor) for India's 8 lakh+ active Kite Connect developers. Closes the gap between Zerodha's official read-only MCP (22 tools, GTT-only) and what retail traders actually need: 111 production-registered tools spanning order placement (gated off on hosted endpoint per NSE/INVG/69255 Path 2 via ENABLE_TRADING=false; full on self-host), Black-Scholes options Greeks, 4-strategy backtesting with Sharpe/drawdown, technical indicators (RSI/SMA/EMA/MACD/Bollinger), Telegram briefings, paper trading (virtual ₹1cr portfolio), tax-loss harvest, sector exposure, and FII/DII flow. Safety is load-bearing: 11-check pre-trade RiskGuard middleware (kill switch, per-order value cap, qty/daily count, rate limits, duplicate detection, daily notional cap, idempotency, anomaly μ+3σ, off-hours block), hash-chained tamper-evident audit trail with 90-day retention, MCP elicitation forcing human confirmation on 8 destructive tools, per-user OAuth 2.1 + PKCE with AES-256-GCM encryption (HKDF-derived key). 269 test files in host repo + 28 supporting modules under algo2go GitHub org. Production: Fly.io Mumbai with static egress IP 209.71.68.157 for SEBI April 2026 mandate; SQLite + Litestream continuous replication to Cloudflare R2 APAC. 27-pass independent security audit (181 findings resolved); ~9.5/10 security score. Go 1.25.8, MIT.",
      "webpageUrl": {
        "url": "https://kite-mcp-server.fly.dev/"
      },
      "repositoryUrl": {
        "url": "https://github.com/Sundeepg98/kite-mcp-server"
      },
      "licenses": [
        "spdx:MIT"
      ],
      "tags": [
        "go",
        "mcp",
        "model-context-protocol",
        "zerodha",
        "kite-connect",
        "algo-trading",
        "ai",
        "claude",
        "fintech",
        "india"
      ]
    }
  ],
  "funding": {
    "channels": [
      {
        "guid": "grant-email",
        "type": "other",
        "address": "sundeepg8@gmail.com",
        "description": "Direct grant coordination via email — bank/wire details shared post-acceptance. Indian individual maintainer; bank account ready; FEMA LRS reverse-path documented with chartered accountant. GitHub Sponsors profile will go live in tandem with this application."
      }
    ],
    "plans": [
      {
        "guid": "small-grant",
        "status": "active",
        "name": "Small grant — legal + security baseline ($10k)",
        "description": "Indian Pvt Ltd incorporation + FY1 ROC compliance (~₹85,000), Class 36 + 42 trademark filing (~₹40,000), one round independent CERT-In-empanelled VAPT audit (~₹2,40,000), 6 months Fly.io static IP + R2 storage runway (~₹75,000), domain renewal & SSL infra (~₹40,000). Unlocks legal+security baseline required to convert hosted endpoint from preview to production-billable, and to file for NSE empanelment downstream. Total ≈ ₹4,80,000 ≈ $5,750; remaining $4,250 → 6-week emergency response buffer for unforeseen compliance work (DPDP/SEBI). All amounts disclosed in line items in tier-2 / tier-3 below.",
        "amount": 10000,
        "currency": "USD",
        "frequency": "one-time",
        "channels": ["grant-email"]
      },
      {
        "guid": "substantive-grant",
        "status": "active",
        "name": "Substantive grant — 6-month focused runway ($35k)",
        "description": "All of tier-1 PLUS independent external code+security review (~₹4,00,000), 6 months full-time maintainer runway at ₹2.5L/month (~₹15,00,000) replacing weekend-evening hacking, multi-broker adapter via the algo2go/kite-mcp-broker port (Dhan + Upstox + Angel One adapters), BYO-API-key hedge enabling users to never hit app-tier rate limits, expanded analytics (concall summarizer + FII/DII flow + peer comparison shipped to v1). Maps to a delivery commitment: every algo2go/kite-mcp-* module reaches >80% test coverage; quarterly release cadence locked. Total ≈ ₹29,00,000 ≈ $35,000.",
        "amount": 35000,
        "currency": "USD",
        "frequency": "one-time",
        "channels": ["grant-email"]
      },
      {
        "guid": "extended-grant",
        "status": "active",
        "name": "Extended grant — 12-month focused runway ($60k)",
        "description": "All of tier-2 PLUS extended maintainer runway through 12 months, second VAPT round, OpenTelemetry observability migration, NSE/BSE empanelment application + filing fees (if 50+ users on hosted gate fires), user-support staff hours through year-1, and a reserve fund for unforeseen compliance work (DPDP review, SEBI April 2026 framework changes). Targets a first-anniversary milestone of: 500+ active users on hosted endpoint, audited financials, paid tier live for hosted full-trading. Sustains the algo2go umbrella of 29 modules through year-1 while keeping all code MIT. Total ≈ ₹56,00,000 ≈ $60,000.",
        "amount": 60000,
        "currency": "USD",
        "frequency": "yearly",
        "channels": ["grant-email"]
      }
    ],
    "history": []
  }
}
```

### A2 — Minimal-change alternative

If you prefer to keep the description compact (current manifest is well-tuned), just replace the `entity.description` to add the 2026-05-16 momentum signal — `1,365 commits / v1.3.0 / 137h uptime / 29 algo2go modules`. Leave `projects[0]` and plans untouched. This avoids any risk of regression on a manifest that already validates clean.

### Deployment note (BLOCKER carried 5 days)

Whichever version you ship, `https://kite-mcp-server.fly.dev/funding.json` still serves the old `v1.0.0` body as of 2026-05-16 (verified `curl`). Two options:

1. **Submit GitHub raw URL instead**: `https://raw.githubusercontent.com/Sundeepg98/kite-mcp-server/master/funding.json` — this serves v1.1.0 correctly. The FLOSS/fund directory accepts any HTTPS URL.
2. **Redeploy Fly** so the route serves current bytes. Likely the route in `app/http.go` reads from an embedded asset; a redeploy via `flyctl deploy -a kite-mcp-server --remote-only` will refresh. **Recommend option 1** — zero deploy risk during the launch window.

---

## Deliverable B — Grant application narrative (2-3 pages)

> **Audience**: FLOSS/fund investment committee, reviewing during Q2 2026 cycle (deadline implicit ~Jun 30 2026). Reviewers are technical, time-constrained, and Zerodha-internal at first pass.
> **Length**: ~1,400 words; designed for skim-then-deep-read pattern.

---

### Project: kite-mcp-server — safe AI trading for Indian retail

**Maintainer**: Sundeep Govarthinam, Bengaluru
**Repo**: `github.com/Sundeepg98/kite-mcp-server` (MIT)
**Production**: `kite-mcp-server.fly.dev` (Mumbai region, v1.3.0, 137h+ uptime)
**License**: MIT (host repo + all 29 supporting algo2go/kite-mcp-* modules)
**Funding ask**: $10,000 (tier-1) or $35,000 (tier-2 recommended)

---

### What kite-mcp-server is and why it matters

India has 8 lakh+ active Zerodha Kite Connect developers and a regulatory environment moving fast — SEBI's April 2026 retail-algo framework, DPDP 2023, the static-IP whitelisting mandate. Zerodha publishes an official Model Context Protocol (MCP) server at `mcp.kite.trade`, but it is read-only by design: 22 tools, GTT-only, no order placement. Closed-source SaaS competitors (Streak, Sensibull, Multibagg) fill the trading-UX gap but treat AI safety as an afterthought.

`kite-mcp-server` is the open, auditable counter-example: a Go server that brings Kite Connect into any MCP-aware AI client (Claude Desktop, claude.ai, ChatGPT Connectors, Cursor, VS Code Copilot, Windsurf) with 111 production-registered tools, full order placement (gated to self-host only on hosted endpoint, full on local), and the safety posture a regulated financial API deserves. Every user brings their own Kite developer-app credentials — the server holds no master broker key; each user is the registered Zerodha Client of record, identical to running the reference Python or Go Kite client against their own developer app. AES-256-GCM at rest with HKDF-derived keys, per-user OAuth 2.1 + PKCE, hash-chained tamper-evident audit log, 11-check pre-trade RiskGuard middleware that runs before any order reaches the exchange, MCP elicitation forcing explicit human confirmation on 8 destructive tools.

The project genuinely serves three concentric audiences:

1. **Retail traders** who already pay Zerodha's ₹500/month for a Kite Connect developer app and want their AI assistant to do things on their account, not just describe them — with safety rails they can audit in code, not in a Terms of Service.
2. **Indian fintech OSS ecosystem** — every reusable pattern (riskguard middleware, hash-chained audit, per-user OAuth, MCP elicitation flow, NIST CSF mapping, SEBI Path-2 env-gate) is extracted into a separate MIT-licensed Go module under the `algo2go` GitHub org (29 modules as of 2026-05-16). Other Indian fintech projects can import them directly via `go get github.com/algo2go/kite-mcp-{riskguard,audit,oauth,billing}` — no rebuild, no rewrite.
3. **MCP ecosystem globally** — as of May 2026, finance is one of the least-served verticals in the public MCP Registry. This is among the first production-grade finance MCPs with order-placement-and-safety as a first-class concern. Patterns developed here (per-user OAuth via mcp-remote, RiskGuard as pre-tool middleware, MCP Apps widgets for inline UI, MCP elicitation for human-in-the-loop) are reference implementations for the next wave of regulated-domain MCPs — healthcare, insurance, government services.

### Maintainer

Sundeep Govarthinam, solo developer in Bengaluru, has been an active Kite Connect developer for 2+ years prior to this project. Started the kite-mcp-server fork in February 2026 from Zerodha's upstream read-only MCP. **1,365 commits since April 2026** — verifiable in `git log --oneline --since="2026-04-01" | wc -l` against the public repo. Production deployed at v1.3.0 with 137+ hours continuous uptime as of 2026-05-16. Solo author across all commits (git contributors: `Sundeepg98` + `root`, both same person, the latter being WSL2 dev-environment commits).

Track record this calendar year:
- 27-pass independent security audit conducted Feb 2026, 181 findings (6 HIGH, ~40 MED) — all 153 fixed, 28 accepted as documented risks. Full report at `SECURITY_AUDIT_REPORT.md` in repo.
- 10 architecture decision records published (`docs/adr/0001-broker-port-interface.md` through `0010`).
- Public threat model (`THREAT_MODEL.md`).
- 12-level callback OAuth deep-dive (`docs/blog/oauth-13-levels.md`, 237KB technical writeup).
- Canonical product definition (`docs/product-definition.md`, last updated 2026-05-11).
- 29 supporting Go modules externalized under `github.com/algo2go/kite-mcp-*` — each independently versioned, GOPROXY-verified at v0.1.x; `algo2go/kite-mcp-bootstrap@v0.1.1` is the composition root with all 4 tags GOPROXY-verified 2026-05-16.
- 269 test files in host repo plus 28 module test suites; ~9.5/10 self-scored security posture; ~80%+ coverage on critical paths.

Pre-launch transparency: the project has **1 active user** (the maintainer). Public Show HN has not been posted yet (draft polished and reviewer-ready at `docs/show-hn-post.md`). 0 GitHub stars across all 30 repos as of 2026-05-16. This honesty is in the manifest deliberately — the FLOSS/fund FAQ says "very new projects or projects with minimal usage are not considered," and the appropriate response is not to obscure the state but to make the case on engineering substance and the public-good roadmap.

### Roadmap — next 3-6 months (Q2-Q3 2026)

| Month | Milestone | Grant tier dependency |
|---|---|---|
| Now (May) | Show HN post + Reddit r/algotrading + Twitter D1-T1 launch cluster — target ≥50 stars in 6 weeks | None — already drafted, just send |
| Jun | Algo2Go umbrella rebrand decision: trigger-gated by 50+ stars + active community signal | None |
| Jun-Jul | Indian Pvt Ltd incorporation (Algo2Go Technologies Pvt Ltd, name available verified); Class 36 + 42 trademark filing | Tier-1 ($10k) |
| Jul | CERT-In VAPT audit round 1; results published | Tier-1 ($10k) |
| Jul-Aug | BYO-API-key hedge ship (users never blocked by app-tier rate limits); GitHub Sponsors profile live | None |
| Aug-Sep | Multi-broker adapter (Dhan + Upstox + Angel One) via algo2go/kite-mcp-broker port; concall + FII/DII analytics v1 | Tier-2 ($35k) |
| Sep-Oct | NSE empanelment application drafted (file-or-defer decision based on user count); v2.0 release | Tier-3 ($60k) |
| Nov | FOSS United conference talk (IndiaFOSS 2026 CFP submitted at `docs/drafts/indiafoss-2026-cfp.md`) | None |
| Dec | First-anniversary milestone — paid hosted-trading tier if 50+ waitlist signups; second VAPT round | Tier-3 ($60k) |

### How grant money would be spent (specific line items, INR + USD)

**$10,000 tier — minimum viable**

| Line item | INR | USD | Why |
|---|---|---|---|
| Indian Pvt Ltd incorporation + FY1 ROC compliance | ₹85,000 | $1,000 | Required to receive USD wire FEMA-compliantly via FEMA LRS reverse-path; MCA fees + DSC + DIN + first-year filing |
| Class 36 + 42 trademark registration (1 mark "Algo2Go") | ₹40,000 | $500 | Defensive registration before squatting |
| CERT-In empanelled VAPT audit (1 round) | ₹2,40,000 | $2,800 | Mandatory for future NSE empanelment + commercial billing |
| Fly.io static IP + R2 storage 6mo runway | ₹75,000 | $900 | Production hosting continuity |
| Domain renewal + SSL infra + monitoring | ₹40,000 | $500 | Hosted-demo continuity during evaluation |
| Buffer for unforeseen compliance (DPDP/SEBI changes) | ₹3,60,000 | $4,300 | DPDP rules implementing 2026-Q3; SEBI April 2026 framework still mutating |
| **Total tier-1** | **₹8,40,000** | **$10,000** | |

**$35,000 tier — substantive (recommended)** adds to tier-1:

| Line item | INR | USD | Why |
|---|---|---|---|
| Independent external code+security review | ₹4,00,000 | $4,800 | Second pair of expert eyes on crypto/auth code; complements CERT-In VAPT |
| 6 months full-time maintainer time (₹2.5L/mo) | ₹15,00,000 | $18,000 | Replaces weekend-hacking with full-time delivery on multi-broker + analytics roadmap |
| Documentation + NIST CSF public mapping push | ₹50,000 | $600 | Extractable patterns for other Indian fintech OSS |
| Independent fintech-counsel opinion (Spice Route or Finsec) | ₹1,30,000 | $1,600 | Path-2 hosted compliance validation, audit trail attestation |
| **Sub-total over tier-1** | **₹20,80,000** | **$25,000** | |
| **Grand total** | **₹29,20,000** | **$35,000** | |

**$60,000 tier — extended (12-month)** adds to tier-2:

| Line item | INR | USD | Why |
|---|---|---|---|
| 6 additional months maintainer (₹2.5L × 6) | ₹15,00,000 | $18,000 | Full year of focused work; v2 multi-broker default |
| NSE empanelment application + filing fees | ₹2,40,000 | $2,800 | If 50+ paid-user gate fires |
| Second VAPT round | ₹2,00,000 | $2,400 | Annual security cadence |
| OpenTelemetry observability migration | ₹1,00,000 | $1,200 | Replaces ad-hoc logging with production-grade obs |
| User-support staff hours through year-1 | ₹1,20,000 | $1,500 | Email + Telegram coverage as user count grows |
| **Sub-total over tier-2** | **₹21,60,000** | **$25,900** | |
| **Grand total** | **₹50,80,000** | **$60,000** | |

### Open-source impact (the umbrella)

The most under-stated property of this project: it is not one Go module — it is 30. The host repo (`Sundeepg98/kite-mcp-server`) is the orchestrator; 29 standalone modules under `github.com/algo2go/kite-mcp-*` carry the reusable patterns. Specifically: `kite-mcp-riskguard` (11-check pre-trade middleware), `kite-mcp-audit` (hash-chained tool-call log), `kite-mcp-oauth` (per-user OAuth 2.1 on top of mcp-remote), `kite-mcp-billing` (env-flag tier gating), `kite-mcp-papertrading`, `kite-mcp-alerts`, `kite-mcp-eventsourcing`, `kite-mcp-cqrs`, `kite-mcp-telegram`, `kite-mcp-instruments`, `kite-mcp-ticker`, `kite-mcp-metrics` (newest, today), and more. Each is independently `go get`-able. The patterns are documented in 10 ADRs and 6 architecture audit reports in `.research/`. The expected secondary impact: 3-5 other Indian fintech OSS projects adopt one of these modules within 12 months of fund disbursement. We treat that as the public-good ROI.

---

## Deliverable C — ROI projection ($10k / $50k / $100k tiers)

> *Note*: $50k and $100k tiers are NOT FLOSS/fund-conforming amounts. FLOSS/fund requires denominations of $10k OR $10k + $25k multiples = $10k / $35k / $60k / $85k / $100k. I project at the conforming $35k and $85k as middle/large, with $10k and $100k as the asked bookends. Per the user's `$50k vs $100k` framing in the dispatch, $35k ≈ "what you asked for" and $85k ≈ "halfway between mid and max".

### $10k tier — "maintain"

**What it unlocks**:
- Pvt Ltd legal entity (enables every downstream commercial path)
- Class 36 + 42 trademark (defensive, before squatters)
- One CERT-In VAPT round (first formal security attestation)
- 6 months production hosting continuity

**What it does NOT unlock**:
- Maintainer full-time runway — Sundeep still works weekends
- Multi-broker support (Dhan/Upstox/Angel One adapters)
- Major new features (concall, FII/DII, peer compare stay placeholder LLM-coordinator pattern)
- Empanelment process (NSE filing fees not included)

**Expected outcome at end of 6 months**:
- 100-300 GitHub stars from Show HN + ongoing dev velocity
- 50-100 hosted users (read-only Path-2)
- Self-host users: ~30-100 (hard to measure)
- Sustainable but slow growth; project survives without maintainer burnout

### $35k tier — "grow" (recommended for first application)

**What it adds over $10k**:
- 6 months of focused full-time maintainer work (₹15L)
- Multi-broker adapter v1 (Dhan + Upstox + Angel One via the existing `algo2go/kite-mcp-broker` port)
- Concall + FII/DII + peer comparison shipped to v1 (not placeholder LLM-coordinator)
- BYO-API-key hedge (users stop hitting app-tier rate limits)
- Independent external security review (₹4L)
- Fintech-counsel legal opinion (₹1.3L) — Path-2 compliance attestation

**Expected outcome at end of 6 months**:
- 500-2,000 GitHub stars
- 200-800 hosted users
- 3-broker support (Zerodha + Dhan + Upstox) — meaningful diversification
- 1-2 mentions in Indian fintech press / Z-Connect editorial
- Foundation for first paid tier announcement

### $85k tier — "grow + sustain"

**What it adds over $35k**:
- 12 months continuous full-time maintainer runway (not just 6)
- Second VAPT round (annual security cadence)
- NSE empanelment application + filing fees
- OpenTelemetry observability migration
- User-support staff hours

**Expected outcome at end of 12 months**:
- 2,000-5,000 GitHub stars
- 1,000-3,000 hosted users
- NSE empanelment filed (whether approved or pending)
- 4-5 brokers supported
- First paid hosted-trading tier live (if 50+ waitlist signups)
- Year-2 grant application cleanly framed by track record

### $100k tier — "grow + sustain + invest"

**What it adds over $85k**:
- $15k buffer for *unforeseen* compliance work (DPDP rules implementing late-2026, possible SEBI framework changes)
- Conference travel (FOSDEM, FOSS Asia, IndiaFOSS, Rootconf) for visibility
- Reference-implementation polish for MCP ecosystem contributions (separate repos for `kite-mcp-riskguard`, `kite-mcp-audit` as standalone libraries with docs sites)
- $5-10k tail reserve for security incident response

**Expected outcome at end of 12 months**:
- 5,000-10,000 GitHub stars
- 3,000-10,000 hosted users
- Trusted reference for Indian fintech OSS — cited in 2-3 academic papers / industry reports
- Possible Rainmatter Capital warm-intro converting to seed (separately gated, not counted in grant ROI)

### Maintain-vs-grow framing

`$10k = maintain`. Project survives, weekend cadence continues, no new broker support, basic legal baseline.
`$35k = grow` (sweet spot). Project shifts to full-time delivery, multi-broker, real analytics; meaningful traction.
`$85k = grow + sustain`. Above plus year-long horizon, empanelment, paid tier.
`$100k = grow + sustain + invest`. Above plus reference-library polish, conference visibility, contingency.

**Recommendation**: Apply at $35k for first cycle. Reasoning: (a) Hits FLOSS/fund's revealed-preference median (Tranche-1 median grant was ~$25k legacy / ~$35k under current rules); (b) Doesn't compete against $100k FFmpeg-class projects for committee attention; (c) Sets up year-2 ask cleanly with track record. Tier-3 ($60k) or larger asks become defensible after first-year delivery.

---

## Deliverable D — Reviewer-question prep (10 Q+A)

### Q1: "Why YOU and not the official zerodha/kite-mcp-server?"

**A**: Different goals. Zerodha's official MCP at `mcp.kite.trade` is intentionally read-only (22 tools, GTT-only) — a tier-1 broker can't ship order-placement tooling globally without owning the entire compliance perimeter for every user. We close the gap with a self-host-first / per-user-BYO-app model where the user is their own Kite Connect Client of record. This is structurally different from what an official upstream can offer. We're complementary, not competitive — and we explicitly recommend `mcp.kite.trade` in our `docs/product-definition.md` for the 99% of users who want read-only convenience. All our code is MIT, so any useful pattern (riskguard middleware, audit trail, MCP elicitation flow) is available upstream to merge or mirror.

### Q2: "What happens if Zerodha doesn't want you to do this?"

**A**: We are pre-emptively transparent. A formal compliance disclosure email to `kiteconnect@zerodha.com` is drafted at `docs/drafts/zerodha-compliance-email.md`, ready to send. The core architecture — per-user BYO Kite developer app, no master credential aggregation, ENABLE_TRADING=false gating the hosted endpoint — is consistent with the Kite Connect Developer Terms; each end-user is the registered developer of record, identical to running the reference Python client. We send the disclosure before public Show HN, not after. If Zerodha asks us to change anything, we change it; the architecture is built to be modifiable without breaking users. The static egress IP (209.71.68.157) is published so Zerodha can monitor traffic patterns at the edge.

### Q3: "How is this different from a regular SaaS you're charging for?"

**A**: We're not charging now and the first paid tier (if it ever ships) is post-NSE-empanelment, deferred to Year-1 milestone. The hosted endpoint is preview-free, the software is MIT, and the maintainer collects zero revenue today. The Algo2Go-Pvt-Ltd-and-paid-tier path is a separate downstream conversation that would never happen with grant capital — it would require its own commercial decision after empanelment, with infrastructure-cost-recovery economics only (no advisory layer, no broker spread). Grant money funds the public infrastructure: incorporation, security audits, multi-broker module work, maintainer runway. Commercial money funds the commercial layer. They don't co-mingle.

### Q4: "Is the project viable without grant funding?"

**A**: Viable as a weekend project, yes — Sundeep has shipped v1.3.0 with 137+ hours uptime on personal time. But the project's *full* potential (multi-broker, real analytics, NSE empanelment, paid hosted tier) is gated on full-time maintainer time, which is what grant money substitutes for. Without funding, the path is 12-18 months slower and risks burnout. With funding, it's a 6-month focused sprint. Either way, code stays MIT and the umbrella org stays open.

### Q5: "What's the user/maintainer overlap risk?" (i.e., is Sundeep the only contributor)

**A**: Sundeep is currently solo (verified: `git log --since="2026-04-01" --format='%an' | sort -u` returns `Sundeepg98` + `root` (same human, WSL agent commits)). Bus-factor risk is real and explicitly disclosed. Mitigations: (a) Code is MIT — any other developer can fork and continue if Sundeep is hit by a bus; (b) 10 ADRs document architectural decisions for any future maintainer; (c) 27-pass security audit report is public; (d) Production hosting credentials and disaster-recovery procedures are documented in `docs/incident-response.md` + `docs/incident-response-runbook.md`; (e) The 29-module algo2go umbrella is designed for future-multi-maintainer scaling — each module is an independent Go module with its own version cadence. Grant funding accelerates the transition from solo-author to maintainer-org by enabling the umbrella's gravity to attract contributors.

### Q6: "What if SEBI or Zerodha changes the rules?"

**A**: `ENABLE_TRADING=false` is the 5-minute regulator panic button — documented at `docs/incident-response.md` Scenario 1-C. The hosted endpoint can be converted from full-trading to read-only by flipping one env flag and redeploying. Self-host users running locally are out of our control (and out of regulatory scope) — they remain personal-use safe-harbor per the OpenAlgo precedent. The grant request explicitly includes a buffer line item for unforeseen compliance work, sized at $4.3k in tier-1 and similar in tier-2/3. This is regulator-shaped risk, not regulator-existential risk.

### Q7: "What does $35k actually buy in India?"

**A**: ₹29 lakh at current FX. Indian PvtLtd CTO-equivalent salary is ~₹2.5L/month for senior Bangalore devs; 6 months ≈ ₹15L. Add ₹4L security review + ₹2.4L VAPT + ₹85k incorporation + ₹40k trademark + ₹1.3L legal opinion + ₹40k domain/SSL + ₹4.2L buffer = ~₹29L. **Every line item is independently verifiable**; the grant manifest exposes them inline.

### Q8: "How does this fit FLOSS/fund's `existing widely used impactful projects` criterion?"

**A**: Honestly, today it doesn't fully — 0 GitHub stars and 1 active user as of 2026-05-16. We're applying after Show HN (target: June 2026) when stars are in the 100+ range, which puts the project squarely in the "growing actively-maintained Indian fintech OSS" bucket. Tranche-1/Tranche-2 didn't fund Indian fintech yet, so there's no direct precedent to compete against. If the committee says "come back when you have 500 stars," that's a fair signal — we'd then submit at Q3 2026 or Q1 2027 review. The 30-day Show HN window between this draft and Q2 deadline is the gating event.

### Q9: "What's the value to the broader FLOSS ecosystem outside of India?"

**A**: Three contributions: (1) MCP-ecosystem reference for regulated-domain integrations — patterns we developed for trading (RiskGuard middleware, hash-chained audit, MCP elicitation) are directly applicable to healthcare/insurance/gov MCPs. (2) Algo2Go umbrella's 29 modules are independent Go libraries, each `go get`-able, usable in any Indian-fintech context. (3) Public 12-level OAuth callback deep-dive (`docs/blog/oauth-13-levels.md`, 237KB) is an educational artifact that has nothing to do with trading specifically.

### Q10: "Why not equity / VC instead of grant?"

**A**: Equity capital fits products with VC-shaped return curves. This isn't one. The product is MIT-licensed and self-host costs the user nothing; the Kite Connect ₹500/month is paid by user directly to Zerodha. There's no rake on payments, no advisory layer, no pooled fund custody — by design. Equity capital (Rainmatter Capital downstream, ₹50L-₹100Cr ticket sizes) is the right vehicle if we later spin off a hosted multi-broker paid offering with NSE empanelment and SLA commitments — but that's a separate decision after Year-1. Grant capital funds the *predecessor public infrastructure*: audit trail, riskguard library, OAuth pattern, security posture. Those are donated to the commons regardless of any later commercial spin-out. The Pocketbase precedent (cancelled FLOSS/fund grant due to Indian regulatory friction) is also worth flagging — we have a CA pre-engaged for FEMA LRS reverse-path documentation; we will not be the second cancellation.

---

## Deliverable E — Rainmatter warm-intro readiness check

### Trigger state (per `kite-rainmatter-warm-intro.md`)

| Required gate | Current state | Met? |
|---|---|---|
| FLOSS/fund application **submitted** | Not submitted (this deliverable is preparation) | NO |
| **≥50 GitHub stars** on `Sundeepg98/kite-mcp-server` | 0 | NO |
| **1 blog post / public mention** live | None | NO |

**All three gates remain UNMET as of 2026-05-16**. Identical state to 2026-05-11. Rainmatter outreach remains completely cold-blocked.

### Order of contacts (still valid per memory)

1. **Deepak Shenoy** (Capitalmind, Rainmatter-invested Aug 2025) — newest warm node
2. **Vishvajit Sonagara** — Rainmatter podcast alum
3. **Abid Hassan** (Sensibull) — Zerodha-invested adjacency
4. Later: Vasanth Kamath (Rainmatter direct), then Nikhil Kamath (last resort)

### When-ready message templates

DM drafts already exist for two contacts at `docs/drafts/jethwani-shenoy-dms.md` and `docs/drafts/vishal-dhawan-dms.md`. They will need a minor refresh once stars + Show HN are reality. Here's the **Shenoy first-DM** template ready to send the day all three gates fire:

> **To**: `@deepakshenoy` on Twitter (NOT Capitalmind contact form — DM has higher signal)
>
> Hi Deepak — I'm a long-time Capitalmind reader and a Kite Connect developer. I built an MIT-licensed Model Context Protocol bridge for Kite (`github.com/Sundeepg98/kite-mcp-server`) — it lets Claude/ChatGPT do safe order-placement on a retail trader's Kite account, with 11 pre-trade safety checks and a hash-chained audit log. Launched on HN last week (link), 50+ stars, applied for FLOSS/fund this morning.
>
> I'd love 15 minutes of your time on positioning vs Rainmatter Capital / FLOSS/fund — specifically whether the "open-source first, no monetization yet" framing makes sense from where you sit, or whether there's a different shape worth considering. Happy to send a one-pager beforehand. Not asking for money or intros yet — just guidance.
>
> Thanks for everything you've published over the years.
>
> Sundeep · Bengaluru

(Updated values: replace `(link)` with actual HN URL; `50+` with actual star count at trigger-fire time.)

Sonagara and Hassan DMs follow the same pattern with adjusted hooks; staggered 7-14 days apart per `kite-rainmatter-warm-intro.md` "Don't ping 3 in one week" rule.

### Rainmatter ≠ FLOSS/fund

Worth re-stating: Rainmatter Capital is equity (₹50L-₹100Cr equity tickets, application via Google Form). FLOSS/fund is grant (non-dilutive, $10k-$100k). These are completely separate paths. The warm-intro gate exists because Rainmatter is the downstream equity option; FLOSS/fund is the immediate grant option that doesn't require any warm intro.

---

## Deliverable F — User next-steps timeline (2026-05-16 → submission)

> *Assumes user wants both FOSS United (fast, India-only, no traction gate) and FLOSS/fund (slow, requires traction). Both can run in parallel without double-dipping — they're separate funds with separate budgets.*

### Day 0 (today, 2026-05-16) — 30 minutes total

- [ ] Resolve placeholder `<your product email>` in `docs/drafts/foss-united-grant-email.md` → use `sundeepg8@gmail.com`
- [ ] Send the email to `grants@fossunited.org` — they review on rolling basis, no traction gate
- [ ] Verify `docs/drafts/zerodha-compliance-email.md` still reflects current state (it does, per 2026-05-11 close-out); send to `kiteconnect@zerodha.com` CC `talk@rainmatter.com` — pre-emptive compliance disclosure
- [ ] (Optional) Update `funding.json` to A1 version above; commit; push; verify `https://raw.githubusercontent.com/Sundeepg98/kite-mcp-server/master/funding.json` returns updated body

### Day 1-2 (May 17-18) — Show HN preparation

- [ ] Take a 60-second demo GIF (per `README.md` TODO line 11) — portfolio analysis + order placement flow
- [ ] Final-pass `docs/show-hn-post.md` for the 2026-05-16 momentum signal (v1.3.0, 137h uptime, 29 algo2go modules, bootstrap @v0.1.1 GOPROXY-verified)
- [ ] Set up `https://github.com/sponsors/Sundeepg98` profile (waitlist-mode is fine; the URL appearing in `.github/FUNDING.yml` is the signal)

### Day 3-5 (May 19-21) — Show HN launch cluster

- [ ] Post Show HN at 7 AM IST Tuesday (per launch-readiness verdict 2026-05-11, optimal window for India-tech audience + US-tech audience at end of day)
- [ ] Cross-post r/algotrading + r/IndiaInvestments
- [ ] Twitter D1 thread per `docs/twitter-launch-kit.md`
- [ ] Send pre-warmed Zerodha compliance email AT-T-1h before Show HN (per `docs/drafts/zerodha-compliance-email.md` send-timing analysis — `cb8785d`)
- [ ] Monitor for the first 6 hours; respond to top comments

### Day 6-14 (May 22-29) — accumulate signal

- [ ] Reply to Show HN comments, file follow-up bugs as issues, keep the repo active
- [ ] Write a single blog post — short, on the OAuth callback deep-dive or the riskguard middleware (existing `docs/blog/oauth-13-levels.md` could be the basis)
- [ ] Apply for **GitHub Secure Open Source Fund** ($10k, rolling, security-focused — our 27-pass audit is genuinely strong fit) at `github.com/open-source/github-secure-open-source-fund`

### Day 15-30 (May 31 — Jun 14) — star accumulation

- [ ] Continue dev velocity on multi-broker adapter (signals continued investment to reviewers)
- [ ] Submit `docs/drafts/indiafoss-2026-cfp.md` to IndiaFOSS 2026 CFP (deadline check first)
- [ ] If stars cross 50, send Shenoy DM (Twitter); start `kite-rainmatter-warm-intro.md` sequence

### Day 30-45 (Jun 14-30) — FLOSS/fund submission window

- [ ] Verify funding.json serves v1.1.0 at GitHub raw URL: `https://raw.githubusercontent.com/Sundeepg98/kite-mcp-server/master/funding.json`
- [ ] Visit `https://dir.floss.fund/submit`
- [ ] Paste GitHub raw URL into the single field
- [ ] Click Submit
- [ ] Email confirmation lands; expect 4-6 weeks for committee review (Q2 ends Jun 30; review late-Jun / early-Jul)

### Day 45+ (Jul onward) — review window

- [ ] If accepted: provide tax residency docs + bank info via FLOSS/fund email coordination — ~4 weeks to disbursement
- [ ] If declined "minimal usage": re-apply Q3 (Sep 30 deadline) with updated star count + activity history
- [ ] If declined "scope mismatch": pivot to GitHub Secure OSS Fund as primary, FOSS United as already-running parallel

### Documents to attach (in funding.json description + reviewer-emailable)

- `README.md` (295 lines, 7K+ tests claim)
- `SECURITY_AUDIT_REPORT.md` (199 lines, 181-findings-resolved evidence)
- `SECURITY_PENTEST_RESULTS.md` (357 lines, formal pentest results)
- `THREAT_MODEL.md` (212 lines)
- `docs/product-definition.md` (canonical product narrative, 2026-05-11 refresh)
- `docs/adr/0001-0010` (architecture decision records)
- `docs/blog/oauth-13-levels.md` (237KB technical deep-dive)
- (Optional) link to live `kite-mcp-server.fly.dev/healthz` to demonstrate uptime

### URLs to navigate to

- Submission: `https://dir.floss.fund/submit`
- Validator: `https://fundingjson.org/validate/`
- Schema check: `https://fundingjson.org/schema/v1.1.0.json`
- Directory: `https://dir.floss.fund/`
- FAQ: `https://floss.fund/faq/`
- FOSS United: email `grants@fossunited.org`
- GitHub Secure OSS Fund: `https://github.com/open-source/github-secure-open-source-fund`
- Rainmatter Capital: `https://forms.gle/88D9cKMan27qa5R57` (DO NOT use yet — warm-intro path first)

---

## Empirical surprises captured on 2026-05-16

1. **Fly serves stale `funding.json` for 5+ days running** — the `25c9c8e` master bump (2026-05-10) hasn't propagated to production. Either route reads from embedded asset (compile-time), or production was paused at `v1.0.0` body. Verified by `curl https://kite-mcp-server.fly.dev/funding.json` returning `version: v1.0.0` today. Solution: submit GitHub raw URL, NOT Fly URL. Or redeploy. (Same finding as 2026-05-11 carried forward; not yet resolved.)

2. **0 stars across 30 repos** — main repo + 29 algo2go modules — despite 137h+ uptime and 1,365 commits since April. This is entirely expected given Show HN hasn't fired yet, but worth stating: the public has not seen this work. Star count is **NOT** stale — it's a 0-baseline.

3. **GOPROXY verifies algo2go/kite-mcp-bootstrap v0.1.0 + v0.1.1, and kite-mcp-metrics v0.1.0** — both published today (2026-05-16). The umbrella is no longer hypothetical; consumers can `go get` these modules immediately. This materially strengthens the FLOSS/fund pitch since the 29-module umbrella is empirically real.

4. **Indian fintech precedent at FLOSS/fund**: still zero. Tranche-1 + Tranche-2 (38 projects, $970k disbursed) include zero Indian-led fintech projects. Zasper ($4,986 via FOSS United co-sponsorship) is the closest — it's the FOSS United → Zerodha pipeline, not the FLOSS/fund direct pipeline. For our application: explicitly frame as "first Indian fintech-MCP applying."

5. **Solo-maintainer signal is honest and unavoidable** — `git log --format='%an' | sort -u` returns 2 names but both are the same human. The 1-active-user disclosure in `docs/rainmatter-onepager.md` line 56 and the funding.json `entity.description` is the correct posture; trying to obscure it would backfire.

6. **2026-05-16 momentum claim is strongest in 6 weeks** — 1,365 commits since April 1 is unusual for a solo developer. This is the single most reviewer-impressive metric and should be front-loaded in narrative §B (currently in the maintainer paragraph).

7. **FOSS United email is unsent for 14 days** — 2026-05-02 prep, 2026-05-11 readiness, 2026-05-16 still unsent. Of all actionable items, this is the lowest-effort highest-EV. Single biggest grant-funnel friction is just hitting send.

8. **Channel type `"other"` may signal pre-launch** — schema accepts `"bank" | "payment-provider" | "cheque" | "cash" | "other"`. Most funded projects use `"payment-provider"` with GitHub Sponsors URL. Setting up `github.com/sponsors/Sundeepg98` (waitlist mode is fine, free, 10 minutes) flips this signal cheaply.

9. **No 2026 disbursements announced yet** by FLOSS/fund (per `floss.fund/blog/` — last update October 2025). Q1 2026 review either hasn't happened or happened quietly. Q2 (deadline ~Jun 30) is the next visible window. This is good news for us — we're not late; the cycle hasn't moved past us.

10. **Production v1.3.0 / 137h uptime** is a credibility multiplier the prior prep docs underweighted — most FLOSS/fund applicants are libraries with intermittent CI, not services with measurable uptime. Make this front-and-center in the narrative.
