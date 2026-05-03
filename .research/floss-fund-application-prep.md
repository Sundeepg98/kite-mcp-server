# FLOSS/fund Application Prep — kite-mcp-server

**Status:** Research deliverable. NOT a submission. Submission is human-driven via `https://dir.floss.fund/submit`.
**Author:** Research agent (orchestrator-dispatched)
**Date:** 2026-05-02
**Repo:** https://github.com/Sundeepg98/kite-mcp-server
**Maintainer:** Sundeep Govarthinam (`sundeepg8@gmail.com`)

---

## TL;DR — Is the application submission-ready today?

**No. Three blocking issues, two soft issues. Estimated 30–60 minutes of fixes.**

| # | Severity | Issue | Fix |
|---|---|---|---|
| 1 | **BLOCKER** | `funding.json` `wellKnown` URL points to `/blob/main/funding.json` but repo's default branch is `master` — link is broken. Validator at `dir.floss.fund/validate` will flag this as **"Unverified URL"**. | Change branch to `main` on GitHub OR change `wellKnown` to `/blob/master/funding.json` (raw URL recommended). |
| 2 | **BLOCKER** | Plan amounts violate FLOSS/fund denomination rule. Per `floss.fund/faq`: minimum **$10,000**, multiples of **$25,000 thereafter** → valid: $10k, $35k, $60k, $85k, $100k. Current plans `$25,000` (mid-grant) and `$50,000` (annual stipend) are non-conforming. | Re-tier to `$10k` / `$35k` / `$60k` (or `$85k`). |
| 3 | **BLOCKER (soft eligibility)** | FAQ explicitly excludes "very new projects with minimal usage." Current state: 1 user (maintainer), pre-launch, no GitHub stars / Show HN yet. Memory note `kite-floss-fund.md` already specifies the trigger: ≥50 stars + 1 HN/blog post. | Defer submission until ≥50 stars + Show HN landed. Don't burn the application slot on a cold submission. |
| 4 | Soft | `FUNDING.json` (capitalized) is duplicate of `funding.json` and is **not git-tracked**. Confusing. Spec says lowercase `funding.json`. | Delete `FUNDING.json` (uppercase) since validator only reads the manifest URL submitted. |
| 5 | Soft | `funding.json` channel has `"type": "other"` with `"address": "sundeepg8@gmail.com"` — works but weak. Most accepted recipients use `"type": "payment"` with bank/wire pointer. | Acceptable for v1 but plan to upgrade once Pvt Ltd incorporated and bank account is live. |

**Path forward:** Fix #1, #2, #4 before any submission. Hold #3 until trigger criteria met. Application content (sections 3a–3g below) is largely drafted; copy-paste ready.

---

## Phase 1 — Empirical state (in-repo)

### Files that exist
| File | Status | Path |
|---|---|---|
| `funding.json` | tracked, valid v1.1.0 schema (declares `version: v1.0.0`) | `D:\Sundeep\projects\kite-mcp-server\funding.json` |
| `FUNDING.json` | **untracked** duplicate of above (not in git) | `D:\Sundeep\projects\kite-mcp-server\FUNDING.json` |
| `.github/FUNDING.yml` | tracked, sets `github: Sundeepg98` for GitHub Sponsors button | `D:\Sundeep\projects\kite-mcp-server\.github\FUNDING.yml` |
| `docs/floss-fund-proposal.md` | tracked, has `<product-email-placeholder>` TODO unresolved | `D:\Sundeep\projects\kite-mcp-server\docs\floss-fund-proposal.md` |
| `docs/drafts/foss-united-grant-email.md` | tracked, ready-to-send FOSS United email (different fund) | `D:\Sundeep\projects\kite-mcp-server\docs\drafts\foss-united-grant-email.md` |

### What's drafted, published, missing

**Drafted (in repo, MIT licensed, public):**
- `funding.json` manifest with 3 plans ($10k / $25k / $50k yearly) — needs amount fix
- `docs/floss-fund-proposal.md` — 1-page narrative pitch (close to ready, has `<product-email-placeholder>`)
- `FUNDING.json` (duplicate, unused)

**Published (live):**
- `funding.json` is on GitHub default branch — accessible at `https://github.com/Sundeepg98/kite-mcp-server/blob/master/funding.json` (note: `master` not `main`)
- GitHub Sponsors button points to `Sundeepg98` profile (no Sponsors profile set up yet — verify before submitting)

**NOT submitted:**
- No application has been filed at `https://dir.floss.fund/submit`
- No correspondence with FLOSS/fund team in repo or memory

---

## Phase 2 — FLOSS/fund landscape (web research, May 2026)

### Canonical URL
- **`https://floss.fund`** — primary site (Zerodha-funded initiative since 2024)
- **`https://flossfund.org`** — does NOT resolve (returns ECONNREFUSED). The trailing `/` (slash) URL is correct: `floss.fund` not `flossfund.org`. Memory note `kite-floss-fund.md` says `floss.fund` — verified correct.
- Application submission: `https://dir.floss.fund/submit`
- Validator: `https://dir.floss.fund/validate`
- FAQ: `https://floss.fund/faq/`

### Application form structure (sparse by design)

The `/submit` endpoint asks for **only one field: the URL of your `funding.json` manifest.**

That is the entire form. Everything else (project description, ask amount, plan tiers, channels) lives **inside the JSON manifest**. The manifest content IS the application. This means: the quality of the `funding.json` `description`, `plans[].description`, and project metadata directly determines selection probability.

Implication: every word of the `description` field is real estate that the selection committee reads. Maximize it.

### Eligibility criteria (FAQ-derived, May 2026)

**Eligible:** "Individuals, projects, groups, communities, or organisations." Indian individual maintainer pre-incorporation: **yes, eligible**.

**Banking requirement:** Applicant or legal entity must have a bank account and necessary tax documents to receive funds. For India, this means PAN + bank account + ability to handle a USD wire receipt (FEMA-compliant). Pocketbase's cancelled grant (`github.com/pocketbase/pocketbase/discussions/7287`) shows this is a real friction point — the FLOSS/fund team had to switch to "wire transfer from India with several cross-jurisdictional paperwork" after a GitHub partnership fell through. Plan for this.

**Excluded (REJECTION CRITERIA — verbatim from FAQ):**

> "FLOSS/fund currently focuses on supporting existing, widely used, and impactful projects to specifically contribute to their sustainability, and very new projects or projects with minimal usage are not considered for the time being."

This is the hardest filter. **kite-mcp-server has 1 user.** The maintainer's own framing in `docs/drafts/foss-united-grant-email.md` says "current user count is 1 (myself)... I would rather apply with working code and no users than with inflated metrics" — that honesty is the right posture but won't pass the filter on Tranche 3 / 2026 when 50+ projects compete for 10–30 slots.

### Cadence

**Quarterly review.** Investment committee evaluates applications "at the end of every quarter." Disbursement timeline: ~4 weeks after acceptance (banking + tax paperwork). 2025 had two tranches: May ($325k / 9 projects) and October ($645k / 29 projects). 2026 cycle has not been announced as of session date.

### Grant denominations (verbatim from FAQ)

**Minimum $10,000. Multiples of $25,000 thereafter. Maximum $100,000 per year.**

Valid asks: `$10,000`, `$35,000`, `$60,000`, `$85,000`, `$100,000`. Anything else is a malformed application. Our current `funding.json` violates this with `$25,000` (mid-grant plan) and `$50,000` (annual stipend) — both non-conforming.

### Recipients to date (signal for what they fund)

**Tranche 1 — May 2025 — $325k / 9 projects:**

| Project | Amount | Type |
|---|---|---|
| OpenSSL Library | $100,000 | Critical infra (cryptographic toolkit) |
| Network Time Protocol | $60,000 | Critical infra (NTP daemon) |
| ImageMagick | $50,000 | Image manipulation |
| Krita | $50,000 | Digital painting |
| libjpeg-turbo | $25,000 (legacy denom) | Image compression |
| LibreTranslate | $10,000 | Translation |
| Weblate | $10,000 | Localization |
| x64dbg | $10,000 | Debugger |
| XZ tools | $10,000 | Compression (post-CVE-2024-3094 hardening) |

**Tranche 2 — Oct 2025 — $645k / 29 projects:** FFmpeg ($100k), F-Droid ($50k), HOTOSM ($50k), OpenStreetMap ($30k), Blender ($25k), Ente ($25k), KDE ($25k), Matrix ($25k), OpenRefine ($25k), Rethink DNS ($25k), Sequoia PGP ($25k), Wireshark ($25k), Zig ($25k), Crystal ($15k), Gleam ($15k), Kiwix ($15k), Dokku ($10k), dotenvx ($10k), freeCodeCamp ($10k), Graphile ($10k), LFortran ($10k), OCaml/Tarides ($10k), pgmpy ($10k), postmarketOS ($25k), quic-go ($10k), tus ($10k), vale ($10k), Yjs ($10k), Zen Browser ($10k).

**Pattern:**
- **Zero India-based recipients** in either tranche (Rethink DNS is Indian-developer-led but project is global). Zerodha-the-funder hasn't yet funded an Indian fintech-adjacent OSS project. Could be opportunity (no Indian-fintech precedent) OR could be reason for rejection (selection committee may see "we already fund Rethink DNS as our India quota").
- **Zero pre-launch projects.** All 38 recipients have multi-year track records, install bases in millions, or critical-infra status.
- **Lots of solo/small-team maintainers** (x64dbg, Yjs, Crystal, Gleam, Graphile, dotenvx, pgmpy) — individuals are accepted, but they have substantial usage.
- **Grant size correlates with criticality, not project age**: OpenSSL $100k (security), FFmpeg $100k (multimedia infrastructure), Krita $50k (community size). Trading-tooling for one country's retail traders is not in the same league of "criticality" by FLOSS/fund's own selection bar.

### Sources

- [FLOSS/fund main](https://floss.fund/)
- [FAQ](https://floss.fund/faq/)
- [Submit](https://dir.floss.fund/submit)
- [Validate](https://dir.floss.fund/validate)
- [funding.json spec](https://fundingjson.org/)
- [First tranche announcement](https://floss.fund/blog/update-2025-may/)
- [Second tranche announcement](https://floss.fund/blog/second-tranche-2025-anniversary/)
- [2025 disbursements list](https://floss.fund/projects/2025/)
- [Pocketbase cancellation thread](https://github.com/pocketbase/pocketbase/discussions/7287)
- [The Drop Times coverage of 1st-year retro](https://www.thedroptimes.com/55345/flossfund-allocates-1m-globally-in-first-year-calls-indias-sovereign-foss-strategy)

---

## Phase 3 — Application content drafts

### 3a. Project description (≤200 words) — for `funding.json` `projects[].description`

Current draft (in `funding.json`) is 175 words. Replace with this tightened version (191 words):

```
kite-mcp-server is an MIT-licensed Model Context Protocol (MCP) server that turns any
MCP-aware AI client (Claude, ChatGPT, Cursor, VS Code Copilot) into a power-user
trading copilot for Indian retail Zerodha Kite Connect users. It extends Zerodha's
official read-only MCP (22 tools, GTT-only) with ~80 tools spanning order placement,
options Greeks (Black-Scholes), backtesting (4 strategies with Sharpe/drawdown),
technical indicators, portfolio analytics, sector exposure, tax-loss harvest,
Telegram alerts, paper trading (virtual ₹1 crore portfolio), and a 9-check
RiskGuard safety layer (kill switch, per-order ₹50k cap, 20-orders/day, 10/min
rate limit, duplicate detection, daily ₹2L cap, idempotency, anomaly detection,
auto-freeze).

Per-user OAuth 2.1 + PKCE — each user brings their own Kite developer app;
credentials and tokens AES-256-GCM encrypted at rest (HKDF-derived keys).
SQLite + Litestream replication to Cloudflare R2. Full hash-chained audit trail
with 90-day retention, CSV/JSON export. 7,000+ tests across 159 files. Production
on Fly.io (Mumbai region, static egress IP for SEBI-mandated whitelisting).
Self-hostable via Dockerfile.selfhost. Hosted demo at kite-mcp-server.fly.dev,
read-only per NSE/INVG/69255 Annexure I Para 2.8.
```

### 3b. Impact narrative (≤300 words) — for committee review packet / proposal doc

```
Three audiences benefit, in widening circles.

(1) The 8 lakh+ active Kite Connect developers. India's retail trading population
has spent the past 5 years migrating to algo-curious tooling, but the available
options bifurcate into closed SaaS (Streak, Sensibull) and DIY scripts. There is
no MIT-licensed, production-grade middle ground that lets a non-programmer drive
their Kite account through a conversational AI — and crucially, lets them do it
*safely* (kill switch, order caps, audit trail) rather than autonomously
(uncapped LLM-driven execution). This server is that middle ground.

(2) The Indian fintech OSS ecosystem. The codebase commits, in code, to patterns
that are missing in this niche: AES-256-GCM for credentials, hash-chained audit
log, RiskGuard middleware as a pre-trade gate, MCP elicitation for confirmation
flows, NIST CSF mapping, SEBI Path-2 read-only deployment via env-flag
(`ENABLE_TRADING=false`). Every one of these patterns is extractable by other
Indian fintech maintainers. A 27-pass independent security audit (181 findings,
all resolved) and a public threat model (`THREAT_MODEL.md`) are reference docs
the broader community can cite.

(3) The MCP ecosystem globally. As of May 2026, finance is one of the
least-served verticals on the public MCP registry. This is among the first
production-quality finance MCPs with order-placement-with-safety-rails as a
first-class concern. Adoption patterns here (per-user OAuth, riskguard
middleware ordering, audit trail design) inform the next wave of regulated-domain
MCP servers. Already extracted: 8 Claude Skills wrapper, plugin SDK,
documented OAuth 13-levels deep-dive (`docs/blog/oauth-13-levels.md`).
```

### 3c. Why FLOSS/fund (not VC) — explicit rationale

```
This project will not generate a VC-shaped return curve. The economics are
infrastructure, not application:

— No upsell ramp. The product is MIT-licensed; self-host costs nothing.
  The Zerodha Kite Connect developer app (₹500/month, paid by user directly to
  Zerodha) is the only mandatory cost, and we don't collect it.

— No pooled-fund custody. Each user remains their own Zerodha Client of record.
  We never hold user money or trade on the user's behalf. There is no Stripe-style
  payments-take-a-rake business model embedded.

— No advisory layer. We refuse to ship buy/sell recommendations. Our entire
  premise is that the human user (or their LLM client) makes the call; we just
  expose the tools and enforce the safety rails. SEBI RA registration is
  explicitly a non-goal.

What this *can* generate is durable public infrastructure that hundreds of
Indian retail traders use to interact with their own broker accounts more safely.
That outcome fits a grant. It does not fit equity.

Equity capital (e.g., Rainmatter Capital downstream) is the right vehicle if we
later spin off a hosted, multi-broker, paid offering with NSE empanelment and
SLA commitments. A FLOSS/fund grant funds the *predecessor public infrastructure*:
the audit trail, the riskguard library, the OAuth pattern, the security posture,
the multi-broker port. Those are donated to the commons regardless of any later
commercial spin-out.
```

### 3d. Budget proposal — three tiers

**Note:** Amounts re-aligned to FLOSS/fund denomination rules ($10k / $35k / $60k / $85k / $100k).

#### $10,000 tier — minimum viable (small-grant)

| Line item | INR | USD | Rationale |
|---|---|---|---|
| Indian Pvt Ltd incorporation + FY1 ROC compliance | ₹85,000 | $1,000 | Required to receive USD wire FEMA-compliantly; MCA fees + DSC + DIN + first-year filing |
| Trademark Class 36 + Class 42 (1 mark) | ₹40,000 | $500 | Defensive registration before competitors squat |
| CERT-In empanelled VAPT audit (1 round) | ₹2,40,000 | $2,800 | Mandatory for any future regulated-entity application |
| Independent code/security review | ₹4,00,000 | $4,800 | Second pair of expert eyes on crypto/auth code |
| Domain + infra runway 6 months (Fly.io + R2 + UnifiedTLS + monitoring) | ₹75,000 | $900 | Keep hosted demo live during evaluation |
| **Total** | **₹8,40,000** | **$10,000** | |

#### $35,000 tier — substantive (likely target)

Adds to $10k tier:

| Line item | INR | USD | Rationale |
|---|---|---|---|
| 4 months focused maintainer time (₹4L/mo) | ₹16,00,000 | $19,200 | Replaces weekend-hacking with full-time delivery on roadmap below |
| Multi-broker adapter (Dhan port behind broker port) | included | included | Removes Zerodha lock-in; same MCP surface |
| BYO-API-key hedge | included | included | Users never blocked by app-tier rate limits |
| Concall + FII/DII + peer-compare analytics | included | included | Reduces info asymmetry vs Bloomberg-tier desks |
| Documentation push (NIST CSF mapping public, threat model expansion) | ₹1,20,000 | $1,400 | OSS-ecosystem extractable patterns |
| Independent fintech-counsel opinion (Spice Route or Finsec) | ₹3,40,000 | $4,000 | Path-2 hosted compliance posture validation |
| **Total (over $10k)** | **₹20,60,000** | **$24,600** | |
| **Grand total** | **₹29,00,000** | **$34,600 → $35,000** | |

#### $60,000 tier — extended (12-month focused runway)

Adds to $35k tier:

| Line item | INR | USD | Rationale |
|---|---|---|---|
| 6 additional months of maintainer time | ₹24,00,000 | $28,800 | Full year of focused work; ships v2 with multi-broker default |
| NSE empanelment application (legal + filing) | ₹3,40,000 | $4,000 | If 50+ paid users gate fires, Path-2 → Path-3 transition |
| **Total (over $35k)** | **₹27,40,000** | **$32,800** | |
| **Grand total** | **₹56,00,000** | **$67,400 → $60,000** | |

(If asking for $60k, drop NSE empanelment line; cover from later commercial revenue.)

#### $100,000 tier — maximum

Adds to $60k tier: independent VAPT round 2 ($5k), expanded UI/UX (web dashboard polish, $8k), OpenTelemetry observability migration ($5k), public conference talk circuit (Rootconf, IndiaFOSS, FOSDEM travel — $4k), reserve fund for unforeseen compliance work ($18k). Grand total ≈ $100,000.

**Recommendation:** Apply at the **$35,000** tier (the lowest standard increment above $10k). Rationale: high enough to cover the actual deliverables in the proposal; low enough that the committee budget allocator doesn't trade us off against a $100k FFmpeg-class project. This matches FLOSS/fund's revealed preference in tranche 1 (median grant ~$25k legacy / now $35k under new rules).

### 3e. Milestones / deliverables (≤200 words)

```
At $35,000 (12-month plan, quarterly milestones):

Q1 — Legal + security baseline
- Pvt Ltd incorporated, GST registered
- Class 36 + 42 trademark filed
- CERT-In VAPT audit round 1 complete, findings published
- Public threat model expanded (DPDP, SEBI Path-2 framing)
- BYO-API-key hedge shipped (users not blocked by app rate limits)

Q2 — Multi-broker + analytics
- Dhan adapter shipped behind broker port (same MCP surface)
- analyze_concall + get_fii_dii_flow + peer_compare tools shipped (LLM-coordinator pattern)
- Independent fintech-legal opinion received and disclosed

Q3 — Distribution + ecosystem
- 200+ GitHub stars, public Show HN landed
- 8 Claude Skills published (morning/EOD/options-strategy/etc.)
- Conference talk landed (Rootconf or IndiaFOSS 2026)
- 100+ active hosted users (read-only)

Q4 — Sustainability
- Optional paid hosted-trading tier live (only if 50+ waitlist signups)
- NSE empanelment application drafted (file-or-defer decision)
- Annual independent security audit round 2
- Annual maintenance stipend application to FLOSS/fund (if continued usage)
```

### 3f. Why this project, why now — momentum signals

- **1,076 git commits** since fork, **994 commits in past 5 months** (Dec 2025 – May 2026) — unmistakable maintainer dedication signal
- **7,000+ tests** across 159 test files (README badge)
- **27-pass manual security audit, 181 findings, all resolved** (`SECURITY_AUDIT_REPORT.md`, `SECURITY_PENTEST_RESULTS.md`)
- **NIST CSF mapping** (`docs/nist-csf-mapping.md`) — rare for Indian fintech OSS
- **9-check RiskGuard** runs before every order — hash-chained audit trail post-fact
- **Production deployment on Fly.io Mumbai region** with static egress IP for SEBI April 2026 mandate
- **Published on MCP Registry** (per memory — verify pre-submission)
- **Path-2 hosted compliance posture** — `ENABLE_TRADING=false` env flag is the regulator panic button (5 minutes to flip)
- **Algo2Go umbrella brand reserved** (per `kite-algo2go-rename.md`) — credible commercial roadmap once incorporation lands
- **Active commit cadence** (994 commits in 5mo) = burn-rate signal that grant funding directly converts to OSS output

### 3g. Past contributions / credibility

- Solo maintainer of the fork since inception (Feb 2026)
- Active Kite Connect developer for **2+ years** (per `funding.json` `entity.description`)
- Published a 13-level deep-dive on OAuth callback architecture (`docs/blog/oauth-13-levels.md` — 237KB technical writeup)
- Published a complete product-definition doc separating product code from internal R&D journal (`docs/product-definition.md`)
- Maintains 10 ADRs documenting architectural decisions (`docs/adr/0001` through `0010`)
- 95.08 / 95.69 architecture quality score (per memory note `kite-architecture-fix-apr-2026.md` referenced in main MEMORY.md)
- MIT licensed; upstream attribution to Zerodha Tech preserved in `LICENSE` and `NOTICE`
- Indian Pvt Ltd incorporation pending — explicitly disclosed in `funding.json` (transparency signal)

---

## Phase 4 — Indian-OSS narrative angles

Each = 2–3 sentences usable in impact narrative or committee follow-up call.

### Financial inclusion

> 8 lakh+ Indian retail traders have access to the Zerodha Kite Connect API but lack the engineering resources to build production-grade tooling around it. Bloomberg / Refinitiv / FactSet are economically out of reach. This server collapses that asymmetry by exposing institutional-grade analytics (Black-Scholes Greeks, sector exposure, tax-loss harvest, technical indicators) through a conversational interface with safety rails — at zero marginal cost to the user.

### AI democracy

> An LLM client running on a retail trader's laptop is now a more capable trading copilot than what most institutional desks had access to 10 years ago. The remaining gap is *connection-to-real-account* with safety. This project closes that gap with an MIT-licensed reference implementation: per-user OAuth, hash-chained audit, 9-check RiskGuard middleware, and elicitation-based confirmation. It removes the "AI-is-too-risky-near-money" objection by encoding the safety rails in code that the user can audit.

### Regulatory transparency

> Indian fintech OSS rarely engages publicly with the regulatory frame: SEBI April 2026 algo framework, DPDP 2023, CERT-In incident-reporting, NIST CSF posture. This codebase commits, in public docs, to all four — `docs/sebi-paths-comparison.md`, `docs/nist-csf-mapping.md`, `THREAT_MODEL.md`, `docs/incident-response.md` are reference material that other Indian fintech OSS maintainers can fork and adapt. Raising the regulatory bar publicly is the project's largest non-code contribution.

### MCP-ecosystem contribution

> Among the first production-quality finance MCP servers globally. As of May 2026, the public MCP registry has fewer than 5 production-grade finance servers. Patterns developed here (per-user OAuth via mcp-remote, RiskGuard as pre-tool middleware, MCP Apps widgets for inline UI, hash-chained audit log, MCP elicitation for human-in-the-loop) are reference implementations for the next wave of regulated-domain MCP servers — not just trading, but healthcare, insurance, government services.

### Reverse-pollination

> Every reusable component is exposed as a Go package with stable interfaces: `kc/riskguard` (9-check pre-trade middleware, applicable to any order-placing system), `kc/audit` (hash-chained tool-call log, applicable to any LLM-driven side-effecting service), `oauth/` (per-user OAuth 2.1 + PKCE on top of mcp-remote, applicable to any MCP-server-with-credentials), `kc/billing` (tier gating via env flag, applicable to any feature-flagged regulated service). The components are extractable; the patterns are documented in ADRs. The expected secondary impact is 3–5 other Indian fintech OSS projects adopting one of these patterns within 12 months of fund disbursement.

---

## Phase 5 — Submission strategy

### Submit BEFORE or AFTER Show HN?

**Recommendation: AFTER Show HN, gated on ≥50 GitHub stars.**

| Argument | Pro before | Pro after | Verdict |
|---|---|---|---|
| Eligibility filter | "very new / minimal usage" — hard fail today | Show HN gives 50–500 stars in 24h, demonstrates "widely used" criterion | **AFTER** |
| Q3 2026 quarter window | If applying for Q3 (Jul–Sep), need to submit by Sep 30 | Show HN should land Jun-Jul; stars in by Aug; submit late Aug | **AFTER** with Q3 timing |
| Risk of cold submission | Single rejection consumes social capital — committee remembers names | Submitted-after-traction shows we read the FAQ | **AFTER** |
| Risk of waiting | Q4 is the last 2026 tranche; if we miss Q3, we lose 6 months | Q4 deadline ~Dec 30; Show HN by Sep covers either window | Either is OK |

**Concrete plan:** Show HN by July 2026. Stars by August. Submit `funding.json` to `dir.floss.fund/submit` last week of August. Targets Q3 review window (typically end-September to mid-October).

### Attachments / supporting links

The application form takes only the manifest URL. **All supporting evidence must be linked from inside `funding.json` `description` fields or hosted at the linked URLs.**

Pre-submission checklist of public-facing supporting URLs:
- `https://github.com/Sundeepg98/kite-mcp-server` — repo
- `https://kite-mcp-server.fly.dev/` — live hosted instance
- `https://kite-mcp-server.fly.dev/mcp` — MCP endpoint (smoke-test from `mcp-remote`)
- `SECURITY_AUDIT_REPORT.md` (in repo root, public)
- `THREAT_MODEL.md` (in repo root, public)
- `docs/architecture-diagram.md` (in repo, public)
- `docs/tool-catalog.md` (in repo, public — confirms ~80 tool count)
- `docs/floss-fund-proposal.md` (in repo, public — long-form pitch)
- `docs/blog/oauth-13-levels.md` (in repo, public — credibility)
- `https://github.com/Sundeepg98/kite-mcp-server/actions` — CI green badge
- `server.json` on the MCP Registry (per memory — verify URL pre-submission)

### Follow-up cadence

If no response in **6 weeks** post-submission (covers a quarter-end + 2-week disbursement window):
- **Week 6**: Light email to `floss@zerodha.com` (or whatever the FLOSS/fund team contact is on `floss.fund/faq`) — "Submitted manifest at <URL> on <date>; happy to provide additional info if useful."
- **Week 10**: Follow up once more with a one-line update ("v1.1.0 shipped, 3 new analytics tools, X new stars") — demonstrates ongoing maintenance.
- **Week 14**: Move on. Re-apply next quarter with new evidence.

### Backup grants if FLOSS/fund declines

| Grant | Amount | Eligibility | Suitability |
|---|---|---|---|
| **FOSS United Fellowship** | ₹16,500 – ₹1,20,000 / project ₹30k – ₹5L | Indian individual maintainer eligible | **Already have draft email** at `docs/drafts/foss-united-grant-email.md`. Send 1–2 weeks before or after FLOSS/fund. Different funds; not double-dipping. |
| **GitHub Secure Open Source Fund** | $10,000 / project | Rolling, security-focused, individual maintainer OK | Strong fit — 27-pass security audit + RiskGuard + AES-256-GCM encryption posture. Apply if FLOSS/fund declines on traction grounds. |
| **Open Source Collective (fiscal sponsorship)** | Variable, transparent funding via Open Collective platform | Individual maintainers (since policy update) | Useful as fiscal-sponsor for one-off donations from end-users; not a grant per se. |
| **Mozilla MOSS** | Up to $250k historically | Indefinite hiatus as of May 2026 | Skip. Replaced by Mozilla Technology Fund (different scope). |
| **Sloan Foundation OSS** | Variable | Mostly research-tied; not a fit for fintech | Skip. |
| **NumFOCUS** | N/A — fiscal sponsor for scientific computing | Not a fit | Skip. |
| **GitHub Accelerator** | $20k stipend + program | Cohort-based; cycles closed | Watch for 2026 cohort announcement; prepare a parallel application if announced. |

**Sequence:** FLOSS/fund (primary) → FOSS United (1–2 weeks separate) → GitHub Secure Open Source Fund (rolling) → fiscal-sponsor route via Open Source Collective (if individual donations appear).

---

## Phase 6 — Pre-submission checklist (≤15 items)

Run through this before clicking Submit at `dir.floss.fund/submit`. All items must be **YES**.

| # | Item | YES/NO |
|---|---|---|
| 1 | `funding.json` is at repo root and reachable at `https://github.com/Sundeepg98/kite-mcp-server/blob/master/funding.json` (or `/raw/master/funding.json`) | ☐ |
| 2 | `wellKnown` URL in `funding.json` matches the actual default branch (`master` not `main`) — currently broken, must fix | ☐ |
| 3 | Plan amounts use only `$10,000` / `$35,000` / `$60,000` / `$85,000` / `$100,000` — currently violates with `$25,000` and `$50,000` | ☐ |
| 4 | `entity.email` and `funding.channels[].address` use a real product email Sundeep monitors (not the renusharmafoundation address — banned for product work per user rule) | ☐ |
| 5 | `funding.json` validates clean at `https://dir.floss.fund/validate` (no "Unverified URL" warning) | ☐ |
| 6 | Repo has ≥50 GitHub stars (proxy for "widely used" eligibility filter) | ☐ |
| 7 | Show HN has been posted publicly (Hacker News) and is referenceable | ☐ |
| 8 | At least one external blog post / writeup (Z-Connect editorial, personal blog, dev.to, IndiaFOSS talk) — proves "impact" | ☐ |
| 9 | `SECURITY_AUDIT_REPORT.md` is in repo and pasteable as a link | ☐ |
| 10 | `docs/floss-fund-proposal.md` `<product-email-placeholder>` TODO is resolved | ☐ |
| 11 | `FUNDING.json` (uppercase duplicate) is removed (one canonical manifest only) | ☐ |
| 12 | GitHub Sponsors profile at `https://github.com/sponsors/Sundeepg98` is live (referenced in `.github/FUNDING.yml`) | ☐ |
| 13 | Submission is timed within 4 weeks of a quarter-end (Mar 31 / Jun 30 / Sep 30 / Dec 31) for that quarter's review window | ☐ |
| 14 | A single Indian bank account capable of receiving USD wire is identified (or Pvt Ltd entity if grant tier > $10k) | ☐ |
| 15 | A separate FOSS United email (queued in `docs/drafts/foss-united-grant-email.md`) is prepared but NOT sent yet — backup grant kept warm | ☐ |

---

## Appendix — Concrete fixes (NOT applied; for the user's next pass)

### Fix #1 — `wellKnown` URL

```diff
       "repositoryUrl": {
         "url": "https://github.com/Sundeepg98/kite-mcp-server",
-        "wellKnown": "https://github.com/Sundeepg98/kite-mcp-server/blob/main/funding.json"
+        "wellKnown": "https://raw.githubusercontent.com/Sundeepg98/kite-mcp-server/master/funding.json"
       },
```

(Use the `raw.githubusercontent.com` URL because GitHub's `/blob/` URL is HTML-wrapped, not JSON. Some validators reject HTML-wrapped manifests.)

### Fix #2 — Plan amounts

```diff
       {
         "guid": "mid-grant",
         "status": "active",
         "name": "Mid grant — 6-month focused runway",
         "description": "...",
-        "amount": 25000,
+        "amount": 35000,
         "currency": "USD",
         "frequency": "one-time",
         "channels": ["grant-email"]
       },
       {
         "guid": "annual-stipend",
         "status": "active",
         "name": "Annual maintenance stipend",
         "description": "...",
-        "amount": 50000,
+        "amount": 60000,
         "currency": "USD",
         "frequency": "yearly",
         "channels": ["grant-email"]
       }
```

### Fix #3 — Remove duplicate `FUNDING.json`

```bash
rm FUNDING.json
git rm FUNDING.json  # only if it ever gets staged
```

### Fix #4 — Channel type

```diff
   "funding": {
     "channels": [
       {
         "guid": "grant-email",
-        "type": "other",
+        "type": "payment",
         "address": "sundeepg8@gmail.com",
         "description": "Direct grant disbursement via email coordination..."
       }
     ],
```

(Spec is loose on `type`; `"payment"` is the conventional value for direct-bank flows. `"other"` works but signals less polish.)

### Fix #5 — Resolve placeholder in `docs/floss-fund-proposal.md`

```diff
 ## Contact
 
-- Email: <product-email-placeholder> <!-- TODO: replace with product email before publishing -->
+- Email: sundeepg8@gmail.com
 - GitHub: https://github.com/Sundeepg98
 - Project: https://github.com/Sundeepg98/kite-mcp-server
```

(Or whatever dedicated product email Sundeep configures — explicitly NOT the renusharmafoundation address.)

---

## End-state: when this is submission-ready

All 15 checklist items YES. Quarter-end window within 4 weeks. Show HN landed. ≥50 stars. Validator green. Then — and only then — paste `https://github.com/Sundeepg98/kite-mcp-server/blob/master/funding.json` (or the raw URL) into `dir.floss.fund/submit`. Click submit. Email confirmation lands. Wait 4–6 weeks for committee review.

Submission cost: 30 seconds. Preparation cost: this document plus 30–60 minutes of fixes. Net expected value (per memory `kite-floss-fund.md`): $10,000 – $35,000 grant + warm-intro to Zerodha/Rainmatter ecosystem at zero equity dilution.
