# INDEX.md — Question-Keyed Research Lookup

**Date**: 2026-05-11 IST
**Master HEAD audited**: `91d834f` (`docs(verification): empirical re-verification across 16 active research docs`)
**Production**: v1.3.0 / tools=111 / machine version 273 / image `deployment-01KR9FPJC88YA80VWS7VMTWTY7`
**Scope**: 7 research locations covered (`.research/` active + archive, user `memory/`, `MEMORY.md`, repo root, `docs/`, project + repo `CLAUDE.md`)
**Charter**: question-keyed (not file-keyed) lookup so future sessions can answer "what's X?" without re-spawning research agents.

**Verification protocol** per row:
- **Last verified**: date of last empirical or web-source verification (or *unverified/derived* if no probe-date is cited)
- **Status**: **FRESH** (verified ≤30d) / **STALE-PENDING** (verified >30d, may need re-check) / **EMPIRICAL** (probe-able now via the listed `Probe path`) / **NARRATIVE** (judgment-load-bearing, not empirically falsifiable) / **SUPERSEDED** (older claim; see referenced newer entry)
- **Probe path**: command/URL to re-verify if empirical

---

## §0 — How to use this doc

1. **For a known question**: ctrl-F or `grep` the question column. Each row points to the canonical answer file:section + last-verified date. If status is STALE-PENDING and decision is high-stakes, re-probe before asserting.
2. **For an unknown topic**: skim the §1 research-streams overview to find the right stream; then dive into that stream's docs.
3. **For a stale-finding cleanup pass**: filter rows with `Status: STALE-PENDING` and re-verify the Probe path; promote to FRESH on success.
4. **When adding new research**: pick the right category in §2-§9. If no row matches, add one. Entries with overlapping answers in multiple files should pick the canonical-source row by (most recent verification > most empirically grounded > most cross-referenced).
5. **When archiving research**: update the affected rows' Answer location to `.research/archive/<topic>/<file>.md` so the lookup still works post-archival.

---

## §1 — Research Streams (one-paragraph orientation per stream)

Eleven active streams identified across 7 locations:

| # | Stream | Authoritative location | Stewards |
|---|---|---|---|
| 1 | **Production state + master deploy invariant** | `.research/STATE.md` + `.research/decisions/production-master-gap-report.md` + `.research/decisions/dr-drill-results-2026-05-11.md` | chain agent (deploys); audit/synthesis (research docs) |
| 2 | **Architecture: Path A modules + Tier 1+2 facades + Phase 2.x persistence + multi-cell scaling** | `.research/STATE.md §1` + `.research/decisions/phase-2-6-r10-decisions.md` + `.research/decisions/path-e-try-before-buy-results.md` + `.research/10000-agent-blocker-analysis.md` + `.research/archive/path-a-modules/` (28 module-pick docs) | path-a-owner; capacity-architect |
| 3 | **Launch-path execution: items #42-#46 (TM filing, dr-drill, demo GIF, Reddit warmup, Show HN)** | `.research/launch-path-execution-playbooks.md` + `.research/algo2go-reservation-runbook.md` + `.research/demo-recording-production-guide.md` + `.research/reddit-subreddit-specific-strategy.md` + `.research/twitter-build-in-public-weeks-1-4.md` + `.research/day-1-launch-ops-runbook.md` | audit/synthesis (capacity-architect); user (manual execution) |
| 4 | **Strategic / forward-tracks (5 tracks: Phase 3, Phase 1.4 CI, NSE empanelment, launch path, other)** | `.research/forward-tracks-strategic-review.md` + `.research/team-scaling-cost-benefit-per-axis.md` | capacity-architect |
| 5 | **Regulatory / compliance (SEBI rules, DPDP, NSE empanelment, MCA, IP whitelist, daily token expiry)** | `memory/kite-landmines.md` + `memory/kite-cost-estimates.md` + `memory/kite-fintech-lawyers.md` + `memory/kite-sebi-otr-feb-2026.md` + `memory/kite-path2-architecture.md` + `memory/feedback_cheapest_compliance_action.md` | user (offline conversations w/ Zerodha + lawyers); orchestrator (synthesis) |
| 6 | **Brand + distribution (Algo2Go rename, FLOSS/fund, Rainmatter, MCP Registry, awesome-mcp lists, Z-Connect)** | `memory/kite-algo2go-rename.md` + `memory/kite-floss-fund.md` + `memory/kite-rainmatter-warm-intro.md` + `memory/kite-mcp-registry-publisher.md` + `memory/kite-awesome-mcp-listings.md` + `memory/kite-zerodha-no-marketplace.md` + `memory/kite-registry-and-funding-refs.md` | orchestrator (synthesis); user (warm-intros) |
| 7 | **Security posture (audits, hardening sessions, riskguard, encryption, threat model)** | repo root `SECURITY_AUDIT_REPORT.md` + `THREAT_MODEL.md` + `memory/kite-audit.md` + `memory/kite-security-posture.md` + `memory/kite-security-hardening-2026-04.md` + `memory/kite-riskguard-tightened.md` | audit (TDD discipline); user (acceptance) |
| 8 | **Competitor landscape + product strategy** | `memory/kite-competitors-corrected.md` + `memory/kite-product-strategy.md` + `memory/kite-next-roadmap.md` + `memory/kite-mrr-reality.md` | orchestrator (synthesis); user (strategy decisions) |
| 9 | **Operations + runbooks (deploy, incident, dr-drill, monitoring, env vars, kite-token-refresh)** | repo `docs/pre-deploy-checklist.md` + `docs/incident-response.md` + `docs/monitoring.md` + `docs/operator-playbook.md` + `docs/kite-token-refresh.md` + `memory/kite-deploy-ops-runbooks.md` | chain agent; user (incident response) |
| 10 | **Feedback rules + standing user rules** | `memory/MEMORY.md` (User Rules section) + `memory/feedback_*.md` + `memory/user_*.md` (~15 files) | orchestrator (must obey); user (rule-author) |
| 11 | **MCP ecosystem (registry, widget capability detection, skills wrapper, callback OAuth flow)** | `memory/kite-callback-deepdive.md` + `memory/kite-widget-capability-detection.md` + `memory/kite-skills-wrapper.md` + `docs/callback-deep-dive-13-levels.md` + `memory/mcp-servers.md` | audit; user (MCP client integrations) |

Each stream below has a question-keyed lookup table. Rows are sorted by query-frequency (most-asked first within a stream) where determinable, otherwise alphabetical by question.

---

## §2 — Financial / Costs

| Question | Answer location | Last verified | Status | Probe path |
|---|---|---|---|---|
| What does SEBI RA registration cost (Year 1)? | `memory/kite-cost-estimates.md` §"SEBI Registered Analyst" | 2026-04-17 | STALE-PENDING | external — call Spice Route Legal / Finsec |
| ₹1.1L-1.8L Y1 + ₹1L locked refundable; ₹25-50k/yr renewal; NISM cert every 3 yr | (same) | (same) | (same) | (same) |
| What does Body Corporate RA cost? | `memory/kite-cost-estimates.md` §"Body Corporate RA" | 2026-04-17 | STALE-PENDING | external |
| ₹7-9L Y1 + ₹25L locked refundable | (same) | (same) | (same) | (same) |
| What does CERT-In VAPT cost? | `memory/kite-cost-estimates.md` §"CERT-In VAPT" | 2026-04-17 | STALE-PENDING | external |
| ₹1-2L per cycle × 2 cycles/year = ₹3-5L/yr | (same) | (same) | (same) | (same) |
| What does Pvt Ltd incorporation cost (India)? | `memory/kite-cost-estimates.md` §"Pvt Ltd Incorporation" | 2026-04-17 | STALE-PENDING | https://www.vakilsearch.com pricing page |
| Vakilsearch ₹999 base + total Y1 ₹55-85k including MCA fees + DIN + first-year ROC compliance + CA retainer ₹3k/mo | (same) | (same) | (same) | (same) |
| What does NSE empanelment cost? | `memory/kite-cost-estimates.md` §"NSE Empanelment" + `memory/kite-mrr-reality.md` | 2026-04-17 | STALE-PENDING | https://www.nseindia.com/static/trade/empanelled-algo-providers-exchange |
| ₹4-8L Y1 incl. NSE inspection + audit + bond + docs + legal; precedent: Quick Algoplus ₹20k paid-up capital | (same) | (same) | (same) | (same) |
| What does Algo2Go TM filing cost (direct vs Vakilsearch)? | `.research/launch-path-execution-playbooks.md` §Item 4; `.research/STATE.md` §8.3 | 2026-05-10 | FRESH | https://www.intepat.com/blog/trademark-registration-fees-india |
| Direct via ipindiaonline.gov.in: ₹4,500/class × 2 (Class 9 software + Class 42 SaaS) = ₹9,000. Vakilsearch ₹19-22k. ₹10-13k savings via direct. | (same) | (same) | (same) | (same) |
| What is the Kite Connect API price/month? | `memory/MEMORY.md` line ~70 (kite-mcp-server section) | 2026-05-07 | STALE-PENDING | https://kite.trade/connect/pricing |
| ₹500/mo per app (reduced from ₹2000 mid-2025); 1 active session per app | (same) | (same) | (same) | (same) |
| What's the realistic 12-month MRR target? | `memory/kite-mrr-reality.md` §"12-month MRR ceiling" | 2026-04-17 | STALE-PENDING | NARRATIVE (synthesis judgment) |
| ₹15-25k/mo realistic; composition: 500-2K free + 10-25 paid @ ₹1,999/yr or ₹799/mo; annual reduces churn 51% per Paddle benchmark | (same) | (same) | (same) | (same) |
| When to invest the ₹4-8L empanelment fee? | `memory/kite-mrr-reality.md` §"Empanelment investment is GATED" | 2026-04-17 | STALE-PENDING | NARRATIVE |
| Only ≥50 paid annual subs (₹1L+ ARR) + ≥500 MAU + ≥1,000 GitHub stars + legal opinion letter | (same) | (same) | (same) | (same) |
| What's the full compliance stack cost (Year 1) if going fully regulated? | `memory/kite-cost-estimates.md` §"Total compliance stack" | 2026-04-17 | STALE-PENDING | external (lawyer + CA + SEBI fees may shift) |
| ~₹12L out-of-pocket + ₹1L locked (Pvt Ltd ₹85k + SEBI RA ₹1.8L + CERT-In ₹3L/yr + Empanelment ₹6L Y1) | (same) | (same) | (same) | (same) |
| What does fintech lawyer engagement cost? | `memory/kite-fintech-lawyers.md` §"Engagement costs" | 2026-04-17 | STALE-PENDING | external — call Spice Route Legal / Finsec |
| 1-hour consult ₹15-35k; written opinion 5-10 pages ₹3-5L; ongoing retainer ₹50k-1L/mo | (same) | (same) | (same) | (same) |

---

## §3 — Regulatory / Compliance

| Question | Answer location | Last verified | Status | Probe path |
|---|---|---|---|---|
| What does SEBI's April 2026 algo framework actually require? | `memory/kite-sebi-otr-feb-2026.md` + `memory/kite-path2-architecture.md` | 2026-04-19 | STALE-PENDING | https://www.sebi.gov.in (search "algo provider circular") |
| 10 OPS threshold + Algo-ID per order + static IP + 2FA/OAuth + daily session reset + broker-as-principal. Effective 2026-04-01 (live, no delay). | (same) | (same) | (same) | (same) |
| What's the SEBI OTR exemption band for algo orders (Feb 2026 circular)? | `memory/kite-sebi-otr-feb-2026.md` | 2026-04-19 | STALE-PENDING | external — Business Today / Angel One / Fyers |
| Equity-options ±40% LTP (or ₹20); cash/futures ±0.75% LTP; DMM excluded entirely. Effective 2026-04-06. | (same) | (same) | (same) | (same) |
| Why does the hosted Fly.io deployment have ENABLE_TRADING=false? | `memory/kite-path2-architecture.md` + `.claude/CLAUDE.md` (project) §"Path 2 compliance" + `fly.toml` | 2026-05-11 | FRESH+EMPIRICAL | `cat fly.toml | grep ENABLE_TRADING` |
| Path 2 architecture: hosted = read-only analytics + paper trading; self-host = full trading. Eliminates sub-broker classification risk from shared static egress IP. ENABLE_TRADING=false gates ~18 order tools. Self-host with own static IP + own broker dev app for execution. | (same) | (same) | (same) | (same) |
| What's the static egress IP for Fly.io BOM region, and how does it interact with SEBI IP whitelist? | `memory/MEMORY.md` line ~99 + `memory/kite-landmines.md` §4 + `mcp/plugin_widget_ip_whitelist.go:54` (per `.research/10000-agent-blocker-analysis.md` L1.2) | 2026-04-13 | STALE-PENDING | `flyctl ips list -a kite-mcp-server` (auth-gated) |
| `209.71.68.157` (BOM region). Each user must whitelist this in their Kite developer console for order placement (SEBI Apr 2026 mandate). Field is plural ("Whitelisted IPs" — array; multi-cell-friendly). | (same) | (same) | (same) | (same) |
| When does Kite access token expire? | `memory/MEMORY.md` line ~73 + `docs/kite-token-refresh.md` | 2026-04-13 | STALE-PENDING | external (Zerodha may change behavior) |
| ~6 AM IST daily; smart token expiry detection in code; auto re-auth via mcp-remote (eliminates double login). | (same) | (same) | (same) | (same) |
| When does the MCP bearer JWT expire? | `memory/MEMORY.md` line ~99 (kite-mcp-server section) | 2026-04-13 | STALE-PENDING | empirical via `oauth/config.go:31` line check |
| 24 hours (default in `oauth/config.go:31`; app constructs Config without override). Dashboard JWT cookie: 7 days (`oauth/middleware.go:120`). **Note: an earlier "4h expiry" claim was a stale plan that never landed — do not quote.** | (same) | (same) | (same) | (same) |
| What's the DPDP Act 2023 timeline? | `memory/kite-sebi-otr-feb-2026.md` §"DPDP Act 2023 timeline" | 2026-04-19 | STALE-PENDING | https://www.meity.gov.in (DPDP Phase 2 + 3 notifications) |
| Phase 2 consent-manager registration: Nov 13 2026. Phase 3 notice/consent/breach/rights: May 13 2027. No new DPB consultation papers in Apr 2026 audit window. | (same) | (same) | (same) | (same) |
| What's the DPDP Act risk for unmitigated processing of Kite credentials? | `memory/kite-landmines.md` §2 | 2026-04-17 | STALE-PENDING | external (lawyer) |
| Up to ₹250 crore fines for data-principal violations. Currently processing Kite credentials + holdings without DPIA, DPO, consent ledger. Mitigation: paid lawyer consult before paid tier. | (same) | (same) | (same) | (same) |
| What are the 5 Kite-MCP "landmines" (adversarial review)? | `memory/kite-landmines.md` (full doc) | 2026-04-17 | STALE-PENDING | external |
| (1) Zerodha "Kite" TM bomb (Class 36 + 42); (2) TERMS/PRIVACY without lawyer + DPDP fine risk; (3) prompt-injection → market manipulation via sub-cap orders (FIXED at `7cd7b35`); (4) shared static egress IP across users (sub-broker classification risk); (5) GitHub name collision with Zerodha upstream | (same) | (same) | (same) | (same) |
| What's the SEBI Cloud Framework (CSCRF) status for kite-mcp-server? | `memory/kite-landmines.md` + `memory/MEMORY.md` 2026-04 entry | 2026-04 | STALE-PENDING | external |
| Algo vendors are AGENTS not REs per Dec 2024 framework. Below paid-sub threshold our Path 2 stays safe-harbor. | (same) | (same) | (same) | (same) |
| What's the cheapest single compliance action right now? | `memory/feedback_cheapest_compliance_action.md` (referenced from `kite-landmines.md`) | 2026-04-17 | STALE-PENDING | NARRATIVE |
| Email `kiteconnect@zerodha.com` with 3 questions (BYO-developer-app architecture, paid-subs threshold, OSS algo precedent). Cost ₹0. Establishes paper trail before monetization. | (same) | (same) | (same) | (same) |
| Pre-drafted Zerodha compliance email? | `docs/drafts/zerodha-compliance-email.md` | unverified | STALE-PENDING | `ls docs/drafts/zerodha-compliance-email.md` |
| Ready-to-send draft exists in repo. | (same) | (same) | (same) | (same) |
| Are pre-drafted DPDP reply templates available? | `docs/dpdp-reply-templates.md` | unverified | STALE-PENDING | `ls docs/dpdp-reply-templates.md` |
| Yes (file exists in repo). | (same) | (same) | (same) | (same) |
| What does NSE empanelment list look like (current)? | `memory/kite-registry-and-funding-refs.md` §"NSE Empanelled Algo Providers" | 2026-04-17 | STALE-PENDING | https://www.nseindia.com/static/trade/empanelled-algo-providers-exchange |
| 11 NSE + 3 BSE-only = 14 total. Mostly 2-5 person Pvt Ltds. Quick Algoplus is structural analog (₹20k paid-up). | (same) | (same) | (same) | (same) |
| Path A vs Path B SEBI strategy comparison? | `docs/sebi-paths-comparison.md` | unverified | STALE-PENDING | `ls docs/sebi-paths-comparison.md` |
| Reference doc exists in repo (sebi-paths-comparison.md). Worth re-reading before lawyer consult. | (same) | (same) | (same) | (same) |

---

## §4 — Security

| Question | Answer location | Last verified | Status | Probe path |
|---|---|---|---|---|
| What was the Feb 2026 security audit outcome? | repo root `SECURITY_AUDIT_REPORT.md` + `memory/kite-audit.md` | 2026-03-01 | SUPERSEDED-by-newer-audits-but-foundational | `head -50 SECURITY_AUDIT_REPORT.md` |
| 27 manual passes, 181 findings (6 HIGH, ~40 MED), 100% file coverage. 153 fixed, 28 accepted risk. Deployed v43 on 2026-03-01. | (same) | (same) | (same) | (same) |
| What was the Mar 2026 quality audit outcome? | `memory/kite-audit.md` §"Quality Audit (Mar 2026)" | 2026-03 | STALE-PENDING-but-foundational | `git log --grep="quality audit"` |
| 22 findings (3 critical) → fixed. Review-of-reviews +12 → fixed. 270+ tests added. | (same) | (same) | (same) | (same) |
| What's the current security posture vs other Indian MCP brokerage bridges? | `memory/kite-security-posture.md` | 2026-04-17 | STALE-PENDING | NARRATIVE (Agent 54 verdict) |
| Best-in-class as of Apr 2026. Benchmark: 11 NSE empanelled + 3 BSE + official Kite MCP + ~8 other MCP attempts. None have layered middleware (audit + riskguard + elicitation + auth) AND AES-256-GCM AND hash-chain audit AND uniform tool annotations AND paper-trading mw. | (same) | (same) | (same) | (same) |
| What 3 hardening gaps remain post-2026-04 hardening session? | `memory/kite-security-posture.md` §"3 hardening gaps remaining" | 2026-04-17 | SUPERSEDED — gaps 1+2 SHIPPED in `kite-security-hardening-2026-04` | NARRATIVE |
| (1) Idempotency keys on orders — SHIPPED via `kc/riskguard/dedup.go` SHA256 + 15-min TTL; (2) Anomaly detection μ+3σ — SHIPPED via `kc/audit/anomaly.go` + cache; (3) Tool-description integrity check — SHIPPED via `mcp/integrity.go` SHA256 manifest at startup. **All 3 shipped.** | (same) | (same) | (same) | (same) |
| What's in the late-2026-04 security hardening batch? | `memory/kite-security-hardening-2026-04.md` | 2026-04 | STALE-PENDING | `git log --grep="security"` |
| Code: dedup.go (idempotency), anomaly.go + anomaly_cache.go, guard.go +checkAnomalyMultiplier +checkOffHours, integrity.go (tool-description manifest), requestid.go (X-Request-ID UUIDv7), hashpublish.go (SSRF blocklist), envcheck.go. CI: test-race.yml, security-scan.yml, sbom.yml, v4-watchdog.yml. Tests: 14 fuzz harnesses (423k execs, 0 failures on common_fuzz). | (same) | (same) | (same) | (same) |
| What are the current RiskGuard checks (count + names)? | **EMPIRICAL** at `D:/Sundeep/projects/algo2go/kite-mcp-riskguard/guard.go` (was `kc/riskguard/guard.go` pre-Path A.21 promotion); README says BOTH "11" and "9" (intra-doc inconsistency); `.claude/CLAUDE.md` says "9"; `.research/audits/2026-05-11/active-docs-verification-2026-05-11.md` §17.2 reconciles | 2026-05-11 | EMPIRICAL — multiple counts depending on framing | `grep -E "RejectionReason\s*=" D:/Sundeep/projects/algo2go/kite-mcp-riskguard/*.go \| wc -l` |
| **17 distinct `RejectionReason` constants** total. **11 user-facing pre-trade checks** per README L22 (kill switch + order value cap ₹50k + qty limit + daily count 20/day + rate limit 10/min + per-second + duplicate 30s + daily ₹2L + idempotency + anomaly μ+3σ + off-hours). **9 in `.claude/CLAUDE.md` middleware-chain doc** (older framing pre-2026-04 hardening). **Pick ONE framing per doc and apply consistently** (per `.research/audits/2026-05-11/active-docs-verification-2026-05-11.md` §17.2). | (same) | (same) | (same) | (same) |
| What are the riskguard tightened defaults (post-7cd7b35)? | `memory/kite-riskguard-tightened.md` | 2026-04-17 | STALE-PENDING | `git show 7cd7b35` |
| 20 orders/day (was 200), ₹2L daily value (was ₹10L), ₹50k per-order (was ₹5L), RequireConfirmAllOrders=true (was false). Tune knobs: RISKGUARD_MAX_ORDERS_PER_DAY, *_DAILY_VALUE_INR, *_ORDER_VALUE_INR, *_REQUIRE_CONFIRM, *_KILL_SWITCH. | (same) | (same) | (same) | (same) |
| Where's the threat model? | repo root `THREAT_MODEL.md` + `docs/threat-model.md` + `docs/threat-model-extended.md` | unverified | STALE-PENDING | `ls THREAT_MODEL.md docs/threat-model*.md` |
| Three threat-model docs in repo. Use the extended doc for depth; root for quick reference. | (same) | (same) | (same) | (same) |
| What's the encryption posture? | `memory/MEMORY.md` line ~85 (kite-mcp-server full 4-layer persistence) + `memory/kite-security-posture.md` | 2026-04-17 | STALE-PENDING | `grep -r "AES-256-GCM" kc/alerts/` |
| AES-256-GCM via HKDF from OAUTH_JWT_SECRET. 4 layers: KiteTokenStore (cached access tokens), KiteCredentialStore (API key/secret pairs), AlertStore, ClientStore (OAuth client_secret). All survive restart. | (same) | (same) | (same) | (same) |
| Hash-chain audit log details? | `memory/MEMORY.md` line ~140 (kite-mcp-server features) | 2026-04 | STALE-PENDING | `grep -r "hashchain" kc/audit/` |
| `tool_calls` table; middleware via `WithToolHandlerMiddleware`; buffered async writer; smart per-tool summaries; PII redaction; 90-day retention cleanup; CSV/JSON export; timeline at `/dashboard/activity`. | (same) | (same) | (same) | (same) |
| Where's the SECURITY POSTURE doc? | repo `docs/SECURITY_POSTURE.md` + `memory/kite-security-posture.md` | unverified | STALE-PENDING | `ls docs/SECURITY_POSTURE.md` |
| `docs/SECURITY_POSTURE.md` exists in repo. | (same) | (same) | (same) | (same) |

---

## §5 — Competition + Distribution

| Question | Answer location | Last verified | Status | Probe path |
|---|---|---|---|---|
| Who are the real competitors (and which are NOT real)? | `memory/kite-competitors-corrected.md` | 2026-04-17 | STALE-PENDING | external — Google "Indian fintech AI assistant" |
| Real: **Multibagg AI** (Shark Tank backed, ₹50cr valuation, 22k signups in 1wk Jan 2026, anti-MCP publicly). Adjacent: Sensibull (Zerodha-invested), Smallcase, Streak, official Kite MCP (22 read-only tools). NOT a threat: Dhanarthi (only 100 Play Store installs, side project). | (same) | (same) | (same) | (same) |
| Does Zerodha operate a public app marketplace? | `memory/kite-zerodha-no-marketplace.md` | 2026-04-18 | STALE-PENDING | https://kite.trade |
| **No.** Hand-picks 4 portfolio apps (Coin/Smallcase/Streak/Sensibull) — Zerodha-owned or Rainmatter portfolio. No self-serve directory. No submission process. Implication: distribution flows via GitHub topic tags + MCP Registry + awesome-mcp-servers + Z-Connect editorial pitch (post-500★). | (same) | (same) | (same) | (same) |
| What's the priority order for awesome-mcp-servers PR submissions? | `memory/kite-awesome-mcp-listings.md` | 2026-04-18 | STALE-PENDING | external — peer lists may change rules |
| (1) punkpeye/awesome-mcp-servers (85k★, <1hr merges, append `🤖🤖🤖` for fast-track, `### 💰 Finance & Fintech`); (2) mcpservers.org submission form (covers wong2 4k★ which refuses direct PRs; $39 fast-review optional); (3) jaw9c/awesome-remote-mcp-servers (1k★, strict OAuth 2.0 + production-ready). Skip appcypher (stale since 2025-09). glama.ai auto-indexes ~1wk. | (same) | (same) | (same) | (same) |
| Direct competitor on punkpeye Finance list? | `memory/kite-awesome-mcp-listings.md` §"Direct competitor" | 2026-04-18 | STALE-PENDING | https://github.com/punkpeye/awesome-mcp-servers |
| `aranjan/kite-mcp` — Python, 14 tools, TOTP auto-login, local-only. Our differentiators: 80+ tools (vs 14), hosted+self-host (vs local-only), OAuth 2.1 per-user (vs shared TOTP), alerts+Telegram, backtesting, paper trading ₹1cr, riskguard 11 checks, SEBI Apr-2026 / DPDP-aware. | (same) | (same) | (same) | (same) |
| What's the FLOSS/fund path (Zerodha OSS grants)? | `memory/kite-floss-fund.md` + `memory/kite-registry-and-funding-refs.md` | 2026-04-17 | STALE-PENDING | https://floss.fund/ |
| Zerodha's $1M/yr OSS fund. Grant size $10k-$100k. **Non-dilutive, individuals eligible** (no incorporation required). Process: publish `funding.json` in repo root + 1-page proposal + submit at floss.fund. Trigger: ≥50 GitHub stars + 1 blog post / HN submission + funding.json committed. **Cost: zero, just effort.** Pre-drafted email at `docs/drafts/foss-united-grant-email.md`. | (same) | (same) | (same) | (same) |
| What's the Rainmatter warm-intro path? | `memory/kite-rainmatter-warm-intro.md` + `memory/kite-registry-and-funding-refs.md` | 2026-04-17 | STALE-PENDING | external — Twitter handles change |
| **DO NOT cold email founders.** Trigger only after FLOSS/fund submitted + ≥50 stars. Priority order: (1) **Deepak Shenoy** (@deepakshenoy, Capitalmind — Rainmatter invested Aug 2025); (2) **Vishvajit Sonagara** (@iamvishvajit, Rainmatter podcast alum); (3) **Abid Hassan** (@abidsensibull, Sensibull). Later: Vasanth Kamath (@vasanthkamath), Nikhil Kamath (@nikhilkamathcio — last resort, do not burn until Pvt Ltd + 500 users). Channel: Twitter DMs (NEVER cold email). Pre-drafted DMs at `docs/drafts/jethwani-shenoy-dms.md` + `docs/drafts/vishal-dhawan-dms.md`. | (same) | (same) | (same) | (same) |
| Difference between Rainmatter Foundation, Rainmatter Capital, FLOSS/fund? | `memory/kite-floss-fund.md` §"Rainmatter vs FLOSS/fund confusion" | 2026-04-17 | STALE-PENDING | external |
| **Rainmatter Foundation**: CLIMATE/ENVIRONMENT vertical (wrong target, do not apply). **Rainmatter Capital**: EQUITY fund, requires Pvt Ltd + traction. **FLOSS/fund**: OSS GRANTS, individuals OK, our actual fit. Rainmatter Capital cold-app form: `https://forms.gle/88D9cKMan27qa5R57`; email `investments@rainmatter.com`. | (same) | (same) | (same) | (same) |
| How to publish to MCP Registry? | `memory/kite-mcp-registry-publisher.md` | 2026-04-19 | STALE-PENDING | https://github.com/modelcontextprotocol/registry/releases |
| `mcp-publisher` CLI binary-only on Windows. Auth: GitHub OAuth device flow (no PAT). `mcp-publisher login github` then `validate ./server.json` then `publish ./server.json`. Synchronous (no human moderation). Verify via `curl https://registry.modelcontextprotocol.io/v0.1/servers/io.github.sundeepg98/kite-mcp-server`. **⚠️ Registry is in preview — data resets possible.** Auth path that works: `MCP_GITHUB_TOKEN=$(gh auth token) ./mcp-publisher.exe login github` (zero device flow). | (same) | (same) | (same) | (same) |
| Have we already published to MCP Registry? | `memory/kite-mcp-registry-publisher.md` §"Published 2026-04-19" | 2026-04-19 | STALE-PENDING | `curl https://registry.modelcontextprotocol.io/v0.1/servers/io.github.Sundeepg98/kite-mcp-server` |
| **YES** — `io.github.Sundeepg98/kite-mcp-server` v1.2.0 published 2026-04-19, status active, isLatest. Prior `io.github.Sundeepg98/kite-trading` v1.0.0 set to `deleted`. | (same) | (same) | (same) | (same) |
| What's the official Kite MCP (mcp.kite.trade)? | `memory/kite-registry-and-funding-refs.md` §"Official Kite MCP" + `memory/kite-competitors-corrected.md` | 2026-04-17 | STALE-PENDING | https://mcp.kite.trade/mcp |
| URL: `mcp.kite.trade/mcp`. **22 tools** (read-only + GTT). Free, no developer app needed (Zerodha hosts). Our differentiation: order placement, alerts+Telegram, ticker, multi-user, open-source, self-hostable, riskguard, paper trading, options Greeks, backtesting. | (same) | (same) | (same) | (same) |
| What's the product strategy / expansion roadmap? | `memory/kite-product-strategy.md` + `memory/kite-next-roadmap.md` | 2026-04-04 | STALE-PENDING | NARRATIVE |
| Vision: India's AI-native Wealth Operating System. Phase 1 (Q2-Q3 2026): Multi-asset wealth view (MF, FD, gold, NPS) — $154M WealthTech market 21% CAGR. Phase 2 (Q3-Q4 2026): AA APIs (Setu/Finvu) — $40M PF market 20.7% CAGR. Phase 3 (Q1 2027): B2B/RIA tools — 988 SEBI-RIAs. Phase 4 (Q2 2027): Crypto. Phase 5 (H2 2027): Global markets. Strategic directions: multi-broker (3-4mo) > MCP Apps UI (4-6wk) > Registry+monetization (1-2wk) > Autonomous agent (6-8wk) > Plugin system (4-6wk). | (same) | (same) | (same) | (same) |

---

## §6 — Technical / Architecture

| Question | Answer location | Last verified | Status | Probe path |
|---|---|---|---|---|
| What's the production state right now? | `.research/STATE.md` §1.1 + `.research/decisions/production-master-gap-report.md` | 2026-05-11 | EMPIRICAL | `curl https://kite-mcp-server.fly.dev/healthz` |
| v1.3.0 / tools=111 / Fly.io BOM region / machine version 273 / image `deployment-01KR9FPJC88YA80VWS7VMTWTY7` / deployed 2026-05-10 17:44 UTC against commit `bc5043e`. Master HEAD `91d834f` is 5 commits ahead — all `.research/`-only (excluded from Docker context). **NO deploy gap exists.** | (same) | (same) | (same) | (same) |
| How many MCP tools does the production binary register? | `.research/STATE.md` §1.1 + `.research/decisions/production-master-gap-report.md` §1.4 | 2026-05-11 | EMPIRICAL | `wsl bash -c "cd /mnt/d/Sundeep/projects/kite-mcp-server && go build -o /tmp/kmcp . && /tmp/kmcp 2>&1 \| head -5"` |
| **111** = 93 registered + 18 gated_trading (when ENABLE_TRADING=false). **NOT 130** — that's a `grep mcp.NewTool(` over `mcp/` which counts 19 test fixtures in `_test.go` files. Always compile-and-run, never grep-and-count. Methodology rule pinned at `.research/STATE.md` §11. | (same) | (same) | (same) | (same) |
| How many algo2go modules are external? | `.research/STATE.md` §1.1 + `memory/session_2026-05-10_path-a-complete.md` | 2026-05-11 | EMPIRICAL | `ls D:/Sundeep/projects/algo2go/ \| wc -l` |
| **28** modules: alerts, aop, audit, billing, broker, clockport, cqrs, decorators, domain, eventsourcing, i18n, instruments, isttz, legaldocs, logger, money, oauth, papertrading, registry, riskguard, scheduler, sectors, telegram, templates, ticker, usecases, users, watchlist. Path A inauguration COMPLETE (v252 with kc/sectors → A.27 added clockport on top). | (same) | (same) | (same) | (same) |
| How many in-tree workspace members? | `.research/STATE.md` §1.1 + `go.work` | 2026-05-11 | EMPIRICAL | `cat go.work \| grep -E "^\s*\./"` |
| **4** (root + plugins + testutil + app/providers). Was 30 (initial) → 11 (mid-Path-A post A.20) → 4 (post A.27 clockport closure). | (same) | (same) | (same) | (same) |
| What's the Tier 1 closure-DI state? | `.research/STATE.md` §1.2 + `.research/audits/2026-05-11/STATE-claims-audit-2026-05-11.md` (verifies SHAs) | 2026-05-11 | EMPIRICAL | `git log -1 34a32bf fd4b20e 650f4c3` |
| **CLOSED.** Tier 1.1 brokers (`34a32bf`, 8 closure pairs) + Tier 1.2 eventing (`fd4b20e`, 16 closure pairs) + Tier 1.3 scheduling (`650f4c3`, 4 closure pairs). 2 facades remain deferred (StoreRegistry + SessionLifecycleService). | (same) | (same) | (same) | (same) |
| What's the Tier 2 pure-function registrar state? | `.research/STATE.md` §1.2 + `.research/audits/2026-05-11/STATE-v2-fresh-eyes.md` §3 | 2026-05-11 | EMPIRICAL | `git log --oneline | grep "Tier 2"` |
| **CLOSED.** 8 total pure-function registrars (1 pre-existing precedent + 7 extracted, OAuth + 6 sub-registrars). Unit tests added at `1c54773 test(kc/manager): add unit tests for 7 pure-function registrars (closes C3)`. | (same) | (same) | (same) | (same) |
| What's the Phase 2.x persistence factory state? | `.research/STATE.md` §1.3 + `.research/decisions/phase-2-6-r10-decisions.md` v8 | 2026-05-11 | EMPIRICAL | `cat app/providers/alertdb.go \| head -60` |
| **Phase 2.6 architecturally CLOSED.** `ProvideAlertDB` factory accepts `Driver=sqlite\|postgres\|turso` via env switch. SQLite default (production runs this). Postgres adapter (Phase 2.0-2.5) shipped + `OpenLibSQL` constructor (Phase 2.6 Path 6) shipped at `algo2go/kite-mcp-alerts d3c2a4a`. **libsql-client-go has GitHub deprecation banner BUT is the right choice for our CGO-free pure-remote architecture.** Production stays on SQLite (`Driver` unset → default branch). Step 4 (test/dev Fly deploy) SKIPPED — defensible engineering. | (same) | (same) | (same) | (same) |
| What's the Path E try-before-buy result (Turso vs DO)? | `.research/decisions/path-e-try-before-buy-results.md` | 2026-05-10 | FRESH | external — re-probe Turso/DO dashboards |
| Track 1 (Turso aws-ap-south-1): COMPLETED — hello-world succeeded; 5 min signup; $0; Mumbai region listed. Track 2 (DO BLR1, fresh account): **FALSIFIED** — DO docs claim BLR1 supports managed Postgres but UI showed only NA/EU regions. Track 3 (1-week synthetic load): NOT STARTED. | (same) | (same) | (same) | (same) |
| What's the 10K-agent capacity blocker analysis? | `.research/10000-agent-blocker-analysis.md` | 2026-05-06 | STALE-PENDING (some claims have stale paths post Path A) | NARRATIVE |
| 5 layers (Regulatory / Infrastructure / Data+Auth / Dev Coordination / Operational). Cost ceiling collapsed 75% post-corrections (₹3.5-4.5L/mo → ~₹50K/mo founder-only). Calendar: 6-12mo solo / 3-6mo Pre-Seed-funded. Two empirical corrections: (a) Whitelisted-IPs field is plural (multi-cell-friendly); (b) SEBI 10/sec is per-(user-app) not per-operator (BYO-developer-app architecture is naturally per-user-segregated). | (same) | (same) | (same) | (same) |
| What's the Phase 3 multi-cell first step? | `.research/STATE.md` §3.1 + `.research/forward-tracks-strategic-review.md` Track 1 | 2026-05-11 | NARRATIVE | `flyctl machines clone <bom-id> --region bom -a kite-mcp-server` |
| **Trigger NOT fired** (need ≥100 sustained concurrent users; we are at 0 paid). Smallest first step: `flyctl machines clone` — single command, ~60-90s, ~₹30/day, same static egress IP, dual-purpose with HN-surge prep. Cost ceiling: 2 cells ₹1-2k/mo → 5 cells ₹2.5-5k/mo → 10 cells ₹5-10k/mo → 100 cells ₹50k-1L/mo. | (same) | (same) | (same) | (same) |
| What's the OAuth callback flow? | `memory/kite-callback-deepdive.md` + `docs/callback-deep-dive-13-levels.md` (full 237KB archive) | 2026-03 | STALE-PENDING | external (kite.trade may change) |
| Three callback URLs: (1) Kite→Server `/callback`; (2) Server→localhost `:3334/oauth/callback` for mcp-remote; (3) `/auth/browser-login` for ops dashboard. Single `/callback` multiplexed by `flow` param (oauth/browser/default). 8-step OAuth flow: 401 → discovery → dyn client reg → /oauth/authorize (packs state into redirect_params) → Kite login → /callback (HMAC verify + auth code) → JS redirect → /oauth/token (PKCE). `redirect_params` piggyback trick: `oauthState{ClientID,RedirectURI,CodeChallenge,State}` JSON→base64→HMAC-SHA256→smuggled through Kite's redirect_params. | (same) | (same) | (same) | (same) |
| What's the agent-domain map? | `.research/agent-domain-map.md` | 2026-05-09 | STALE-PENDING (header line 16 cites stale "v228 LIVE; tools=130; 40-deploy") | NARRATIVE |
| 5 canonical roles: `chain` (deploys), `audit` (feature TDD), `path-a-owner` (module promotion), `playwright` (visual verification), `capacity-architect` (research). Each role has owns-exclusively + forbidden-paths. Disjoint-scope conventions for parallel dispatch. **Header production state needs refresh** per `.research/audits/2026-05-11/active-docs-verification-2026-05-11.md` §2. | (same) | (same) | (same) | (same) |
| What's the multi-broker abstraction plan? | `memory/kite-next-roadmap.md` §"Multi-Broker Abstraction" + `docs/multi-broker-plan.md` | 2026-04-03 | STALE-PENDING | NARRATIVE |
| 3-4 month effort. `broker.Client` interface already exists; need adapters for Angel One (smartapigo SDK exists), Dhan (godhanhq SDK exists), Upstox. Zerodha 15.76% market share, Angel One 16.3%, Groww 18.9% (no API yet). All 78 tools + paper trading + backtesting + riskguard + Telegram + audit-trail are broker-agnostic in logic. | (same) | (same) | (same) | (same) |
| Should service/UC layer emit `domain.Order` directly (Shape B) or stay on `broker.Order` DTOs with point-of-use wrap (Shape A)? | `.research/brief-2b-service-layer-domain-emission-2026-05-16.md` | 2026-05-16 | EMPIRICAL | `grep -rln 'domain\.New(Order\|Position\|Holding)FromBroker' --include=*.go kite-mcp-{bootstrap,kc,usecases}` |
| Shape A vs Shape B feasibility — **VERDICT: stay on A, do not ship B.** Empirical wrap-call density 9 sites / 7 files; Shape B would add ~25-35 parallel methods + ~690 LOC + ~17-26h for ~9 saved future wrap-calls (ROI 2-3h/site avoided). Contradicts Patterns §5 (Composed Interface narrows; Shape B widens) + §1.5 Sprint 2-4 wall lesson. Falsifiability triggers: 5× density rise, 8+ method cluster, multi-broker landing, or MCP-tool-framework requirement. | (same) | (same) | (same) | (same) |

---

## §7 — Launch Operations (item-by-item)

| Question | Answer location | Last verified | Status | Probe path |
|---|---|---|---|---|
| Is the Algo2Go GitHub org claimed? | `.research/audits/2026-05-11/active-docs-verification-2026-05-11.md` §12 + `memory/session_2026-05-10_path-a-complete.md` | 2026-05-11 | EMPIRICAL | `curl https://api.github.com/orgs/algo2go` |
| **YES, CLAIMED 2026-05-05** with 28 repos. (Earlier `algo2go-reservation-runbook.md` says AVAILABLE — superseded.) | (same) | (same) | (same) | (same) |
| Is algo2go.com still available? | `.research/audits/2026-05-11/active-docs-verification-2026-05-11.md` §1 | 2026-05-11 | EMPIRICAL | `curl https://rdap.verisign.com/com/v1/domain/algo2go.com` (HTTP 404 = available) |
| **YES, still available** (RDAP 404 = unregistered). Not yet purchased as of 2026-05-11. | (same) | (same) | (same) | (same) |
| What's the TM filing procedure (Algo2Go, direct via ipindiaonline.gov.in)? | `.research/launch-path-execution-playbooks.md` §Item 4 | 2026-05-10 | FRESH | https://ipindiaonline.gov.in/eregister/ |
| ₹4,500/class (individual filer) × 2 (Class 9 software + Class 42 SaaS) = ₹9,000. ~50-75min agent + 15-30min user. 5 user halts: scope confirm → IPIndia login → form review → PAN upload → DSC-or-affidavit → payment. Trademark search BEFORE filing at `https://tmrsearch.ipindia.gov.in/eregister/`. | (same) | (same) | (same) | (same) |
| What's the R2 dr-drill state? | `.research/decisions/dr-drill-results-2026-05-11.md` | 2026-05-11 | FRESH+EMPIRICAL | `gh workflow run dr-drill.yml -R Sundeepg98/kite-mcp-server` |
| **R2 backup chain healthy** (Litestream PID 645 actively replicating, 10s sync interval, R2 endpoint with bom region `auto`). Schema integrity OK + 27 tables + hkdf_salt 64-hex (32 bytes) PRESENT. **2 operational gaps**: (a) GitHub repo Actions secrets unset → monthly cron fails at env-var gate (run id 25205029746 failed in 11s); (b) `cmd/dr-decrypt-probe` source dir does NOT exist → playbook Item 2 build will fail. | (same) | (same) | (same) | (same) |
| Where's the demo GIF recipe? | `.research/demo-recording-production-guide.md` | 2026-05-02 | STALE-PENDING (ScreenToGif winget + 5 embed slots are durable) | NARRATIVE |
| Demo A: 30-second silent GIF. Install ScreenToGif (`winget install --id NickeManarin.ScreenToGif`). Paper-trading mode ON. 5-step scenario (portfolio → alert → Telegram). 10 fps, ≤4MB, save to `docs/assets/demo-portfolio-alert.gif`. 5 embed slots: README hero, Twitter Day-1 T1, Reddit r/algotrading, Show HN body, landing.html hero. **`docs/assets/` directory does not yet exist** — created on first GIF. | (same) | (same) | (same) | (same) |
| Reddit warmup strategy + verbatim r/algotrading post? | `.research/reddit-subreddit-specific-strategy.md` | 2026-05-02 | STALE-PENDING (verbatim post body needs patch — "80 tools, 330 tests" → "111, ~9000") | external — Reddit subreddit metadata may change |
| Day-1 +12h primary: r/algotrading (1.86M subs, OSS-friendly, no AI-content ban). Drop r/Zerodha (350 subs, restricted), r/programming (3 rules close us out). r/IndianStockMarket has hard "no AI-generated content" rule (2026-04-23) — frame as developer tool, not AI assistant. **User has NO Reddit account `Sundeepg98`** (verified 2026-05-02 reddit.com 404) — **must create + 6-day warmup** for ≥30-50 comment karma to escape new-account auto-shadowban. | (same) | (same) | (same) | (same) |
| What's the Show HN submit timing + title? | `.research/launch-path-execution-playbooks.md` §Item 5 | 2026-05-10 | FRESH | https://news.ycombinator.com/showhn.html |
| **Tuesday 06:45 PT** (= 19:15 IST evening). Title: `Show HN: kite-mcp-server – Self-hosted MCP for Zerodha Kite, with riskguards`. URL: `https://github.com/Sundeepg98/kite-mcp-server` (NOT landing page). HN convention: URL submission with EMPTY Text field; body posted as FIRST COMMENT. 4 agent halts (pre-flight blockers, body review, pre-stage decision, final submit click). | (same) | (same) | (same) | (same) |
| What's the day-1 surge profile + capacity break-points? | `.research/day-1-launch-ops-runbook.md` Phase 1 | 2026-05-02 | STALE-PENDING-but-load-bearing | NARRATIVE |
| 50-150 concurrent at peak (3K-8K unique pageviews over 4-8h front-page window). 95% never leave GitHub (zero Fly.io load). 3-5% click hosted demo. 0.3-1% wire up MCP+OAuth. Pre-stage second `bom` machine 10min before submit. Capture `flyctl status` + `flyctl image show` snapshot to sticky note for rollback. Run `./scripts/smoke-test.sh` (13 checks) — all green required. Verify Litestream WAL freshness (mtime within 60s during business hours). **`flyctl releases list` is NOT a valid subcommand — substitute `flyctl status` + `flyctl image show`.** | (same) | (same) | (same) | (same) |
| What's the Twitter cadence Weeks 1-4? | `.research/twitter-build-in-public-weeks-1-4.md` | 2026-05-02 | STALE-PENDING (D1-T1 needs patch — "~80 tools, 9 checks, ~330 tests" → "111, 11, ~9000") | NARRATIVE |
| 3 content rules: (1) no tips/signals/PNL/forward-return ever; (2) lead with code (every claim → github.com/Sundeepg98/... deep-link); (3) cap volume 3 tweets/day, 1 thread/week. Day-1 sequencing per `day-1-launch-ops-runbook.md` Phase 6. 50-star Rainmatter warm-intro trigger. Star-spike target: 25-60 realistic / 50-150 optimistic / 1-5 pessimistic. | (same) | (same) | (same) | (same) |
| What's the og-image production state? | `.research/audits/2026-05-11/active-docs-verification-2026-05-11.md` §1 | 2026-05-11 | EMPIRICAL | `curl -sIo /dev/null -w "HTTP %{http_code}" https://kite-mcp-server.fly.dev/og-image.png` |
| **HTTP 200** (FALSIFIED earlier 404 BLOCKER claim from `final-pre-launch-verification.md` 2026-05-03). | (same) | (same) | (same) | (same) |
| Is flyctl auth working? | `.research/audits/2026-05-11/active-docs-verification-2026-05-11.md` §1 + `.research/decisions/production-master-gap-report.md` | 2026-05-11 | EMPIRICAL | `flyctl auth whoami` |
| **YES, working** (chain agent + verification dispatch both used flyctl successfully without reauth). Earlier "30-min Playwright reauth" framing in `final-pre-launch-verification.md` + `forward-tracks-strategic-review.md` is FALSIFIED. | (same) | (same) | (same) | (same) |
| What's in the 35-item pre-launch checklist? | `.research/final-pre-launch-verification.md` Phase 4 | 2026-05-03 | SUPERSEDED (verdict + 3 blockers all FALSIFIED at HEAD `91d834f`) | NARRATIVE |
| 35 items across 6 categories (code/repo, README, hosted demo flow, Show HN claims, deployment, ops). **All 3 verdict-blockers (deploy stale, og-image 404, flyctl auth) are FALSIFIED at HEAD `91d834f`.** Doc should be archived to `.research/archive/audits-completed/`. The 35-item checklist remains useful as a launch-day template. | (same) | (same) | (same) | (same) |
| What's the launch-blockers-apr18 list? | `memory/kite-launch-blockers-apr18.md` | 2026-04-18 | SUPERSEDED (most fixed; widget compat matrix still useful reference) | external |
| Critical: hundreds of build artifacts at root. High: missing smithery.yaml, .env.example, SECURITY.md vuln-disclosure, root Dockerfile. Widget `ui://` compat matrix: Claude.ai/Desktop ✓, VS Code 1.95+ ✓, Goose ✓, ChatGPT Apps ⚠️ (needs `openai/outputTemplate` shim), Claude Code/Cursor/Continue/Zed/Cline/Windsurf ❌. **Most blockers fixed. Widget compat matrix still useful reference.** | (same) | (same) | (same) | (same) |
| Where are pre-drafted launch fixes (smithery.yaml, ChatGPT shim)? | `memory/kite-launch-ready-fixes.md` | 2026-04-18 | STALE-PENDING — verify post-launch state | `ls smithery.yaml mcp/ext_apps.go` |
| `smithery.yaml` content ready (runtime: container; configSchema with OAUTH_JWT_SECRET, EXTERNAL_URL, ENABLE_TRADING). ChatGPT Apps SDK shim: 2-line change in `mcp/ext_apps.go` line ~339 — add `openai/outputTemplate` alongside `ui/resourceUri`, same URI value, ~2hr work total. | (same) | (same) | (same) | (same) |

---

## §8 — Brand / Content

| Question | Answer location | Last verified | Status | Probe path |
|---|---|---|---|---|
| Why rename to Algo2Go? | `memory/kite-algo2go-rename.md` | 2026-04-17 | STALE-PENDING | external (TM database) |
| Zerodha owns "Kite" TM Class 36 + 42; we're unambiguously infringing once revenue appears. Algo2Go: domain available, TM available (Class 36/42), GitHub user/org available, npm/PyPI available. Backup name: **Tradarc** (coined wordmark, strongest as non-descriptive). **Note**: `algo2go-reservation-runbook.md` 2026-05-03 found `tradarc.com` IS REGISTERED to Server Plan Srl since 2001-05-04 — backup not clean. | (same) | (same) | (same) | (same) |
| Is `tradarc.com` clean as a backup name? | `.research/algo2go-reservation-runbook.md` §"CRITICAL CORRECTION" + `.research/STATE.md` §8.4 | 2026-05-03 | STALE-PENDING-but-empirically-strong | `curl https://rdap.verisign.com/com/v1/domain/tradarc.com` |
| **NO** — registered to Server Plan Srl since 2001-05-04. Expired 2026-05-04 BUT most domains auto-renew. Don't gamble. If user wants real backup name, fresh research needed. (Memory `kite-algo2go-rename.md` 2026-04-17 claim is STALE.) | (same) | (same) | (same) | (same) |
| What's the dashboard design vision? | `memory/kite-dashboard-design.md` | 2026-04-04 | STALE-PENDING | NARRATIVE |
| Observability layer for AI-assisted trading. NOT a trading terminal (Kite does that), NOT a chat interface (Claude does that). Flight recorder. Unique value: AI activity audit trail + alert lifecycle + tool usage analytics + cross-session history + multi-user overview + credential mgmt. Auth: Callback Session Establishment pattern (cookie set during MCP OAuth callback) deployed at `b550b70`. | (same) | (same) | (same) | (same) |
| What's the Claude Skills wrapper? | `memory/kite-skills-wrapper.md` | 2026-04-17 | STALE-PENDING | `ls D:/Sundeep/projects/kite-mcp-server/skills/` |
| Commit `60e552c`. `skills/` folder with 8 SKILL.md files: morning brief, trade check, EOD review, options analysis, paper-trade onboarding, portfolio diagnostic, tax-loss harvesting, setup+IP whitelist. Reuses `~/.claude/plugins/local/kite-trading/`. Dual-publish: plugin (slash commands) + skills folder (drop into user config). | (same) | (same) | (same) | (same) |
| Where's the README hero claim integrity table? | `.research/audits/2026-05-11/active-docs-verification-2026-05-11.md` §11 + `.research/final-pre-launch-verification.md` Phase 2 | 2026-05-11 | EMPIRICAL | `head README.md` |
| **README has intra-doc inconsistency**: line 3 + line 22 say "11 pre-trade checks"; line 82 says "9 safety checks". Same file. Fix: pick ONE framing, apply consistently. | (same) | (same) | (same) | (same) |
| Where are the show-hn body + replies? | `docs/show-hn-post.md` | unverified-after-edit | STALE-PENDING (numbers may need refresh) | `wc -l docs/show-hn-post.md` |
| 3 title options + 500-word body + 13 prepared replies. Numbers (110+ tools, 11 RiskGuard, ~9k tests) need cross-check vs current README before final submit. | (same) | (same) | (same) | (same) |
| Where's the product-definition source-of-truth? | `docs/product-definition.md` | unverified | STALE-PENDING | `ls docs/product-definition.md` |
| Differentiation table at lines 73-86 (this server vs official Kite MCP vs Streak). Lifted verbatim into Day 1 + Day 5 Twitter threads. | (same) | (same) | (same) | (same) |
| Where are pre-drafted Twitter / Reddit launch posts? | `docs/twitter-launch-kit.md` + `docs/reddit-buildlog-posts.md` + `docs/launch/03-twitter-thread.md` (NOTE: `docs/launch/` may not exist anymore — verify) | unverified | STALE-PENDING | `ls docs/twitter-launch-kit.md docs/reddit-buildlog-posts.md` |
| Twitter: bio + pinned tweets + 14-day evergreen cadence. Reddit: 850-word + 420-word draft pair. **`docs/launch/` subdirectory does NOT exist anymore** per filesystem check 2026-05-11; the `03-twitter-thread.md` reference in `twitter-build-in-public-weeks-1-4.md` is stale. | (same) | (same) | (same) | (same) |
| Where's the floss-fund proposal draft? | `docs/floss-fund-proposal.md` + `docs/drafts/foss-united-grant-email.md` | unverified | STALE-PENDING | `ls docs/floss-fund-proposal.md docs/drafts/` |
| Both files exist in repo. | (same) | (same) | (same) | (same) |
| Where are pre-drafted Twitter DMs to Rainmatter contacts? | `docs/drafts/jethwani-shenoy-dms.md` + `docs/drafts/vishal-dhawan-dms.md` | unverified | STALE-PENDING | `ls docs/drafts/` |
| Both DM drafts exist in repo. Use after FLOSS/fund submission + ≥50 stars. | (same) | (same) | (same) | (same) |

---

## §9 — Session Lessons + Standing Rules

| Question | Answer location | Last verified | Status | Probe path |
|---|---|---|---|---|
| Why "compile-and-run" beats "grep-and-count"? | `.research/STATE.md` §5.6 + `.research/STATE.md` §11 + `.research/decisions/production-master-gap-report.md` §1.5 | 2026-05-11 | FRESH | NARRATIVE — methodology rule |
| `grep -rE 'mcp\.NewTool\("' mcp/` returns 130 raw matches but 19 of those are in `_test.go` fixtures, never registered in production. Correct method: compile-and-run binary, read `Tool registration complete registered=N excluded=N gated_trading=N total_available=N` startup log line. The flawed STATE.md "tools=130 in-tree" claim caused 4 consecutive synthesis dispatches to recommend "production deploy is the #1 unblock" against a non-existent gap. **Cost: ~6 hours of misdirected synthesis.** Lesson is durable — applies to ANY grep-derived metric (test counts, riskguard checks, etc.). | (same) | (same) | (same) | (same) |
| Why "WSL2 mandatory for go test/build"? | `memory/feedback_wsl_for_go_test.md` + `memory/MEMORY.md` line 24 | 2026-05-04 | FRESH-NARRATIVE | external (WSL2 vs Windows-native test results) |
| Windows-native is SAC-flaky (50-70% failure rate); WSL2 is reliable. Every brief that runs `go test` MUST direct the agent to WSL2. Never fall back to Windows-native; defer instead. | (same) | (same) | (same) | (same) |
| Why "no git stash anywhere"? | `memory/feedback_no_stash_anywhere.md` + `memory/MEMORY.md` line 17 | 2026-04 | FRESH-NARRATIVE | NARRATIVE |
| WSL2 verification mirror, source-of-truth tree, any clone — stash is forbidden everywhere. Functional risk identical regardless of which working tree. Use worktrees per agent for isolation when 3+ concurrent agents. | (same) | (same) | (same) | (same) |
| What's the team-agent commit protocol? | `memory/user_team_commit_protocol.md` + `memory/MEMORY.md` line 20 | 2026-04 | FRESH-NARRATIVE | NARRATIVE |
| For team-agent sessions on a SHARED repo: use `git commit -o -- <paths>` + plain merge (NEVER `git add -A`, NEVER `git pull --rebase`). For scale / safety-first: per-teammate git worktrees via `scripts/agent-worktree-init.sh`. | (same) | (same) | (same) | (same) |
| When do research agents hit diminishing returns? | `memory/feedback_research_diminishing_returns.md` + `memory/MEMORY.md` reference | 2026-04-17 | FRESH-NARRATIVE | NARRATIVE |
| ~10-agent mark on a given question. Public-internet research hits ceiling for niche topics (SEBI, Indian fintech). After ~10 research agents, shift to execution. Adversarial / alternative-framing extracts more value than "go deep on X". Exception: single facts that block ₹1L+ decisions. | (same) | (same) | (same) | (same) |
| Why "main agent is orchestrator only"? | `memory/user_agent_orchestration_rule.md` + `memory/MEMORY.md` line 5 | 2026-04 | FRESH-NARRATIVE | NARRATIVE |
| All research and concrete execution work goes through sub-agents; main session dispatches, synthesizes, tracks state. Exception: trivial orientation reads + single-line health checks. | (same) | (same) | (same) | (same) |
| Why "reuse research agents for execution via SendMessage"? | `memory/user_agent_reuse_for_execution.md` + `memory/MEMORY.md` line 6 | 2026-04 | FRESH-NARRATIVE | NARRATIVE |
| When research agent has found actionable work, ping back via SendMessage to execute rather than spawning fresh execution agent. Preserves researched state; saves orchestrator context. | (same) | (same) | (same) | (same) |
| Why "default to team agents for 3+ concurrent agents"? | `memory/user_team_agents_default.md` + `memory/MEMORY.md` line 19 | 2026-04 | FRESH-NARRATIVE | NARRATIVE |
| Set up Claude Code team config at session start (not mid-flight) when 3+ agents work on shared codebase. Ad-hoc `Agent()` + `SendMessage` produces concurrent-edit friction. | (same) | (same) | (same) | (same) |
| Why "trust empirical over research scoping"? | `memory/feedback_research_vs_empirical_grounding.md` + `memory/MEMORY.md` line 23 | 2026-04 | FRESH-NARRATIVE | NARRATIVE |
| When research agent's pattern-survey says "easy fix" and executor's empirical code-read flags structural blockers, the executor wins. Dispatch executor to verify dependency graph BEFORE committing to research-recommended cleanups <100 LOC. | (same) | (same) | (same) | (same) |
| Why "decoupling investments — agent-concurrency denominator, not user-MRR"? | `memory/feedback_decoupling_denominator.md` + `memory/MEMORY.md` line 22 | 2026-04 | FRESH-NARRATIVE | NARRATIVE |
| When analyzing architectural decoupling patterns (DI containers, logger interfaces, middleware split, full ES), evaluate ROI against multi-agent parallel-dev velocity, NOT user-revenue. Drop "ceremony"/"premature" prejudging labels; state preconditions explicitly. | (same) | (same) | (same) | (same) |
| What's the cheapest compliance action? | `memory/feedback_cheapest_compliance_action.md` + `memory/kite-landmines.md` "Bottom line" | 2026-04-17 | STALE-PENDING-but-durable-recommendation | NARRATIVE |
| Email `kiteconnect@zerodha.com` with 3 questions before any monetization. ₹0 cost. Establishes paper trail. Flips legal posture from "unauthorized operator" to "in-process compliance review". Pre-drafted at `docs/drafts/zerodha-compliance-email.md`. | (same) | (same) | (same) | (same) |
| Why "no Foundation email in product work"? | `memory/user_email_rule.md` + `memory/MEMORY.md` line 4 | standing | FRESH-NARRATIVE | NARRATIVE |
| `g.karthick.renusharmafoundation@gmail.com` is Foundation-context only; must NOT appear in any product communication, signature, config, or draft. | (same) | (same) | (same) | (same) |

---

## §10 — MCP Ecosystem (registry, widgets, callbacks, skills)

| Question | Answer location | Last verified | Status | Probe path |
|---|---|---|---|---|
| Which MCP clients support `ui://` widgets? | `memory/kite-launch-blockers-apr18.md` §"Widget `ui://` compatibility matrix" + `memory/kite-widget-capability-detection.md` | 2026-04-18 | STALE-PENDING | empirical (test on each client) |
| Full: Claude.ai web, Claude Desktop, VS Code Copilot 1.95+, Goose. Partial: ChatGPT (needs `openai/outputTemplate` shim — see launch-ready-fixes). None: Claude Code (terminal), Cursor, Continue, Zed, Cline, RooCode, Windsurf, 5ire. **`ui://` is NOT in core MCP spec** — Anthropic-originated extension. PR `modelcontextprotocol/specification#518` (UI Resources, Nov 2025) still draft. Capability negotiated via `initialize.capabilities.extensions["io.modelcontextprotocol/ui"]`. **Strip widget metadata from non-widget clients** (`mcp/ext_apps.go` `stripUIResourceURIFromTools`) shipped at `ac18858`. | (same) | (same) | (same) | (same) |
| What MCP servers are configured user-scope? | `memory/mcp-servers.md` | 2026-03 | STALE-PENDING | `cat ~/.claude.json` |
| User-scope (`~/.claude.json`): memory, kokoro-tts, ralph-loop, gmail, workspace, gcloud, cclsp, tavily, gemini-cli, gemini-api. **gemini-cli uses Google Code Assist** (1000 req/day, all models). **gemini-api uses API key only** (250/day Flash only, Pro blocked). | (same) | (same) | (same) | (same) |
| Where's the kite-fly MCP wired? | `memory/MEMORY.md` line ~70 (kite-mcp-server section) | 2026-04 | STALE-PENDING | `cat ~/.claude.json | jq '.mcpServers."kite-fly"'` |
| `D:\Sundeep\projects\kite-mcp-server\run-server.cmd` (PowerShell Start-Process to detach). Works on Claude Code (`kite-fly` MCP), Desktop Chat, Cowork (via Fly.io). `claude mcp add` bash `/c` expansion bug — always fix `C:/` → `/c` in `~/.claude.json`. mcp-remote cache at `~/.mcp-auth/mcp-remote-{version}/`. | (same) | (same) | (same) | (same) |
| What admin MCP tools exist? | `memory/kite-admin-tools-2026-04.md` | 2026-04 | STALE-PENDING | `grep -r "admin_get_user_baseline\|admin_stats_cache_info\|admin_list_anomaly_flags\|server_version" mcp/` |
| 3 admin: `admin_get_user_baseline` (per-user μ+3σ, 30-day, threshold), `admin_stats_cache_info` (hit rate, max/current size, TTL), `admin_list_anomaly_flags` (anomaly-blocked orders, default 24h, aggregate by user). 1 utility: `server_version` (git SHA via `runtime/debug.ReadBuildInfo()` + uptime + region + env flags). | (same) | (same) | (same) | (same) |

---

## §11 — Empirical-Probe Quick Reference

For any "what's X right now?" question — these probes return load-bearing facts in <30 seconds:

| Question | Probe |
|---|---|
| Is production healthy? | `curl https://kite-mcp-server.fly.dev/healthz` |
| What's the production tool count? | (same — read `tools` field) |
| What's the master HEAD? | `cd D:/Sundeep/projects/kite-mcp-server && git log -1 --format="%h %s"` |
| How many algo2go modules external? | `ls D:/Sundeep/projects/algo2go/ \| wc -l` |
| How many in-tree workspace members? | `cat D:/Sundeep/projects/kite-mcp-server/go.work \| grep -c "^\s*\./"` (returns 3 explicit; +1 implicit root = 4) |
| Is og-image deployed? | `curl -sIo /dev/null -w "HTTP %{http_code}" https://kite-mcp-server.fly.dev/og-image.png` |
| Is algo2go GitHub org claimed? | `curl https://api.github.com/orgs/algo2go` (200 = claimed; 404 = available) |
| Is algo2go.com domain available? | `curl https://rdap.verisign.com/com/v1/domain/algo2go.com` (404 = available) |
| Does cmd/dr-decrypt-probe exist? | `ls D:/Sundeep/projects/kite-mcp-server/cmd/dr-decrypt-probe 2>&1` |
| Is flyctl auth working? | `flyctl auth whoami` |
| What's deployed on Fly.io? | `flyctl status -a kite-mcp-server` (machine version + region + image hash) |
| What's in fly.toml? | `cat D:/Sundeep/projects/kite-mcp-server/fly.toml \| grep -E "ENABLE_TRADING\|primary_region\|min_machines"` |
| What's the actual tool count from the binary? | `wsl bash -c "cd /mnt/d/Sundeep/projects/kite-mcp-server && go build -o /tmp/k . && OAUTH_JWT_SECRET=xxx... /tmp/k 2>&1 \| grep total_available"` |
| What does the dr-drill workflow do? | `cat D:/Sundeep/projects/kite-mcp-server/.github/workflows/dr-drill.yml` |
| What's the dr-drill last run state? | `gh run list --workflow dr-drill.yml -R Sundeepg98/kite-mcp-server -L 1` |
| How many RiskGuard reasons? | `grep -E "RejectionReason\s*=" D:/Sundeep/projects/algo2go/kite-mcp-riskguard/*.go \| wc -l` |
| MCP Registry entry status? | `curl https://registry.modelcontextprotocol.io/v0.1/servers/io.github.Sundeepg98/kite-mcp-server` |

---

## §12 — Gap Analysis (questions we should be able to answer but no doc covers)

These gaps surfaced during inventory. Each is a candidate for a new memory note OR a new `.research/` doc.

| Gap | Why it matters | Fix |
|---|---|---|
| **What's the OAUTH_JWT_SECRET rotation cadence and procedure?** | Mentioned in `memory/MEMORY.md` line 99 ("monthly rotation good hygiene") but no actual procedure documented. Item 2 prod-keys dr-drill assumes secret hasn't rotated; if it has, drill fails with exit-code 6. | Document procedure: how to generate new value (`openssl rand -hex 32`), how to coordinate with stored encrypted columns (re-encrypt or re-issue?), `flyctl secrets set OAUTH_JWT_SECRET=...`, how to re-run dr-drill after rotation. |
| **How many test functions does the binary actually have (compile-and-run authoritative count)?** | README claims vary (16,209 → 8,790 → ~9000 cumulative). Empirical: 4,881 in-tree + 4,089 in 28 algo2go modules = 8,970 if we sum. **No single canonical answer.** | Add `find . -name '*_test.go' -not -path './vendor/*' \| wc -l` + `grep -rE "^func Test" --include="*_test.go" . \| wc -l` to a CI workflow output that updates a README badge automatically. |
| **What's the exact procedure to provision GitHub Actions secrets for dr-drill.yml?** | `dr-drill-results-2026-05-11.md` finding (a): repo Actions secrets unset. Need: gh CLI commands to set the 6 secrets (4 R2 + 2 Telegram) idempotently. | Document: `gh secret set LITESTREAM_R2_ACCOUNT_ID --body "..."` etc. Include where to get values (Cloudflare R2 dashboard URL pattern). |
| **What's the implementation plan for `cmd/dr-decrypt-probe`?** | Referenced by `scripts/dr-drill-prod-keys.sh:147-166` but source doesn't exist. ~1-2hr Go work. Item 2 of launch playbook can't complete until this is built. | Add a stub design doc or open a GitHub issue with design + acceptance criteria. |
| **Has the smithery.yaml from `kite-launch-ready-fixes.md` actually been committed?** | Memory lists ready-to-commit content. Need `ls smithery.yaml` to verify. | Verify, then promote to memory if yes; or surface as TODO if no. |
| **What's the current Twitter follower count + GitHub star count?** | Both are launch triggers (≥50 stars for FLOSS/fund + Rainmatter). No doc tracks them. | Add a periodic probe: `gh repo view Sundeepg98/kite-mcp-server --json stargazerCount` + Twitter API or manual check. |
| **What's the funding.json status? Is it published in repo root?** | `kite-floss-fund.md` says publish funding.json in root. No verification doc. | `ls funding.json` + verify against https://floss.fund/funding-manifest/ schema. |
| **Where are the awesome-mcp-servers PRs (have we submitted)?** | `kite-awesome-mcp-listings.md` lists priority order but no submission log. | Add submission log doc tracking PR numbers + status per list. |
| **What's the current MRR (vs the ₹15-25k target)?** | `kite-mrr-reality.md` is the target; no doc tracks actual MRR. | At launch + paid users: track in a simple monthly snapshot doc. |
| **What's the Stripe / Razorpay billing integration status?** | Mentioned as "1-week effort" in `forward-tracks-strategic-review.md` Track 5.5 but no design doc. | Surface as a future research dispatch when paid-trial signals demand. |
| **What's the actual Twitter handle activity (last post date, follower count, engagement rate)?** | Identity anchor `@Sundeepg98` cited but no activity doc. | Add an empirical probe + manual periodic update. |
| **Is the Reddit `u/Sundeepg98` account created yet?** | `reddit-subreddit-specific-strategy.md` says NO as of 2026-05-02. Status today unknown. | `curl https://www.reddit.com/user/Sundeepg98/about.json` (404 = not created; 200 = created with karma data). |

---

## §13 — MEMORY.md Update Suggestions (surface only — do NOT commit yet)

The user's `MEMORY.md` line-limited index has gaps relative to the active research. Suggested additions (each <200 chars, one-line-per-topic format):

```
## Suggested additions to MEMORY.md (surfaced 2026-05-11; user to approve before adding)

# 2026-05 corpus + curation
- [2026-05-10 algo2go GitHub org CLAIMED](session_2026-05-10_path-a-complete.md) — 28 modules external; org created 2026-05-05 with 28 repos at github.com/algo2go (id 281974878); Sundeepg98 owner; Path A inauguration COMPLETE
- [2026-05-10 STATE.md canonical research index](state-md-canonical.md) — .research/STATE.md is the orchestrator's first-read; 14 active docs + 82 archived; question-keyed lookup at .research/INDEX.md
- [2026-05-11 grep-error correction](state-md-tools130-correction.md) — STATE.md `1e80930` had tools=130 grep error (counted test fixtures); patched at `bea1e11`. Methodology rule: compile-and-run > grep for any binary-state metric. Cost: ~6h misdirected synthesis.
- [2026-05-11 production = master modulo .research/-only](production-master-gap-report.md) — production at `bc5043e` matches master HEAD modulo doc-only commits; v1.3.0/tools=111 invariant verified by independent compile-and-run; "production stale" framing FALSIFIED across forward-tracks + final-pre-launch-verification.md
- [2026-05-11 R2 dr-drill state](dr-drill-results-2026-05-11.md) — backup chain healthy + salt preserved; 2 ops gaps: GitHub repo Actions secrets unset + cmd/dr-decrypt-probe source missing; both block playbook items #1+#2 until fixed
- [2026-05-11 active docs verification](active-docs-verification-2026-05-11.md) — 4 critical disagreements across 16 active docs; grep-error pattern propagated from STATE.md to forward-tracks/launch-playbooks/agent-domain-map/10000-agent — needs back-fill patches
```

Plus 4 standing rules to consider promoting to MEMORY.md User Rules section:

```
- [Compile-and-run > grep-and-count for binary-state metrics](feedback_compile_and_run_methodology.md) — grep over mixed code+test directories over-counts test fixtures; always read `total_available=N` startup log line OR `curl /healthz` to count tools/checks/etc. Pure grep is NOT authoritative.
- [Verify before recommend in synthesis docs](feedback_verify_before_synthesize.md) — when synthesis dispatch derives claims from earlier docs, re-verify load-bearing facts at HEAD. Otherwise grep-error / staleness propagates through dispatch chain (cost: ~6h misdirected synthesis observed in STATE.md tools=130 saga).
- [Date stamps required on synthesis claims](feedback_dated_synthesis.md) — every load-bearing claim in synthesis docs must cite a "Last verified" date OR be marked unverified/derived. Stale synthesis without dates cannot be re-checked efficiently.
- [Empirical-probe quick reference at .research/INDEX.md §11](feedback_empirical_probe_reference.md) — for any "what's X right now?" question, prefer the §11 single-line probes over re-deriving research. <30s answers for most production state questions.
```

---

## §14 — Orphan Docs (in archive, but referenced by hot-path)

Cross-checked active docs' references against `.research/archive/`. Findings:

| Archived doc | Referenced by (active) | Why kept | Recommendation |
|---|---|---|---|
| `archive/path-a-modules/path-a-*-pick.md` (28 files) | `memory/session_2026-05-10_path-a-complete.md` references arc-completion via filename pattern | Module-promotion mechanics for git-archaeology; Path A pattern is reusable for future similar work | KEEP in archive; no action needed |
| `archive/audits-completed/path-to-100*.md` | `memory/team-scaling-cost-benefit-per-axis.md` cites architecture 95.69 ceiling from these | Anchor doc for axis-ceiling calibration | KEEP in archive |
| `archive/tier-anchor-design/multi-repo-execute-or-defer.md` | `.research/forward-tracks-strategic-review.md` cites multi-repo decision context | Path A motivation context | KEEP in archive |
| `archive/audits-completed/_extracted-ux-audit.md` | `memory/team-scaling-cost-benefit-per-axis.md` cites UX 72→84 | Hire-trigger calibration anchor | KEEP in archive |
| `archive/session-scratch/observation-gate-analysis.md` | (not currently referenced from active docs) | Empirical falsification of 24h observation gate | KEEP — useful for future "why did we stop doing X?" questions |
| `archive/audits-completed/path-to-100-final.md` | `memory/team-scaling-cost-benefit-per-axis.md` cites scorecard | Hire-trigger anchor | KEEP |

**No orphan-with-broken-reference findings.** All archived docs that are referenced from hot-path active docs are findable via the archive index in `.research/STATE.md` §7.

---

## §15 — Maintenance Protocol for INDEX.md

This doc, like STATE.md, decays. To keep it useful:

### When to update INDEX.md

1. **A new question-class emerges** (a question we should be able to answer that has no row): add row + cite source.
2. **A doc gets archived**: update `Answer location` to `archive/<topic>/<file>.md` so the lookup still works.
3. **A claim's status changes** (FRESH → STALE-PENDING after 30d, or SUPERSEDED when patched): update `Last verified` + `Status` columns.
4. **An empirical probe path changes** (e.g., flyctl subcommand renamed): update `Probe path` column.

### When NOT to update INDEX.md

- Don't update on every commit; weekly cadence during pre-launch is fine.
- Don't add narrative-only rows that won't help future synthesis.
- Don't duplicate STATE.md content; INDEX.md is the lookup, STATE.md is the source-of-truth narrative.

### Quick-add template

```
| New question being asked? | `path/to/canonical/file.md` §section | YYYY-MM-DD | FRESH | `probe command` |
| Answer summary in next row (or inline if short). | (same) | (same) | (same) | (same) |
```

---

## §16 — Source Verification (this doc)

| Probe | Result | Tool used |
|---|---|---|
| `git pull --ff-only origin master` | up-to-date at `91d834f` | git |
| `ls .research/*.md` | 20 active md files (16 + 4 today's verifications/state-v2/diff/dr-drill) | ls |
| `ls .research/archive/<5 subdirs>/*.md` | 30 + 22 + 20 + 4 + 6 = 82 archived | ls |
| `ls C:/Users/Dell/.claude/projects/D--Sundeep-projects/memory/*.md` | 75 files (much more than dispatch said ~50) | ls |
| `ls D:/Sundeep/projects/kite-mcp-server/*.md` | 12 root-level (ARCHITECTURE, CHANGELOG, CONTRIBUTING, COVERAGE, PRIVACY, README, SECURITY, SECURITY_AUDIT_FINDINGS, SECURITY_AUDIT_REPORT, SECURITY_PENTEST_RESULTS, TERMS, THREAT_MODEL) | ls |
| `ls D:/Sundeep/projects/kite-mcp-server/docs/` | 94 entries (88 .md + drafts/, evidence/, blog/, adr/, superpowers/) | ls |
| `ls D:/Sundeep/projects/.claude/CLAUDE.md` | 1 file (gh CLI rules) | ls |
| `ls D:/Sundeep/projects/kite-mcp-server/.claude/CLAUDE.md` | 1 file (TDD/architecture/middleware-chain rules) | ls |
| `curl https://kite-mcp-server.fly.dev/healthz` | `tools=111 version=v1.3.0 uptime=2h34m25s` (today) | curl |
| `curl -sIo /dev/null -w "HTTP %{http_code}" /og-image.png` | HTTP 200 | curl |
| `WebFetch rdap.verisign.com/com/v1/domain/algo2go.com` | HTTP 404 (still available) | WebFetch |
| `WebFetch api.github.com/orgs/algo2go` | HTTP 200, created 2026-05-05, 28 repos (CLAIMED) | WebFetch |

**Verification status of the INDEX itself**: each row's "Last verified" + "Status" columns are derived from the underlying doc's verification or empirical-probe date. INDEX.md inherits the staleness of its sources.

**Total questions indexed**: ~120 across §2-§10 (financial, regulatory, security, competition, technical, launch, brand, lessons, MCP ecosystem) + §11 (16 quick probes) + §12 (12 gap rows) + §13 (10 MEMORY.md suggestions) + §14 (6 orphan checks).

**Methodology rule applied throughout**: compile-and-run authoritative for tool counts (per STATE.md §11 lesson). Pure grep flagged as over-counting. Cross-references re-verified against current filesystem state.
