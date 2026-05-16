# GitHub Secure Open Source Fund — Application Draft

**Project:** `kite-mcp-server` — Self-hosted Model Context Protocol server for Zerodha Kite Connect (Indian retail brokerage).
**Repository:** `https://github.com/Sundeepg98/kite-mcp-server`
**Deployment:** `https://kite-mcp-server.fly.dev`
**License:** MIT
**Maintainer:** Sundeep Govarthinam (`@Sundeepg98`), Bengaluru, India.
**Contact:** `g.karthick@gmail.com`
**Draft status:** Not yet submitted (task #327).
**Eligibility note:** Application form at `https://docs.google.com/forms/d/e/1FAIpQLScDBalom0XhmJrvyI3kwD7dZ-dD4_uhmLNysVXtA8fH_WUKoA/viewform`. Rolling basis, considered for all 2025 program sessions. Single application = considered for all upcoming sessions.

---

## 1. Project tagline

A production MCP server that gives LLM clients (Claude, ChatGPT, Cursor) safe access to a regulated Indian retail-broker API. **Real money flows through 111 tools — security is not optional infrastructure, it's the product surface itself.**

## 2. Why security-focused

`kite-mcp-server` sits at an unusually consequential intersection:

- **Real money handling.** Production tools place orders against live Indian retail-brokerage accounts via Zerodha Kite Connect. A single prompt-injection failure or auth bypass converts directly into lost funds for end users.
- **Multi-tenant OAuth.** The hosted instance at `kite-mcp-server.fly.dev` proxies OAuth 2.1 + PKCE flows for arbitrary users, each bringing their own ₹500/month Kite developer-app credentials. Per-user token isolation + credential encryption are load-bearing.
- **Direct-execution AI agent surface.** LLMs are not deterministic. Tools that can trade have to be designed with the assumption that the LLM will, at some point, do the wrong thing. Riskguard chains + elicitation + audit trails exist to make those failures bounded and forensically reconstructable.
- **Regulated jurisdiction (SEBI India).** April 2026 algo-trading mandate requires whitelisted static egress IPs for any order placement from non-end-user infrastructure. Compliance posture must be baked in, not bolted on.

This is not "open-source project that happens to handle credentials." This is open-source infrastructure where security failures compound into financial harm to retail users — which is exactly the impact the GitHub Secure OSS Fund is designed to address.

## 3. What we've shipped (security-wise) — honest state

### 3.1 Formal audit (2026-02-24)

Conducted a 27-pass manual security audit. Catalogued **181 findings** across all 47 Go source files (now 437 test files + ~9,000 tests across 32 algo2go modules after subsequent decomposition).

**Honest tally:**

| Severity | Count | Fixed | Open |
|---|---|---|---|
| HIGH | 6 | **6 (100%)** | 0 |
| MEDIUM | 42 | 16 | 26 |
| LOW | 110 | 47 | 63 |
| INFO | 23 | 5 | 18 |
| **Total** | **181** | **74 (41%)** | **107 (59%)** |

(Source: `SECURITY_AUDIT_FINDINGS.md` in repo, verified 2026-05-16.)

**Why this state is honest, not aspirational:** all 6 HIGH-severity findings (SSE auth bypass, access-token logging, redirect URI scheme bypass, missing read-header timeout, shutdown-order issue, credential IDOR) are FIXED. The 107 open findings are predominantly LOW + INFO — error-return ignores, missing `Strict-Transport-Security` reasonsings, defense-in-depth opportunities, etc. None are exploitable on their own; many are documented as "accepted risk" with rationale. Public tracking at `SECURITY_AUDIT_FINDINGS.md`.

### 3.2 Encryption-at-rest

Per-user Kite developer-app credentials + access tokens + OAuth client registrations stored in SQLite, encrypted with **AES-256-GCM** keyed via **HKDF** from a single `OAUTH_JWT_SECRET` operator secret. Four independently-derived sub-keys (`hkdf-info`-segmented) cover token-store / credential-store / oauth-client / pii fields. Verified end-to-end via the `cmd/dr-decrypt-probe` binary (closes the prior-blind-spot where disaster-recovery drills passed but encrypted columns were never decryption-tested).

### 3.3 Defense-in-depth at the HTTP boundary

Per-IP rate limits on every authenticated surface:
- `/auth/*` endpoints: 2 req/sec
- `/oauth/token` (PKCE exchange): 5 req/sec
- `/mcp` (tool dispatch): 20 req/sec

CSP + HSTS + X-Frame-Options + X-Content-Type-Options headers enforced. CSRF tokens on dashboard mutations. Per-user OAuth: zero global broker credentials on the hosted instance — compromise of the operator doesn't compromise users.

### 3.4 Path 2 compliance gate

Hosted instance runs with `ENABLE_TRADING=false`. The 18 order-placement tools (place_order, modify_order, GTT variants) are GATED OFF on the public Fly.io endpoint pursuant to NSE/INVG/69255 Annexure I §2.8. Only self-hosted instances under the user's own SEBI whitelist run order-placement code in production. The boundary is enforced at server startup (registered=93 + gated=18 = 111 total), not at request time — a tool that's gated off cannot be invoked at all.

### 3.5 Riskguard pre-trade safety chain

**11 checks** run before any order reaches Kite, in this exact order: kill-switch · ₹50k order-value cap · qty limit · 20 orders/day · rate-limit · per-second rate · 30s duplicate · ₹2L daily notional · idempotency dedup · anomaly μ+3σ · off-hours block. Plus circuit-breaker + global-freeze layers. Independent of the LLM's reasoning — if the LLM gets prompt-injected into trying to liquidate a portfolio, the riskguard chain still trips. Implemented at `algo2go/kite-mcp-riskguard` (separate Go module, reusable for any broker integration).

### 3.6 Hash-chained audit trail

Every MCP tool invocation persists a row to SQLite with `SHA-256(prev_row || this_row)` chaining. Tamper-evident: modifying any historical row breaks every subsequent hash. Replay verifies integrity in O(n). 90-day retention. CSV + JSON export from `/dashboard/activity`. The LLM cannot lie about what it did.

### 3.7 Elicitation on destructive tools

8 tools are marked `destructiveHint: true` per the MCP spec — `place_order`, `modify_order`, `cancel_order`, `place_gtt`, `modify_gtt`, `delete_gtt`, `create_alert`, `delete_alert`. Compliant MCP clients (Claude Desktop, claude.ai web, Cursor) render a user-confirm dialog before the tool fires. Fails open for older clients — but riskguard still runs regardless.

### 3.8 Maintenance OS (development-time hooks)

A set of **8 PreToolUse hooks** runs against every code-modification action during development, preventing the most common security regressions before they reach the repo:

- `pre-write-secret-scan.py` — fail-closed on any `Write|Edit|MultiEdit` containing patterns matching `KITE_API_KEY=`, `OAUTH_JWT_SECRET=`, AWS-style access keys, etc. Allow-list via `<!-- secret-scan-allow: <reason> -->` comment for legitimate documentation citations.
- `pre-write-frontmatter-validator.py` — enforces `as-of:` + `re-verify-by:` on research docs.
- `pre-write-cross-ref-validator.py` — prevents broken cross-refs across renamed/archived docs.
- `pre-write-numeric-consistency.py` — catches numeric drift between docs claiming the same metric.
- `session-start-freshness-check.py` — surfaces stale claims at session start.
- `post-tool-grep-trap.py` — flags fragile shell-history-leak patterns.
- `post-tool-memory-md-regen.py` — keeps user-scope memory canonical.
- `audit-auto-archive.py` — periodic archival.

(All in `~/.claude/hooks/validators/`, applied via Claude Code's hook system. Pattern documented at `.research/architectural-patterns-record.md`.)

## 4. What the grant would fund

The Secure OSS Fund grant ($10k disbursed as $6k on-program + $2k at 6mo + $2k at 12mo) maps cleanly to four concrete security investments we have queued but cannot self-fund:

### 4.1 Independent external security audit ($5,000)

The 2026-02 audit was self-conducted (27-pass, 181 findings). An independent external auditor would (a) re-verify our resolution status on the 74 FIXED findings, (b) re-rate the 107 OPEN findings against current code, (c) probe areas the self-audit may have missed — most importantly: prompt-injection attack surface on the LLM-tool boundary, where Indian retail-trading context creates unique threat models that generic SaaS audits don't cover. Target firm: CERT-In empanelled VAPT provider (lower cost) or a fintech-specialist firm (higher cost, better signal).

### 4.2 CERT-In VAPT audit ($3,000)

Cert-In (Indian Computer Emergency Response Team) Vulnerability Assessment and Penetration Test is the Indian-jurisdiction requirement for processing financial data. Currently informal. The grant funds the formal certification, which is a prerequisite for processing payments or qualifying for Indian fintech accelerators (Rainmatter, FOSS United, etc.).

### 4.3 Prompt-injection chaos engineering ($1,500)

Adversarial-prompt test corpus. Build a battery of 50+ documented prompt-injection scenarios against every destructive tool. Continuous evaluation in CI. Pattern modeled on Anthropic's published red-team methodology + Stripe-style chaos-engineering for failure-mode discovery. Outputs: published red-team report + integration tests that fail-closed on regressions.

### 4.4 Security incident response runbook + on-call rotation ($500)

For a sole maintainer, "incident response" is currently me reading my email. Grant funds documented runbook, public security@ contact, GPG key for encrypted vulnerability disclosure, and a 90-day signed-commitment to response SLAs.

### 4.5 Program participation time-cost (in-kind)

15 hours over 3 weeks + 2.5 hours each at 6mo + 12mo check-ins = 20 hours total. This is in-kind contribution to the program, not grant-funded — but represents real opportunity cost for a sole maintainer (estimated ₹15k of focused-time at ₹750/hr equivalent contractor rate).

**Total grant allocation: $10,000 fully accounted.**

## 5. Maintainer commitment

- **Time:** I will commit the required 15 hours over 3 weeks + 5 hours of check-ins.
- **Continuity:** kite-mcp-server is my primary project. I run my own money on this daily — incentive is aligned with security excellence by direct exposure to failure modes.
- **Public maintenance:** all security work happens in the public repo. Audit reports, threat models, riskguard tests, hook implementations — all MIT-licensed.
- **Disclosure posture:** I will publish any CVE issued during the program. The 107 open findings remain publicly tracked at `SECURITY_AUDIT_FINDINGS.md` regardless of grant outcome.
- **No vendor lock-in:** the project remains MIT. SQLite + Litestream + Cloudflare R2 give point-in-time recovery and a $0/month backup story. If I disappear, the binary remains self-recoverable and the entire stack is reproducible by anyone with the repo.

## 6. Honesty markers

- **Stars at application time: 0** (verified via `gh api`). This is a pre-launch project. Show HN submission planned for Tue 2026-05-26.
- **107 of 181 audit findings remain OPEN.** All 6 HIGH are FIXED; the open ones are predominantly LOW + INFO. We do not claim "fully resolved."
- **No vulnerabilities disclosed by external parties yet** because no public security@ address exists yet. The grant explicitly funds creating one.
- **Hosted instance has `ENABLE_TRADING=false`.** Order placement is local-only on the hosted endpoint. We do not claim end-to-end production trading hardness — we claim end-to-end *read-only-and-compliance-gate* hardness, with self-hosters running the trading code under their own SEBI whitelist.
- **Single-broker (Zerodha) for now.** Upstox/Dhan/Angel One adapters are planned. The security claims here apply to the Zerodha Kite Connect integration specifically.
- **Sole maintainer.** No team. The grant's "max 3 people" cap is comfortable; I am 1 of 1.
- **No prior grant from this fund or similar.** This is a first-time application. FLOSS/fund + FOSS United applications are also queued; if multiple fund, I will disclose all sources publicly.
- **Indian jurisdiction.** GitHub Sponsors supports India; eligibility confirmed.

## 7. Project metrics (verified 2026-05-16)

| Metric | Value | Source |
|---|---|---|
| Production version | v1.3.0 | `curl /healthz` |
| Consecutive deploys with tools=111 invariant | 67 | deploy chain |
| Production uptime | 138h+ continuous | `/healthz` |
| MCP tools registered | 111 (93 active + 18 gated_trading) | startup log |
| RiskGuard checks | 11 | `algo2go/kite-mcp-riskguard/guard.go` |
| Tests | ~9,000 across 437 test files | README L25 |
| External Go modules (algo2go org) | 32 | `ls D:/Sundeep/projects/algo2go/` |
| Source files (algo2go ecosystem) | ~250 non-test .go files | per-module `find` |
| LOC decomposed into reusable modules | ~49,400 (Sprint 0 + Phase 0/1/2) | session memory |
| MCP Registry entry | `io.github.Sundeepg98/kite-mcp-server@1.2.0` active since 2026-04-19 | `registry.modelcontextprotocol.io/v0/servers?search=kite` |
| Security findings catalogued | 181 (6 HIGH all FIXED; 74 of 181 total FIXED) | `SECURITY_AUDIT_FINDINGS.md` |
| Maintenance OS hooks | 8 (secret-scan, frontmatter, cross-ref, numeric-consistency, freshness, grep-trap, memory-regen, auto-archive) | `~/.claude/hooks/validators/` |

## 8. Why kite-mcp-server fits the GitHub Secure OSS Fund thesis

The fund's stated thesis (per `github.blog/news-insights/company-news/announcing-github-secure-open-source-fund/`): support critical OSS infrastructure where security failures have outsize downstream impact. Indian retail brokerage automation via LLM agents is precisely that intersection — every user we serve handles their own money, every order we route is real, every credential we cache is recoverable real-world value to an attacker.

The fund's program structure (3-week security education + community + tooling access) maps cleanly to where we have gaps: external review, formal CERT-In certification, structured prompt-injection testing, and incident response. The financial component ($10k) is exactly the order-of-magnitude needed to fund those four investments. The check-in cadence (6mo + 12mo) is a useful accountability mechanism.

## 9. References + cross-links

- **Codebase**: `https://github.com/Sundeepg98/kite-mcp-server` (MIT, public master)
- **Hosted instance**: `https://kite-mcp-server.fly.dev` (read-only demo; OAuth gates)
- **MCP Registry entry**: `https://registry.modelcontextprotocol.io/v0/servers?search=kite`
- **Security docs (in repo)**:
  - `SECURITY.md` — public disclosure policy (vulnerabilities@ address — currently maintainer email; grant funds upgrade to dedicated security@)
  - `SECURITY_AUDIT_REPORT.md` — 27-pass manual audit narrative
  - `SECURITY_AUDIT_FINDINGS.md` — line-by-line findings + status
  - `SECURITY_PENTEST_RESULTS.md` — penetration-test results
  - `THREAT_MODEL.md` — adversary classes + assumptions
- **Riskguard module (separate algo2go repo)**: `https://github.com/algo2go/kite-mcp-riskguard` (MIT, reusable)
- **Audit module**: `https://github.com/algo2go/kite-mcp-audit` (hash-chained audit trail, reusable)
- **MCP Apps widgets** (rendered inline in chat for portfolio/orders/alerts): part of `kite-mcp-server`
- **Companion proposal**: `docs/floss-fund-proposal.md` — concurrent FLOSS/fund application; same security posture, different funding angle

## 10. Open questions (for user, pre-submit)

1. **Eligibility region**: India is listed under GitHub Sponsors supported regions, but worth re-verifying current 2026 list at `https://docs.github.com/en/sponsors/getting-started-with-github-sponsors/about-github-sponsors`. If India eligibility has changed, an EU/US co-applicant might be needed — defers to user.
2. **Time-window**: 3-week program requires focused 15h. If user has a competing time-bound commitment in the next quarter (e.g. employment relocation), submit timing should align with available 3-week window.
3. **Security@ contact**: form will likely ask for a security disclosure address. Currently `g.karthick@gmail.com` works but a dedicated `security@kite-mcp-server.fly.dev` or `security+kite@<personal-domain>` is more credible. User decision: create now or defer to post-grant.
4. **Co-maintainers**: form allows up to 3. Default: solo (Sundeep only). If user wants to add co-maintainers, names + GitHub handles + commitment confirmations needed.
5. **Public disclosure timing**: form will likely ask if the project can be listed publicly as a fund participant. Default yes; user decision if conflict with launch timing.
6. **Submission timing relative to Show HN**: Show HN is targeted Tue 2026-05-26. The grant application is rolling and reviewed across multiple program sessions. Submitting before vs. after Show HN doesn't materially affect grant outcome, but Show HN traffic could populate "community adoption" claims for the application. **Recommendation: submit AFTER Show HN to capture any star/engagement signal.**

---

## Appendix A — Compressed application body (if form has a 500-word limit)

> kite-mcp-server is a production Model Context Protocol server that bridges LLM clients to Zerodha Kite Connect — India's largest retail-broker REST API. 111 tools, 11-check pre-trade safety chain, hash-chained audit log, per-user OAuth 2.1, AES-256-GCM encryption at rest, ~9,000 tests across 437 test files, 32 reusable Go modules at the `algo2go` org. Production v1.3.0 with 138+ hours continuous uptime and 67 consecutive deploys with tool-count invariant.
>
> Security matters here because real money flows through every order tool. A 27-pass internal audit catalogued 181 findings (all 6 HIGH severity FIXED; 74 of 181 total FIXED; 107 OPEN predominantly LOW + INFO with documented rationale). Defense-in-depth covers per-IP rate limiting (auth 2/sec, token 5/sec, MCP 20/sec), SEBI April 2026 algo-mandate compliance gate (`ENABLE_TRADING=false` on hosted instance), elicitation on 8 destructive tools, and 8 development-time PreToolUse hooks preventing secret leaks before commit.
>
> The grant would fund: independent external audit ($5k), formal CERT-In VAPT certification ($3k), prompt-injection chaos engineering corpus ($1.5k), security incident response setup ($500). Total $10k, fully accounted. The 15-hour program commitment is feasible — kite-mcp-server is my primary project; I run my own money through it daily, so the incentive alignment is intrinsic.
>
> Honesty markers: 0 stars at application time (pre-Show-HN), 107 audit findings remain OPEN with public tracking at `SECURITY_AUDIT_FINDINGS.md`, hosted instance is read-only by design with order placement on self-hosters' own SEBI whitelist, single-broker (Zerodha) for now with multi-broker adapters planned. Sole maintainer; MIT license; no prior grants from this fund.
>
> Project: `github.com/Sundeepg98/kite-mcp-server`. MCP Registry: `io.github.Sundeepg98/kite-mcp-server@1.2.0` (active since 2026-04-19). Contact: `g.karthick@gmail.com`.

---

*This document does not change code. It does not change project posture. It captures the grant-application narrative for user review pre-submission.*
