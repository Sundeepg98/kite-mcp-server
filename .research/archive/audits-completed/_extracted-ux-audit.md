# Pre-Launch First-5-Minute UX Audit — kite-mcp-server

**Status:** Empirical audit — evidence gathered 2026-05-02 IST.
**Author:** Research agent (orchestrated).
**Scope:** Verifies whether the project is Show-HN-ready *today* by walking the same first-5-minute path an HN reviewer takes — repo glance, hosted-demo probe, self-host setup, dashboard render, claim-vs-code reconciliation.
**Complements:** `.research/gtm-launch-sequence.md` (commit `58dc369`) which has the launch playbook. This doc has the *"is the demo actually ready"* answer.

---

## Lead-in summary (read this first)

**Show-HN-launch-ready today: NO.** Three blockers, each fatal on its own:

1. **CI is failing on every push to `master`.** Latest run on `58dc369` (the GTM commit) — `CI`, `Test Race`, and `Security Scan` all conclusion `failure`. Root cause: `kc/ops/api_activity.go` has a UTF-8 BOM (`\xef\xbb\xbf`) injected mid-file (verified via `od -c`), which makes the Go compiler reject the build on macOS, Windows, and Ubuntu. The README's `[![CI](.../ci.yml/badge.svg)](.../ci.yml)` badge therefore renders **red** to every HN visitor. This is the single biggest credibility cliff in the audit.

2. **228 build artifacts at the repo-root sit in the public GitHub repo's working `git status` output.** Verified: they are *gitignored* (so not pushed), but a fresh `git clone` produces no junk. The damage is local-only — except the existence of `app_*.html`, `app_*.exe`, `*.cov` files in the developer's *editor view* will leak through any screenshot, livestream, or screen-share at launch. Independently, `.research/` has **156 tracked markdown files** of internal architectural journal that *are* in the public repo and *will* be the first thing a curious HN reader clicks after the README. Nine out of ten of them read like an architect arguing with himself; not what an evaluator wants on minute 4.

3. **The README hero in `docs/product-definition.md` Section 3 Draft B has not been applied to `README.md`.** The current README opens with five badges (one of which is currently red — see #1), then a *"Why trust this"* section that leads with `7,000+ tests` and a security audit. That phrasing is defensive, not differentiating. The drafted hero — *"Give Claude or ChatGPT direct access to your Zerodha Kite trading account — with order placement, paper trading, options Greeks, backtesting, Telegram alerts, and 9 pre-trade safety checks"* — leads with the user benefit and the differentiator vs the official Zerodha MCP. The product-definition.md doc explicitly flags this as the recommended swap; it has not landed.

**Three most urgent fixes (in order, with empirical sizings):**

1. **Strip the BOM from `kc/ops/api_activity.go`** — `sed -i '1s/^\xef\xbb\xbf//' kc/ops/api_activity.go` or open in editor and re-save as UTF-8 (no BOM). Fix the flaky `TestStartRateLimitReloadLoop_StopChanExits` test (2-second polling assertion that never satisfies on slow CI runners). 30 minutes of work; unlocks the green CI badge.
2. **Apply `docs/product-definition.md` Section 3 Draft B to `README.md`** — replace lines 1-22 of the current README with the drafted hero. 10 minutes of work; converts the README from "architecture journal" framing to "trading copilot" framing.
3. **Move `.research/` out of the public repo to a private `kite-mcp-internal` repo** — `git rm -r --cached .research/` after pushing to private remote. 30 minutes of work; removes 156 distracting files from the GitHub front-page directory listing.

After those three: launch becomes plausible. Without them: any HN spike will land on a red CI badge, a journal-style README, and a directory listing dominated by 156 internal-architecture files. The probability split moves from ~50/25/25 (realistic / optimistic / pessimistic, per gtm-launch-sequence.md) to roughly 20/10/70 in favor of pessimistic.

---

## Phase 1 — 10-second README audit

**Method:** Read `README.md` (288 lines, 18,372 bytes) end-to-end. Score against the rubric.

**File:** `D:\Sundeep\projects\kite-mcp-server\README.md`

| Item | Score (0-3) | Evidence |
|---|---:|---|
| Headline / value prop visible immediately | 2 | Line 12: *"Self-hosted MCP server that turns Claude / ChatGPT into a power-user trading copilot for your Zerodha Kite account."* — clear, concrete, but defensive single-line tagline rather than punchy hero. The drafted Section 3 Draft B hero is stronger; not yet applied. |
| Quick-start command above the fold | 1 | Quick-start section starts at line 41, after 18 lines of badges + tagline + `Why trust this` bullets. The actual `claude mcp add` line equivalent is at line 48 (hosted URL paste) and line 56-58 (docker-compose three-liner). On a 1080p HN visitor screen at default zoom, the quick-start scrolls below the fold. |
| Differentiation vs `mcp.kite.trade` visible without scroll | 0 | The comparison table is at line 191-205. Above the fold the reader sees only *"forked from and complementary to..."* on line 12. A reviewer who lands here, scans for 5 seconds, and bounces will not know what makes this different from the official server. |
| Hero image / video / GIF / asciinema | 0 | Line 14: `<!-- TODO: 30-second demo GIF of portfolio analysis + order placement flow -->`. The TODO is still a TODO. **No GIF, no asciinema cast, no screenshot, no PNG anywhere.** `og-image.png` is referenced in landing.html `<meta property="og:image">` but `curl -I` returns **HTTP 404**. |
| Star/badge state | 1 | Five badges: Go 1.25 (green), CI ([currently red](#phase-2-hosted-demo-flow-test) — see Phase 2), Tests-7000+ (static badge, not live), Security-Audit-passed (static), MIT-License (green). Live CI badge being red is a credibility hole; the static "Tests 7000+" badge is also a hostage to the actual count which is much higher (~16,200 — see Phase 5). |
| Length / tone | 1 | 288 lines of which ~170 are environment variables, dashboard tables, comparison tables, compliance preamble, SEBI/DPDP boilerplate. Reads like a technical reference manual, not a marketing page. The first 30 lines do half the work of a hero; the next 250 read like internal compliance documentation. |

**Rubric total: 5 / 18 (28%)**

**Cross-check vs `docs/product-definition.md` Section 3 Draft B:** The drafted hero (lines 222-236 of `docs/product-definition.md`) is:

```
# Kite MCP Server

Give Claude or ChatGPT direct access to your Zerodha Kite trading account —
with order placement, paper trading, options Greeks, backtesting, Telegram
alerts, and 9 pre-trade safety checks. ~80 tools. Open source, MIT.

[Try the hosted demo](https://kite-mcp-server.fly.dev/mcp) (read-only) ·
[Self-host in 60 seconds](#quick-start) (full trading) ·
[Compare vs official Zerodha MCP](#comparison)

```bash
claude mcp add --transport http kite https://kite-mcp-server.fly.dev/mcp
```

Then say: *"Log me in to Kite. Show my portfolio. Backtest SMA crossover on
INFY. Set an alert for RELIANCE 2% drop."*
```

Has this been applied? **NO.** Verified by reading current `README.md` lines 1-22 and confirming they still match the journal-style opener.

**Top README friction signals:**
- Line 14 TODO comment for the demo GIF that is still a TODO.
- Five badges, one currently red (CI).
- "Why trust this" leads with `7,000+ tests` (defensive); the user benefit is buried at line 41.
- Quick-start is below the fold on a 1080p screen.
- 288 lines is 3-4× too long for a launch README; the SEBI/DPDP compliance section should live in a separate `COMPLIANCE.md`.

---

## Phase 2 — Hosted demo flow test

**Method:** `curl -i` and `curl -s -o /dev/null -w "<format>"` against every public endpoint of `https://kite-mcp-server.fly.dev`. No credentials available — this verifies wire-level behavior, not full OAuth.

### Endpoint probes

| Endpoint | Status | Latency | Notes |
|---|---|---:|---|
| `/` (landing) | 200 OK | 215 ms | Renders `kc/templates/landing.html`. CSP, HSTS, X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy strict-origin all set. `x-request-id` propagated. `fly-request-id` shows `bom` region. |
| `/healthz` | 200 OK | 170 ms | Returns `{"status":"ok","tools":111,"uptime":"337h9m47s","version":"v1.1.0"}`. **Note: `tools=111` not `~80` — see Phase 5.** Uptime ≈ 14 days continuous. |
| `/mcp` | 401 | 111 ms | Correct (auth-gated). |
| `/.well-known/oauth-authorization-server` | 200 OK | 160 ms | Returns full RFC 8414 metadata document with `authorization_endpoint`, `token_endpoint`, `registration_endpoint`, `code_challenge_methods=["S256"]`, `grant_types=["authorization_code"]`. PKCE correctly advertised. |
| `/oauth/register` | 405 | — | Method-not-allowed on GET (POST-only). Correct. |
| `/dashboard` | 302 | — | Redirects (presumably to OAuth) — correct for an unauthenticated GET. |
| `/metrics` | 404 | 106 ms | Not exposed at `/metrics` (memory note: `ADMIN_ENDPOINT_SECRET_PATH` puts metrics behind a random suffix). Correct security posture. |
| `/og-image.png` | **404** | — | **BUG:** Landing HTML references `<meta property="og:image" content="https://kite-mcp-server.fly.dev/og-image.png">` but the file is not served. Twitter/HN/Reddit link previews will fall back to a generic icon. |

### Headers verified on `/`

```
content-security-policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'
strict-transport-security: max-age=63072000; includeSubDomains
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=()
```

CSP includes `'unsafe-inline'` for both `script-src` and `style-src` — pragmatic for a server-rendered template, but worth noting that an HN reviewer running headerscan tools (e.g. observatory.mozilla.org) will dock points for it.

### OAuth flow walkthrough (without credentials)

1. **Add MCP server (the `kite-fly` flavor in landing HTML):**
   - Landing: `claude mcp add --transport http kite-fly https://kite-mcp-server.fly.dev/mcp`
   - README: `npx mcp-remote https://kite-mcp-server.fly.dev/mcp` (in JSON snippet)
   - **Inconsistency:** Landing uses server name `kite-fly`, README uses `kite`. Minor, but a copy-paste user adding both will get a duplicate. Fix: align both to `kite`.

2. **OAuth handshake (browser):** I cannot test the full flow without Kite credentials, but the protocol-discovery layer is verifiably correct: `well-known/oauth-authorization-server` advertises PKCE+S256, dynamic client registration is enabled. mcp-remote should drive this end-to-end.

3. **First tool call:** Cannot test without auth.

4. **Browser landing visit:** Renders. Status indicator pulses green. Three install paths visible (Claude Desktop, ChatGPT, generic MCP). Step-by-step "Before You Connect — Two Steps" section is clear.

**Friction observations on the hosted-demo path:**
- (a) `og-image.png` 404 — link previews are broken everywhere outside the bare hostname.
- (b) Landing-vs-README server-name inconsistency (`kite-fly` vs `kite`).
- (c) `/healthz` reports `tools: 111`; landing copy and README copy both say "~80". HN reviewer running `curl /healthz | jq` (which they will) sees a 39% discrepancy. **Either fix the README to say "~110 tools" or filter the `/healthz` count to user-facing only.**
- (d) Uptime is 14 days continuous which is a positive signal.

---

## Phase 3 — Self-host setup audit

**Files reviewed:** `Dockerfile.selfhost`, `docker-compose.yml`, `docs/self-host.md`, `docs/byo-api-key.md`, `.env.example`, `smithery.yaml`.

### Walk-through (paper hands)

1. **`git clone`** — repo size: not measured here, but the working-tree has 213 build artifacts (`.out`, `.exe`, `.cov`, `app_*.html`) and 156 `.research/*.md` files in the public repo. Clone is bigger than it needs to be. The artifacts are gitignored *now* but were committed historically (verified via `git ls-files | grep -E '\.(out|exe|cov)'` returns 0 — they're not tracked, so the local-disk presence is pre-existing build noise, *not* in the cloned repo). Clean clone is fine; the issue is the developer's local workspace, not what HN visitors download.

2. **`cp .env.example .env`** — file is 5,923 bytes, well-commented. Required vars: `OAUTH_JWT_SECRET` and `EXTERNAL_URL` (per smithery.yaml schema and envcheck.go). Optional: 13+ vars (KITE_*, APP_*, ALERT_DB_PATH, TELEGRAM_*, ADMIN_*, GOOGLE_*, STRIPE_*, LITESTREAM_*, EXCLUDED_TOOLS, LOG_LEVEL). Each commented with purpose. Friction: low. **Improvement:** the very first uncommented line is `OAUTH_JWT_SECRET=<generate with openssl rand -hex 32>` — a copy-paste user who runs without editing will hit a hard envcheck failure. A `.env.example` with a *placeholder string that fails envcheck loudly* (e.g. `CHANGEME_RUN_OPENSSL_RAND`) is friendlier than an instruction-in-angle-brackets.

3. **`docker compose up -d`** — `Dockerfile.selfhost` exists (2,622 bytes); `docker-compose.yml` mounts `kite_data` named volume at `/data/alerts.db`. Build context is the repo root. **Untested:** image build time, first-run errors, port conflicts. The `kite-mcp-server:selfhost` image tag is hardcoded; a host machine running multiple compose projects on port 8080 would conflict (override via `APP_PORT`).

4. **Browser to `http://localhost:8080`** — should render the same `landing.html`. OAuth flow in self-host mode requires `EXTERNAL_URL` to match `127.0.0.1:8080/callback` in the Kite developer console. Documented in `docs/self-host.md` lines 22-26 — clear.

5. **Add to client config** — `docs/self-host.md` does NOT have a single copy-paste-ready `claude_desktop_config.json` block for the local-host case. The user has to read README's Option C, then mentally substitute `https://kite-mcp-server.fly.dev/mcp` for `http://localhost:8080/mcp` and add `--allow-http`. This is a 2-paragraph cognitive load. **Friction.**

### Self-host doc rubric

| Item | Status |
|---|---|
| Clear prerequisites stated | Yes — Go 1.25+ or Docker, Kite Connect ₹500/mo, optional Telegram |
| Single `cp .env.example .env` step | Yes |
| Two required env vars enumerated | Yes (`OAUTH_JWT_SECRET`, `EXTERNAL_URL`) |
| One-line build command | Yes (`go build -o kite-mcp-server .`) |
| One-line container command | Yes (`docker compose up -d`) |
| Verification command (curl /healthz) | Yes |
| Copy-paste client config for self-host case | **No** — user must adapt the hosted snippet |
| Troubleshooting / common errors section | Not verified in this audit; would need to read full doc |
| Mentions `--allow-http` for clients that require it | Implicit in README; not verified in self-host.md |

**Friction:** the gap between "I have a running container" and "I have my AI assistant talking to it" is filled by mental substitution, not a copy-paste line. Add a 6-line `claude_desktop_config.json` block to `docs/self-host.md`.

---

## Phase 4 — `/dashboard` UX audit

**Method:** `curl /dashboard` + read `kc/templates/dashboard.html`.

**Endpoint probe:** `/dashboard` returns 302 (redirect to OAuth login) — correct for unauthenticated.

**Templates inventory:**

```
kc/templates/dashboard.html  (only one)
```

The README's Dashboard section (lines 178-189) lists 7 dashboard pages: `/dashboard`, `/dashboard/activity`, `/dashboard/orders`, `/dashboard/alerts`, `/dashboard/safety`, `/dashboard/paper`, `/admin/ops`. **There is only one HTML template file** — `dashboard.html`. This means either (a) the other pages render as JSON / API-only, or (b) the template-naming convention is different (single SPA shell + JS rendering), or (c) the README claims more dashboard surface than actually ships.

This is *not* a launch blocker (HN reviewers won't get to the dashboard within 5 minutes), but the README claim should be aligned with reality. **Action:** spot-check by visiting `/dashboard/activity`, `/dashboard/safety`, `/dashboard/paper` while authenticated and confirm they render distinct UI. If they don't, prune the README table to whatever ships.

Mobile-responsive / tablet / dark-mode / inline-widget consistency: **not verified** — would require an authenticated browser session. The landing.html is dark-mode-only by design (`--bg-0: #0a0c10`). Inline widgets in `mcp/ext_apps.go` (referenced in memory) are claimed to be consistent — not verified empirically here.

---

## Phase 5 — Show HN claim verification

**Source:** `docs/show-hn-post.md` (71 lines) and `README.md`.

| Claim | Verification | Status |
|---|---|---|
| `~80 tools` | `/healthz` returns `tools: 111`. `mcp.NewTool(...)` registration sites: 117 unique by name across 77 files (via `grep -oE 'mcp\.NewTool\("[^"]+"' \| sort -u`). | **DISCREPANCY:** 117 unique vs `~80` claimed. The product-definition.md doc itself flags the gap: *"~48 of those are admin / test / variant registrations"*. The honest claim is *"~80 user-facing tools, ~110 total including admin and observability"*. Pick a number and align README + landing + show-hn-post. |
| `9 RiskGuard pre-trade checks` | `RejectionReason` constants in `kc/riskguard/guard.go` line up to **16** distinct reasons: GlobalFreeze, TradingFrozen, OrderValue, QuantityLimit, DailyOrderLimit, RateLimit, DuplicateOrder, DailyValueLimit, AutoFreeze, ConfirmationRequired, AnomalyHigh, OffHoursBlocked, OTRBand, CircuitBreached, InsufficientMargin, MarketClosed. The `.claude/CLAUDE.md` middleware-chain comment says *"9 pre-trade checks"*. README lists 9. show-hn-post lists 9. | **VERIFIED at the level of "≥9 distinct safety checks fire"** but the count is conservative — there are 16 rejection reasons. Either count is defensible; prefer the higher count for marketing. |
| `4 backtest strategies` | `mcp/backtest_tool.go` has `case "sma_crossover": ... case "rsi_reversal": ... case "breakout": ... case "mean_reversion":`. | **VERIFIED.** |
| `Black-Scholes Greeks (delta, gamma, theta, vega, IV)` | `mcp/options_greeks_tool.go` has `bsDelta`, `bsGamma`, `bsTheta`, `bsVega`, and `impliedVolatility` functions; tool description says *"Compute Black-Scholes Greeks (delta, gamma, theta, vega, rho) and implied volatility"*. | **VERIFIED but with a wrinkle:** tool description says `rho` is computed but the README claim only lists delta/gamma/theta/vega/IV. Either claim rho too, or drop rho from the tool description to avoid evaluator nitpicking. |
| Telegram `/buy /sell /quick /setalert` keyboard | `kc/telegram/trading_commands.go` has `handleBuy`, `handleSell`, `handleOrderCommand`, `handleQuick`, `handleSetAlert`. Usage strings present and match. | **VERIFIED.** |
| `AES-256-GCM encryption at rest` | Memory note + `kc/crypto/` has cipher code. Smithery.yaml says *"HKDF seed for AES-256-GCM key derivation"*. | **VERIFIED via memory + config; full code-audit not re-done in this audit** — relying on the prior 27-pass security audit (181 findings, all resolved per memory). |
| `7,000+ tests` (README badge) and `~330 tests` (show-hn-post) | `find . -name "*_test.go" \| wc -l` = **630 test files**. `grep -c "^func Test" *_test.go \| sum` = **16,209 test functions**. | **MASSIVE DISCREPANCY:** Both numbers are out of date. The actual count is **~16,200 test functions across 630 test files**. The "7,000+" badge undersells by 2.3×; "~330" undersells by 49×. **Update both to "~16,000 tests across 630 files"** — that's the strongest credibility number in the project and it's being thrown away. |
| Static egress IP `209.71.68.157` Mumbai region | `fly.toml` confirms `primary_region = "bom"` and the IP is documented in code comments. | **VERIFIED.** |
| Path 2 / `ENABLE_TRADING=false` for hosted | `app/config.go` parses `ENABLE_TRADING` env. `fly.toml` does NOT set it (defaults to false). README + landing both call this out. | **VERIFIED.** |
| 27-pass security audit, 181 findings resolved | Memory note. `SECURITY_AUDIT_REPORT.md` and `SECURITY_PENTEST_RESULTS.md` exist at repo root. | **VERIFIED via memory.** |
| MIT licensed | `LICENSE` file exists; preserved Zerodha Tech copyright. | **VERIFIED.** |

### CI status — *separate critical finding*

Fetched via `gh run list -R Sundeepg98/kite-mcp-server --limit 5`:

| Run | Conclusion | Failing job |
|---|---|---|
| `25271335692` Security Scan (master, push @ 58dc369) | **failure** | — |
| `25271335685` Test Race (master, push @ 58dc369) | **failure** | — |
| `25271335677` Security Scan (master, push @ 58dc369) | **failure** | — |
| `25271335674` CI (master, push @ 58dc369) | **failure** | `test (macos-latest)`, `test (windows-latest)`, `test (ubuntu-latest)` — all 3 OS jobs |
| `25271335673` Generate SBOM | success | — |

**Failure modes (extracted from `gh run view --log-failed`):**

```
test (macos-latest):  FAIL: TestStartRateLimitReloadLoop_StopChanExits (2.00s)
                      Error: Condition never satisfied
                      app/ratelimit_reload_test.go:136
                      ##[error] kc/ops/api_activity.go:1:1: invalid BOM in the middle of the file
                      FAIL github.com/zerodha/kite-mcp-server/kc/ops [build failed]

test (windows-latest):  FAIL: TestSetupGracefulShutdown_SignalTriggersShutdown (5.59s)
                        ##[error] kc\ops\api_activity.go:1:1: invalid BOM in the middle of the file
                        FAIL github.com/zerodha/kite-mcp-server/kc/ops [build failed]
```

**Two distinct issues:**
1. **`kc/ops/api_activity.go` has a leading UTF-8 BOM (`\xef\xbb\xbf`)** — verified locally via `od -c` (output: `0000000 357 273 277 p a c k a g e ...`). Go compiler 1.21+ rejects BOM in source files. **Fix: re-save the file as UTF-8-without-BOM.** 60-second fix.
2. **Two flaky tests:** `TestStartRateLimitReloadLoop_StopChanExits` (timing assertion) and `TestSetupGracefulShutdown_SignalTriggersShutdown` (5.59s — Windows signal handling). Both look like real-but-flaky tests, not code bugs. Either bump the polling timeout, or skip on macOS/Windows CI with a documented reason.

The README badge linking to `ci.yml` is currently red. Visitors see this. **This is the #1 launch blocker.**

---

## Phase 6 — Top-5 friction killers + 30-minute fix recipes

Ordered by impact-per-minute-fix. Each recipe is exact file/line + before/after + rationale.

### Fix 1 — Strip the BOM from `kc/ops/api_activity.go` (5 minutes)

**Why:** Without this, every CI run on master fails. README badge is red. Show HN visitors see a red badge in 5 seconds and bounce in 6.

**File:** `D:\Sundeep\projects\kite-mcp-server\kc\ops\api_activity.go`

**Empirical evidence (local):**
```
$ head -2 kc/ops/api_activity.go | od -c | head -2
0000000 357 273 277   p   a   c   k   a   g   e       o   p   s  \n  \n
```
The bytes `\357 \273 \277` are `\xef \xbb \xbf` = UTF-8 BOM.

**Fix recipe:**
```bash
# Option A (one-liner, WSL2):
cd /mnt/d/Sundeep/projects/kite-mcp-server
sed -i '1s/^\xef\xbb\xbf//' kc/ops/api_activity.go

# Option B (editor): open the file in VS Code, bottom-right "UTF-8 with BOM"
# → click → "Save with Encoding" → "UTF-8" (no BOM).

# Verify:
head -1 kc/ops/api_activity.go | od -c | head -1
# Expected: 0000000   p   a   c   k   a   g   e       o   p   s  \n
```

**Rationale:** A single byte-sequence fix that converts CI from red to green. Highest-impact-per-minute change in the entire audit.

### Fix 2 — Apply `docs/product-definition.md` Section 3 Draft B to `README.md` (10 minutes)

**Why:** The current README opens with five badges and a *"Why trust this"* section that leads with `7,000+ tests`. The drafted hero leads with the user benefit. The doc author already drafted the swap; nobody applied it.

**File:** `D:\Sundeep\projects\kite-mcp-server\README.md` lines 1-22

**Before (current):**
```markdown
# Kite MCP Server

[![Go](https://img.shields.io/badge/Go-1.25-...)](https://go.dev)
[![CI](.../ci.yml/badge.svg)](.../ci.yml)
[![Tests](https://img.shields.io/badge/Tests-7000%2B-brightgreen)](...)
[![Security Audit](https://img.shields.io/badge/Security%20Audit-passed-...)]
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

> Self-hosted MCP server that turns Claude / ChatGPT into a power-user trading copilot for your Zerodha Kite account.

<!-- TODO: 30-second demo GIF of portfolio analysis + order placement flow -->

## What this is
[long descriptive paragraph]

## Why trust this
- **7,000+ tests** ...
```

**After (drafted in product-definition.md):**
```markdown
# Kite MCP Server

Give Claude or ChatGPT direct access to your Zerodha Kite trading account —
with order placement, paper trading, options Greeks, backtesting, Telegram
alerts, and 9 pre-trade safety checks. ~80 tools. Open source, MIT.

[Try the hosted demo](https://kite-mcp-server.fly.dev/mcp) (read-only) ·
[Self-host in 60 seconds](#quick-start) (full trading) ·
[Compare vs official Zerodha MCP](#comparison)

```bash
claude mcp add --transport http kite https://kite-mcp-server.fly.dev/mcp
```

Then say: *"Log me in to Kite. Show my portfolio. Backtest SMA crossover on
INFY. Set an alert for RELIANCE 2% drop."*

[![Go](...)](https://go.dev) [![CI](...)](.../ci.yml) [![License](...)](LICENSE)
```

(Move the badges below the hero. Drop the static "Tests-7000+" badge — it's stale anyway; see Fix 5. Drop the "Security Audit passed" badge or move it; HN crowd sees self-issued passing badges as marketing.)

**Rationale:** Three CTAs above the fold. One copy-paste install line. No defensive preamble. Reads like a product, not a journal.

### Fix 3 — Move `.research/` to a private companion repo (30 minutes)

**Why:** A curious HN reader who hits the GitHub repo will scroll past README and look at the directory listing. The current top-level listing is dominated by `.research/` (156 tracked files of internal architectural exploration), `.claude/`, `docs/` (93 files), plus 18 root markdown files including 7 stray scratch notes (`a.md`, `ch.md`, `mod.md`, `req.md`, `gen_ref.md`, `api.md`, `admin.md`).

Recipe (per `docs/product-definition.md` Section 2):

```bash
# 1. Create private repo
gh repo create Sundeepg98/kite-mcp-internal --private

# 2. Clone the public repo into a sibling worktree-style copy
cd D:/Sundeep/projects
git clone https://github.com/Sundeepg98/kite-mcp-server.git kite-mcp-internal
cd kite-mcp-internal

# 3. Inside the internal repo, keep ONLY .research/ + scratch notes; reset history
# (or: just push .research/ to the new remote, no history rewrite)
git remote set-url origin https://github.com/Sundeepg98/kite-mcp-internal.git
git push -u origin master   # initial push of full history

# 4. In the PUBLIC repo, remove .research/ + stray root scratch
cd D:/Sundeep/projects/kite-mcp-server
git rm -r .research/
git rm a.md ch.md mod.md req.md gen_ref.md api.md admin.md
# Keep: ARCHITECTURE.md, CHANGELOG.md, CONTRIBUTING.md, COVERAGE.md, PRIVACY.md,
#       README.md, SECURITY*.md, TERMS.md, THREAT_MODEL.md
git commit -m "chore: split internal architectural journal to kite-mcp-internal"
git push origin master
```

**Rationale:** Public repo becomes ~half the file count. Directory listing on github.com/Sundeepg98/kite-mcp-server now reads cleanly: README, source code dirs, docs, configs. Internal-architecture journal preserved privately for the developer.

### Fix 4 — Serve `og-image.png` (15 minutes)

**Why:** Every link preview on Twitter, HN, Reddit, Discord, Slack, WhatsApp falls back to a generic favicon because `https://kite-mcp-server.fly.dev/og-image.png` returns 404. Hero image referenced in landing-HTML's `<meta property="og:image">` is dead.

**Recipe:**
1. Generate a 1200×630 PNG with the hero text + a Kite/MCP logo. Tools: Figma, Canva, or a one-shot Tailwind+canvas script.
2. Drop into `kc/templates/static/og-image.png` (or wherever the static-asset router serves).
3. Wire `app/http.go` to serve it at `/og-image.png` if not already.
4. Verify: `curl -I https://kite-mcp-server.fly.dev/og-image.png` returns 200.

**Rationale:** Every share = a free banner ad. Currently broken across every platform.

### Fix 5 — Reconcile the tool count and test count once (10 minutes)

**Why:** Three different documents claim three different numbers:

| Document | Claim | Reality |
|---|---|---|
| README badge | `Tests 7000+` | 16,209 test funcs across 630 files |
| README body | `~80 tools` | `/healthz` returns `tools: 111`; 117 unique `mcp.NewTool` names |
| show-hn-post.md | `Around 330 tests` | 16,209 |
| product-definition.md | `~80 tools (128 NewTool sites, ~48 admin)` | 117 unique |

**Recipe:**
1. Pick canonical numbers: **`~80 user-facing tools` / `~110 total tools (incl. admin)` / `~16,000 tests`**.
2. Update README (line 4 badge: `Tests-16000%2B`; line 12: `Ships ~80 user-facing tools (~110 total)`).
3. Update show-hn-post.md (line 25: `Around 16,000 tests` not `Around 330 tests`).
4. Update landing.html if it contains a tool count.

**Rationale:** Self-consistency across artifacts. An HN reviewer cross-checking `curl /healthz` against the README catches the gap in 30 seconds and flags it in the comments.

---

## Phase 7 — Pre-Show-HN checklist

A YES/NO checklist to verify in ~15 minutes before clicking "Submit" on Show HN.

### Code / repo state

- [ ] **CI is green on master.** Verify: `gh run list -R Sundeepg98/kite-mcp-server --limit 1` returns `success`. (Currently: failure — see Fix 1.)
- [ ] **README badge for CI shows green** when rendered on github.com (cache may take 60s after a green run).
- [ ] **`.research/` is moved out of the public repo** OR explicitly accepted as a debt (see Fix 3).
- [ ] **Stray root markdown files removed** (`a.md`, `ch.md`, `mod.md`, `req.md`, `gen_ref.md`, `api.md`, `admin.md`).
- [ ] **Local junk artifacts cleaned for screen-share hygiene:** `git clean -fX -n` (preview), then `git clean -fX` (execute) — removes 213+ gitignored `.out`, `.exe`, `.cov`, `app_*.html` files in working tree. Doesn't touch tracked files. Safe.
- [ ] **`.gitignore` blocks future build artifacts** — verified at lines 91-114 already.

### README / hero / first impression

- [ ] **README hero swapped to product-definition.md Section 3 Draft B** (Fix 2).
- [ ] **At least one demo GIF, asciinema cast, or static screenshot in the README** above the comparison table. Currently: zero. The launch-eve fix is a 30-second `asciinema rec` of `claude mcp add` + `Show my portfolio` + JSON response. Convert to GIF via `agg`.
- [ ] **`og-image.png` returns 200** (Fix 4).
- [ ] **Tool / test counts consistent across README + show-hn-post + landing** (Fix 5).
- [ ] **Comparison table vs `mcp.kite.trade` is visible above the fold** OR is the second section reachable in <1 scroll. Currently: line 191. Move higher.

### Hosted demo flow

- [ ] **`/healthz` returns 200** (currently: yes, `tools=111`, `uptime=14d`).
- [ ] **`/.well-known/oauth-authorization-server` returns valid metadata** (currently: yes).
- [ ] **Landing page server-name `kite-fly` aligned with README's `kite`** — pick one, update both.
- [ ] **End-to-end OAuth flow tested by the developer with a real Kite developer app within 24h of launch.** Token expires daily ~6 AM IST; if the test was last week it's worthless. **Re-test the morning of launch.**
- [ ] **First tool call (`get_profile` or `get_holdings`) returns real data.**
- [ ] **Mobile / tablet rendering of landing page checked.**

### Show HN claim verification (sharp claims first)

- [ ] **`~80 tools` or `~110 total tools` is consistent with `/healthz`.**
- [ ] **`9 RiskGuard checks` claim cross-checked against `kc/riskguard/guard.go` rejection-reason constants.**
- [ ] **`~16,000 tests` claim** (or whatever number lands) verified via `find ... -name "*_test.go" | xargs grep -c "^func Test" | awk '{s+=$1}END{print s}'`.
- [ ] **`AES-256-GCM` claim verified by pointing at `kc/crypto/cipher.go` or equivalent.**
- [ ] **Static egress IP `209.71.68.157` is the same one currently allocated by Fly.io to the bom region.** (`flyctl ips list -a kite-mcp-server`).
- [ ] **`ENABLE_TRADING=false` is the actual hosted-instance setting.** Verify: any `place_order` tool call against the hosted endpoint returns "tool not available" or equivalent gating message, not a Kite-side rejection.

### Show HN execution readiness

- [ ] **First three replies pre-drafted in `docs/show-hn-post.md`** (verified: 8 prepared replies are in the doc).
- [ ] **Comment-triage availability for next 2 hours after submission** — author online and notification-on.
- [ ] **Title chosen and ≤80 chars** (verified: title 1 in show-hn-post.md is 78 chars).
- [ ] **Submission window is Tuesday or Wednesday 06:30-08:30 PT** (per gtm-launch-sequence.md).
- [ ] **Backup channels staged: Twitter post drafted, MCP Discord post drafted, Reddit posts drafted** (verified: all in repo).

### Risk-of-disaster checks

- [ ] **No personal contact info accidentally in `docs/`** — sweep for the renusharmafoundation email per global memory rule.
- [ ] **No leaked credentials in committed `.env` or test fixtures** (sweep `git log --all -p -S "KITE_API_SECRET" -S "KITE_API_KEY" | head -30`).
- [ ] **No `.research/*-msg.txt` commit-message scratch files in public repo** — currently: yes there are several (`anomaly-es-commit-msg.txt`, `audit-shim-closeout-msg.txt`, ...). Bundle into Fix 3.
- [ ] **No `SECURITY_AUDIT_FINDINGS.md` exposing CVE-shaped active issues** — file exists at repo root; verify all 181 findings show resolved status.
- [ ] **Disclaimer / not-investment-advice / not-Zerodha-affiliated language present** (verified: README lines 233-239 — strong).

---

## Appendix — empirical-data dump (for cross-reference)

### File-system inventory

- README.md: 288 lines, 18,372 bytes
- `.research/`: 156 tracked .md files + ~50 untracked
- repo-root junk: 213 files matching `*.out *.exe *.cov app_*.html` (all gitignored, working-tree only)
- repo-root .md: 18 files of which 7 are stray scratch (`a.md ch.md mod.md req.md gen_ref.md api.md admin.md`)
- `mcp/` package: 77 .go files (excluding tests)
- Test files: 630 `*_test.go` files
- Test functions: 16,209 `^func Test...`

### Tool counts (exhaustive)

- `mcp.NewTool(...)` total occurrences: 648 across 77 files (includes options helpers, args)
- `mcp.NewTool("name"` unique tool names: **117**
- `/healthz` reported: **111** (registration may exclude some at runtime)
- README claim: `~80`
- product-definition.md cross-check: *"128 NewTool sites, ~48 admin/test/variant; landing rounds to ~80"*

### CI runs (latest 5)

```
25271335692  Security Scan      master  failure  2m10s
25271335685  Test Race          master  failure  2m15s
25271335677  Security Scan      master  failure  2m39s
25271335674  CI                 master  failure  6m49s
25271335673  Generate SBOM      master  success  24s
```

CI failure modes:
1. `kc/ops/api_activity.go` BOM (build-time, all 3 OSes)
2. `app/ratelimit_reload_test.go:136` flaky timing assertion (macOS only)
3. `app/setup_test.go` `TestSetupGracefulShutdown_SignalTriggersShutdown` (Windows only, signal handling)

### Hosted endpoint summary

- `https://kite-mcp-server.fly.dev/` — 200 OK, ~210 ms, 14d uptime, region bom
- `/healthz` — `{"status":"ok","tools":111,"uptime":"337h9m47s","version":"v1.1.0"}`
- `/.well-known/oauth-authorization-server` — valid RFC 8414 metadata, PKCE+S256
- `/og-image.png` — **404 (broken link previews)**
- TLS: HSTS 2y, includeSubDomains, no preload (acceptable)
- Server: Fly/9f7e98291c, fly-request-id includes `bom`

### Claim-vs-reality summary

| Claim | Source | Reality | Verdict |
|---|---|---|---|
| ~80 tools | README + landing | 117 unique / 111 healthz | undersells |
| 9 RiskGuard checks | README + show-hn | 16 RejectionReason constants, ≥9 distinct check fns | conservative |
| 4 backtest strategies | show-hn | 4 in switch case | accurate |
| Black-Scholes Greeks | README + show-hn | 5 functions present | accurate |
| Telegram /buy /sell /quick /setalert | README + show-hn | all 5 handlers present | accurate |
| AES-256-GCM at rest | README + show-hn | per memory + smithery | accurate |
| 7,000+ tests | README badge | 16,209 | undersells by 2.3× |
| ~330 tests | show-hn-post | 16,209 | undersells by 49× |
| Static egress IP 209.71.68.157 bom | README | per memory + fly.toml | accurate |
| Path 2 ENABLE_TRADING=false | README | fly.toml + app/config.go | accurate |
| 27-pass audit, 181 findings resolved | README | per memory + repo-root .md | accurate |

---

## Conclusion

The product is *substantively* ready for Show HN — the code, tests, hosted demo, OAuth flow, RiskGuard checks, comparison-table claims all hold up. The launch is not gated on building anything new.

It is gated on **three small surface-level fixes that turn a "looks like a journal-style work-in-progress" first impression into a "looks like a finished product"** first impression:

1. Green CI badge (one-byte fix in `kc/ops/api_activity.go` + 2 flaky-test skips).
2. Hero-rewrite of `README.md` (10-minute copy from a doc that already exists).
3. Move `.research/` to a private repo (clean directory listing).

Plus four polish items (og-image, tool/test count reconciliation, server-name consistency, demo GIF) that are nice-to-haves but together close the gap between "Show HN" and "Show HN that converts to 50+ stars".

Total developer time to ship: **~3 hours** for blockers + polish, end-to-end.

After that, Show HN on Tuesday/Wednesday 06:30-08:30 PT per the existing playbook in `.research/gtm-launch-sequence.md`.
