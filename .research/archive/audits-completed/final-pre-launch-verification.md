# Final Pre-Show-HN Verification

**HEAD**: `ad1e263` (fix(e2e): relax server-card identity assertion to accept SEP-1649 + SEP-2127 shapes)
**Date**: 2026-05-03
**Scope**: Last empirical readiness check before Submit. No code edits.

## Verdict

**NOT LAUNCH-READY RIGHT NOW.** Three blockers, all <2-hour remediable:

1. **Hosted demo is 548 commits stale.** `/healthz` reports `v1.1.0`/`tools=111`/`uptime=14d`. README and Show-HN copy claim 117 tools. The most recent ~50 commits include CI fixes, BOM strip, security patches (CVE GO-2026-4762 grpc bump, gosec 21 issues), `.research` move-out, README hero rewrite, og-image, Upstox/TurtleStack additions — none of which are live. **`flyctl deploy -a kite-mcp-server` required before launch.**
2. **`og-image.png` returns HTTP 404 on hosted instance.** File exists in repo (`kc/templates/static/og-image.png`) and route is wired (`app/http.go:523-524`), but not deployed. HN/Twitter/LinkedIn link previews will be broken. Same fix as #1 — deploy.
3. **flyctl auth expired** — cannot deploy without re-auth. `Error: No access token available. Please login with 'flyctl auth login'`. Note from MEMORY.md: re-login via Playwright CLI auth URL.

After deploy + flyctl reauth: launch-ready. Window per `58dc369`: Tuesday or Wednesday 06:30-08:30 PT.

---

## Phase 1 — Hosted demo health

### Deployed vs HEAD gap

| Metric | Deployed (Fly.io) | Master HEAD `ad1e263` | Gap |
|--------|-------------------|----------------------|-----|
| Version | `v1.1.0` | (untagged, post-v1.1.0) | **548 commits behind** |
| Tools | `111` | 122 unique / 128 NewTool() | +6 to +17 |
| Uptime | 342h28m (14.3d) | n/a | last deploy ~Apr 18 |

Deployed `v1.1.0` corresponds to the `v1.1.0` git tag (Apr 18 2026). The Dockerfile pins `ARG VERSION=v1.1.0` and `server.json` already declares `1.2.0` for next release.

### HTTP smoke probes (status / key field / anomaly)

| Endpoint | Status | Key Field | Anomaly |
|----------|--------|-----------|---------|
| `/` | 200 | landing HTML, OG meta tags present | none |
| `/healthz` | 200 | `{"status":"ok","tools":111,"uptime":"342h28m34s","version":"v1.1.0"}` | tools=111 vs claimed 117 |
| `/og-image.png` | **404** | "Page Not Found" | **BLOCKER — not deployed** |
| `/.well-known/oauth-authorization-server` | 200 | full OAuth metadata, S256 PKCE | none |
| `/.well-known/mcp/server-card.json` | 200 | `serverInfo.description` says "111 tools", protocolVersion 2025-06-18 | tools=111 (matches /healthz) |
| `POST /mcp` (unauth initialize) | 401 | `WWW-Authenticate: Bearer resource_metadata=...` | correct, not 5xx |

No 5xx anywhere. All security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options) intact.

---

## Phase 2 — Post-fix repo state

### README hero (lines 1-5)

YES — applied the product-led copy from `product-definition.md` Draft B. Three CTAs above fold (`Try the hosted demo` / `Self-host in 60 seconds` / `Compare vs official`). Tests claim **16,209** in badge — this is **NOT** what `find -name '*_test.go' | xargs grep -c '^func Test'` returns. See claims integrity below.

### Numeric claims integrity

| Claim | Source location | Empirical | Verdict |
|-------|-----------------|-----------|---------|
| 117 tools | README L3, L21; show-hn L20, L25, L49 | 122 unique / 128 NewTool() / **111 deployed** | inconsistent — README leads to claim, healthz shows 111 (deploy gap), code has 122. README's 117 is between empirical 111 and 122 — likely a count from prior commit. **Update to 122 OR redeploy first to make 111 visible** |
| 16,209 tests | README L15, L25 | **8,790** (`grep -h '^func Test' \| wc -l`) or **9,021** (incl. subtests) | **OFF BY ~2x — possible double-count from old worktrees pollution at audit time**. The d7b9d5f Phase 5 audit recorded 16,209; current state is 8,790 distinct top-level test funcs. If the README badge is referenced as evidence on HN, this becomes an integrity issue. **RECOMMEND: re-derive number on master HEAD with `grep -c '^func Test'` and update both badge + body before launch.** |
| 9 RiskGuard checks | README L28; show-hn L20, L25, L43, L49 | **15 distinct** `RejectionReason` constants in `kc/riskguard/guard.go:50-101` | **conservative number is fine** for HN — README enumerates 8 by name + auto-freeze = 9; the additional 6 (Confirmation/Anomaly/OffHours/OTRBand/CircuitBreached/InsufficientMargin/MarketClosed) are listed inside the prose elsewhere. Honest under-claim. |
| AES-256-GCM | README L27; show-hn L25 | `kc/alerts/crypto.go:196-235` confirms `aes.NewCipher` + `gcm.Seal` | YES |
| 4 backtest strategies | implicit; mcp/backtest_tool.go | sma_crossover, rsi_reversal, breakout, mean_reversion | YES |
| 6 Greeks (delta/gamma/theta/vega/IV/rho) | mcp/options_greeks_tool.go | bsDelta + bsGamma + bsTheta + bsVega + bsRho + impliedVolatility | YES |
| 4 Telegram trading commands | /buy /sell /quick /setalert | bot.go confirms | YES |
| `bom` region | README implied; show-hn L25 | `fly.toml: primary_region = "bom"` | YES |
| `ENABLE_TRADING=false` | show-hn L31 | `fly.toml: ENABLE_TRADING = "false"` | YES |
| static egress IP `209.71.68.157` | show-hn L25 | UNVERIFIED (flyctl auth expired); IP correct per MEMORY.md | DEFER — verify post-flyctl-reauth via `flyctl ips list -a kite-mcp-server` |

### Differentiation table additions

YES — Upstox MCP (line 48) and TurtleStack (line 51) rows present in `docs/show-hn-post.md` prepared replies. "First / the only" framing audit:

- L11 (title rationale): "first" appears in word "self-hosted signals first", not as superiority framing — fine
- L34 (post body): "First, I want critique" — first-person word, not framing — fine
- L73 (registry reply): "wanted to stabilise the OAuth ... layer first" — adverb, not claim — fine
- No "the only Indian-broker MCP" / "first to ship" / "only one with riskguards" framing detected. Clean.

### Prepared replies count

13 prepared replies in `docs/show-hn-post.md` (counted via `grep -c '^\*\*"'`). Brief said 12 expected — **within rounding**, no concern.

---

## Phase 3 — CI workflow status at HEAD

`gh run list --branch master -L 8` at HEAD `ad1e263`:

| Workflow | At HEAD ad1e263 | At HEAD 017366f (parent) | Notes |
|----------|----------------|------------------------|-------|
| CI (3 OS) | not yet run | success | the e2e relaxation patch only modifies test, expect green |
| Test Race | not yet run | success | ditto |
| Docker Build | not yet run | success | |
| Generate SBOM | not yet run | success | |
| Security Scan ×2 | not yet run | success ×2 | post-grpc + gosec patches verified clean |
| Playwright E2E | not yet run | **FAILURE** | This is what `ad1e263` is meant to fix |

**Wait for HEAD `ad1e263` CI completion before launch** — confirm Playwright E2E is now green. If still red after this fix, defer launch. The diagnosis in `.research/playwright-2-remaining-diagnosis.md` says the server-card relaxation should pass; the second `tools/list` failure was deferred as a stale-test issue, but check the workflow output to confirm only that specific test failure remains.

---

## Phase 4 — 35-item pre-launch checklist (from d7b9d5f Phase 7)

### Code / repo state (6 items)

| # | Item | Status |
|---|------|--------|
| 1 | CI green on master | **PENDING** at HEAD ad1e263 (parent green ex-Playwright) |
| 2 | README CI badge green | will follow #1 |
| 3 | `.research/` moved to private OR accepted as debt | **ACCEPTED** per user — moved to `Sundeepg98/kite-mcp-internal` (commit dd8be3a); current public `.research/` has 1 file (the playwright diagnosis) — that re-tracking is per user's call |
| 4 | Stray root .md removed (a/ch/mod/req/gen_ref/api/admin) | **YES** — none tracked in git |
| 5 | Local junk artifacts cleaned for screen-share | **NO** — 171 stray `.out` files in working tree (untracked, but visible in any `ls`/file picker during a streamed demo). Run `git clean -fX` before launch if streaming. |
| 6 | `.gitignore` blocks future build artifacts | YES (per d7b9d5f audit, lines 91-114) |

### README / hero (5 items)

| # | Item | Status |
|---|------|--------|
| 7 | Hero swapped to product-definition Draft B | YES |
| 8 | Demo GIF / asciinema / screenshot above comparison | **NO** — none in README. Last-mile fix recipe in d7b9d5f was a 30-sec asciinema + agg→GIF. Defer-or-fix call. |
| 9 | `og-image.png` returns 200 | **NO** — 404 on Fly.io (file in repo, not deployed). **BLOCKER** |
| 10 | Tool/test counts consistent | **NO** — 117/16,209 in README vs 111/8,790 empirical. **BLOCKER (lite)** |
| 11 | Comparison table above fold | UNVERIFIED here; per d7b9d5f at line 191 — needs re-check on current README, but landing page CTAs already tease the comparison |

### Hosted demo flow (6 items)

| # | Item | Status |
|---|------|--------|
| 12 | `/healthz` 200 | YES |
| 13 | `/.well-known/oauth-authorization-server` valid | YES |
| 14 | server-name alignment landing vs README | server-card says "Kite Trading MCP Server" / claude mcp add example uses `kite` — minor naming variance, not user-facing blocker |
| 15 | OAuth flow tested with real Kite app within 24h | **MUST DO morning of launch** — token expires daily ~6 AM IST |
| 16 | First tool call returns real data | follows from #15 |
| 17 | Mobile/tablet rendering checked | UNVERIFIED |

### Show HN claim verification (6 items)

| # | Item | Status |
|---|------|--------|
| 18 | Tool count consistent | **NO** (see above) |
| 19 | 9 RiskGuard checks vs constants | YES (conservative under-claim — 15 actual) |
| 20 | Test count claim verified | **NO** (16,209 vs 8,790) |
| 21 | AES-256-GCM verified | YES — `kc/alerts/crypto.go` |
| 22 | Static egress IP `209.71.68.157` confirmed | UNVERIFIED (flyctl auth expired) |
| 23 | `ENABLE_TRADING=false` is hosted setting | YES via `fly.toml` |

### Show HN execution readiness (5 items)

| # | Item | Status |
|---|------|--------|
| 24 | First three replies pre-drafted | YES — 13 prepared replies |
| 25 | Author online for 2h after submit | author-decision |
| 26 | Title ≤80 chars | YES — title 1 is 78 chars |
| 27 | Submission window Tue/Wed 06:30-08:30 PT | author-decision |
| 28 | Backup channels (Twitter, MCP Discord, Reddit) drafted | per d7b9d5f Phase 7 verified |

### Risk-of-disaster checks (5 items)

| # | Item | Status |
|---|------|--------|
| 29 | No personal contact info in `docs/` | foundation-slug email check: 1 hit in `docs/drafts/zerodha-compliance-email.md` — needs sweep before launch (per global memory rule) |
| 30 | No leaked credentials in tracked files | UNVERIFIED here; per CLAUDE.md fixes already applied |
| 31 | No `.research/*-msg.txt` scratch in public repo | **PARTIAL** — playwright-diagnosis is fine; root-tree has many `*-msg.txt` files locally but per `git ls-files .research/` only 1 file is tracked — clean in repo |
| 32 | `SECURITY_AUDIT_FINDINGS.md` shows resolved | per CLAUDE.md history (181 findings, 153 fixed, 28 accepted) |
| 33 | Disclaimer/not-investment-advice present | YES per d7b9d5f Phase 7 (README L233-239) |

### Additions

| # | Item | Status |
|---|------|--------|
| 34 | flyctl auth working | **NO — token expired** |
| 35 | Hosted SHA matches README claims | **NO — 548 commits behind** |

**Tally**: NO/PARTIAL = 9 items; PENDING = 2; UNVERIFIED = 5; YES = 19. Of the NOs, **3 are launch-blocking** (deploy gap, og-image, claims/empirical mismatch); **2 are launch-day chores** (OAuth re-test morning of, screen-share cleanup); rest are minor or already accepted as debt.

---

## Phase 5 — Final verdict

**NOT launch-ready right now.** Specific blockers, each <2hr remediable:

1. **Deploy current master to Fly.io** (15min once flyctl auth works) — fixes og-image 404, brings deployed tool count in sync, ships all post-Apr-18 security/CI fixes
2. **Re-auth flyctl** (5min via Playwright CLI auth URL — see MEMORY.md note)
3. **Reconcile tool/test counts in README + show-hn-post** (15min) — re-run the empirical commands on current HEAD, update 117→122 (or whatever post-deploy `/healthz` shows) and 16,209→8,790; update both prose + badge

Optional but recommended: sweep foundation-slug hit in `docs/drafts/zerodha-compliance-email.md`; `git clean -fX` for screen-share hygiene; verify mobile rendering of landing page; morning-of OAuth re-test.

After 1+2+3: launch window per `58dc369` = Tuesday 06:30-08:30 PT or Wednesday 06:30-08:30 PT.

---

## Phase 6 — Diminishing returns honesty

This is the 11th research dispatch this session. Of the findings:

- **NEW (added value over prior research):**
  1. Concrete deployment gap quantified (548 commits, `v1.1.0` from Apr 18)
  2. og-image 404 confirmed live on Fly.io (was guessed-at in d7b9d5f, never live-probed there)
  3. flyctl auth state surfaced as a precondition blocker
  4. Test count drift since d7b9d5f Phase 5 (was 16,209 then; 8,790 now — possible worktree pollution cleanup since)
  5. CI status at HEAD ad1e263 still pending — must wait for green Playwright before launch
- **CONFIRMED-PRIOR (no new info, just final-state proof):**
  1. CI workflows green at parent commit (017366f) modulo Playwright
  2. AES-256-GCM, 4 backtest strategies, 6 Greeks, 4 Telegram cmds, `bom` region, `ENABLE_TRADING=false`
  3. Differentiation table has Upstox + TurtleStack
  4. 13 prepared replies (close enough to expected 12)
  5. Hero copy applied
  6. RiskGuard 9 vs 15 — conservative claim is fine

Honest verdict: The blocker list is real and would have been missed without this dispatch (specifically: og-image deployment status, claims/empirical drift, flyctl auth). Worth the dispatch. **But after these three blockers clear, do NOT spawn a 12th research agent — go.**
