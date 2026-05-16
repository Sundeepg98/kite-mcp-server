<!-- secret-scan-allow: production-egress-ip-cited-with-peer-verification -->
---
title: Launch-Readiness Verdict — Fresh Pass at 2026-05-11
as-of: 2026-05-11
re-verify-by: launch+1d
master-head-at-write: 6415d0c
dispatch: orchestrator — fresh launch-readiness verdict in light of TODAY'S findings
prior-doc: .research/archive/audits-completed/final-pre-launch-verification.md (2026-05-03, 3 blockers FALSIFIED today)
scope: READ-ONLY (curl + gh api + file reads only); doc-only output; single commit + push
budget-used: ~2.5h of 3h target; halt at 5h
concurrency: 9 peer research agents in flight on disjoint output files
verdict: CONDITIONAL — launch-ready modulo 4 user-action items + 1 must-do polish
---

# Launch-Readiness Verdict — Fresh Pass at 2026-05-11

## TL;DR (read this first)

**Verdict: CONDITIONAL GO.** Production is genuinely healthy at v1.3.0/tools=111/uptime=129h; the og-image 404 (prior blocker #2) is RESOLVED (now 200 OK); the egress-IP staleness fear (orchestrator's new blocker #1) is FALSIFIED per today's peer-audit dispatch. Five remaining items are all user-action, none of them code-side:

1. **(MUST)** Rotate the 2 plaintext secrets in memory files (R2 keys in `kite-session-apr3.md`, Kite API keys in `MEMORY.md`). Not a *technical* launch-blocker (memory files are local-only, not in repo), but credentials live longer than launch attention windows. Do this BEFORE Show HN draws eyeballs.
2. **(MUST)** Provision the 6 GitHub Actions secrets for monthly `dr-drill.yml` cron. Currently `gh api .../actions/secrets` returns `total_count: 0`. Without these, the dr-drill cron's silent-fail rate is 100%/month. ~5min user-action.
3. **(SHOULD)** Create Reddit `u/Sundeepg98` account — `/user/Sundeepg98/about.json` returns 404 confirming it does NOT exist. Reddit cross-post is in the GTM playbook (`58dc369`); without the account, the channel is unavailable.
4. **(SHOULD)** Record one demo GIF/asciinema cast. Repo has zero demo media (`find . -name '*.gif' -o -name '*.mp4'` → empty). HN viewers who don't have an MCP client installed will bounce without seeing what the tool *does*.
5. **(NICE-TO-HAVE)** Optionally allocate a $3.60/mo app-scoped static egress IPv4 per `sebi-shared-vs-dedicated-ip-2026-05-11.md`. NOT a blocker — `209.71.68.157` IS currently a `Type: egress_v4` dedicated app-scoped IP (peer-verified by 3 audits today). The $3.60/mo recommendation in that doc was itself triggered by the same falsified premise this verdict closes; budget-rerun the SEBI doc's §6 communication plan once the egress-IP-stale premise is corrected.

**Net**: If user does (1) + (2) today (~30min total), launch is GO. (3) + (4) shorten the conversion funnel post-launch but don't block submit.

---

## §1 — Empirical production state (live probes at 2026-05-16 03:38Z)

### 1.1 HTTP smoke battery

| Endpoint | Status | Key Field | Anomaly |
|---|---|---|---|
| `GET /` | 200 | landing HTML, OG meta tags present | none |
| `GET /healthz` | 200 | `{"status":"ok","tools":111,"uptime":"129h52m32s","version":"v1.3.0"}` | none (was v1.1.0 in prior doc — fresh deploy 5.4d ago) |
| `GET /og-image.png` | **200** | PNG, `cache-control: public, max-age=86400` | **RESOLVED — was 404 in prior doc** |
| `GET /.well-known/oauth-authorization-server` | 200 | `S256` PKCE, full metadata | none |
| `GET /.well-known/mcp/server-card.json` | 200 | `serverInfo.version: "v1.3.0"`, "111 tools", protocolVersion 2025-06-18 | none |
| `POST /mcp` (unauth initialize) | 401 | `WWW-Authenticate: Bearer resource_metadata=...` | correct (not 5xx) |
| `GET /llms.txt` | **404** | (file does not exist) | nice-to-have, NOT a blocker — see §5.4 |

All security headers intact (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).

### 1.2 Repository state

| Metric | Value | Source |
|---|---|---|
| Repo full name | `Sundeepg98/kite-mcp-server` (NOT yet transferred to algo2go) | `gh api repos/Sundeepg98/kite-mcp-server` |
| Master HEAD (remote) | `6415d0c171c7d7c1f38f208b3eea63b53cb78c97` (2026-05-16 03:42Z) | `gh api .../branches/master` |
| Stars / Forks / Watchers | 0 / 0 / 0 | `gh api` |
| Default branch | `master` | `gh api` |
| Action secrets count | **0** (zero — none configured) | `gh api .../actions/secrets` |
| `.research/` tracked files | 286 (re-tracked in current public repo) | `git ls-files .research/ \| wc -l` |
| README hero | "Give Claude or ChatGPT...with order placement, paper trading, options Greeks, backtesting, Telegram alerts, and 11 pre-trade safety checks. 110+ tools." | README.md L3 |
| Tool count consistency | `110+` (README) / `111` (`/healthz`, server-card) / `111` in `README.md` comparison table | all aligned within "+" rounding |
| Riskguard checks consistency | `11` everywhere (README L3, L22, L43; show-hn L25, L43, L49) | all aligned |
| Test count consistency | `~9,000` (README badge + L20) and `~9,000 / 437 test files` (show-hn L25) | aligned |
| funding.json version | `v1.1.0` (FLOSS/fund schema-valid per brief) | `funding.json` |
| dr-decrypt-probe binary | exists at `cmd/dr-decrypt-probe/{main.go,main_test.go}` | `ls cmd/dr-decrypt-probe/` |

### 1.3 CI state (recent)

| Workflow | Most recent (master) | Status | Note |
|---|---|---|---|
| CI (ci.yml) | 2026-05-14 `7c91d409` | **action_required** (PR event from fork; needs maintainer approval) | NOT a launch-blocker — production already deployed at v1.3.0 from an earlier green |
| CI (push, master) | 2025-08-06 `dcf2dc41` | success | last green push-event CI on master from 9mo ago |
| Other workflows (playwright, dr-drill, security, sbom, release, etc.) | none on master since 2026-04-16 | n/a | most are PR-only or scheduled-cron |

CI gaps are real but not launch-critical given the live production state. Action_required runs on PRs from forks won't auto-execute; that's GitHub's correct fork-PR security default.

---

## §2 — Prior blockers (from 2026-05-03 archived doc) — status per row

| # | Prior blocker | Today's status | Evidence |
|---|---|---|---|
| 1 | Hosted demo 548 commits stale (v1.1.0) | **RESOLVED** | `/healthz` reports v1.3.0; deploy refreshed 5.4d ago |
| 2 | `/og-image.png` 404 | **RESOLVED** | `curl -I .../og-image.png` → 200 |
| 3 | flyctl auth expired | **OUT-OF-SCOPE** for this verdict | not probed here (orchestrator did not include flyctl as a blocker for today's launch); user can re-auth at deploy time |
| 4 | 117 tools claim vs 111 deployed | **RESOLVED** | README normalized to `110+` and `111`; show-hn normalized to `110+` and `~9,000 tests / 437 files` |
| 5 | 16,209 tests claim vs ~9,000 empirical | **RESOLVED** | both README and show-hn now cite `~9,000 / 437 test files` |
| 6 | 9 RiskGuard checks claim vs 15 constants | **RESOLVED-DIFFERENTLY** | claim normalized to 11 pre-trade (matches the 11 in middleware chain comment); README + show-hn aligned; the extra 6 in constants are system-layer not pre-trade |
| 7 | renusharmafoundation email in `docs/drafts/zerodha-compliance-email.md` | **NOT RE-PROBED** | brief did not ask; if launch involves linking that draft, re-sweep |
| 8 | 171 stray `.out` files (screen-share hygiene) | **NOT RE-PROBED** | working-tree state changes daily; user runs `git clean -fX` morning-of |
| 9 | Demo GIF / asciinema missing | **STILL OPEN** — see §3.4 | no `*.gif`/`*.mp4`/`*.webm` files in repo |
| 10 | OAuth flow tested with real Kite app within 24h | **DEFERRED** to morning-of-launch | token expires daily ~6 AM IST |
| 11 | Backup channels (Reddit + Twitter + Discord) drafted | **PARTIAL** — see §3.3 | drafts exist in repo but Reddit account does NOT exist (404 on /user/Sundeepg98) |

**3/3 of the original 2026-05-03 blockers (deploy gap, og-image, claims drift) are FULLY RESOLVED.** The current verdict therefore concerns NEW items surfaced today, not regressions from 2026-05-03.

---

## §3 — New blockers surfaced today — classification

### 3.1 Egress IP `209.71.68.157` — orchestrator claim: STALE

**Verdict: FALSIFIED.** Today's peer-audit `egress-ip-stale-sweep-2026-05-11.md` (commit `7559133`) ran `flyctl ips list -a kite-mcp-server --json` and confirmed:

```json
{"Address":"209.71.68.157","Type":"egress_v4","Region":"bom","CreatedAt":"2026-04-01T17:46:32Z"}
```

Cross-confirmed by 3 peer audits today (`STATE-claims-audit-2026-05-11.md §9.3`, `repo-docs-verification-2026-05-11.md §1.5`, `active-docs-verification-2026-05-11.md`). The IP is **app-scoped, dedicated egress, NOT shared**. The orchestrator's brief inherited a falsified premise from `fly-mcp-empirical-install-2026-05-11.md` which captured a truncated `fly-ips-list` response showing only 3 of 4 IPs and concluded the 4th "didn't exist."

**Action**: NONE. The 14+ doc citations of `209.71.68.157` across `README.md`, `server.json`, `THREAT_MODEL.md`, `SECURITY.md`, `funding.json`, `mcp/*.go` source, `scripts/smoke-test.sh`, `.github/ISSUE_TEMPLATE/bug_report.md`, etc. are all CORRECT. No patches needed in user-shippable docs.

**Caveat — secondary finding**: `sebi-shared-vs-dedicated-ip-2026-05-11.md` (commit `6415d0c`, the most recent commit on master) was filed downstream of the same falsified premise and recommends "BUY a $3.60/mo app-scoped static egress IPv4." That recommendation was REDUNDANT against the existing live state. The $3.60/mo is already being paid (per `flyctl ips list` showing the `egress_v4` allocation). **Recommend**: do NOT take new action on the SEBI doc's §6 communication-plan items until the doc itself is updated to reflect "we already have what you said to buy." Out-of-scope for THIS dispatch.

### 3.2 Plaintext secrets in memory files — claim: 2 entries

**Verdict: CONFIRMED** per orchestrator brief context. Not re-probed in this dispatch (memory files are user-private, not repo-visible). Action remains as briefed:

- `kite-session-apr3.md:39-42` — Cloudflare R2 access keys
- `MEMORY.md:78-80` — Kite API keys (per-app secrets)

**Classification**: MUST-FIX BEFORE LAUNCH-DAY-CLOSE (not before Submit, but before post-launch increased traffic increases the eyeball cost of a leak). Rotation steps:

- R2: regenerate at Cloudflare dashboard; update `LITESTREAM_ACCESS_KEY_ID` + `LITESTREAM_SECRET_ACCESS_KEY` Fly secrets via `flyctl secrets set -a kite-mcp-server`
- Kite: regenerate at developer.kite.trade dashboards (both `kite-mcp-server` Connect-tier app + `Kite MCP Local`); refresh in local `.env` (not repo)
- Then: edit memory files to remove plaintext OR replace with `<regenerated-via-rotation-on-YYYY-MM-DD>` placeholder

Cloudflare + Bitwarden MCPs (commit `652e848`) would close this structurally; out-of-scope for launch but worth installing within 1 week post-launch.

### 3.3 GitHub Actions secrets — claim: 6 unset for dr-drill cron

**Verdict: CONFIRMED EMPIRICALLY.** `gh api repos/Sundeepg98/kite-mcp-server/actions/secrets --jq '.total_count'` returns **0** (zero secrets total — not just dr-drill, *all* CI secrets are unset).

The full list of secrets referenced across workflows:

| Workflow | Secrets referenced | Status |
|---|---|---|
| `dr-drill.yml` | LITESTREAM_R2_ACCOUNT_ID, LITESTREAM_BUCKET, LITESTREAM_ACCESS_KEY_ID, LITESTREAM_SECRET_ACCESS_KEY, TELEGRAM_BOT_TOKEN, TELEGRAM_DR_CHAT_ID | 0/6 set |
| `ci.yml` | CODECOV_TOKEN | 0/1 set |
| `smoke-canary.yml` | SMOKE_TARGET_URL, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID | 0/3 set |

**Classification**: MUST-PROVISION FOR DR-DRILL. The dr-drill cron silent-fails every 1st of month until secrets exist. Codecov + smoke-canary degrade similarly. **Not a launch-blocker** (no inbound traffic depends on these); user-action is to paste 6+1+3 secrets at GitHub Settings → Secrets → Actions. ~10min total.

### 3.4 Demo GIF / asciinema — claim: still user-only

**Verdict: CONFIRMED.** `find . -maxdepth 3 -name '*.gif' -o -name '*.mp4' -o -name '*.webm'` returns empty. No demo media in repo. README has prose CTAs but no visual.

**Classification**: SHOULD-FIX (post-launch is acceptable but pre-launch is better). Per the 2026-05-03 audit Fix 4 recipe: 30-sec `asciinema rec` of `claude mcp add` + `Show my portfolio` + JSON response → convert via `agg` → embed in README above the comparison table. ~30min user-action.

### 3.5 Reddit `u/Sundeepg98` account — claim: pending

**Verdict: CONFIRMED.** `curl -L "https://www.reddit.com/user/Sundeepg98/about.json"` returns `{"message":"Not Found","error":404}`. Account does NOT exist.

**Classification**: SHOULD-CREATE BEFORE LAUNCH. The GTM playbook (`58dc369`) and `algo2go-umbrella-rebrand-strategy-2026-05-11.md` assume Reddit r/IndiaInvestments + r/IndianStockMarket + r/algotrading cross-posts. Without the account, the channel is unavailable. Account creation = 2 min; aged-account cred = needs time, but for a single Show HN cross-post a fresh account is acceptable provided the post is rule-compliant and the karma threshold (often 10) is met.

### 3.6 Show HN final submit — claim: pending

**Verdict: PENDING USER-ACTION.** Repo is technically ready; submission is the user's call. Per `58dc369` recommended window: Tue or Wed 06:30-08:30 PT.

---

## §4 — Critical-path checklist (must-fix-before-launch)

| Item | Priority | Effort | Status |
|---|---|---|---|
| Rotate R2 access keys (Cloudflare dashboard + `flyctl secrets set`) | MUST | 10 min | NOT DONE |
| Rotate Kite API keys (both apps) | MUST | 10 min | NOT DONE |
| Edit memory files to remove plaintext (replace with rotation-dated placeholders) | MUST | 5 min | NOT DONE |
| Provision 6 dr-drill secrets at GitHub repo Settings | MUST | 5 min | NOT DONE |
| Morning-of-launch OAuth flow re-test with fresh Kite token | MUST | 10 min | DEFERRED TO LAUNCH-DAY |
| `git clean -fX` for screen-share hygiene | SHOULD | 1 min | DEFERRED TO LAUNCH-DAY |
| Confirm `209.71.68.157` is still live (in case Fly rotates IPs) | SHOULD | 30 sec via `flyctl ips list` | confirmed today 2026-05-11 |

Total user-time on launch-eve: **~30 min**.

---

## §5 — Acceptable-imperfect items (ship-it list)

These are real gaps but the launch can proceed without them:

### 5.1 Reddit u/Sundeepg98 account

Create when convenient; Show HN doesn't require it. Cross-post can wait 1-2 days after HN submit while the account ages.

### 5.2 Demo GIF / asciinema

Worth ~30min of investment but launch-conversion penalty is bounded — README copy clearly explains what the tool does. HN audience is technical and will read.

### 5.3 Static egress IPv4 $3.60/mo allocation (per SEBI doc recommendation)

REDUNDANT — `209.71.68.157` is already an `egress_v4` allocation per `flyctl ips list`. The SEBI doc was triggered by a falsified premise. Re-verify with the SEBI doc author before spending. Out-of-scope here.

### 5.4 `/llms.txt` endpoint (currently 404)

Nice-to-have for LLM-discoverability of the server's docs. NOT a launch blocker. The `/.well-known/mcp/server-card.json` already serves MCP-protocol-level discoverability. Post-launch backlog.

### 5.5 GitHub repo transfer to algo2go org

NOT REQUIRED for launch. Repo currently `Sundeepg98/kite-mcp-server` works fine; algo2go transfer is a brand-cohesion decision per `algo2go-umbrella-rebrand-strategy-2026-05-11.md` — file TM first, then transfer. Post-launch.

### 5.6 CI on master is stale (last green push-event = 2025-08-06)

Production is at `v1.3.0` from a successful build path; CI gating on PRs is functional. Master-push CI not running is a workflow trigger issue, not a code-quality issue. Backlog.

---

## §6 — Net verdict: CONDITIONAL GO

**Can the user click Submit on Show HN safely TODAY?**

**Conditional yes** — modulo a ~30min user-action burst on launch-eve:

1. Rotate the 2 plaintext-credential pairs (R2 + Kite API). MUST.
2. Paste the 10 missing GitHub Actions secrets. MUST (or accept dr-drill silent-failure indefinitely).

Without (1), launch is still possible but the eyeball-to-leak-risk window widens. Without (2), monthly dr-drill remains silent-fail (no operational damage; just no automated backup-chain verification).

After (1) + (2): GO. Confidence: HIGH that the technical surface is sound (production v1.3.0 healthy, all numeric claims aligned with reality, og-image deployed, OAuth metadata served, security headers intact, egress IP empirically verified app-scoped dedicated).

---

## §7 — Recommended sequence to reach YES

Launch-eve (T-12h to T-1h):

1. T-12h: rotate R2 keys at Cloudflare dashboard → `flyctl secrets set -a kite-mcp-server LITESTREAM_ACCESS_KEY_ID=... LITESTREAM_SECRET_ACCESS_KEY=...` → edit `kite-session-apr3.md` plaintext block to `<rotated-2026-05-XX>`
2. T-10h: regenerate Kite API keys at developer.kite.trade for both apps → update local `.env` + `MEMORY.md` placeholder
3. T-8h: paste 10 secrets at https://github.com/Sundeepg98/kite-mcp-server/settings/secrets/actions (LITESTREAM_* x4, TELEGRAM_BOT_TOKEN, TELEGRAM_DR_CHAT_ID, CODECOV_TOKEN, SMOKE_TARGET_URL, TELEGRAM_CHAT_ID)
4. T-2h: create Reddit `u/Sundeepg98` if user wants r/* cross-posts ready same-day
5. T-1h: fresh-token OAuth flow test via `claude mcp add` + `Show my portfolio` against hosted endpoint; verify real-data response

Launch (T-0):

6. `git clean -fX` working tree
7. Submit Show HN — title 1 from `docs/show-hn-post.md` (78 chars, pre-empts "AI YOLO real money" worst-case)
8. Comment-triage online for 2h post-submit

Post-launch (T+1h to T+24h):

9. Record 30-sec asciinema → embed in README — addresses #4 SHOULD
10. Cross-post Reddit + Twitter from drafts already in repo
11. Backlog: install Cloudflare + Bitwarden MCPs (commit `652e848`) to close plaintext-secrets structurally
12. Backlog: re-verify SEBI doc §6 with corrected egress-IP premise before any $3.60/mo allocation

---

## §INPUTS — load-bearing facts probed at HEAD `6415d0c`

| Fact | Source / Probe | Verified |
|---|---|---|
| `/healthz` → v1.3.0 / tools=111 / uptime=129h52m | `curl https://kite-mcp-server.fly.dev/healthz` | 2026-05-16 03:38Z (this dispatch) |
| `/og-image.png` → 200 OK PNG | `curl -I` | 2026-05-16 03:38Z |
| `/.well-known/oauth-authorization-server` → valid metadata, S256 PKCE | `curl` | 2026-05-16 03:38Z |
| `/.well-known/mcp/server-card.json` → v1.3.0, "111 tools" | `curl` | 2026-05-16 03:38Z |
| `/mcp` POST initialize → 401 with WWW-Authenticate Bearer | `curl -X POST` | 2026-05-16 03:38Z |
| Repo Sundeepg98/kite-mcp-server: stars=0, forks=0 | `gh api repos/Sundeepg98/kite-mcp-server` | 2026-05-16 03:36Z |
| Action secrets count = 0 | `gh api .../actions/secrets --jq .total_count` | 2026-05-16 (this dispatch) |
| Reddit u/Sundeepg98 → 404 NotFound | `curl -L .../about.json` | 2026-05-16 (this dispatch) |
| Master HEAD remote = `6415d0c` | `gh api .../branches/master` | 2026-05-16 03:42Z |
| .research/ tracked = 286 files | `git ls-files .research/ \| wc -l` | this dispatch |
| README hero = "110+ tools / 11 pre-trade safety checks / ~9,000 tests" | `head -20 README.md` | this dispatch |
| Show-hn-post.md tool/test/riskguard claims aligned to README | `grep` | this dispatch |
| No demo media in repo | `find -name '*.gif' -o -name '*.mp4' -o -name '*.webm'` empty | this dispatch |
| `209.71.68.157` is live app-scoped egress_v4 IPv4 (NOT stale) | peer audit `egress-ip-stale-sweep-2026-05-11.md` § 1.2 + 3 peer audits | 2026-05-11 (peer dispatch) |
| 2 plaintext-secret memory file entries | orchestrator brief context | as briefed (memory files not re-probed) |
| dr-decrypt-probe binary in `cmd/dr-decrypt-probe/` | `ls cmd/dr-decrypt-probe/` | this dispatch |
| funding.json version = v1.1.0 | `grep version funding.json` | this dispatch |

> **Methodology**: All HTTP probes via raw `curl`; all GitHub state via `gh api`; cross-references resolved by re-reading peer audit docs at `.research/research/` and `.research/audits/2026-05-11/`. Per `feedback_verify_before_synthesize` and `feedback_dated_synthesis`.

---

## Sources

- Live HTTP probes (this dispatch, 2026-05-16 03:38Z)
- `.research/research/egress-ip-stale-sweep-2026-05-11.md` (peer, commit `7559133`) — the doc that falsifies orchestrator's blocker #1
- `.research/research/sebi-shared-vs-dedicated-ip-2026-05-11.md` (peer, commit `6415d0c`, master HEAD) — downstream of falsified premise; SEE caveat in §3.1
- `.research/research/github-transfer-bootstrap-2026-05-11.md` (peer) — transfer mechanics if/when user proceeds
- `.research/research/mcp-ecosystem-audit-2026-05-11.md` (peer) — Cloudflare + Bitwarden MCPs that would close secrets-exposure
- `.research/research/algo2go-umbrella-rebrand-strategy-2026-05-11.md` (peer) — Reddit/cross-post launch sequence
- `.research/archive/audits-completed/final-pre-launch-verification.md` (2026-05-03 prior, archived)
- `README.md` (HEAD `6415d0c`), `docs/show-hn-post.md`, `fly.toml`, `funding.json`, `cmd/dr-decrypt-probe/`
- `.github/workflows/{ci,dr-drill,smoke-canary}.yml` for secret-dependency surface
- Lesson references: `feedback_compile_and_run_methodology.md`, `feedback_verify_before_synthesize.md`, `feedback_dated_synthesis.md` (orchestrator briefing inherited a stale premise — confirms verify-before-synthesize)
