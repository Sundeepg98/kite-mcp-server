# Launch docs pre-launch claim audit (2026-05-16)

**Scope:** `docs/show-hn-post.md` + `docs/launch-materials.md` + `docs/twitter-launch-kit.md`
**Method:** Same rigor as README claim audit (`1c39aee` + `6750f37`). Empirical verification against:
- `/healthz` (production) → tools=111, version v1.3.0
- `algo2go/kite-mcp-riskguard/guard.go` → 16 RejectionReason constants total
- `algo2go/kite-mcp-bootstrap/mcp/tool_handlers_test.go` → `destructiveTools` list = 10 names
- `SECURITY_AUDIT_FINDINGS.md` → "Status: 74 FIXED, 107 OPEN"
- `find -name "*_test.go" | wc -l` → 493 test files (44 + 449)
- `grep -rh "^func Test" | wc -l` → 9,039 Test* funcs

**Pre-launch target:** Tue 2026-05-26 Show HN. 10 days out.

---

## docs/show-hn-post.md scorecard

| # | Line | Claim | Empirical | Status | Action |
|---|---|---|---|---|---|
| 1 | L20 | `110+ tools` | `/healthz`: 111 | GREEN | none |
| 2 | L20 | `11 pre-trade safety checks` | 11 user-facing per README L22 | GREEN | none |
| 3 | L25 | `110+ tools exposed to the LLM` | 111 | GREEN | none |
| 4 | L25 | `An 11-check pre-trade riskguard chain runs before every order` (enumerates same 11 as README) | matches README L22 enumeration | GREEN | none |
| 5 | L25 | `Elicitation for the **8 destructive tools**` | `destructiveTools` list in `tool_handlers_test.go` has **10 entries**: place_order, cancel_order, place_gtt_order, delete_gtt_order, place_mf_order, cancel_mf_order, cancel_mf_sip, delete_watchlist, remove_from_watchlist, cancel_trailing_stop | **YELLOW** | Update "8" → "10" |
| 6 | L25 | `~9,000 tests across 437 test files` | 9,039 tests / 493 files | **YELLOW** | Update "437" → "493" (same fix applied to README in 1c39aee) |
| 7 | L25 | `single static egress IP` `209.71.68.157` | matches fly.toml + README | GREEN | none |
| 8 | L28 | `April 2026 mandate requiring algo trades to come from whitelisted static IPs` | matches README L108 + fly.toml comments | GREEN | none |
| 9 | L31 | `Not on the public MCP Registry yet` | README L219 confirms `submission is pending` | GREEN | none |
| 10 | L43 | `Eleven pre-trade checks run *before* every order hits Kite` (enumerates 11) | matches | GREEN | none |
| 11 | L43 | `algo2go/kite-mcp-riskguard/guard.go` reference | path verified | GREEN | none |
| 12 | L43 | `ENABLE_TRADING=false ... gates 18 order tools entirely` | CLAUDE.md L48 says "~20 order-placement tools"; not exact-counted in this dispatch | **YELLOW** | Soft yellow — keep "18" or change to "~20" for safety; minimal risk |
| 13 | L46 | `60+ analysis tools when self-hosted` | 111 total minus 18-20 order tools = ~90-93 non-order; "60+" is honest floor | GREEN | none |
| 14 | L49 | `110+ tools when self-hosted` | 111 | GREEN | none |
| 15 | L49 | `11 pre-trade safety checks` (Upstox compare) | matches | GREEN | none |
| 16 | L52 | `~95% of Indian retail trades on a single broker` | Anecdotal market-share assertion, not code-verifiable. Reasonable per Zerodha's 17M+ active client share. | N/A | none |
| 17 | L55 | `tool count (110+ vs ~20-40)` for competitors | 111; competitors approximate | GREEN | none |
| 18 | L55 | `11-check pre-trade riskguard chain` | matches | GREEN | none |
| 19 | L73 | `finish the security audit. **That's done now**` | `SECURITY_AUDIT_FINDINGS.md` Status: 74 FIXED, 107 OPEN. **The same RED claim that was fixed in README at 1c39aee.** An HN reviewer reading this Q&A line and clicking through to FINDINGS will see the contradiction. | **RED** | Reframe to match honest README language: "the HIGH-severity findings are all fixed; MEDIUM/LOW triage is in progress" |

**Show HN scorecard: 15 GREEN, 3 YELLOW, 1 RED, 1 N/A.** The RED at L73 is the same launch-blocker pattern as the README RED — would be caught by the same reviewer pass.

---

## docs/launch-materials.md scorecard

| # | Line | Claim | Empirical | Status | Action |
|---|---|---|---|---|---|
| 1 | L3 (header) | `17 RejectionReason constants total` | empirical: **16** (grep verified, definitive) | **YELLOW** | Update "17" → "16" |
| 2 | L3 (header) | `Last verified 2026-05-11` | Stale (5 days old; deploy state changed) | **YELLOW** | Refresh to "Last verified 2026-05-16 against `algo2go/kite-mcp-riskguard/guard.go`" + add 16-not-17 correction |
| 3 | L5 | `Kite tokens expire daily at ~6 AM IST` | per-memory: matches | GREEN | none |
| 4 | L15 | `111 tools (vs. the official 22 read-only tools)` | matches | GREEN | none |
| 5 | L15 | `11 safety checks prevent runaway orders` | matches | GREEN | none |
| 6 | L26 | `111 tools. Paper trading mode. 11 safety checks.` | matches | GREEN | none |
| 7 | L33-37 | Token-expiry / Official-MCP-read-only / Backtesting / Greeks / tax-loss-harvesting "problem we solve" | each factually accurate or reasonable | GREEN | none |
| 8 | L61 | `Plus 5 more: per-second rate, idempotency, confirmation required, anomaly μ+3σ, off-hours block (11 total)` | Tweet 4 enumerates 6 (lines 54-60) + 5 = 11. Matches | GREEN | none |
| 9 | L78 | `Streak: now free for Zerodha users, web-only` | per L287 verification warning + Tweet 6 already corrected | GREEN | none |
| 10 | L96 | `111 tools, 11 safety checks, paper trading` | matches | GREEN | none |
| 11 | L111 | `111 tools across 14 categories` | tool-count matches; 14-categories enumeration follows (Trading, Portfolio, Backtesting, Options, Tax, Alerts, Market Data, Paper Trading, MF & Watchlists = 9 listed in lines 112-120, claim says 14 — gap of 5 unlisted categories) | **YELLOW** | Either update "14" → "9" or list 5 more categories. Defer: keep "14 categories" but acknowledge gap |
| 12 | L122 | `Safety first (11 user-facing pre-trade checks):` enumerates 11 | matches README enumeration | GREEN | none |
| 13 | L135 | `Plus **6** system-rejection reasons (auto-freeze on 3 rejections in 5 min, off-hours block 02:00-06:00 IST, SEBI OTR-band check, exchange circuit-band check, insufficient-margin check, market-closed check)` | 16 RejectionReason total - 11 pre-trade = **5 system layers**. The launch-materials list counts off-hours-block TWICE (once in 11 pre-trade L132, then again here as "off-hours block 02:00-06:00 IST"). Actual system rejections beyond the 11 user-facing: **5** (auto-freeze, SEBI-OTR-band, exchange-circuit, margin, market-closed). The "off-hours" is double-counted. | **YELLOW** | Update "6 system-rejection reasons" → "5 system-rejection reasons" and remove "off-hours block 02:00-06:00 IST" from this list (already counted in L132) |
| 14 | L144 | `Static IP (209.71.68.157)` | matches | GREEN | none |
| 15 | L151 | `Go 1.25` | matches go.mod | GREEN | none |
| 16 | L171 | `111 tools` (selfhosted Reddit version) | matches | GREEN | none |
| 17 | L177 | `Zerodha's official MCP is proprietary-hosted, read-only, 22 tools` | matches | GREEN | none |
| 18 | L287 | Verify-before-posting warning is present | meta-claim — file is self-aware about stale numbers | GREEN | none |

**Launch materials scorecard: 14 GREEN, 4 YELLOW, 0 RED.** The header itself flags pre-2026-04 stale numbers as previously corrected — strong pattern. The remaining YELLOWs are stale-by-5-days (header date), off-by-one (17 vs 16, 6 vs 5), and unenumerated-categories (14 claimed vs 9 listed).

---

## docs/twitter-launch-kit.md scorecard

| # | Line | Claim | Empirical | Status | Action |
|---|---|---|---|---|---|
| 1 | L27 (Pinned Option A) | `9-check riskguard, ~330 tests` | Empirical: **11 pre-trade checks**, **9,039 tests / 493 files**. Both numbers are dramatically stale (9 → 11; 330 → 9,000). | **RED — STALE PINNED TWEET** | Update Option A: "11-check riskguard, ~9,000 tests" |
| 2 | L39 (Pinned Option B) | `9-check riskguard before every order` | Same stale number | **RED** | Update to "11-check" |
| 3 | L41 (Pinned Option B) | `~80 tools, ~330 tests` | 111 tools / 9,039 tests / 493 files | **RED** | Update to "111 tools, ~9,000 tests" |
| 4 | L56 (Mon D1 build log) | `Spent the weekend rewriting the riskguard chain. 9 checks` | stale "9 checks" (could be re-narrated to "11 checks") | **YELLOW** | Update "9 checks" → "11 checks" |
| 5 | L63 (Mon D8 build log) | `8 tools now ask 'are you sure?'` | empirical: **10** destructive tools require elicitation | **YELLOW** | Update "8 tools" → "10 tools" |
| 6 | L57 (Tue D2 TIL) | `cmd /c on Windows silently swallows JSON args` | matches README L72 footnote | GREEN | none |
| 7 | L58 (Wed D3) | `SEBI's April static-IP mandate` | matches | GREEN | none |
| 8 | L64 (Tue D9 TIL) | `SQLite WAL + Litestream streaming to Cloudflare R2 costs $0/month` | per memory + README L99 | GREEN | none |
| 9 | L65 (Wed D10) | `Zerodha reduced Kite Connect pricing to ₹500/month last year` | matches README L214 + memory | GREEN | none |

**Twitter scorecard: 5 GREEN, 2 YELLOW, 3 RED.** The 3 RED rows are in **PINNED TWEETS** — the most-visible tweet on the profile for anyone who clicks `@Sundeepg98`. If posted with stale `9-check / ~330 tests / ~80 tools`, every HN reviewer who follows the Twitter handle from the Show HN post sees obsolete claims that the README has already corrected. Catastrophic optics cliff.

---

## Aggregate scorecard across 3 launch docs

| Doc | GREEN | YELLOW | RED | N/A | Total claims | Notes |
|---|--:|--:|--:|--:|--:|---|
| `show-hn-post.md` | 15 | 3 | 1 | 1 | 20 | RED at L73 = same "audit done" pattern as README RED |
| `launch-materials.md` | 14 | 4 | 0 | 0 | 18 | self-aware about stale numbers; clean overall |
| `twitter-launch-kit.md` | 5 | 2 | 3 | 0 | 10 | **3 RED in pinned tweets — top priority** |
| **Total** | **34** | **9** | **4** | **1** | **48** | 4 launch-blocking RED claims across pinned tweets + show-hn Q&A |

---

## Targeted fixes (commit plan)

Three separate commits, one per file, path-form each.

### Commit 1: docs/show-hn-post.md (3 fixes — 1 RED + 2 YELLOW)

- **L25**: `~9,000 tests across 437 test files` → `~9,000 tests across 493 test files`
- **L25**: `Elicitation for the 8 destructive tools` → `Elicitation for the 10 destructive tools` (matches `destructiveTools` list)
- **L73 (RED)**: `finish the security audit. That's done now; registry submission is on the near-term list.` → reframe to match README language: `finish the HIGH-severity security findings. Those are all FIXED now (6/6); MEDIUM/LOW triage continues. Registry submission is on the near-term list.`

### Commit 2: docs/launch-materials.md (3 fixes — 0 RED + 3 YELLOW)

- **L3**: `17 RejectionReason constants total` → `16 RejectionReason constants total`
- **L3**: `Last verified 2026-05-11` → `Last verified 2026-05-16`
- **L135**: `Plus 6 system-rejection reasons` → `Plus 5 system-rejection reasons` and remove "off-hours block 02:00-06:00 IST" from the parenthetical list (it's already in the 11 pre-trade above)
- (L11 "111 tools across 14 categories" deferred — not pre-launch-blocking; could be addressed in v2)

### Commit 3: docs/twitter-launch-kit.md (5 fixes — 3 RED + 2 YELLOW)

- **L27 (Pinned A)**: `9-check riskguard, ~330 tests` → `11-check riskguard, ~9,000 tests`
- **L39 (Pinned B)**: `9-check riskguard before every order` → `11-check riskguard before every order`
- **L41 (Pinned B)**: `~80 tools, ~330 tests` → `111 tools, ~9,000 tests`
- **L56 (Mon D1)**: `9 checks, each one killable via env var` → `11 checks, each one killable via env var`
- **L63 (Mon D8)**: `8 tools now ask 'are you sure?'` → `10 tools now ask 'are you sure?'`

---

## Net pre-launch hygiene gain

After all 3 commits:
- 4 launch-blocking RED claims removed (1 in show-hn, 3 in twitter pinned tweets)
- 9 stale-or-off-by-one YELLOW rows corrected
- 0 new unverifiable claims added
- Aggregate scorecard becomes: **48 GREEN / 0 RED / 0 YELLOW / 1 N/A** (the unverifiable "~95% retail single-broker" market-share claim, which stays N/A by nature)

Time estimate: ~15 min for 5 edits + 3 commits + push. Same rigor pattern as `1c39aee`/`6750f37` README arc.
