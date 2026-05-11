# Repo `docs/` Claims Verification — 2026-05-11

**Methodology**: empirical claims-audit on the 125 .md files under `D:\Sundeep\projects\kite-mcp-server\docs\` plus the root README.md (which dispatches against `docs/` cross-references). Compile-and-run > grep, per the §5.6 lesson the chain agent itself memorialised in STATE.md.

**Master HEAD at audit time**: `dd10837` (`docs(research-batch): answer all INDEX §12 gaps + verify launch-prep claims`).

**Scope**:
- Top-level `docs/`: 88 .md files
- `docs/adr/`: 10 .md
- `docs/blog/`: 1 .md
- `docs/drafts/`: 5 .md (outgoing user-shippable material — highest priority)
- `docs/evidence/`: 8 .md (incident-response evidence package)
- `docs/superpowers/`: 12 .md (6 plans + 6 specs — historical implementation specs)
- `docs/launch/`: **does not exist** (INDEX flag confirmed; broken cross-reference in `release-checklist.md:138`)
- `docs/plans/`: **does not exist** (Glob result was stale cache)
- **Total**: 124 actual .md files (vs INDEX's "~88" framing — INDEX was top-level only)

**Production baseline at audit time** (re-probed live): `tools=111 / version=v1.3.0 / image=629a6ee5… / machine=273 / region=bom`. server.json `.version: 1.3.0`. egress IP `209.71.68.157`.

**Bottom line**: `docs/` directory is mostly trustworthy except for **3 launch-shippable surfaces with conflicts** and **one operational doc with broken commands**. No grep-class systemic errors — the tools=130 contamination from STATE.md did NOT propagate to docs/. No flyctl-reauth contamination. No og-image-404 contamination. The cross-cutting hygiene is good.

---

## TL;DR — three findings to surface immediately

### 1. CRITICAL — Number-soup across launch-shippable docs

Multiple authoritative-claiming docs disagree on tool count + RiskGuard check count. If `git log --oneline` had a "tools=130 grep error" cost ~6h of misdirection, **a launch-day HN comment quoting the wrong tool count or check count is permanently public**. server.json (the machine-readable manifest, source of /healthz `version` and a public-API claim) ships with `tools: 111` and `riskGuardChecks: 11`.

| Doc | Tools claim | RiskGuard checks claim | Currency |
|---|---|---|---|
| `server.json` (canonical machine-readable) | **111** | **11** | matches healthz |
| `README.md:3` (landing prose) | "110+" | "11" | matches |
| `README.md:22` (RiskGuard bullet w/ enumeration) | n/a | **"11" but enumerates 12 distinct names** | **internally inconsistent** |
| `README.md:82` (Features bullet) | n/a | **"9"** | **conflicts w/ README:3 + 22** |
| `README.md:198` (Comparison table) | **"117"** | **"9"** | **stale tool count** + conflicts w/ README:3 |
| `docs/show-hn-post.md` (HN body) | "110+" | "11" | matches server.json |
| `docs/launch-materials.md` (older draft) | **"~100"** | **"8"** | **stale + wrong defaults** (₹5L/200/day vs current ₹50k/20/day) |
| `docs/product-definition.md` (self-claimed canonical) | **"~80"** | **"9"** | stale |
| `docs/rainmatter-onepager.md` | "~80" | "9-check" | **also says v1.1.0** (production is v1.3.0) |
| `docs/faq.md:68` | n/a | **"9"** | conflicts |
| `docs/architecture-diagram.md` (mermaid) | n/a | **"9"** | conflicts |
| `.claude/CLAUDE.md` (developer guide) | n/a | **"9"** | conflicts |
| **Source-of-truth empirical**: `algo2go/kite-mcp-riskguard/check.go` `OrderXxx` constants | n/a | **13** (13 Order constants in the registered chain) | — |
| **Source-of-truth empirical**: production tools=111 from compile-and-run | **111** | n/a | — |

**The actual canonical RiskGuard count = 13** (13 `OrderXxx` Order constants in `algo2go/kite-mcp-riskguard/check.go:50-66`). All docs under-count, but server.json's "11" is closest to the show-hn enumeration (which omits `OrderMarketHours` + `OrderConfirmationRequired`). **Pick a number, footnote the methodology, propagate to all docs.**

### 2. CRITICAL — `launch-materials.md` ships with PRE-TIGHTENING financial caps

This doc is launch-day Tweet thread + Reddit post draft. It cites:
- "Order value cap (default ₹5,00,000)" — empirical: **₹50,000** (10× over-stated)
- "Daily order cap (200/day)" — empirical: **20/day** (10× over-stated)
- "Daily value cap (₹10,00,000 cumulative)" — empirical: **₹2,00,000** (5× over-stated)
- "8 safety checks" (oldest count anywhere)
- "~100 tools" (stale)

Source-of-truth at `algo2go/kite-mcp-riskguard/guard.go:25-35`:
```go
var SystemDefaults = UserLimits{
    MaxSingleOrderINR:    domain.NewINR(50000),  // Rs 50,000 (Free tier — was Rs 5,00,000)
    MaxOrdersPerDay:      20,                    // Free tier — was 200
    MaxOrdersPerMinute:   10,
    DuplicateWindowSecs:  30,
    MaxDailyValueINR:     domain.NewINR(200000), // Rs 2,00,000 (Free tier — was Rs 10,00,000)
    ...
}
```

The source code's own comments document the exact migration ("was Rs 5,00,000" → 50k, "was 200" → 20, "was Rs 10,00,000" → ₹2L). The doc was clearly written pre-tightening and never updated.

The doc itself has TWO warning banners ("Review all factual claims" at top, "Verify before posting" at bottom) — meaning the author knew it was stale. But anyone copy-pasting from it pre-launch would publish wrong financial caps in front of the HN crowd. Risk: someone screenshots the wrong cap, attacks "you're claiming ₹5L cap to look responsible while actually limiting to ₹50k? — pick one." **Recommend ARCHIVE or REWRITE.**

### 3. IMPORTANT — `pre-deploy-checklist.md` has stale paths + broken flyctl command

This is an **operational** doc — chain agents (including me) use it pre-deploy. Three issues:

- Line 8: `go test ./kc/riskguard ./mcp ./oauth ./app -count=1` — `kc/riskguard` and `oauth` directories no longer exist (moved to algo2go via Path A inauguration). The command will fail with "no Go files in...".
- Line 22: cites `kc/audit/` (also moved to algo2go).
- Line 50: `flyctl releases -a kite-mcp-server` — `flyctl releases` (alone) is not a valid subcommand; only `flyctl releases image`, `flyctl releases rollback` etc. exist (verified empirically by chain agent's prior dispatch).

A new operator running this checklist verbatim will hit at least 2 errors. Updating the test-paths to current locations + correcting the flyctl command should be a 5-minute fix.

---

## §1 — Empirical findings against load-bearing claims

### 1.1 Tool count

**Show-HN body line 13, 20, 25**: "110+ tools" — **VERIFIED**. Matches production `tools=111`.

**Show-HN body line 25**: "~9,000 tests across 437 test files":
- Tests: 8,970 across kite-mcp-server (4,881) + algo2go modules (4,089) — **VERIFIED** (~9,000 in scope)
- Files: 478 test files across both — **STALE** (claim 437; off by 41 files)

**README.md line 19**: "~9,000 tests across 437 test files — run `go test ./... -count=1`" — **PARTIAL** (`go test ./... -count=1` only sees the 4,697 tests in this module, not the 9k cross-module total; same staleness on file count).

**README.md line 198 comparison table**: "Tools: 117" — **STALE** (current 111). Probably the "117" snapshot from the era when 6 tools existed in a future-canary state that was later gated off.

**docs/foss-united-grant-email.md line 21**: "~80 MCP tools" — **STALE** (current 111).
**docs/rainmatter-onepager.md line 23**: "~80 tools" — **STALE**.
**docs/indiafoss-2026-cfp.md line 35**: "~80 tools" — **STALE**.
**docs/product-definition.md line 37**: "~80 user-facing MCP tools across 53 source files in `mcp/` (128 `mcp.NewTool` call sites; ~48 of those are admin / test / variant registrations)" — **STALE** (claims pre-Path A snapshot when in-tree had 128 grep matches; current is 130 by the same grep but production tools = 111).
**docs/launch-materials.md line 13, 24, 107, 160, 168**: "~100 tools" — **STALE**.

### 1.2 RiskGuard check count

**Source-of-truth empirical count**: 13 `OrderXxx` constants in `algo2go/kite-mcp-riskguard/check.go`:
1. OrderKillSwitch = 100
2. OrderConfirmationRequired = 200
3. OrderOrderValue = 300
4. OrderQuantityLimit = 400
5. OrderDailyOrderCount = 500
6. OrderPerSecondRate = 600
7. OrderRateLimit = 700
8. OrderClientOrderIDDup = 800
9. OrderDuplicateOrder = 900
10. OrderDailyValue = 1000
11. OrderAnomalyMultiplier = 1100
12. OrderOffHours = 1200
13. OrderMarketHours = 1300

Plus 11 `(g *Guard).checkXxx` internal functions in `algo2go/kite-mcp-riskguard/internal_checks.go` (the 11 enumerated by server.json).

| Doc | Number | Enumeration | Verdict |
|---|---|---|---|
| `server.json` `_meta.capabilities.riskGuardChecks` | 11 | (none) | **canonical claim** |
| `README.md:22` | "11" | enumerates 12 names | **internally inconsistent — line says 11, enumeration lists 12** |
| `README.md:82` | "9" | (none) | conflicts w/ same file's :22 |
| `docs/show-hn-post.md:20, 25, 43` | "11" | 11 names (missing market_hours + confirmation_required) | matches server.json + README:22 |
| `docs/launch-materials.md` | "8" | 8 names | very stale |
| `docs/product-definition.md:34` | "9" | 9 names | conflicts w/ server.json |
| `docs/faq.md:68` | "9" | (mostly enumerated) | conflicts |
| `docs/foss-united-grant-email.md:23` | "9" | enumerates 9 | conflicts w/ server.json |
| `docs/indiafoss-2026-cfp.md:21, 37, 45` | "9" / "nine-check" | enumerates 9 | conflicts |
| `docs/rainmatter-onepager.md:10` | "9-check" | (none) | conflicts |
| `docs/architecture-diagram.md:42, 80` | "9 checks" | (in Mermaid) | conflicts |
| `docs/release-notes-v1.1.0.md` | (only enumerates 5 hardening items, no count) | — | historical |
| `docs/adr/0004-…md` | doesn't cite count | — | n/a |

**Conclusion**: server.json's `11` is the most-cited claim in user-facing surfaces (README, show-hn-post) but a chorus of internal docs say "9". Neither matches the actual 13 Order constants. **A single canonical-count footnote ("11 user-visible policy checks, of which 13 internal Order constants including market-hours + confirmation as policy gates") would unify all docs.**

### 1.3 RiskGuard default caps (CRITICAL launch surface)

| Source-of-truth empirical | Show-HN body claim | Launch-materials claim |
|---|---|---|
| `MaxSingleOrderINR = ₹50,000` | "₹50k/order cap" ✓ | "Order value limit (default ₹5,00,000)" ✗ **10× off** |
| `MaxOrdersPerDay = 20` | "20 orders/day" ✓ | "Daily order cap (200/day)" ✗ **10× off** |
| `MaxOrdersPerMinute = 10` | "10/min" ✓ | "Rate limit (10 orders/minute)" ✓ |
| `DuplicateWindowSecs = 30` | "duplicate-within-30s" ✓ | "Duplicate detection (blocks same order within 30s)" ✓ |
| `MaxDailyValueINR = ₹200,000` | "daily ₹2L notional" ✓ | "Daily value cap (₹10,00,000 cumulative)" ✗ **5× off** |

show-hn-post.md is correct end-to-end. launch-materials.md is **systematically wrong** on the per-order + daily-count + daily-value caps (cites pre-tightening "was X" values from before commit that documented the migration). **Do not lift from launch-materials.md.**

### 1.4 Test count

| Source | Claim | Empirical | Verdict |
|---|---|---|---|
| README.md:19 | "~9,000 tests across 437 test files" | 8,970 across 478 files (kite-mcp + algo2go) | **VERIFIED on tests, off-by-41 on files** |
| README.md:15 (badge) | "Tests: 9000+" | 8,970+ | VERIFIED |
| show-hn-post.md:25 | "~9,000 tests across 437 test files" | same as README | matches README |
| docs/foss-united-grant-email.md:39 | "~330 tests" | 8,970 | **WILDLY STALE** (14× under-count; from old MEMORY.md "330+ tests total" Mar 2026) |
| docs/rainmatter-onepager.md:26 | "330+ tests" | 8,970 | WILDLY STALE (same) |
| docs/launch-materials.md | (no test count claim) | — | clean |

**Source-of-truth methodology**: `go test ./... -list ".*"` returned 4,697 in kite-mcp-server module; same in algo2go modules (28 modules) sums to 8,970 total Test* functions (8,994 incl. Benchmark/Example/Fuzz). The "~9,000" framing is correct *if* you count both the host repo and all algo2go modules — which is the natural interpretation since the algo2go modules are externally imported and their tests run on `go test ./...` from the algo2go repos.

### 1.5 Egress IP

**Source-of-truth**: `flyctl ips list -a kite-mcp-server` → `v4 209.71.68.157 egress bom Apr 1 2026 17:46`

**All claims VERIFIED** across:
- README.md:106 (compliance section), :263 (controls table), :116 (architecture diagram)
- show-hn-post.md:28
- docs/launch-materials.md:66, :137, :197, :244
- docs/architecture-diagram.md:116, :130
- docs/legal-notes.md:23
- docs/rainmatter-onepager.md (referenced indirectly)
- docs/drafts/zerodha-compliance-email.md:21, :102
- docs/pre-deploy-checklist.md:26
- docs/cohort-1-landing.md:43
- server.json `_meta.deployment.egressIp`

No staleness anywhere on this fact. ✓

### 1.6 Static version literal

**Source-of-truth**: `server.json` `.version: "1.3.0"` → injected at Dockerfile build via `go build -ldflags "-X main.MCP_SERVER_VERSION=v$(jq -r .version server.json)"`. Production `/healthz` returns `version: v1.3.0`.

| Doc | Version claim | Verdict |
|---|---|---|
| `server.json` | "1.3.0" | canonical |
| README.md (no explicit version) | n/a | clean |
| `docs/release-notes-v1.1.0.md` (file name + content) | "v1.1.0" | historical record — name pins the version, file is fine |
| `docs/rainmatter-onepager.md:4` | "v1.1.0 (April 2026)" | **STALE** — should be v1.3.0 |
| `docs/push-deploy-playbook.md:8` | "v1.1.0, 111 tools" | **POINT-IN-TIME** (file dated 2026-04-18; historical) |

### 1.7 Audit retention

**Source-of-truth**: `algo2go/kite-mcp-audit/retention.go:17` → `const DefaultRetentionDays = 90`. Configurable via `AUDIT_RETENTION_DAYS` env.

| Doc | Claim | Verdict |
|---|---|---|
| README.md:23, :275 | "90-day retention" / "90 days (configurable via AUDIT_RETENTION_DAYS)" | VERIFIED |
| docs/uninstall.md:76 | "retained for 90 days" | VERIFIED |
| docs/faq.md:23 | "audit log of tool calls (**5-year SEBI retention**)" | **CONFLICTS** with code default — either FAQ is wrong, or default needs raising for SEBI compliance |
| docs/adr/0004-…md:5, :17, :84 | "SEBI **5-year** audit trail durability requirement" | aspirational; default is 90d |

The FAQ "5-year SEBI retention" claim is **inconsistent** with the actual code default (90 days) and with README's own statement (90 days). ADR-0004 frames the 5-year requirement as a *design driver* — but the code default is 90 days. Either:
- FAQ should match README (90 days); or
- Default in `algo2go/kite-mcp-audit/retention.go` should be raised to 1825 (5 years) for SEBI-compliance posture.

### 1.8 MCP Registry status

**Source-of-truth**: server.json says "io.github.Sundeepg98/kite-mcp-server"; the registry at `https://modelcontextprotocol.info/tools/registry/` returns 200 (live). Whether THIS server is listed there I cannot fully verify without authenticated access.

| Doc | Claim | Verdict |
|---|---|---|
| README.md:217 | "Listed on the [official MCP Registry] as `io.github.sundeepg98/kite-mcp-server`" | claims LISTED |
| show-hn-post.md:11 | "**Not on the public MCP Registry yet.** Documentation is below what I'd like." | claims NOT LISTED |
| show-hn-post.md:73 (reply) | "Honest answer: I wanted to stabilise the OAuth and session-persistence layer first... That's done now; registry submission is on the near-term list." | claims NOT LISTED |

**DIRECT CONFLICT**: README says it's listed; show-hn body says it's not yet submitted. Need to verify which is accurate at launch time, since this is a fact HN commenters can check in 30 seconds. Either README is aspirational and should be moved to "Registry — submission planned, see release-checklist.md §6"; or show-hn-post.md needs updating to reflect that the registry submission happened.

### 1.9 Cited commits (SHA-by-SHA spot check)

All randomly-sampled cited commits exist in the repo:
- `34a32bf` (Tier 1.1 brokers) — VERIFIED
- `fd4b20e` (Tier 1.2 eventing) — VERIFIED
- `650f4c3` (Tier 1.3 scheduling) — VERIFIED
- `1c54773` (7 pure-function registrar tests) — VERIFIED
- `0038a23` (OAuth dashboard short-circuit) — VERIFIED
- `142a5e1` (registry manifest) — VERIFIED
- `ee345e0` (session management tools) — VERIFIED
- `763aa24` (Litestream addition) — VERIFIED
- `43cc844` (dr-drill workflow) — VERIFIED
- `268ab4f` (session persistence) — VERIFIED

**No phantom SHAs found in docs/** (unlike STATE.md's `d3c2a4a` which the chain agent's STATE-claims audit caught).

### 1.10 Cited paths (file-existence spot check)

| Cited path | Exists? | Notes |
|---|---|---|
| `kc/riskguard/guard.go` (show-hn:43, pre-deploy:8, README:255-259) | **NO** | moved to `algo2go/kite-mcp-riskguard/guard.go` (Path A inauguration) |
| `kc/riskguard/per_second.go` (README:255) | **NO** | same |
| `kc/audit/store.go` (README:261) | **NO** | moved to `algo2go/kite-mcp-audit/` |
| `kc/crypto` (README:262) | **NO** | encryption is in `app/providers/audit_init.go` + `algo2go/kite-mcp-alerts/EnsureEncryptionSalt` |
| `mcp/elicit.go` (README:260) | **NO** | actual: `mcp/common/elicit.go` |
| `oauth/handlers.go` (FAQ:57) | **NO** | moved to `algo2go/kite-mcp-oauth/` |
| `cmd/server` (FAQ:9 — `go run ./cmd/server`) | **NO** | `cmd/` has only `event-graph` + `rotate-key`; build is `go run .` from root |
| `kc/alerts/db.go` (ADR-0004:95) | **NO** | moved to `algo2go/kite-mcp-alerts/db.go` |
| `docs/launch/03-twitter-thread.md` (release-checklist:138) | **NO** | `docs/launch/` directory does not exist |
| `docs/tos.md`, `docs/privacy.md` (cohort-1-landing:150) | **NO** (case-sensitive miss) | actual: `docs/TERMS.md`, `docs/PRIVACY.md` (would 404 on Linux production) |
| `plugin.json` at repo root (zerodha-compliance-email:48) | **NO** at root | actual: `.claude-plugin/plugin.json` |

**11 broken file/path references found** — vast majority are Path A inauguration migrations (kc/riskguard, kc/audit, kc/alerts, oauth/ all moved to `algo2go/kite-mcp-*` modules and docs didn't update). These don't break runtime — they just confuse readers + break "Audit my reasoning" workflows for new contributors who try to grep the cited files.

### 1.11 Foundation email check (CLAUDE.md MEMORY.md rule)

**Per user's CLAUDE.md global rules**: `renusharmafoundation` email must NEVER appear in product files.

Empirical scan: `grep -rE "renusharmafoundation" docs/` — **CLEAN** (zero hits in docs/).
Empirical scan: same against README.md, SECURITY.md, server.json, funding.json, .env.example, .claude-plugin/plugin.json — **CLEAN**.

The `docs/drafts/zerodha-compliance-email.md` send-readiness checklist (line 49) claims "DONE — Verified" for "no foundation-context email reference in body or signature" — **VERIFIED**.

### 1.12 Egress IP — repeated check

Already covered in §1.5. All 14+ doc citations of `209.71.68.157` match the live `flyctl ips list` output. No staleness on this fact anywhere in docs/.

### 1.13 Cross-cutting contamination scan (per dispatch instruction)

Per the dispatch's note about systematic errors from prior work:

| Bug pattern | grep | Result in docs/ |
|---|---|---|
| `tools=130` or `130 tools` (the bad grep figure) | scanned all `.md` in docs/ | **0 hits** |
| `flyctl reauth via playwright` or `reauth playwright` | scanned all `.md` in docs/ | **0 hits** |
| `og-image.png 404` or `og-image 404` | scanned all `.md` in docs/ | **0 hits** |

**docs/ is clean of the systematic errors found in `.research/`**. The STATE.md grep contamination did not propagate; the FALSIFIED claims (flyctl reauth, og-image 404) are not load-bearing here.

### 1.14 New systematic patterns I spotted

- **Path A inauguration didn't update cross-references**: every `kc/<module>` path citation in docs/ that should now point to `algo2go/kite-mcp-<module>/` is stale. This is the dominant single failure mode (11 broken paths found in a sample of ~12 docs). **All docs that reference internal source paths need a sweep against the algo2go layout.**
- **"Number-of-checks" disagreement is durable** — 8, 9, 11, 12, 13 all appear depending on the doc. None of them are wrong in isolation; they count different things (registered Checks vs internal check methods vs registered+circuit-breaker+freeze layers). **A canonical-count + methodology footnote in a single source-of-truth + propagation is overdue.**
- **server.json is the only doc that pulls structured numbers directly from the implementation** (via `version: "1.3.0"` ldflags injection + manually-maintained `capabilities.tools: 111`). **Treat server.json as the canonical numeric source** for any doc-side claim, and add server.json review to the pre-deploy checklist.

---

## §2 — Per-file summary table

The full 124-file table is verbose; this rolls up by category with action verdict. SURVIVES UNCHANGED = no factual issues found; NEEDS PATCH = surface issues but content mostly correct; NEEDS REWRITE = systematic factual issues or stale snapshot; ARCHIVE = historical record, move to docs/archive/.

| File | Verdict | Reason |
|---|---|---|
| **High-risk launch-shippable docs** | | |
| `docs/show-hn-post.md` | NEEDS PATCH | Reconcile w/ README (registry status conflict); confirm RiskGuard count canonical = 11 footnoted as "user-visible checks; 13 Order constants including market_hours + confirmation_required" |
| `README.md` | NEEDS PATCH | Number-soup: line 3 says 11 checks, line 22 enumerates 12, line 82 says 9; line 198 table says 117 tools (stale, current 111); stale paths to `kc/riskguard/`, `kc/audit/store.go`, `kc/crypto`, `mcp/elicit.go` |
| `docs/launch-materials.md` | NEEDS REWRITE | Pre-tightening financial caps (₹5L/200/day/₹10L vs current ₹50k/20/day/₹2L) + 8 safety checks + ~100 tools; doc self-flags but anyone copy-pasting ships wrong numbers |
| `docs/drafts/foss-united-grant-email.md` | NEEDS PATCH | "~80 tools" + "330+ tests" + "9 pre-trade checks" all stale; ready-to-send status means high impact |
| `docs/drafts/indiafoss-2026-cfp.md` | NEEDS PATCH | "~80 tools" stale; "9-check pre-flight guard" inconsistent w/ server.json's 11 |
| `docs/drafts/jethwani-shenoy-dms.md` | SURVIVES UNCHANGED | Placeholders flagged; no load-bearing factual claims to verify |
| `docs/drafts/vishal-dhawan-dms.md` | SURVIVES UNCHANGED | Pure outreach template; placeholders flagged |
| `docs/drafts/zerodha-compliance-email.md` | NEEDS PATCH | `plugin.json` cited at root but file is at `.claude-plugin/plugin.json`; otherwise verified clean (no Foundation email, ₹500/mo cost, egress IP all correct) |
| `docs/rainmatter-onepager.md` | NEEDS PATCH | Version "v1.1.0" stale (current v1.3.0); "~80 tools" stale; "330+ tests" stale |
| `docs/cohort-1-landing.md` | NEEDS PATCH | `./tos.md` doesn't exist (case-sensitive `TERMS.md`); `./privacy.md` only works on case-insensitive FS (Linux production would 404); landing-page copy |
| `docs/twitter-launch-kit.md` | UNREAD | Did not sample; likely similar staleness to launch-materials.md (same era) |
| `docs/reddit-buildlog-posts.md` | UNREAD | Did not sample; likely outdated numbers |
| `docs/substack-week-1-options-greeks.md` | UNREAD | Cohort-adjacent; can defer |
| **User-facing technical docs** | | |
| `docs/PRIVACY.md` + `docs/TERMS.md` | UNREAD | Should be re-verified against TERMS/PRIVACY drafts pending legal review (DRAFT banner per README) |
| `docs/uninstall.md` | SURVIVES UNCHANGED | 90-day retention claim VERIFIED against algo2go/kite-mcp-audit/retention.go; matches README |
| `docs/faq.md` | NEEDS PATCH | `cmd/server` build path doesn't exist (should be `go run .`); `oauth/handlers.go` path stale; "5-year SEBI retention" vs actual 90d default — pick one |
| `docs/architecture-diagram.md` | SURVIVES UNCHANGED + NEEDS PATCH | Mermaid is current; "9 checks" cited contradicts server.json's 11 |
| `docs/legal-notes.md` | SURVIVES UNCHANGED | Concise; egress IP + AES-256-GCM all match |
| **ADRs (`docs/adr/`)** | | |
| `docs/adr/0001-broker-port-interface.md` | UNREAD | Likely architectural with stale paths |
| `docs/adr/0002-sqldb-port-postgres-readiness.md` | UNREAD | Phase 2 readiness — likely contains stale `kc/alerts/db.go` path reference |
| `docs/adr/0003-per-user-oauth-optional-global-credentials.md` | UNREAD | OAuth path likely stale |
| `docs/adr/0004-sqlite-litestream-r2-over-postgres.md` | NEEDS PATCH | Cites `kc/alerts/db.go` (stale path); "SEBI 5-year audit trail" framing inconsistent w/ 90d default; otherwise all SHAs + Litestream binary version VERIFIED |
| `docs/adr/0005-tool-middleware-chain-order.md` | UNREAD | Likely cites moved kc/ paths |
| `docs/adr/0006-fx-adoption.md` | UNREAD | Need to spot-check |
| `docs/adr/0007-canonical-cross-language-plugin-ipc.md` | UNREAD | Need to spot-check |
| `docs/adr/0008-decorator-option-4-go-reflection-aop.md` | UNREAD | Need to spot-check |
| `docs/adr/0009-ipc-contract-spec-jsonrpc.md` | UNREAD | Need to spot-check |
| `docs/adr/0010-stack-shift-deferral.md` | UNREAD | Need to spot-check |
| **Operational runbooks** | | |
| `docs/release-checklist.md` | NEEDS PATCH | Line 138 references `docs/launch/03-twitter-thread.md` — directory doesn't exist; otherwise all SHAs + namespace verified |
| `docs/pre-deploy-checklist.md` | NEEDS PATCH | Line 8 `go test ./kc/riskguard ./mcp ./oauth ./app` — `kc/riskguard` + `oauth/` paths gone (Path A); line 50 `flyctl releases` not a valid subcommand |
| `docs/push-deploy-playbook.md` | ARCHIVE | Snapshot from 2026-04-18 deploy event w/ specific HEAD `8c76e90`; preserved for retrospective; should move to docs/archive/ |
| `docs/operator-playbook.md` | UNREAD | Operational; verify before launch |
| `docs/incident-response.md` + `docs/incident-response-runbook.md` | UNREAD | Crisis runbooks; high-priority re-verify |
| `docs/release-notes-v1.1.0.md` | ARCHIVE | Historical release notes; filename pins version |
| `docs/releasing.md` | UNREAD | Likely overlap w/ release-checklist.md |
| `docs/monitoring.md`, `docs/event-flow.md`, `docs/audit-export.md` | UNREAD | Need spot-check |
| `docs/wsl2-setup-runbook.md` | UNREAD | Setup doc; lower priority |
| `docs/sac-runbook.md`, `docs/git-hooks.md`, `docs/uninstall.md` | UNREAD-EXCEPT-UNINSTALL | uninstall verified; others lower priority |
| **Compliance / SEBI docs** | | |
| `docs/sebi-paths-comparison.md` | UNREAD | Path 2 comparison; check before launch |
| `docs/access-control.md`, `docs/data-classification.md` | UNREAD | Compliance posture docs |
| `docs/threat-model.md`, `docs/threat-model-extended.md` | UNREAD | Security posture |
| `docs/SECURITY_POSTURE.md` | UNREAD | Large doc; spot-check during launch prep |
| `docs/RETENTION.md` | UNREAD | Likely contains 5-year vs 90-day tension |
| `docs/nist-csf-mapping.md`, `docs/risk-register.md` | UNREAD | Lower priority |
| `docs/dpdp-reply-templates.md`, `docs/data-classification.md` | UNREAD | DPDP-readiness templates |
| `docs/asset-inventory.md` | UNREAD | Operational |
| `docs/config-management.md`, `docs/change-management.md`, `docs/continuous-monitoring.md` | UNREAD | Operational |
| `docs/recovery-plan.md` | UNREAD | DR doc; cross-check w/ ADR-0004 |
| `docs/vendor-management.md`, `docs/vulnerability-management.md` | UNREAD | Operational |
| `docs/security-scanning.md`, `docs/sbom.md` | UNREAD | Lower priority |
| `docs/tls-self-host.md`, `docs/self-host.md` | UNREAD | Setup docs |
| **Brand / outreach** | | |
| `docs/engagement-mr-karan.md` | SURVIVES UNCHANGED | Strategic plan; self-flags unverified at line 136 |
| `docs/algo2go-tm-search.md` | UNREAD | Trademark research; sensitive |
| `docs/kite-forum-replies.md` | UNREAD | Outgoing; verify before send |
| `docs/floss-fund-proposal.md` | UNREAD | Outgoing; likely stale numbers (similar to grant draft) |
| `docs/renusharma-email-cleanup-report.md` | UNREAD | One-time cleanup report; historical |
| `docs/cohort-1-surveys-emails.md` | UNREAD | Cohort prep |
| `docs/launch-materials.md` | NEEDS REWRITE | (see above — wrong financial caps) |
| **Product / strategy** | | |
| `docs/product-definition.md` | NEEDS PATCH | Self-claims canonical (line 3); "~80 tools" + "9 checks" stale; should be updated to match server.json or marked NOT canonical |
| `docs/billing-activation-plan.md`, `docs/multi-broker-plan.md` | UNREAD | Strategy docs |
| `docs/path-6a-risk-audit.md`, `docs/option-c-implementation-plan.md` | UNREAD | Phase 2 docs; likely historical |
| `docs/byo-api-key.md`, `docs/client-examples.md`, `docs/cookbook.md` | UNREAD | User-facing; spot-check |
| `docs/claude-desktop-config.md` | UNREAD | Setup doc |
| `docs/chatgpt-apps-validation.md` | UNREAD | Likely contains current ChatGPT support claims |
| `docs/tool-catalog.md`, `docs/tool-renames.md` | UNREAD | Likely stale w/ Path A renaming |
| `docs/env-vars.md` | UNREAD | Important — should match README env table |
| `docs/adding-a-new-tool.md` | UNREAD | Dev guide |
| `docs/kite-token-refresh.md`, `docs/kite-version-hedge.md` | UNREAD | Operational |
| `docs/E2E_TEST_REPORT.md` | UNREAD | Likely historical |
| `docs/callback-deep-dive-13-levels.md` | UNREAD | 237KB — deep technical; lower priority |
| **Audit / triage docs (likely historical)** | | |
| `docs/consistency-audit-2026-04-18.md` | ARCHIVE | Date-stamped; one-time audit |
| `docs/delete-candidates-verification.md`, `docs/deploy-impact-analysis.md` | ARCHIVE | One-time analyses |
| `docs/pre-push-audit.md`, `docs/privacy-terms-source-compare.md` | ARCHIVE | One-time |
| `docs/placeholder-substitution-map.md`, `docs/session-2026-04-18-handoff.md` | ARCHIVE | Session-specific |
| `docs/triage-execution-guide.md`, `docs/triage-script-analysis.md` | ARCHIVE | Worktree-cleanup era |
| `docs/untracked-files-triage.md`, `docs/worktree-cleanup-plan.md` | ARCHIVE | Worktree era |
| `docs/worktree-merge-sequence.md`, `docs/worktree-merge-sequence-v2.md` | ARCHIVE | Worktree era |
| `docs/gitignore-policy-analysis.md`, `docs/remember-md-anomaly.md` | ARCHIVE | One-time analyses |
| `docs/deferred-items.md`, `docs/mcp-registry-prepublish-checklist.md` | UNREAD | Pre-launch checklist; verify before launch |
| **Evidence package (`docs/evidence/`)** | | |
| `docs/evidence/*` (all 8 files) | SURVIVES UNCHANGED (template) | Incident-response evidence templates; pre-built per design; no factual claims to falsify (filled at incident time) |
| **Blog** | | |
| `docs/blog/oauth-13-levels.md` | UNREAD | Technical deep-dive; spot-check |
| **Superpowers (specs + plans)** | | |
| `docs/superpowers/plans/*.md` (6 files) | ARCHIVE | Apr-2026 implementation plans for features now shipped (audit, elicitation, paper-trading, riskguard, htmx, dashboard-auth) |
| `docs/superpowers/specs/*.md` (6 files) | ARCHIVE | Apr-2026 specs; features shipped |

**Sampled coverage**: ~22 of 124 files read in full (priority: launch-shippable + outgoing + README-class + operational). Remaining 102 files inventoried + spot-flagged for issues; full deep-read should be a follow-up if launch timing permits.

---

## §3 — Concrete patch list (for downstream cleanup dispatch)

In priority order:

### Group A — Launch-blocking surfaces (do before Show HN)

1. **`docs/launch-materials.md`** — ARCHIVE to `docs/archive/launch-materials-pre-tightening.md` and DO NOT use. The financial caps (₹5L/200/day/₹10L) are 5-10× wrong vs current. show-hn-post.md is the canonical replacement.
2. **`README.md`** — line 22 says "11 pre-trade checks" but enumerates 12 names; line 82 says "9 safety checks"; line 198 table says "117 tools" — these are internally inconsistent + stale. Pick a canonical number (recommend matching server.json's 11) + propagate. Fix stale paths: `kc/riskguard/per_second.go`, `kc/riskguard/guard.go`, `kc/audit/store.go`, `kc/crypto`, `mcp/elicit.go` → all moved to `algo2go/kite-mcp-*` or `mcp/common/`.
3. **`docs/show-hn-post.md`** — reconcile MCP Registry status with README (currently README says LISTED, body line 11 says NOT YET).

### Group B — Outgoing drafts (verify before send)

4. **`docs/drafts/foss-united-grant-email.md`** — update "~80 tools" → "111 tools"; "330+ tests" → "~9,000 tests"; "9 pre-trade checks" → match canonical (whatever the final number is).
5. **`docs/drafts/indiafoss-2026-cfp.md`** — same update: "~80 tools" → "111 tools"; "nine-check pre-flight guard" → canonical.
6. **`docs/drafts/zerodha-compliance-email.md`** — fix `plugin.json` checklist reference (line 48) to `.claude-plugin/plugin.json`.
7. **`docs/cohort-1-landing.md`** — fix `./tos.md` → `./TERMS.md` (case-sensitive) and `./privacy.md` → `./PRIVACY.md`.
8. **`docs/rainmatter-onepager.md`** — bump version "v1.1.0 (April 2026)" → "v1.3.0 (May 2026)"; update "~80 tools" → "111 tools"; update "330+ tests" → "~9,000 tests".

### Group C — Operational fixes (used by chain agents)

9. **`docs/pre-deploy-checklist.md`** — line 8 `go test ./kc/riskguard ./mcp ./oauth ./app -count=1` → `go test ./mcp ./app ./kc -count=1` (or specific algo2go module paths); line 50 `flyctl releases` → `flyctl status` (since `releases` alone is not a valid subcommand).
10. **`docs/faq.md`** — line 9 `go run ./cmd/server` → `go run .`; line 23 "5-year SEBI retention" → "90 days (configurable via AUDIT_RETENTION_DAYS)" to match README + uninstall.md.
11. **`docs/release-checklist.md`** — line 138 references `docs/launch/03-twitter-thread.md` — directory doesn't exist; either create `docs/launch/` with the referenced doc or remove the link.

### Group D — Internal cross-cutting (lower urgency)

12. **`docs/product-definition.md`** — either update to match server.json's 111/11 numbers or remove the "Status: Canonical" claim at line 3.
13. **`docs/architecture-diagram.md`** — mermaid line 42 + line 80 say "9 checks" — match canonical.
14. **`docs/adr/0004-…md`** — line 95 `kc/alerts/db.go:13` → `algo2go/kite-mcp-alerts/db.go:13`; reconcile "SEBI 5-year audit trail" with actual 90d default.
15. **`docs/launch-materials.md`** verify-before-posting footnote should ALSO say "DO NOT lift this verbatim; use show-hn-post.md".

### Group E — Path A inauguration sweep (single cross-cutting fix)

A repo-wide grep-and-replace would close ~80% of the docs/ staleness in a single pass:

```
docs/ -- "kc/riskguard/" -> "algo2go/kite-mcp-riskguard/"
docs/ -- "kc/audit/"     -> "algo2go/kite-mcp-audit/"
docs/ -- "kc/alerts/"    -> "algo2go/kite-mcp-alerts/"
docs/ -- "kc/oauth/" / "oauth/handlers.go" -> "algo2go/kite-mcp-oauth/"
docs/ -- "kc/users/"     -> "algo2go/kite-mcp-users/"
... (one entry per algo2go module)
```

This is a 30-minute mechanical pass. Catches stale citations across 11+ docs in one go.

---

## §4 — What I did NOT verify (gaps in scope)

Out of the ~70 distinct factual claim categories I identified across the docs, I deep-verified ~25 and inventory-spotted ~45 more. Specifically:

- **42 docs** marked UNREAD above (would need an additional ~3-4h to deep-read at the same fidelity as the 22 sampled)
- **All 8 ADRs except 0004** — `0001` through `0010` likely contain stale `kc/` path references (Path A inauguration pattern)
- **Compliance docs** (`SECURITY_POSTURE.md`, `RETENTION.md`, `access-control.md`, `data-classification.md`, `threat-model.md`, `threat-model-extended.md`, `nist-csf-mapping.md`, `risk-register.md`, `dpdp-reply-templates.md`)
- **Operational runbooks** (`incident-response.md`, `incident-response-runbook.md`, `operator-playbook.md`, `recovery-plan.md`, `monitoring.md`)
- **Blog deep-dive** (`callback-deep-dive-13-levels.md` 237KB)
- **Outgoing material I didn't sample**: `twitter-launch-kit.md`, `reddit-buildlog-posts.md`, `substack-week-1-options-greeks.md`, `kite-forum-replies.md`, `floss-fund-proposal.md`

The patterns I found in the 22 sampled docs (number-soup, stale Path A paths, "9 vs 11 vs 12 checks", "~80 tools" framing) almost certainly apply across the unread set. A follow-up dispatch deep-reading the remaining ~42 high-priority docs would close the audit.

---

## §5 — Cross-cutting observations

### What works in docs/

- **No tools=130 contamination** — the grep error stayed in `.research/STATE.md` and the audit-agent fix (bea1e11) didn't need to propagate to docs/.
- **No flyctl-reauth contamination** — the FALSIFIED "flyctl reauth via Playwright ~30 min" claim from prior session is absent from docs/.
- **No og-image-404 contamination** — the FALSIFIED claim is absent.
- **Egress IP `209.71.68.157`** — verified across 14+ docs with 100% accuracy. Single source-of-truth held.
- **Git SHA references** — all 10 sampled SHAs exist in repo (no phantom SHAs like STATE.md's `d3c2a4a`).
- **Foundation email exclusion** — VERIFIED clean across all sampled product docs.

### What doesn't work

- **Number-of-checks** disagreement is durable and pre-launch-shippable. server.json says 11, README internally inconsistent (11 enumerated as 12 + later "9"), 5+ other docs say 9, 1 doc says 8. **An HN commenter quoting two different numbers from the same repo is launch-toxic.**
- **Path A inauguration paths** stale across 11+ docs (sampled). The Path A migration shipped code but didn't sweep documentation. Bulk grep-and-replace would close this in 30 minutes.
- **Tool count framing** drifts: 117 (README table), 110+/111 (server.json + show-hn + healthz), ~80 (foss-united, indiafoss, rainmatter, product-definition), ~100 (launch-materials). The "~80" framing in older outgoing material is the most-stale.
- **`launch-materials.md` is a launch-day landmine** — it has pre-tightening RiskGuard caps (₹5L/200/day/₹10L) that contradict the current implementation by 5-10×. The doc's own warning banners acknowledge this but the file is still in the repo, indexed, and reachable by anyone preparing launch copy.

### Methodology note for orchestrator

When evaluating any future "is doc X accurate" question, prefer:

1. **Compile-and-run** (e.g., for tools count: build binary + read `total_available=N` startup log) over `grep -c`
2. **Source-of-truth lookup**:
   - `server.json` for version + tools count + RiskGuard count
   - `algo2go/kite-mcp-riskguard/check.go` Order constants for RiskGuard internals
   - `algo2go/kite-mcp-audit/retention.go:17` for retention default
   - `flyctl ips list` for egress IP
   - `flyctl status` for current image
   - `curl /healthz` for live runtime state
3. **For path citations**: `ls <cited-path>` first — Path A inauguration moved 28 modules and most docs still cite the pre-move paths.

This is the same `compile-and-run > grep-and-count` lesson STATE.md §5.6 already memorialised. Docs/ would benefit from a one-time pass that propagates the lesson + cleans the artifacts.

---

## §6 — Hard rules compliance

| Rule | Status |
|---|---|
| READ-ONLY on all docs and source | ✓ |
| Empirical probes only — NO grep-count-as-evidence for binary state | ✓ — counted via `go test -list` for tests, source enumeration of Order constants for RiskGuard, `curl /healthz` for tools count, `flyctl ips/status` for production state |
| WSL2 for Go probes | ✓ |
| Single output file | ✓ — this file |
| `git commit -o -- <path>` + push | (next step) |
| ~3-4h budget; halt at 5h | ~2h25m wall clock through investigation + writing |
| Surface IMMEDIATELY if CRITICAL user-shippable claim wrong | ✓ — three CRITICAL findings surfaced in TL;DR (launch-materials.md wrong caps; README number-soup; pre-deploy-checklist.md broken commands). show-hn-post.md is acceptably accurate. |

---

## §7 — Verdict

`docs/` is **mostly trustworthy with a launch-blocking number-soup**. Specifically:

- **Show HN body itself (`docs/show-hn-post.md`)** is acceptably accurate end-to-end. The 110+ tools, ₹50k/order, 20/day, ₹2L notional, egress IP — all verified. The "11 checks" claim is internally consistent + matches server.json. The MCP Registry status conflict with README needs reconciling but is fixable in 5 minutes.

- **README** has the number-soup issue (4 conflicting claims documented above). For a landing surface getting HN traffic, this is launch-prep priority #1.

- **launch-materials.md** is a trap; do not copy from it. show-hn-post.md is the corrected replacement.

- **pre-deploy-checklist.md** would fail if a new operator ran it verbatim today; ~5-minute fix.

- **drafts/** outgoing material (4 of 5 drafts) has stale numbers (~80 tools / 330+ tests / 9 checks era). The zerodha-compliance-email is closest to clean but has one wrong file-path checklist item.

- **80%+ of stale-path issues** in docs/ stem from Path A inauguration not updating documentation. A single 30-minute mechanical grep-and-replace would close most of them.

No new grep-class systemic errors found in docs/. No phantom SHAs. No Foundation email leaks. No og-image-404 / flyctl-reauth contamination. The contamination patterns stayed contained to `.research/`.

The follow-up cleanup dispatch from this report has ~15 patches in priority order (Groups A-E above). Estimated total cleanup time: ~2-3 hours, mostly mechanical.
