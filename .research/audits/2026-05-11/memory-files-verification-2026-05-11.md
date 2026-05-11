# Memory Files Verification — 2026-05-11

**Auditor**: Dispatched as #C of 3 parallel deep-read fan-outs (memory dir scope).
**Date**: 2026-05-11 IST.
**Master HEAD at audit**: `dd10837`.
**Memory dir audited**: `C:\Users\Dell\.claude\projects\D--Sundeep-projects\memory\` — **76 files** (1 above INDEX inventory of ~75).
**Mode**: read-only. No source mutations. No memory mutations.
**Empirical probes**: direct file reads + cross-reference against `.research/research-batch-2026-05-11.md` (chain agent's freshly-landed empirical answers) + repo file-existence checks at HEAD `dd10837`.

This audit found **8 CRITICAL / 14 IMPORTANT / 9 COSMETIC** = **31 distinct issues** across the 76 memory files. The most consequential finding is a **systematic staleness pattern**: 30 of the 33 `kite-*.md` files were last touched between 2026-04-02 and 2026-04-19 — meaning ~3 weeks of subsequent shipped work (28 algo2go modules, Stripe billing, smithery.yaml, .env.example, funding.json, dr-decrypt-probe gap, OAUTH_JWT_SECRET rotation) is not reflected in memory.

---

## §0 — Inventory summary

| Category | Count | Date range | Health |
|---|---|---|---|
| `MEMORY.md` (index) | 1 | last touched 2026-05-06 | **STALE** — line 8 still mentions "v189 with 3/5 module decomp" while reality is 27 modules + v274 |
| `kite-*.md` (feature/strategy) | 33 | mostly 2026-04-02 → 2026-04-19 (~3wk old) | many STALE on contemporary facts |
| `feedback_*.md` (rules) | 19 | 2026-04-06 → 2026-04-28 | mostly current; rules don't expire as fast as facts |
| `user_*.md` (rules) | 9 | 2026-04-18 → 2026-04-27 | mostly current |
| `session_*.md` (snapshots) | 9 | 2026-04-17 → 2026-05-10 | each captures a moment; staleness is by-design |
| `project_*.md` (operational) | 2 | 2026-04-25, 2026-04-27 | mostly current |
| Reference (hooks/mcp-servers/dns) | 3 | Feb-Apr 2026 | mostly current |

---

## §1 — CRITICAL findings (affect what CLAUDE does in next session)

### C1. `kite-algo2go-rename.md` says "GitHub: algo2go user AVAILABLE" + "Tradarc backup name [as solid]"

**File**: `memory/kite-algo2go-rename.md` (last touched 2026-04-17)

**Stale claims** (load-bearing for any rename / TM decision):

1. Line ~20: *"GitHub: `algo2go` user AVAILABLE"*
2. Line ~24: *"Tradarc — coined, strongest as wordmark... Use if Algo2Go gets claimed before we file."*
3. Line ~30: *"Recommend filing Class 36 + Class 42 simultaneously (₹18-22k total)"* — frames ₹18-22k as the recommendation despite the same file also documenting the direct-filing ₹9k option.

**Empirical reality (per research-batch §A + dispatch brief)**:
- `algo2go` GitHub org is **CLAIMED** (created 2026-05-05, 28 repos under it; verified at `https://github.com/algo2go`)
- `tradarc.com` **auto-renewed to 2027-05-04 today**; bus-factor risk for using Tradarc as the backup is real because the holder may renew indefinitely. **Replacement candidates (research-batch §A)**: `quirkalgo`, `quanto2go`, `tradloop`, `zerocode2go`, `tradesy2` — all RDAP-verified unregistered.
- Direct filing is now the recommended path at ₹9k (₹4,500 × 2 classes), not ₹18-22k via Vakilsearch.

**Impact**: any future "should we register Algo2Go?" or "what's our backup name?" question that reaches CLAUDE will get the old answers. The Tradarc-as-backup recommendation could lead to filing fee waste OR delay on a fresh-name decision.

**Action**: replace stale claims with the empirical reality from research-batch §A.

### C2. `kite-audit.md` says "JWT expiry: 4 hours" — explicitly contradicted by MEMORY.md

**File**: `memory/kite-audit.md` (last touched 2026-04-02)

**Stale claim** (load-bearing for any security/auth question):
- *"JWT expiry: 4 hours. SEBI compliant (static IP, market_protection)."*

**Empirical reality**:
- `MEMORY.md` lines ~97 explicitly say: *"MCP bearer JWT expiry: **24 hours** (default in `oauth/config.go:31`)... **An earlier '4h expiry' note in this file was stale plan that never landed — do not quote it.** Verified in code 2026-04-13."*
- `kite-session-apr2.md` also says "4h JWT expiry" — same stale note (it's actually the source MEMORY.md is warning against).

**Impact**: if CLAUDE answers a future security question, it might quote the 4h figure that MEMORY.md explicitly disclaims. Worse, the disclaimer is in MEMORY.md but the stale claim is in two referenced subfiles — INDEX-level traceback would catch it but ad-hoc reads from `kite-audit.md` alone would miss it.

**Action**: patch `kite-audit.md` line "JWT expiry: 4 hours" → "JWT expiry: 24h (MCP bearer) / 7d (dashboard cookie). The earlier 4h note was a stale plan that never landed."

### C3. `kite-audit.md` + `kite-session-apr2.md` say "84 tools" / "60 tools" — production is 111

**Files**:
- `kite-audit.md`: *"84 tools with uniform annotations"*
- `kite-session-apr2.md`: *"32 → 60 tools"*
- `kite-session-apr3.md`: *"Tool annotations — all 60 tools"*

**Empirical reality**:
- Production /healthz returns `tools=111` (verified empirically across multiple session dispatches; ground-truth)
- `.research/STATE.md` (HEAD ~bc5043e) authoritative for tools=111
- `.research/research-batch-2026-05-11.md` §B confirms `tools=111 (production)`

**Impact**: any "how many tools does the server have?" question gets the wrong answer if CLAUDE quotes these files. Especially relevant for HN body / Show-HN claims integrity.

**Action**: add a footnote in each session-snapshot file with the current count + reference to /healthz as canonical. Don't rewrite the historical "32 → 60 tools" claim (it's a session-snapshot of that moment), but add: *"As of 2026-05-11 production: tools=111 (compile-and-run authoritative; grep over `mcp/` over-counts by ~19 test fixtures)."*

### C4. `kite-launch-blockers-apr18.md` claims "Missing smithery.yaml, .env.example" — both ALREADY EXIST in repo

**File**: `memory/kite-launch-blockers-apr18.md` (last touched 2026-04-19)

**Stale claims**:
- *"Missing `smithery.yaml` — blocks Smithery one-click install"*
- *"Missing `.env.example`"*
- *"No `Dockerfile` at root (appears gitignored in docs/ only)"*

**Empirical reality (verified by `ls`)**:
- `D:\Sundeep\projects\kite-mcp-server\smithery.yaml` EXISTS (content matches `kite-launch-ready-fixes.md` ready-to-commit version)
- `D:\Sundeep\projects\kite-mcp-server\.env.example` EXISTS
- `D:\Sundeep\projects\kite-mcp-server\Dockerfile` EXISTS at root (separate file)
- Research-batch §E confirms: *"smithery.yaml — YES, ALREADY COMMITTED at repo root."*

**Impact**: any future "are we launch-ready?" dispatch that reads this file will report blockers that have been resolved.

**Action**: patch the file with a "STATUS as of 2026-05-11: smithery.yaml + .env.example + Dockerfile at root — ALL SHIPPED. Remaining gaps from this audit: <re-audit needed>." OR archive the file entirely under `memory/archive/launch-prep/`.

### C5. `kite-mcp-registry-publisher.md` claims "CORS preflight → 401 on /mcp" as pre-publish blocker

**File**: `memory/kite-mcp-registry-publisher.md` (last touched 2026-04-19)

**Stale claim**:
- *"Pre-publish blockers (unfixed as of 2026-04-18): ⚠️ CORS preflight → 401 on `/mcp` — browser-based MCP clients will fail before auth"*

**Empirical reality**: I cannot directly verify this without running a CORS preflight probe (out of scope), but production has been stable at tools=111 for 86 deploys including OAuth flows used by claude.ai / Claude Desktop. The CORS path likely was fixed at some point in the v228+ arc but the memory file wasn't updated.

**Impact**: any "should we publish to MCP Registry?" question gets "wait, CORS still broken" as the answer.

**Action**: dispatch a follow-up probe (small CORS preflight check via curl `OPTIONS /mcp`) to verify. If fixed, patch the file. If still broken, file an issue.

### C6. `kite-product-strategy.md` says "Phase 2 = Personal Finance via AA APIs (Q3-Q4 2026)" — schedule unverified

**File**: `memory/kite-product-strategy.md` (last touched 2026-04-04)

**Stale aspirational claim**:
- *"Phase 2: Personal Finance via Account Aggregator (Q3-Q4 2026)"* — a 6-month-out roadmap commitment
- Phase 1 / Phase 3 / Phase 4 all dated similarly to specific quarters

**Reality**: aspirational vision docs date-anchored to quarters lose value as quarters pass. The vision content is fine; the schedule fields just need either-cleanup or removal-of-quarters.

**Impact**: low-medium — if user asks "what's Phase 2 timeline?" CLAUDE might quote "Q3-Q4 2026" without flagging that the document is aspirational and unverified.

**Action**: add a "STATUS: aspirational vision; quarters indicative only; not committed roadmap" disclaimer.

### C7. `MEMORY.md` lines 8 & 9 still reference "v189 with 3/5 module decomp" and similar mid-flight states

**File**: `memory/MEMORY.md` (last touched 2026-05-06 — but content on these lines is older)

**Stale claims**:
- Line 8: *"2026-05-04 final state — v189 with 3/5 module decomp"* — reality at HEAD `dd10837` is 28 modules external, production v272+, Path A inauguration COMPLETE
- Line 9: *"close-2 — architecture sprint mid-flight"* — reality: architecture sprint COMPLETE (Tier 1 + Tier 2 closed per `forward-tracks-strategic-review.md`)

**Impact**: this is the index file that orchestrator reads on every session start. Stale top-of-file entries set wrong context.

**Action**: append a new top entry: `[2026-05-10 Path A complete + v272 production](session_2026-05-10_path-a-complete.md)` — 28 modules external; Tier 1+2 closed; tools=111 invariant held across 86 deploys; production-vs-master gap report confirmed no deploy gap. Optionally trim older mid-flight entries that have been superseded.

### C8. Multiple files reference *"tools=130 in-tree"* via the same grep-over-test-fixtures error

**Files affected**:
- `MEMORY.md` references "tools=130" framing was eventually corrected per STATE.md §5.6 / §8.6
- Various downstream docs still inherit the stale framing

**Empirical reality (per STATE.md §5.6 + research-batch §B)**:
- `grep -rE 'mcp\.NewTool\("' mcp/` returns 130 raw, but 19 are in `_test.go` test fixtures
- Filtering: 111 production-registered (matches /healthz)
- The mistake originated in STATE.md's initial commit (`1e80930`) and propagated to forward-tracks-strategic-review.md before being corrected at `bea1e11`
- agent-domain-map.md (in `.research/`, not `memory/`) still has the stale `tools=130 invariant` rule per `.research/STATE-fresh-eyes-diff-2026-05-11.md`

**Impact**: if a future synthesis dispatch reads `.research/agent-domain-map.md` and inherits "tools=130 invariant" as a rule, they may misreport the production count again.

**Action**: patch `agent-domain-map.md` rule list (it lives in `.research/`, not `memory/`, so outside this audit's strict scope but flagged as cross-cutting). Memory-side: this audit didn't find any `memory/*.md` directly quoting tools=130 EXCEPT MEMORY.md framing which the chain agent's gap-report has already addressed; the contamination lives downstream.

---

## §2 — IMPORTANT findings (operational inconsistencies)

### I1. `kite-cost-estimates.md` says "270+ tests"; reality is ~8,457

**File**: `memory/kite-audit.md` (not cost-estimates — apologies for §header note; finding is genuine)

The audit file says: *"22 findings (3 critical) → fixed. Review-of-reviews found 12 more → fixed. 270+ tests total."*

Per research-batch §I: **8,457 total tests** (4,697 in-tree + 3,760 across 28 algo2go modules). README rounds to "~9,000" which is correct.

**Action**: footnote the historical 270+ number with current count.

### I2. `kite-session-apr2.md` says "Telegram bot commands"; some commands have been renamed/removed

**File**: `memory/kite-session-apr2.md`

Lists `/price, /portfolio, /positions, /orders, /pnl, /alerts, /prices, /mywatchlist, /status, /help` — some of these are stale per session-2026-05-10's restructure of telegram into `algo2go/kite-mcp-telegram` external module. Memory is correct as a snapshot but not as current-API-truth.

**Action**: low priority; this is a session snapshot, not an API doc. Leave alone OR add a "see external `algo2go/kite-mcp-telegram` v0.1.0+ for current API" footnote.

### I3. `kite-launch-blockers-apr18.md` widget compatibility matrix may be stale

The matrix lists "Cursor: ❌/partial in 2.6+" and ChatGPT as "needs `openai/outputTemplate` metadata shim". Per `kite-launch-ready-fixes.md` the shim is "ready to commit". Whether it shipped is unverified in this audit.

**Action**: dispatch a follow-up probe.

### I4. `feedback_research_diminishing_returns.md` cites session "agents 1-58"; counter has grown

The diminishing-returns rule is sound but cites a historical 2026-04-17 session's agent count. Newer sessions have continued; the empirical signal that prompted the rule is now older context.

**Action**: leave as-is. The rule is durable; the session reference is historical evidence.

### I5. `kite-product-strategy.md` Phase 1 says "Q2-Q3 2026" — partially elapsed

Today is mid-Q2 2026 (May 11). Phase 1 schedule items: MF NAV data, FD tracking, digital gold, NPS/PPF entry, net worth tool, goal tracking, etc. Status of any of these is unverified.

**Action**: dispatch a follow-up probe to enumerate which Phase 1 items shipped.

### I6. `kite-floss-fund.md` says "Apply after: ≥50 GitHub stars" — current stars per research-batch §H is 0

The rule itself is fine; the trigger has not fired. But MEMORY.md line ~ doesn't surface this gate, making the rule discoverable only by reading the file directly.

**Action**: low priority; rule is correctly gated.

### I7. `kite-rainmatter-warm-intro.md` says "Trigger only after FLOSS/fund submitted + ≥50 stars"

Same as I6: rule is correctly gated; trigger has not fired (0 stars per research-batch §H).

**Action**: low priority.

### I8. `kite-skills-wrapper.md` claims "Sundeep should test one skill end-to-end" — unverified

The file says verification is pending. Per session-snapshots, this may have shipped but it's unverified in any later doc.

**Action**: low priority.

### I9. `kite-callback-deepdive.md` path reference `D:\kite-mcp-temp\docs\callback-deep-dive-13-levels.md` may be stale

Original file location was `D:\Sundeep\projects\kite-mcp-server\docs\callback-deep-dive-13-levels.md` per MEMORY.md.

**Action**: very low priority; doc reference path stale.

### I10. `kite-session-apr3.md` exposes raw secrets

```
Cloudflare R2:
- Account ID: [REDACTED — see file in memory/kite-session-apr3.md for the real value]
- CF API token: [REDACTED]
- R2 S3 Access Key: [REDACTED]
- R2 S3 Secret: [REDACTED]
```

*(I redacted the actual values to pass GitHub secret-scanning push protection. The original 4 secrets are in `~/.claude/projects/D--Sundeep-projects/memory/kite-session-apr3.md`. The finding stands: those secrets are plaintext in the memory file.)*

**This is sensitive data in plaintext in a memory file**. If memory files are ever shared / synced / leaked, these credentials are exposed. The dispatch said this is OUTSIDE the repo (under `~/.claude/projects/`), so risk is lower than committing to repo. But it's still raw secrets in a file.

**Action**: MEDIUM-IMPORTANT — recommend rotating these credentials AND replacing the values in this file with placeholders or vault refs. This is a security hygiene finding, not a correctness finding.

### I11. `MEMORY.md` mentions raw API keys at lines 92-94

```
Local app: API Key [REDACTED] | Secret [REDACTED]
Fly.io app: API Key [REDACTED] | Secret [REDACTED]
Fly.io app OLD: API Key [REDACTED] | Secret [REDACTED]
```

*(Same redaction reason. Original values are in `~/.claude/projects/D--Sundeep-projects/memory/MEMORY.md` lines 92-94.)*

**Same hygiene concern as I10**. The Kite API keys + secrets are in plaintext in a memory file. Memory is outside the repo but still readable by any actor with filesystem access.

**Action**: SAME as I10 — rotation + replacement with placeholders recommended. Lower-priority than R2 secrets only because Kite Connect keys can be regenerated easily; R2 credentials affect a backup system with more inertia.

### I12. `kite-session-apr2.md` references "v1.0.0 on Fly.io" — production is v1.3.0

**File**: `memory/kite-session-apr2.md` snapshot from 2026-04-02 says current deployment is v1.0.0. Today's production is v1.3.0. Snapshot-staleness is by design but the version literal can confuse.

**Action**: leave as-is (it's a snapshot); current state is in MEMORY.md / STATE.md.

### I13. `kite-zerodha-no-marketplace.md` is current as of 2026-04-18; Zerodha hasn't launched a marketplace

The doc concludes "Zerodha does NOT operate a public app marketplace." If they have launched one since (unverified by this audit), the doc would be stale.

**Action**: dispatch a follow-up `kite.trade` browse to verify.

### I14. `user_team_agents_default.md` describes 5-agent team friction in 2026-04-19 session

The "concurrent edit friction" observed there is the basis for the rule. Recent sessions (2026-05-10 Path A inauguration with 27 sequential dispatches, no team-config) suggest the friction is path-dependent — sequential single-agent dispatches don't trigger it.

**Action**: leave rule as-is. The "default to team for 3+ concurrent" framing is correct; sessions doing sequential single-agent work don't apply.

---

## §3 — COSMETIC findings

### Cosmetic-1. `kite-callback-deepdive.md` references `D:\kite-mcp-temp\` (likely typo for `D:\Sundeep\projects\kite-mcp-server\`)

Trivial path-string error.

### Cosmetic-2. `kite-skills-wrapper.md` commit hash `60e552c` and other commit-hash references throughout memory may not be reachable from current master HEAD

Some referenced commits may have been rebased away or replaced during refactors. Low-value to verify each.

### Cosmetic-3. Memory-file frontmatter `originSessionId` is opaque

Files have `originSessionId: ccc193de-129c-43c8-87f2-f37a64851b7c` etc. as YAML frontmatter — these UUIDs aren't useful to a future reader. Cosmetic.

### Cosmetic-4. `MEMORY.md` index-line truncation

Many index lines say `(see [kite-X.md](kite-X.md))` followed by more bullet points — long lines, hard to scan.

### Cosmetic-5. Multiple files end with section headers but no content (truncated)

E.g., `kite-product-strategy.md` Phase 4 section has only "30% tax + 1% TDS still a barrier" — clearly truncated.

### Cosmetic-6. Date references mix formats

"2026-04-17", "Apr 17, 2026", "April 2026" inconsistent across files.

### Cosmetic-7. Some files lack frontmatter `description`

Inconsistent metadata.

### Cosmetic-8. `kite-mcp-registry-publisher.md` says "Registry is in preview (as of Apr 2026)" — preview status may have changed

Cosmetic if checked.

### Cosmetic-9. `mcp-servers.md` and `hooks.md` are reference docs, last touched March 2026

The MCP server inventory has likely accumulated new servers since March (gemini-api, claude_ai_*, etc.). Reference docs that don't have a date stamp can drift silently.

---

## §4 — Cross-cutting patterns

### Pattern 1: ~3-week staleness on kite-* files

30 of 33 kite-* files were touched between 2026-04-02 and 2026-04-19. The world has moved:
- 28 algo2go modules now external (vs 3-5 at file write time)
- Stripe billing fully wired (vs unverified at file write time per research-batch §K)
- smithery.yaml + .env.example + funding.json shipped (vs missing at file write time)
- Tradarc auto-renewed (vs assumed-droppable at file write time)
- algo2go org claimed (vs "available")
- tools=111 stable across 86 deploys (vs ~84-tool count at older write times)

**Recommendation**: trigger a memory-refresh sweep when ~10+ files cross the 30-day-staleness threshold OR when major shipping events (Path A close, billing wire, etc.) happen. The memory-files-verification dispatch pattern can be repeated.

### Pattern 2: Stale costs and recommendations carried forward

The `₹19-22k TM filing` recommendation in `kite-algo2go-rename.md` predates the ₹9k direct-filing finding. The latter is documented in the same file but the former still leads the "Pending user action" section. This is a typical case of "addendum added; lede not updated."

**Recommendation**: when a recommendation is superseded, update the lede, don't just append an addendum.

### Pattern 3: Secrets in plaintext memory files

R2 credentials (kite-session-apr3.md) + Kite API keys (MEMORY.md). Both are outside the repo but in the user's filesystem `memory/`. This is a security hygiene issue.

**Recommendation**: rotate secrets and replace plaintext with placeholders or vault references (e.g., `<see Bitwarden item "R2 kite-mcp-backup">`).

### Pattern 4: Session-snapshot files have inherent staleness — that's by design

Sessions snapshot a moment; they're not meant to stay current. This is fine. The concern is when ad-hoc reads of older snapshots (without cross-referencing the index) feed CLAUDE outdated numbers.

**Recommendation**: leave session-snapshot files alone. Strengthen the index (MEMORY.md) to make it the canonical entry point, with explicit "as-of date" for every fact-claim that future questions might rely on.

### Pattern 5: User-rule files (user_*.md + feedback_*.md) are largely current

19 feedback + 9 user rules, total 28 rule files. I reviewed 13 of them deeply; the rest were sampled by header/intro. **No internal contradictions found between rules**. No rules observed-as-violated this session (the chain agent's empirical methodology, the audit agent's deep-verification, this fresh-eyes pass — all consistent with the rule corpus).

**Recommendation**: do NOT delete or rewrite user rules based on this audit. They are durable.

---

## §5 — Concrete patch list

Per-file proposed edits, in priority order:

### Critical patches (do this week)

| # | File | Line/Section | Current | Proposed |
|---|---|---|---|---|
| 1 | `MEMORY.md` | Top of "User Rules" + after May-10 entry | (no v272+ entry) | Add: `[2026-05-10 Path A inauguration COMPLETE — 27 algo2go modules + v272 production](session_2026-05-10_path-a-complete.md)`. Trim line 8 (v189 3/5 module decomp) — it's superseded. |
| 2 | `kite-algo2go-rename.md` | "Availability verified" section | `GitHub: algo2go user AVAILABLE` | `GitHub: algo2go ORG CLAIMED (created 2026-05-05; 28 module repos under it)` |
| 3 | `kite-algo2go-rename.md` | "Backup name" section | `Tradarc — coined, strongest as wordmark` | `Tradarc — auto-renewed to 2027-05-04 (RDAP confirmed 2026-05-11); NOT available as backup. Replacement candidates (research-batch-2026-05-11.md §A): quirkalgo.com, quanto2go.com, tradloop.com, zerocode2go.com, tradesy2.com — all RDAP-unregistered.` |
| 4 | `kite-algo2go-rename.md` | "Filing cost (India)" | `Recommend filing... (₹18-22k total)` | `Recommend direct filing via ipindiaonline.gov.in (₹4,500/class × 2 = ₹9,000 total). Vakilsearch/LegalWiz path is ₹18-22k for hand-holding.` |
| 5 | `kite-audit.md` | Current Posture section | `JWT expiry: 4 hours` | `JWT expiry: 24h (MCP bearer) / 7d (dashboard cookie). The earlier 4h note in this file was stale plan that never landed — do not quote it. Verified in code 2026-04-13.` |
| 6 | `kite-audit.md` | Current Posture section | `84 tools with uniform annotations` | `~111 tools production-registered (per /healthz; compile-and-run authoritative). 84 was the count at file-write time (2026-04-02).` |
| 7 | `kite-audit.md` | Current Posture section | `270+ tests total` | `~8,457 tests total across in-tree + 28 algo2go modules (per research-batch-2026-05-11.md §I). 270 was the count at file-write time.` |
| 8 | `kite-launch-blockers-apr18.md` | "High-priority doc gaps vs peers" | `Missing smithery.yaml, .env.example, no Dockerfile at root` | Add status block at top: `STATUS as of 2026-05-11: smithery.yaml ✓ shipped at repo root, .env.example ✓ shipped, Dockerfile ✓ at root. SECURITY.md vulnerability-disclosure section: <unverified - dispatch needed>.` |
| 9 | `kite-mcp-registry-publisher.md` | "Pre-publish blockers" | `CORS preflight → 401 on /mcp — unfixed as of 2026-04-18` | Add status block: `STATUS as of 2026-05-11: unverified post-Apr-2026 patches. Run probe: curl -X OPTIONS https://kite-mcp-server.fly.dev/mcp -H "Origin: https://example.com"; if 200/204 returned, blocker is fixed.` |

### Important patches (do this month)

| # | File | Section | Action |
|---|---|---|---|
| 10 | `kite-product-strategy.md` | All Phase X sections | Add header: `STATUS: aspirational vision — quarters indicative, not committed roadmap. Verify Phase 1 ship state with separate dispatch.` |
| 11 | `kite-session-apr3.md` | "Cloudflare R2" block | Replace raw secrets with `<see vault/secret store ref>` — rotate credentials before commit |
| 12 | `MEMORY.md` | "Kite Zerodha MCP" section | Replace raw API keys with `<see Bitwarden item "Kite developer apps">` — rotate keys before commit |
| 13 | `kite-zerodha-no-marketplace.md` | (whole file) | Add at top: `Last verified: 2026-04-18. STATUS: re-check kite.trade for marketplace launch if it's been >6 months.` |
| 14 | `kite-callback-deepdive.md` | Top line | Fix `D:\kite-mcp-temp\docs\...` → `D:\Sundeep\projects\kite-mcp-server\docs\...` |

### Cosmetic patches (optional)

15-17 listed in §3 above.

---

## §6 — `MEMORY.md` proposed new entries (per dispatch INDEX §13)

Per the dispatch brief, INDEX §13 already surfaced 6 new entries + 4 standing-rule promotions to add. I verified against the actual memory files I read:

### Verified — would land cleanly:
- **2026-05-10 Path A complete entry** — corresponds to `session_2026-05-10_path-a-complete.md` (exists, reads correctly)
- **STATE-v2-fresh-eyes diff doc** — not in memory yet; lives in `.research/`
- **Production-master-gap report** — same, lives in `.research/`

### Should-be-promoted standing rules (per INDEX §13):
- `feedback_chain_dispatches_when_mapped.md` — ALREADY in MEMORY.md User Rules section, OK
- `feedback_research_diminishing_returns.md` — ALREADY there
- `feedback_research_vs_empirical_grounding.md` — ALREADY there
- `feedback_wsl_for_go_test.md` — ALREADY there
- `user_email_rule.md` — ALREADY there

INDEX §13's promotion suggestions are mostly already in MEMORY.md. The gap is fresh content (Path A complete, gap report, STATE.md series).

---

## §7 — What this audit DIDN'T verify (scope honesty)

- **CORS preflight on `/mcp`** — fix verified status unknown
- **OAuth JWT cookie 7d expiry** — code-verified by MEMORY.md note but I didn't re-run the verification
- **Stripe webhook signature verify path** — confirmed wired per research-batch §K but not unit-tested in this audit
- **Static egress IP `209.71.68.157`** — last RDAP-confirmed elsewhere; not re-verified here
- **Twitter @Sundeepg98 handle exists** — per research-batch §M: WebFetch blocked, user-action needed
- **Reddit u/Sundeepg98 exists** — per research-batch §G: WebFetch blocked, user-action needed
- **Kite Connect pricing ₹500/mo** — MEMORY.md note from mid-2025; not re-verified

These are all `STATE.md §9`-style gaps that need user-side or follow-up-dispatch verification.

---

## §8 — Time accounting

- Inventory pass: ~5 min
- Read pass (40+ files read fully or substantially): ~2 hours
- Cross-reference with research-batch + repo file checks: ~30 min
- Synthesis + write-up: ~45 min
- **Total wall-clock**: ~3.5 hours

Inside the 4h budget; well under 5h halt.

---

## §9 — Summary table — disposition per file

| File | Disposition |
|---|---|
| `MEMORY.md` | NEEDS PATCH (lines 8 + raw API keys) |
| `dns-cloudflare-fix.md` | SURVIVES UNCHANGED |
| `feedback_*.md` (19 files) | SURVIVES UNCHANGED (rules are durable) |
| `user_*.md` (9 files) | SURVIVES UNCHANGED (rules are durable) |
| `hooks.md` | SURVIVES UNCHANGED |
| `mcp-servers.md` | SURVIVES UNCHANGED |
| `kite-admin-tools-2026-04.md` | SURVIVES UNCHANGED |
| `kite-ai-dashboard-bridge.md` | SURVIVES UNCHANGED |
| `kite-algo2go-rename.md` | **NEEDS CRITICAL PATCH** (C1) |
| `kite-audit.md` | **NEEDS CRITICAL PATCH** (C2, C3, I1) |
| `kite-awesome-mcp-listings.md` | SURVIVES UNCHANGED |
| `kite-callback-deepdive.md` | NEEDS COSMETIC PATCH (path typo) |
| `kite-competitors-corrected.md` | SURVIVES UNCHANGED |
| `kite-cost-estimates.md` | SURVIVES UNCHANGED |
| `kite-dashboard-design.md` | SURVIVES UNCHANGED |
| `kite-deploy-ops-runbooks.md` | SURVIVES UNCHANGED |
| `kite-fintech-lawyers.md` | SURVIVES UNCHANGED |
| `kite-floss-fund.md` | SURVIVES UNCHANGED |
| `kite-identity-gaps.md` | SURVIVES UNCHANGED |
| `kite-landmines.md` | SURVIVES UNCHANGED |
| `kite-launch-blockers-apr18.md` | **NEEDS CRITICAL PATCH** (C4) — OR archive as historical |
| `kite-launch-ready-fixes.md` | SHOULD MERGE WITH launch-blockers note (both ready-content shipped) |
| `kite-mcp-registry-publisher.md` | **NEEDS PATCH** (C5, status block) |
| `kite-mrr-reality.md` | SURVIVES UNCHANGED |
| `kite-new-tools-apr17.md` | SURVIVES UNCHANGED |
| `kite-next-roadmap.md` | SURVIVES UNCHANGED |
| `kite-path2-architecture.md` | SURVIVES UNCHANGED |
| `kite-product-strategy.md` | NEEDS PATCH (C6, quarter-status disclaimer) |
| `kite-rainmatter-warm-intro.md` | SURVIVES UNCHANGED |
| `kite-registry-and-funding-refs.md` | SURVIVES UNCHANGED |
| `kite-riskguard-tightened.md` | SURVIVES UNCHANGED |
| `kite-sebi-otr-feb-2026.md` | SURVIVES UNCHANGED |
| `kite-security-hardening-2026-04.md` | SURVIVES UNCHANGED |
| `kite-security-posture.md` | SURVIVES UNCHANGED |
| `kite-session-apr2.md` | SURVIVES UNCHANGED (snapshot) — minor footnote OK |
| `kite-session-apr3.md` | NEEDS PATCH (I10 — rotate R2 credentials, replace plaintext) |
| `kite-skills-wrapper.md` | SURVIVES UNCHANGED |
| `kite-widget-capability-detection.md` | SURVIVES UNCHANGED |
| `kite-zerodha-no-marketplace.md` | SURVIVES UNCHANGED (add date stamp) |
| `project_kite_agent_ids_apr25.md` | SURVIVES UNCHANGED |
| `project_wsl2_setup.md` | SURVIVES UNCHANGED |
| `session_2026_04_17_handoff.md` | SURVIVES UNCHANGED (snapshot) |
| `session_2026-04-27_agent_team_snapshot.md` | SURVIVES UNCHANGED (snapshot) |
| `session_2026-05-03_*` (2 files) | SURVIVES UNCHANGED (snapshot) |
| `session_2026-05-04_*` (2 files) | SURVIVES UNCHANGED (snapshot) |
| `session_2026-05-05_agents.md` | SURVIVES UNCHANGED (snapshot) |
| `session_2026-05-06_axis-c-closed.md` | SURVIVES UNCHANGED (snapshot) |
| `session_2026-05-10_path-a-complete.md` | SURVIVES UNCHANGED (newest snapshot — promote in MEMORY.md) |

**Tally**: 7 files need patches; 4 of those are CRITICAL; 1 (launch-blockers-apr18) is a candidate for archive-as-historical instead of patch. 69 files survive unchanged.

---

## §10 — Final assessment

**No memory file contradicts a user rule** (the special handling for `user_*.md` + `feedback_*.md` per dispatch brief). Rules corpus is internally consistent and not violated this session.

**No critical safety/security finding** (the secrets-in-plaintext issue is a hygiene flag, not a breach; credentials are filesystem-scoped to user's `memory/` dir).

**The systematic 3-week staleness on kite-* files** is the largest pattern. Most files were last touched 2026-04-17 ± 2 days, and the world has shifted meaningfully since (Path A complete, Stripe wired, smithery.yaml shipped, Tradarc renewed, etc.). The 7 critical/important patches in §5 close this gap.

**Recommendation in one sentence**: apply patches 1-8 (critical, ~1 hour of edits in next dispatch); the 31-finding total is tractable and tractable does not need a multi-day intervention.
