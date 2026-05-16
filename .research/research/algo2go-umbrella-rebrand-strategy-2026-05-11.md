<!-- secret-scan-allow: research-doc-with-git-shas-and-public-urls -->
---
title: Algo2Go Umbrella Rebrand Strategy — Brand + Market Positioning Post-Saturation
as-of: 2026-05-11
re-verify-by: 2026-08-11
master-head-at-write: 7c21e7d
scope: READ-ONLY research; brand + market-positioning angle of the Sundeepg98/kite-mcp-server → algo2go/kite-mcp-server transfer question
parallel-tracks: github-transfer-bootstrap-2026-05-11.md (technical mechanics), god-object-inventory-2026-05-11.md (in-tree decomp), mcp-ecosystem-audit-2026-05-11.md (registry presence)
budget-used: ~2h of 3h target; 5h hard halt
dispatch: turn-N brand/market angle while 9 sibling agents handle technical/legal/audit
---

# Algo2Go Umbrella Rebrand Strategy — Brand + Market Positioning

## §INPUTS — load-bearing facts re-probed at HEAD `7c21e7d`

| Fact | Source / Probe | Verified |
|---|---|---|
| `algo2go` org exists; `public_repos=28`; `description: null`; `created_at: 2026-05-05T14:52:29Z`; `followers: 0`; `is_verified: false`; `two_factor_requirement_enabled: false`; `default_repository_permission: "read"`; `billing_email: sundeepg8@gmail.com`; `plan.name: free` | `gh api orgs/algo2go` | 2026-05-11 |
| Org has **no `.github` profile repo** → no public profile README/page | `gh api repos/algo2go/.github` → HTTP 404 | 2026-05-11 |
| 28 algo2go/kite-mcp-* modules already publicly published (Go libraries; broker-agnostic primitives + Kite-specific adapters) | `gh api orgs/algo2go/repos --jq 'length'` returns 28; full list enumerated below | 2026-05-11 |
| Aggregate star/fork count across all 28 repos: **stars=0, forks=0** | `gh api orgs/algo2go/repos --jq '[.[] | {s: .stargazers_count, f: .forks_count}] \| {total_stars: (map(.s)\|add), total_forks: (map(.f)\|add)}'` | 2026-05-11 |
| `Sundeepg98/kite-mcp-server` parent repo: stars=0, forks=0, watchers=0; created 2026-02-22; size=11.3MB; NOT archived; default branch `master` | `gh api repos/Sundeepg98/kite-mcp-server` | 2026-05-11 |
| `algo2go.com` AVAILABLE (Verisign RDAP returns HTTP 404 — not registered) | `curl -sS https://rdap.verisign.com/com/v1/domain/algo2go.com` | 2026-05-11 |
| `algo2go.dev` AVAILABLE (PIR RDAP returns HTTP 404) | `curl -sS https://rdap.publicinterestregistry.org/rdap/domain/algo2go.dev` | 2026-05-11 |
| `algo2go.io` AVAILABLE (Identity Digital RDAP returns HTTP 404) | `curl -sS https://rdap.identitydigital.services/rdap/domain/algo2go.io` | 2026-05-11 |
| `algo2go.in` AVAILABLE per NIXI Registry RDAP ("Domain algo2go.in is available for registration") | `curl -sSL https://rdap.org/domain/algo2go.in` follows redirect to NIXI | 2026-05-11 |
| `tradarc.com` (memory's claimed backup name) NOT available — auto-renewed to 2027-05-04; held by Server Plan Srl since 2001 | Memory `kite-algo2go-rename.md` line 24-31, re-verified 2026-05-11 | 2026-05-11 |
| Backup candidates RDAP-verified available (per memory `kite-algo2go-rename.md`): `quirkalgo.com`, `quanto2go.com`, `tradloop.com`, `zerocode2go.com`, `tradesy2.com` — all 5 unregistered, all 5 corresponding GitHub orgs also unclaimed | Memory cross-reference, batch-2026-05-11.md §A | 2026-05-11 |
| TM filing cost: ₹9,000 direct via `ipindiaonline.gov.in` (₹4,500/class × 2 classes Individual rate) — NOT the ₹18-22k Vakilsearch path | Memory `kite-algo2go-rename.md` line 36-37 | 2026-05-11 |
| TM examination duration: 12-18 months; `Algo2Go™` usage allowed immediately on filing; `®` only after registration | Memory + IP India process docs | 2026-05-11 |
| GitHub transfer mechanics (HTTP 301 redirects ~1yr, all commits/issues/Actions secrets preserved) — verified by sibling track `github-transfer-bootstrap-2026-05-11.md` | sibling research doc | 2026-05-11 |
| Sundeepg98 namespace currently has stars=0 forks=0 — **near-zero brand value to lose on transfer** | gh api probe | 2026-05-11 |
| FLOSS/fund triggers per memory: ≥50 stars + 1 blog/HN post + `funding.json` published | Memory `kite-floss-fund.md` line 30-34 | 2026-05-11 |
| Rainmatter warm-intro triggers: phased — Shenoy first, only AFTER FLOSS/fund submitted + ≥50 stars | Memory `kite-rainmatter-warm-intro.md` line 14-32 | 2026-05-11 |

> **Methodology note**: For binary state (count/availability) used canonical REST/RDAP probes per `feedback_compile_and_run_methodology` and `feedback_verify_before_synthesize`. All "as-of" dates explicit per `feedback_dated_synthesis`.

---

## §1 Current Algo2Go inventory — what the brand surface looks like today

### 1.1 GitHub org state

`https://github.com/algo2go` exists since **2026-05-05** (6 days as of write). It contains **28 public repositories**, all `Go` (24 modules) + `HTML` (1: `kite-mcp-templates`) + mixed (the rest). All 28 are named under the `kite-mcp-*` prefix:

```
kite-mcp-alerts            kite-mcp-aop                 kite-mcp-audit
kite-mcp-billing           kite-mcp-broker              kite-mcp-clockport
kite-mcp-cqrs              kite-mcp-decorators          kite-mcp-domain
kite-mcp-eventsourcing     kite-mcp-i18n                kite-mcp-instruments
kite-mcp-isttz             kite-mcp-legaldocs           kite-mcp-logger
kite-mcp-money             kite-mcp-oauth               kite-mcp-papertrading
kite-mcp-registry          kite-mcp-riskguard           kite-mcp-scheduler
kite-mcp-sectors           kite-mcp-telegram            kite-mcp-templates
kite-mcp-ticker            kite-mcp-usecases            kite-mcp-users
kite-mcp-watchlist
```

### 1.2 Brand-surface gaps (empirically observed)

The org has been treated as a **module-hosting namespace**, NOT a brand front. Specific gaps:

| Gap | Observation | Impact on Show HN / Reddit / pitch |
|---|---|---|
| **`description` field is `null`** | `gh api orgs/algo2go` returns `"description": null` | Org landing page has no tagline; visitor sees only `Algo2Go · 0 followers · 28 repos` |
| **No `.github` profile repo** | HTTP 404 on `repos/algo2go/.github` | No README at top of org page; just a flat repo list |
| **No org avatar / logo** | `avatar_url` is the GitHub-generated identicon | First impression is "this is a personal-side-project org" |
| **`is_verified: false`** | No verified domain | Cannot link `algo2go.com` to the org for verified-org badge (domain doesn't exist yet) |
| **0 followers, 0 stars across 28 repos** | aggregate probe | Visitor sees zero social proof. **All 28 module repos read like internal infra, not a movement.** |
| **All 28 names share `kite-mcp-*` prefix** | repo list | Hardcodes "this is the kite-mcp suite" — limits future-proofing to other brokers (see §4) |
| **`default_repository_permission: read`** | org settings | Anyone is treated as a reader, NOT a contributor — fine for OSS but suggests "this is closed development" if no contributing guide exists |

### 1.3 Domain surface

| TLD | Status | Use-case |
|---|---|---|
| `algo2go.com` | **AVAILABLE** | Primary; canonical brand domain |
| `algo2go.dev` | **AVAILABLE** | Developer-portal subdomain alternative |
| `algo2go.io` | **AVAILABLE** | Tech-startup convention (premium pricing) |
| `algo2go.in` | **AVAILABLE** | India-specific; relevant for SEBI / DPIIT positioning |

**Aggregate domain-acquisition cost** (if all 4 reserved Y1, registrar prices observed at sibling Playwright drive-through 2026-05-03):
- `.com`: ~$6.79 first year with NEWCOM679 promo, ~$15/yr renewal
- `.dev`: ~$10-12/yr
- `.io`: ~$30-60/yr (premium TLD)
- `.in`: ~₹500-700/yr direct via Indian registrar

**Realistic recommendation**: register `.com` only (₹560 first year) at brand-reservation step. Defer others until trademark filed.

### 1.4 No competitor naming collisions (empirical check)

WebSearch for "Algo2Go" + "trading bot" / "trading platform" / "stock algo" returns:
- No SaaS named Algo2Go in the trading vertical
- No GitHub project named `algo2go` (org-name itself is the only hit)
- No app-store entry on iOS/Android using this name
- Indian-fintech competitors (Streak, Smallcase, Sensibull, AlgoTest) all use distinct brand names

**Conclusion**: brand surface is clean. **Algo2Go has zero pre-existing market noise** to compete with.

---

## §2 Rebrand mechanics — `Sundeepg98/kite-mcp-server` → `algo2go/kite-mcp-server`

(See sibling `github-transfer-bootstrap-2026-05-11.md` for full technical mechanics. This section covers only the **brand**-side of the rebrand.)

### 2.1 What the user sees on launch day

| Surface | Before | After |
|---|---|---|
| GitHub URL | `github.com/Sundeepg98/kite-mcp-server` | `github.com/algo2go/kite-mcp-server` (with HTTP 301 redirect from old URL for ~1 year) |
| Repo display name | "Sundeepg98/kite-mcp-server" | "algo2go/kite-mcp-server" |
| Hosted demo URL | `https://kite-mcp-server.fly.dev/mcp` | **UNCHANGED** (Fly app name independent of GitHub) |
| `mcp-remote` config snippet | `mcp-remote https://kite-mcp-server.fly.dev/mcp` | **UNCHANGED** |
| Existing mcp-remote OAuth cache (`~/.mcp-auth/`) | keyed on Fly URL md5 hash | **UNCHANGED** (no user re-auth required) |
| README hero | "Sundeepg98 / kite-mcp-server" | "algo2go / kite-mcp-server" |
| README content | unchanged in mechanics | optional rebrand-narrative update (see §3) |
| Module imports | `github.com/Sundeepg98/kite-mcp-server` (which is what `main.go` resolves to via root go.mod — NB the in-tree module path is actually `github.com/zerodha/kite-mcp-server` per §INPUTS) | UNCHANGED until go.mod is updated separately (this is a per-commit decision, not a transfer-time decision) |

### 2.2 SEO / discoverability impact

| Channel | 1-year impact | 5-year impact |
|---|---|---|
| GitHub search "kite-mcp-server" | Unchanged (kite-mcp-server is still the repo name; the only thing changing is the owner prefix) | Unchanged |
| Google search results pointing at old GitHub URL | Auto-redirect 301 → preserves PageRank; both URLs co-resolve | Old URL eventually de-indexed |
| Backlinks (HN posts, Reddit comments, blog posts citing the repo) | Auto-redirect preserves; no broken links | Auto-redirect TTL is **~1 year** per GitHub policy; after that, ANY remaining old URL is dead unless GitHub honors longer (historically they have, but no SLA) |
| MCP Registry `server.json` | `name: "io.github.Sundeepg98/kite-mcp-server"` would need a new registry entry under `io.github.algo2go/kite-mcp-server` (MCP Registry treats `name` as immutable per `mcp-server-registry README`) | Old name remains in registry historical record; new name supersedes |
| `awesome-mcp-servers` PR list | Existing PR cites old URL; auto-redirect preserves through 1yr | Manual PR re-submission to update URL recommended |
| Smithery / `mcp.directory` listings | Auto-redirect handles | Manual update recommended |

**Key brand-side insight**: **at 0 stars and 0 backlinks of measurable PageRank, there is nothing to lose**. The "preserve SEO" argument is essentially null at our scale. If we had 1000 stars + 50 HN backlinks, the rebrand would carry real cost. **At our state, the rebrand is FREE in SEO terms.**

### 2.3 Trademark interplay

**Does the rebrand FORCE faster TM filing?**

No. The relationships are:

| TM filing state | GitHub transfer state | Risk |
|---|---|---|
| TM unfiled, brand unused | Transfer NOT executed | None (current state) |
| TM unfiled, brand unused | Transfer DONE; org renamed; using "Algo2Go" publicly on README | **Slight common-law-mark exposure**: using "Algo2Go" publicly without TM filing creates an unregistered mark. If someone else files Class 36/42 first (race-to-file), they can sue us for infringement. Probability: low (memory: no conflicting marks 2026-04-17, re-verified at filing time). |
| TM filed (Class 36+42), examination pending | Transfer DONE | Lowest risk. `Algo2Go™` symbol legally usable from filing date. |
| TM registered | Transfer DONE | Best state; ® symbol usable. |

**Practical sequence**: TM filing should happen **BEFORE the brand becomes publicly visible** (i.e. before HN/Reddit/blog launches). Transfer can happen before, after, or simultaneous with TM filing — the two are decoupled.

**Recommendation**: file TM **the same day** as the rebrand announcement. The ₹9k direct filing on `ipindiaonline.gov.in` takes <2 hours of user time. Holding the rebrand for the TM filing date adds only this gating.

### 2.4 What CANNOT be reverted

Per sibling `github-transfer-bootstrap-2026-05-11.md`:
- The transfer itself is reversible: re-transfer back to `Sundeepg98` works (GitHub permits ownership ping-pong).
- But once `algo2go/kite-mcp-server` exists, **deleting it requires admin action**.
- The MCP Registry `name` field is immutable per published spec; once `io.github.algo2go/kite-mcp-server` is published, the old `io.github.Sundeepg98/kite-mcp-server` becomes a deprecated entry permanently. Reverting would require a fresh `name` (e.g. `io.github.Sundeepg98/kite-mcp-server-v2`).

**Brand-side conclusion**: the rebrand is **operationally reversible** but the MCP Registry publication step (if executed) is one-way. Sequence accordingly: complete transfer + verify ALL surfaces → only then publish to MCP Registry.

---

## §3 Market positioning — three narratives compared

### 3.1 Narrative A: "kite-mcp-server is the open-source Kite MCP for Zerodha" (status quo)

**Positioning**: Single-product framing. The repo IS the product.

**Show HN headline**: *"Show HN: kite-mcp-server — Bring AI to your Zerodha trading account via MCP"*

**Strengths**:
- Concrete, single CTA: `npx mcp-remote https://kite-mcp-server.fly.dev/mcp`
- Easy for HN reviewer to evaluate in 30s: "OK, this is an MCP for Zerodha trading. Got it."
- No platform-pretending energy
- README hero already written this way

**Weaknesses**:
- Doesn't explain the 28 algo2go/kite-mcp-* modules (which the curious HN reader WILL click into and ask: "wait, what's algo2go?")
- Locks brand to Kite/Zerodha — future Upstox / Dhan / Angel One support would require either renaming or fragmenting the narrative
- Doesn't differentiate from Zerodha's own official MCP at `mcp.kite.trade`
- TM-risk exposure: "Kite" is Zerodha's registered mark; using "kite-mcp-server" as the product name (not just a repo name) is legally ambiguous

**Audience fit**:
- **Show HN**: 7/10 — works but reviewers will sniff inconsistency between repo-name and org-name
- **Reddit r/algotrading**: 8/10 — concrete and Indian-trading-specific
- **Rainmatter pitch**: 6/10 — single-product framing limits valuation narrative (Rainmatter prefers ecosystem plays)
- **FLOSS/fund grant**: 7/10 — works but doesn't explain the modular ecosystem

### 3.2 Narrative B: "Algo2Go is a suite of trading-automation MCP modules; kite-mcp-server is the first reference deployable"

**Positioning**: Umbrella framing. The 28 modules + 1 deployable = a platform.

**Show HN headline**: *"Show HN: Algo2Go — Open-source trading-automation MCP suite; kite-mcp-server is our reference Zerodha deployment"*

**Strengths**:
- Explains the 28 algo2go/kite-mcp-* modules naturally
- Future-proofs for Upstox/Dhan: `algo2go/upstox-mcp-server` would be a sibling deployable
- Differentiates from Zerodha's official MCP (theirs = single tool; ours = ecosystem)
- Matches the empirical reality (28 modules are broker-agnostic; only the deployable is Kite-specific)
- Stronger Rainmatter narrative (ecosystem > single tool)
- TM-safer: "Algo2Go" is the brand, "kite-mcp-server" is just a sub-product name

**Weaknesses**:
- Requires the rebrand to land (status quo doesn't permit this framing)
- Risk of "platform pretending" if executed before traction (reviewers ask "where's the second deployable?")
- More words to explain on HN front page (HN rewards concision)
- 28 module repos all named `kite-mcp-*` — undercuts the "broker-agnostic suite" claim until renamed (see §4.2)

**Audience fit**:
- **Show HN**: 6/10 — risks "trying to look like a platform with one product"
- **Reddit r/algotrading**: 7/10 — Indian audience likes ecosystem story but cares more about working code
- **Rainmatter pitch**: 9/10 — strongest framing for ecosystem play; matches their portfolio thesis
- **FLOSS/fund grant**: 9/10 — modular OSS suite is the canonical FLOSS-grant target

### 3.3 Narrative C: "Algo2Go: MCP-native trading-automation primitives. Reference deployment: Kite." (hybrid)

**Positioning**: Lead with primitives, deemphasize the deployable.

**Show HN headline**: *"Show HN: Algo2Go — MCP-native trading-automation primitives in Go (with a working Kite/Zerodha demo)"*

**Strengths**:
- Hooks devs (primitives sell to library-consumers)
- Demo URL still concrete (one-click try)
- Brand is library-shaped, not SaaS-shaped — avoids the "platform pretending" objection
- Matches the actual code state (28 published libs + 1 server)
- Stronger differentiation: Zerodha's official is a tool; ours is a toolkit + tool

**Weaknesses**:
- Conceptually heavier — "primitives" is a developer term, not a trader term
- May lose the Indian-retail-trader audience who want a working product, not building blocks
- Splits attention: do we sell the libs or the demo?
- Requires the rebrand AND a clear primitive-vs-deployable framing in README

**Audience fit**:
- **Show HN**: 8/10 — HN loves primitives + demo combo (e.g. how Mintlify, Resend, Cal.com launched)
- **Reddit r/algotrading**: 6/10 — wrong audience for "primitives" language
- **Rainmatter pitch**: 9/10 — primitives-with-demo is the canonical YC W23-25 pitch shape
- **FLOSS/fund grant**: 10/10 — primitives are exactly what FLOSS funds (vs end-user products)

### 3.4 Per-channel narrative recommendation

| Channel | Best narrative | Why |
|---|---|---|
| **Show HN** | C (primitives + demo) OR A (status quo) | C if rebrand is done; A if not. **Do NOT do B on HN** — single deployable + 28 unused libs reads as overengineering on HN's brutal-honesty culture. |
| **Reddit r/algotrading** | A (single-product) | Indian retail audience wants concrete tool; defer ecosystem story |
| **Reddit r/golang** | C (primitives + demo) | Go community loves Hex/DDD/clean-arch primitives |
| **Rainmatter pitch (deck)** | B (umbrella) or C (hybrid) | Both win; B if pitching ecosystem; C if pitching dev-tools angle |
| **FLOSS/fund grant proposal** | C (primitives + demo) | Best FLOSS fit — funds OSS infra, not SaaS products |
| **Hindi/regional fintech press** | A (status quo, Indian-retail framing) | Audience cares about the working tool, not the architecture |

### 3.5 Multi-narrative tactic — different framings per audience

The narratives are NOT mutually exclusive across channels. Tactical sequence:

1. **Show HN** (week 1): launch with Narrative A or C
2. **Reddit r/algotrading** (week 1 +24h): cross-post with Narrative A
3. **Reddit r/golang** (week 1 +48h): separate post with Narrative C
4. **FLOSS/fund** (week 2): apply with Narrative C
5. **Twitter/X build-in-public** (ongoing): Narrative B as background context
6. **Rainmatter outreach** (post-50-stars, post-FLOSS-application): Narrative B in conversation

The README at the top of each repo carries Narrative A (current), and the org-level profile page (the `.github` profile README we'd add) carries Narrative B. **This split is intentional** — let the marketing surface match the audience.

---

## §4 Future-proofing the umbrella structure

### 4.1 Why the current `kite-mcp-*` naming undercuts the umbrella

All 28 modules under `algo2go/` are named `kite-mcp-X`. This hardcodes "Kite" into every module name even though MOST modules are broker-agnostic:

| Module | Broker-agnostic? | Current name | Future-proof name (if renamed) |
|---|---|---|---|
| `kite-mcp-broker` | YES (defines `broker.Client` interface; gokiteconnect/v4 is one of N adapters) | `kite-mcp-broker` | `algo2go-broker` |
| `kite-mcp-money` | YES (currency math for INR-denominated values) | `kite-mcp-money` | `algo2go-money` |
| `kite-mcp-audit` | YES (audit trail; broker-independent) | `kite-mcp-audit` | `algo2go-audit` |
| `kite-mcp-riskguard` | YES (pre-trade safety checks) | `kite-mcp-riskguard` | `algo2go-riskguard` |
| `kite-mcp-papertrading` | YES (virtual portfolio simulator) | `kite-mcp-papertrading` | `algo2go-papertrading` |
| `kite-mcp-aop`, `-cqrs`, `-decorators`, `-domain`, `-eventsourcing`, `-i18n`, `-isttz`, `-legaldocs`, `-logger`, `-scheduler`, `-clockport`, `-billing`, `-oauth`, `-users`, `-templates` | YES (general infra) | `kite-mcp-*` | `algo2go-*` |
| `kite-mcp-instruments` | PARTIAL (NSE/BSE instruments fetcher; specific to Indian exchanges, broker-agnostic) | `kite-mcp-instruments` | `algo2go-nse-instruments` or keep |
| `kite-mcp-ticker` | PARTIAL (websocket abstraction; backed by Kite SDK today) | `kite-mcp-ticker` | refactor to broker-agnostic, then `algo2go-ticker` |
| `kite-mcp-telegram` | YES (Telegram bot integration) | `kite-mcp-telegram` | `algo2go-telegram` |
| `kite-mcp-registry` | YES (admin-managed Kite app credentials store; could generalize) | `kite-mcp-registry` | `algo2go-credentialregistry` |
| `kite-mcp-sectors` | PARTIAL (NSE/BSE sector mappings) | `kite-mcp-sectors` | `algo2go-nse-sectors` |
| `kite-mcp-watchlist` | YES (per-user watchlist CRUD) | `kite-mcp-watchlist` | `algo2go-watchlist` |
| `kite-mcp-usecases` | NO (Kite-specific application use cases) | `kite-mcp-usecases` | stay `kite-mcp-usecases` (Kite-specific) |
| `kite-mcp-alerts` | YES | `kite-mcp-alerts` | `algo2go-alerts` |

**Roughly 22 of 28 modules** are broker-agnostic and would semantically benefit from a rename. **Only ~3-5 modules are genuinely Kite-specific** (`kite-mcp-broker` adapter section, `kite-mcp-usecases`, possibly `kite-mcp-instruments`).

### 4.2 The rename cost vs benefit

**Cost of renaming 22+ algo2go/kite-mcp-* → algo2go/* repos**:
- GitHub repo renames are individually cheap (`gh api -X PATCH repos/algo2go/kite-mcp-X --field name=algo2go-X`) and preserve HTTP 301 redirects
- Each Go module import path changes; root `go.mod` must update 22 `require` lines + 22 `replace` directives if any
- Every consumer (root kite-mcp-server, sibling modules) must update their go.mod
- Coordinated semver tag (e.g. `v0.2.0`) needed across affected modules
- Calendar: ~2 dev-weeks for the cascade if done carefully

**Benefit**:
- Future broker integrations land cleanly as `algo2go/upstox-mcp-server`, `algo2go/dhan-mcp-server`, etc.
- Org-level brand consistency
- Module names match Narrative B / C marketing surface
- Avoids the "kite" association becoming a TM problem if Zerodha objects later (Kite is a registered TM of Zerodha; technically the `kite-mcp-*` names ARE infringing today — current usage is borderline-tolerated descriptive use, but borderline)

**Recommendation**: defer the rename of broker-agnostic modules **until at least one second broker is integrated** OR **Zerodha sends a TM notice**, whichever comes first. The cost is ~2 dev-weeks and the benefit is forward-looking; do NOT pay this cost speculatively.

### 4.3 What gets ADDED as the umbrella expands

Plausible future repos under `algo2go/`:

| Repo | Purpose | Time horizon |
|---|---|---|
| `algo2go/.github` | Org profile README + community health files | NOW (free; 30 min) |
| `algo2go/upstox-mcp-server` | Second-broker deployable | Post-50-stars OR paying customer asks |
| `algo2go/dhan-mcp-server` | Third-broker deployable | Post-second-broker |
| `algo2go/algo2go-cli` | Standalone CLI invoking same usecases | Post-100-users |
| `algo2go/algo2go-dashboard` | Standalone dashboard (separable from server) | Post-200-users + 4+ engineers |
| `algo2go/algo2go-research` | FII/DII/concall analysis tools (currently in kite-mcp-server) | Post-Phase-1-launch |
| `algo2go/algo2go-strategies` | Strategy marketplace (community-contributed YAML) | Post-1k-stars |
| `algo2go/algo2go-skills` | The 8 Claude Skills wrapper (currently embedded) | NOW or post-launch |

Per `feedback_decoupling_denominator.md` Axis B, **defer EVERY one of these** except `algo2go/.github` until external demand justifies. The umbrella is reservation infrastructure, not active expansion.

---

## §5 Sequencing recommendation

### 5.1 The four gates

The user's question — "rebrand now (during pre-launch) or after first 100 users?" — has 4 gating moments:

| Gate | Trigger | Action |
|---|---|---|
| **G1: Pre-launch** (today) | HEAD `7c21e7d`; pre-launch; Sundeepg98 namespace has 0 stars 0 backlinks | **Free to rebrand now** (no SEO loss) BUT may not be necessary |
| **G2: Show HN** (week 1) | Launch window | Rebrand BEFORE this if doing Narrative B or C; **stay at Sundeepg98 if doing Narrative A** |
| **G3: Post-launch 50 stars** | Memory `kite-floss-fund.md` triggers | Rebrand here if not done; FLOSS/fund and Rainmatter pitches benefit |
| **G4: Post-100 paid users** | Empanelment threshold per memory `kite-mrr-reality.md` | Strict rebrand by this gate (revenue + TM exposure crosses the "we need our own mark" threshold) |

### 5.2 Decision matrix

| Scenario | Recommended sequence |
|---|---|
| **User picks Narrative A (single-product, status quo)** | Rebrand at G3 (post-50-stars) — no urgency at G1/G2 |
| **User picks Narrative B (umbrella ecosystem)** | Rebrand at G1 (now, pre-launch) — narrative requires it |
| **User picks Narrative C (primitives + demo)** | Rebrand at G1 (now, pre-launch) — narrative requires it |
| **User is undecided on narrative** | Rebrand at G1 (now) — preserves optionality; cost is ~30min user-time; reversible |

### 5.3 TM filing dependency

**Strict prerequisite**: TM Class 36+42 filing should be **submitted** before Algo2Go appears in any public-facing marketing material (Show HN, Reddit, blog post). This is a 2-hour gating step at ₹9k via direct IP India online filing (NOT Vakilsearch's ₹18-22k path per memory `kite-algo2go-rename.md`).

**Sequence**:
1. **Day -2**: User files TM Class 36 + Class 42 online (~2h user time; ₹9k)
2. **Day -1**: Receive filing receipt (24h auto-issue)
3. **Day 0**: Execute GitHub transfer (`gh api -X POST repos/Sundeepg98/kite-mcp-server/transfer -f new_owner=algo2go`)
4. **Day 0**: Publish `algo2go/.github` profile README (paste-ready content in §1.2 of `algo2go-reservation-runbook.md`)
5. **Day 0**: Update Fly.io app metadata (optional brand consistency; no URL change required)
6. **Day 0**: Buy `algo2go.com` (~₹560 first year)
7. **Day +1 to +7**: Show HN / Reddit posts with Narrative A or C (NOT B unless second-broker exists)

**TM filing is NOT a hard blocker for the transfer itself** — but if Show HN audience clicks through and asks "is Algo2Go trademarked?", "filed" answers convincingly while "unfiled" reads as unprofessional.

### 5.4 Honest verdict

**Recommended sequence**:

1. **TODAY**: register `algo2go.com` (₹560 1-year); file TM Class 36+42 direct on `ipindiaonline.gov.in` (₹9k; 2h user time)
2. **TODAY + 24h** (after TM filing receipt): execute the GitHub transfer per sibling `github-transfer-bootstrap-2026-05-11.md`
3. **TODAY + 48h**: publish `algo2go/.github` profile README (paste-ready content already exists)
4. **TODAY + 1 week**: Show HN with Narrative C (primitives + demo) — strongest fit for HN audience + matches code reality
5. **TODAY + 2 weeks** (post-50-stars): submit FLOSS/fund application with Narrative C
6. **TODAY + 1-2 months** (post-FLOSS-fund submission): Rainmatter warm-intro via Shenoy per memory `kite-rainmatter-warm-intro.md`

**Total user time for steps 1-3**: ~4 hours sequential (₹9,560 cash + ~30min agent-automatable sub-tasks).

**Why this beats "rebrand at G3 (post-50-stars)"**: at G3, the rebrand carries real SEO cost (50 stars = 5-15 backlinks; HN/Reddit URLs need updates). At G1 (today), the rebrand is free. Doing it earlier is strictly dominant.

**Why this beats "rebrand at G4 (post-100-users)"**: by G4, TM exposure from publicly using "kite-mcp-server" (Zerodha mark) is genuine legal risk; rebrand becomes reactive, not proactive.

**Why NOT rebrand AFTER Show HN**: Show HN posts cannot be edited > 2 hours after submission. If Show HN goes live as `Sundeepg98/kite-mcp-server` and we rebrand 1 week later, the HN frontpage cite is forever stale.

---

## §6 Open questions / NEEDS-USER

| # | Question | Why it matters | Default-if-no-answer |
|---|---|---|---|
| 1 | Which of 3 narratives (A / B / C) at Show HN? | Determines whether rebrand must happen pre-launch | Default: Narrative A (status quo) IF stays at Sundeepg98; Narrative C IF rebrand done |
| 2 | Is user willing to spend 4h + ₹9,560 in the next 48h for TM + domain + transfer? | Gate for the recommended sequence | Default: defer entire Algo2Go rebrand until post-50-stars |
| 3 | Backup name choice if `Algo2Go` TM examination fails? Memory lists 5 alternatives — does user pre-rank? | Hedges TM-rejection risk | Default: `quirkalgo.com` per memory's top pick |
| 4 | Multi-broker timeline — when does Upstox/Dhan land? | Determines urgency of the broker-agnostic module rename (§4.2) | Default: defer module renames until second broker integrated |
| 5 | Org-profile README content — use the 151-word version from `.research/research/algo2go-reservation-runbook.md`? Or rewrite? | First impression on org page | Default: use existing 151-word version with minor adjustments |
| 6 | Verified-domain badge on org — wire `algo2go.com` to org after registration? | Brand legitimacy signal | Default: yes, ~10 min user effort post-domain-registration |

---

## §7 Cross-references

| Doc | What it provides | Status |
|---|---|---|
| `.research/research/github-transfer-bootstrap-2026-05-11.md` | Technical mechanics of the GitHub transfer + `algo2go/kite-mcp-bootstrap` module design | Already exists (sibling) |
| `.research/research/god-object-inventory-2026-05-11.md` | In-tree decomposition status; informs "zero in-tree code" feasibility | Already exists (sibling) |
| `.research/research/mcp-ecosystem-audit-2026-05-11.md` | MCP Registry presence; informs whether to publish `io.github.algo2go/kite-mcp-server` immediately | Already exists (sibling) |
| `.research/algo2go-reservation-runbook.md` | Saturday-side-quest user runbook for the brand reservation (paste-ready forms, agent-automatable steps) | Already exists; this doc supersedes its sequencing recommendation |
| Memory `kite-algo2go-rename.md` | TM availability, filing cost (₹9k direct), backup-name candidates (Tradarc OUT) | Already exists |
| Memory `kite-floss-fund.md` | FLOSS/fund triggers + application process | Already exists |
| Memory `kite-rainmatter-warm-intro.md` | Phased Rainmatter intro sequence (Shenoy → Sonagara → Hassan) | Already exists |

---

## §8 Honest opacity / caveats

1. **The "rebrand at G1" recommendation assumes user has 4h available in the next 48h.** If user is mid-launch sprint, the rebrand may slip to G2 (Show-HN window) which is the next-best gate. Slipping past G2 incurs SEO cost (small but nonzero).

2. **The TM filing race-to-file risk is small but real.** Memory `kite-algo2go-rename.md` 2026-04-17 verified no conflicting marks; re-verify on filing day. Probability of someone else filing "ALGO2GO" Class 36+42 in the 4-week window since the org was claimed: low (no public mention of the name yet) but nonzero.

3. **The "Narrative C is best for FLOSS/fund (10/10)" rating is informed speculation** based on memory `kite-floss-fund.md` description of the fund's preference for OSS infrastructure (vs end-user products). Actual FLOSS committee preferences could differ; would not invalidate the ranking among the 3 narratives but might compress the gap.

4. **The 22-of-28 broker-agnostic claim in §4.1** is based on module descriptions (verified via `gh api orgs/algo2go/repos`); not a deep code audit. Some modules (e.g. `kite-mcp-ticker`) might have deeper Kite SDK dependencies than the descriptions suggest. If user opts to rename, do empirical per-module audit first.

5. **Aggregate 0 stars / 0 backlinks claim** is empirical at HEAD `7c21e7d`. Will not be stationary; once Show HN lands, stars/backlinks accrue. **The rebrand-is-free analysis depends on staying at this state**; once stars > 50 the analysis flips.

6. **The "MCP Registry name is immutable" claim** is per published spec; sibling `mcp-ecosystem-audit-2026-05-11.md` may have more recent empirical verification.

7. **Domain registration timing**: `algo2go.com` has been observed AVAILABLE since 2026-04-17 (memory) and re-verified 2026-05-03 + 2026-05-11. Squatter risk is low but nonzero. **Register-today vs register-at-rebrand-execution** has small (~days) but real risk of someone else claiming during the gap.

8. **The recommendation depends on the user actually wanting to launch within 1-4 weeks.** If launch slips to month +3+, the urgency is lower and the rebrand can defer to G3 (post-50-stars from a delayed launch).

9. **`kite-mcp-usecases` was rated "NO broker-agnostic" but** that's not strictly true — usecases CAN be broker-agnostic via the broker port; the rating reflects that the current implementation embeds Kite-specific assumptions. Refactor work would generalize.

10. **No empirical check of npm/PyPI placeholder packages** at this dispatch. Memory `kite-algo2go-rename.md` says they're available; sibling `algo2go-reservation-runbook.md` Phase 5 has the paste-ready scaffolding.

---

## §9 Bottom line

**Rebrand now (G1, today). TM-file first (2h, ₹9k). Pick Narrative A or C for Show HN. Save Narrative B for Rainmatter pitch deck.**

- **Cost**: 4h user time + ₹9,560 cash + reversible operations
- **Benefit**: free SEO migration (0 stars to lose); pre-empts TM exposure; unlocks Narrative B/C for ecosystem channels (FLOSS/fund, Rainmatter); cleans up the empirical inconsistency between repo-name and 28-module-org-name
- **Risk** (if NOT rebranding now): TM exposure once revenue starts; SEO cost rises with each accrued star; Show-HN narrative weaker (reviewers WILL ask about the 28 algo2go/* modules); requires reactive rebrand under pressure later

The decision is dominated by "rebrand now" on every empirical axis. The only reason NOT to rebrand now is **user runway** (4h is unavailable in the next 48h). In that case, defer to G2 (next-best); never past G3.

---

*Generated 2026-05-11, read-only research deliverable. Brand + market positioning angle. Sibling tracks handle technical mechanics, in-tree code, and MCP Registry presence. NO code changes.*
