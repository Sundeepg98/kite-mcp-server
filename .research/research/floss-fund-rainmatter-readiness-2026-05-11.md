---
title: FLOSS/fund + Rainmatter readiness check
as-of: 2026-05-11
re-verify-by: 2026-07-11
status: research deliverable — NOT a submission
prior: .research/floss-fund-application-prep.md (2026-05-02)
session-handoff: continuation 12 days later (agent-team snapshot 2026-05-05 → 2026-05-11)
---

# FLOSS/fund + Rainmatter readiness — empirical state at 2026-05-11

## TL;DR

| Program | Application-ready? | Trigger met? | Blocker |
|---|---|---|---|
| **FLOSS/fund** | YES (manifest validates clean against v1.1.0) | NO (0 stars / minimal-usage filter) | Distribution: 0 GitHub stars; minimal-usage rejection criterion will fire today |
| **FOSS United (project grant)** | YES (email drafted, ₹4L ask, India-individual eligible) | YES (no star threshold; explicitly Indian-individual-friendly) | Just send — `docs/drafts/foss-united-grant-email.md` |
| **GitHub Secure Open Source Fund** | PARTIAL (need GitHub Sponsors profile live) | NO (needs traction signal) | Set up Sponsors; defer until 50+ stars |
| **Rainmatter Capital** | NO (cold-email rule — warm intro only) | NO (50 stars + FLOSS/fund submitted required) | Cold-blocked by playbook in `kite-rainmatter-warm-intro.md` |

**Fastest-pay action (today): send the FOSS United email.** Their grant cadence is rolling, eligibility is India-individual-friendly, ₹4L ask is reasonable, and the email is already drafted and reviewed. No traction threshold blocks this.

**Mid-term (post-Show-HN): FLOSS/fund.** The manifest is now schema-valid v1.1.0. Application is a single-field paste. Submit after Show HN lands ≥50 stars.

**One unexpected finding: production Fly deployment serves stale `v1.0.0` manifest.** Master serves `v1.1.0`. If any FLOSS/fund submission uses the Fly URL (`https://kite-mcp-server.fly.dev/funding.json`), the validator will see v1.0.0. Submit the GitHub raw URL instead, OR redeploy Fly.

---

## §1 — `funding.json` current state

### Empirical probes (run today, 2026-05-11)

| Probe | Value | Verdict |
|---|---|---|
| `cat funding.json \| jq -r .version` | `v1.1.0` | OK |
| Schema validation against `https://fundingjson.org/schema/v1.1.0.json` via `jsonschema` | **PASS** (no errors) | OK |
| `git ls-files funding.json` | tracked | OK |
| `git log --oneline -- funding.json` head | `25c9c8e` (bumped to v1.1.0 on 2026-05-10) | OK |
| Live raw on GitHub (`raw.githubusercontent.com/Sundeepg98/kite-mcp-server/master/funding.json`) | `version: v1.1.0` HTTP 200 | OK |
| Live `https://kite-mcp-server.fly.dev/funding.json` | `version: v1.0.0` HTTP 200 | **STALE** |
| `FUNDING.json` (uppercase) | tracked, byte-identical to `funding.json` (`diff` empty) | benign duplicate |

### Schema-level field check (manual cross-check vs v1.1.0)

| Schema requirement | Our value | OK? |
|---|---|---|
| `version` | `v1.1.0` | YES |
| `entity.type` ∈ `{individual, group, organisation, other}` | `individual` | YES |
| `entity.role` ∈ `{owner, steward, maintainer, contributor, other}` | `owner` | YES |
| `entity.email` valid format | `sundeepg8@gmail.com` | YES (matches user-rule: NOT renusharmafoundation) |
| `entity.webpageUrl.url` valid https | `https://github.com/Sundeepg98` | YES |
| `entity.description` length | 370 chars | YES |
| `projects[].guid` `^[a-z0-9-]+$` | `kite-mcp-server` | YES |
| `projects[].tags` `maxItems: 10` | 10 tags | YES (exactly at cap) |
| `projects[].licenses` SPDX-prefixed | `spdx:MIT` | YES |
| `funding.channels[].type` ∈ `{bank, payment-provider, cheque, cash, other}` | `other` | YES (functionally fine; `payment-provider` would be more polished, see §5 nit) |
| `funding.plans[].frequency` ∈ enum | `one-time` × 2, `yearly` × 1 | YES |
| `funding.plans[].amount` denomination ($10k or +$25k multiples) | $10k / $35k / $60k | YES (was the blocker fixed at `252c460`) |
| `funding.history` | `[]` (empty, valid) | YES |

### Description compelling enough?

`projects[0].description` is 1,296 characters (well under the implicit ~500-token budget reviewers see). Reads as a credible engineering pitch: claims are specific (111 tools, 11 RiskGuard checks enumerated, 9,000 tests across 478 files, AES-256-GCM, HKDF-derived key, hash-chained audit, Litestream + R2, static egress IP for SEBI April 2026 mandate). The numeric specificity is exactly what reviewers reward — it differentiates from the typical "production-grade, battle-tested" hand-wavy applications.

One soft critique: description leads with capability enumeration, not impact. Cross-reference my prior research `.research/floss-fund-application-prep.md` §3a — that draft (191 words, 1,150-ish chars) leads with the user audience and value prop ("turns any MCP-aware AI client into a power-user trading copilot for Indian retail Zerodha Kite Connect users"). The committee reads the funder description as "who does this serve". Consider a description swap if final-polish pass time permits — but not a blocker; current text passes a credibility bar.

### Funding goals quantified?

Yes, three tiers with concrete INR line items inside the descriptions:
- $10k: incorporation ₹85k + trademark ₹40k + CERT-In VAPT ₹2.4L (total ~₹8.4L)
- $35k: above + security review ₹4L + 6mo maintainer runway (total ~₹29L)
- $60k: above + extended maintainer runway + 2nd VAPT + NSE empanelment + OpenTelemetry + reserve (total ~₹56L)

Each plan description explicitly states the rupee total, the USD-equivalent, and the deliverable scope. This is unusually rigorous vs the typical FLOSS/fund applicant who just states a dollar figure.

### Anomalies / outstanding items

1. **Fly deployment stale**: `https://kite-mcp-server.fly.dev/funding.json` returns `version: v1.0.0`. The `25c9c8e` commit bumped the manifest 6 days ago but production hasn't redeployed since then OR the file isn't being served from the live build. Check `app/http.go` route for `/funding.json` — it likely embeds the file at compile-time. **Fix needed before submission: deploy v1.1.0 to Fly.** Or — simpler — submit the GitHub raw URL, not the Fly URL.

2. **`FUNDING.json` duplicate**: byte-identical to `funding.json`. Functionally harmless (validator only reads the URL you paste), but visually odd. Original recommendation (delete) still stands but is low-priority.

3. **`channels[0].type: "other"`** with email address as `address`. Functionally fine; v1.1.0 schema has `bank | payment-provider | cheque | cash | other`. None really matches a pre-incorporation Indian individual with no GitHub Sponsors set up. `"other"` is the honest choice. Could later upgrade to `"payment-provider"` once GitHub Sponsors is live (per `kite-rainmatter-warm-intro.md` plan).

---

## §2 — FLOSS/fund application readiness

### Submission flow (verified empirically)

1. Public funding directory: `https://dir.floss.fund/`
2. Submit: `https://dir.floss.fund/submit` — single field, paste the **public URL of your `funding.json`**
3. Validator: `https://fundingjson.org/validate/` (live tool; paste manifest JSON)
4. Schema source: `https://fundingjson.org/schema/v1.1.0.json` (latest, verified today)
5. The manifest IS the application; no separate form fields. Everything reviewers see is inside the JSON.

### Application cadence and queue state

- Cadence: **quarterly review** ("at the end of every quarter", per FAQ).
- Disbursement lag: ~4 weeks post-acceptance (banking + tax doc paperwork; Indian recipients need tax residency docs per `floss.fund/faq`).
- 2025 disbursed: **$823,281** of the committed $1M (per `zerodha.com/open-source/2025-report/`); remainder "in process".
- 2026 forecast: **another $1M committed** for the year (per FAQ "applications open continuously, $1M committed in 2026").
- **No 2026 Q1 announcement found.** Blog last updated 2025-10-18 ("second tranche and anniversary reflection"). Indicates either (a) Q1 2026 review hasn't happened yet OR (b) it happened quietly without a tranche blog post. Either way, queue is open as of today.

### Eligibility (full match check)

| FAQ criterion | Our state | Pass? |
|---|---|---|
| "Individuals, projects, groups, communities, or organisations" eligible | Individual | YES |
| Indian tax residency docs required at paperwork stage | Sundeep is Indian-resident | YES (will produce when asked) |
| Bank account capable of receiving USD wire | Sundeep has bank account; pre-incorporation USD wire receipt is FEMA-permitted via Liberalised Remittance Scheme reverse path (≤$250k/yr) | YES (verify with CA before submission) |
| Project must be "existing, widely used, and impactful" | **0 stars, 1 active user, pre-Show-HN** | **NO** |
| "Very new projects or projects with minimal usage are not considered" | Currently fails this filter | **NO** |
| Schema-valid `funding.json` | v1.1.0 PASS | YES |

**Verdict**: Application is technically submission-ready (manifest validates, all schema fields present). Eligibility filter on traction is the open blocker.

### Past recipient pattern (signal for fit)

Tranche-1 (May 2025, 9 projects, $325k): OpenSSL ($100k), NTP ($60k), ImageMagick ($50k), Krita ($50k), libjpeg-turbo ($25k legacy denom), LibreTranslate ($10k), Weblate ($10k), x64dbg ($10k), XZ tools ($10k).

Tranche-2 (Oct 2025, 29 projects, $645k): FFmpeg ($100k), F-Droid ($50k), HOTOSM ($50k), OpenStreetMap ($30k), Blender / Ente / KDE / Matrix / OpenRefine / Rethink DNS / Sequoia PGP / Wireshark / Zig ($25k each), Crystal / Gleam / Kiwix ($15k each), 17 projects at $10k each.

Pattern observations vs our profile:
- **All 38 recipients have established usage** — millions of installs (FFmpeg), critical-infra status (OpenSSL, NTP), or established community (Krita, Blender). None were pre-launch with 0 stars.
- **Zero Indian-led recipients** in either tranche. Rethink DNS is the closest (Indian developer team but global-user project). **Trading-vertical OSS: zero.** No fintech projects funded yet. Could be opportunity (no prior-fit precedent to compete against) OR blocker (committee may explicitly avoid sector concentration in a Zerodha-funded fund).
- **Solo individuals DO get funded** — x64dbg, Yjs, Gleam, Graphile, dotenvx are largely solo/2-person efforts. So entity-type is not a blocker, but their projects have measurable adoption.

### Recommendation timing

Per `kite-floss-fund.md` memory and reinforced today: **wait until ≥50 stars + Show HN posted + 1 blog post**. Submit immediately after that's true. Submission cost is 30 seconds; preparation cost is already paid (manifest valid).

Target submission window: late August / early September 2026 (after Show HN ~mid-July 2026, allowing ~6 weeks for star accumulation and trigger to fire). That targets Q3 2026 review cycle (Jul–Sep), with results in October.

---

## §3 — Rainmatter readiness

### Trigger state

Per `kite-rainmatter-warm-intro.md` memory (re-verify-by 2026-10-17):

> "DO NOT cold email founders yet. Warm intros close 10x better than cold. Trigger only after FLOSS/fund submitted + ≥50 stars."

Required gates:
1. FLOSS/fund application **submitted** (not necessarily approved)
2. **≥50 GitHub stars** on `Sundeepg98/kite-mcp-server`
3. 1 blog post live

### Current state (empirical, today)

| Source | Stars | Forks | Watchers | Comment |
|---|---|---|---|---|
| `gh api repos/Sundeepg98/kite-mcp-server` | **0** | 0 | 0 | 0/50 of trigger |
| 28 algo2go/kite-mcp-* repos (sum) | **0** | 0 | 0 | All module extracts are at 0 (extracted privately, then made public 2026-05-11 — orchestration commit `13888e1`) |
| **Combined org+main** | **0** | 0 | 0 | 0% to trigger |

### Distance to trigger

- 0 GitHub stars currently
- Show HN hasn't been posted (no Show-HN marker in `.research/` or commit history; landing day playbook at `.research/day-1-launch-ops-runbook.md` per `ls` output is preparation, not execution)
- 0 blog posts found in launch dir

**Gate** is binding on all three sub-conditions. Rainmatter outreach is **completely cold-blocked** until launch sequence executes.

### One-pager status

- `docs/rainmatter-onepager.md` exists (tracked in git as of `master`, 60 lines, 4014 bytes).
- Three `<placeholder>` slots: `<product-email>`, `<substack-url>`, `<linkedin-url>`. Resolve before any actual share.
- Content is dense, honest (calls out "0 active user [me]", "0 revenue", "no LLP yet"), and structurally compatible with Rainmatter's "API-first / OSS-first / mentorship-not-cash" warm-intro pattern.
- The "honest ask" (point 3) lists "Consideration for FLOSS/fund or FOSS United" as one of three requests — this is the natural handshake between the FLOSS/fund track and Rainmatter conversation. Good integration.

### Warm-intro order (from memory, still valid)

1. **Deepak Shenoy** (Capitalmind, Rainmatter-invested Aug 2025) — newest warm node
2. **Vishvajit Sonagara** — Rainmatter podcast alum
3. **Abid Hassan** (Sensibull) — Zerodha-invested adjacency
4. Later: Vasanth Kamath (Rainmatter direct), then Nikhil Kamath (last resort, gated on Pvt Ltd + 500 users)

DMs preferred over email. Drafts exist at `docs/drafts/jethwani-shenoy-dms.md` and `docs/drafts/vishal-dhawan-dms.md`.

### Rainmatter program structure (verified today)

Per `rainmatter.com` WebFetch:
- **Rainmatter Capital** = equity fund, ₹50L–₹100Cr ticket sizes, no board seats, holistic stage-agnostic eval. Application: `https://forms.gle/88D9cKMan27qa5R57` (Google Form).
- **Rainmatter Foundation** = $200M climate-only fund. **Not for us** (per memory: "do not apply, wrong vertical").
- Sectors: fintech, climate, health, media. We fit "fintech".

**Note**: Rainmatter Capital is **equity, not grant**. Per `kite-floss-fund.md`: "Rainmatter Capital — EQUITY fund, requires Pvt Ltd incorporation + traction." This is not a substitute for FLOSS/fund — it's a downstream pathway. Pvt Ltd incorporation is in `funding.json` plans as the FLOSS/fund $10k tier deliverable, which is the exact ordering memory expects.

### Recommendation

**No Rainmatter action until all 3 trigger conditions met**: FLOSS/fund submitted + ≥50 stars + 1 blog post. Don't break the warm-intro discipline. Once triggered, Sonagara/Shenoy DMs via existing drafts.

---

## §4 — Zerodha FLOSS engagement landscape

### Zerodha's open-source program portfolio (verified at `zerodha.com/open-source/`)

| Program | Type | Amount | India fit | Application |
|---|---|---|---|---|
| **FLOSS/fund** | Grant ($1M/yr) | $10k–$100k | Global; individuals OK; Indian-resident OK | `dir.floss.fund/submit` |
| **FOSS United** | Grant (Zerodha-co-founded) | ₹30k–₹5L (project) / ₹16.5k–₹1.2L (fellowship) | India-only; individuals welcome | `grants@fossunited.org` |
| **Zerodha FOSS Projects** | Internal OSS releases | N/A | N/A (not for external applicants) | `zerodha.tech/projects/` |
| **Open Source Pledge** | Public commitment | N/A | N/A (not for applicants) | `opensourcepledge.com/members/zerodha/` |

### 2025 disbursement summary

Per `zerodha.com/open-source/2025-report/`:
- Zerodha disbursed **$823,281** in 2025 (3x increase vs 2024's $239,600)
- 7 distinct contributions tracked
- FOSS United received **$100k** from Zerodha (separate from FLOSS/fund pipeline)
- India-based projects funded: FOSS United Foundation, osvauld, xenevaOS, dwani AI, Zasper (fintech-adjacent — co-sponsored FOSS United grant, $4,986)
- **Confirms**: Indian-individual fintech OSS does get funded via the Zerodha network — just usually via FOSS United, not FLOSS/fund directly. Zasper is the closest precedent (fintech-adjacent, co-sponsored).

### Past funded projects matching our profile

Search for "kite", "broker", "trading", "MCP", or "fintech" across FLOSS/fund + Zerodha-supported projects in 2025: **none found**. This is the no-precedent-to-cite situation. Frame this in the FOSS United email as "first Indian fintech-MCP project applying" — that's both honest and a positive framing.

### Implication for our funnel

Apply for both **simultaneously, non-competing**:
- FOSS United: ₹4L grant, India-only, no traction threshold → file first, low friction
- FLOSS/fund: $10k–$60k, global, traction threshold → file after Show HN

These are different funds with different criteria. Not double-dipping; the Zerodha 2025 report explicitly treats them as separate budget lines.

---

## §5 — Apply-vs-defer per program

| Program | State today | Action | When |
|---|---|---|---|
| **FOSS United (project grant)** | Email drafted at `docs/drafts/foss-united-grant-email.md`. Ask: ₹4L for 4 months maintainer time. Address: `grants@fossunited.org`. No traction filter blocking. | **SEND** | Today / this week |
| **FLOSS/fund** | `funding.json` v1.1.0 PASS. Production Fly stale (v1.0.0) — fix before submitting, or submit GitHub raw URL. Eligibility filter on traction is binding. | **DEFER** | Late Aug / early Sep 2026 (post-Show-HN, ≥50 stars). Submit GitHub raw URL: `https://raw.githubusercontent.com/Sundeepg98/kite-mcp-server/master/funding.json` |
| **GitHub Secure Open Source Fund** | Rolling, $10k, security-focused. Eligibility: 18+, GitHub Sponsors-supported region (India qualifies), demonstrated traction. Need GitHub Sponsors profile live first. | **DEFER + SETUP** | Set up `https://github.com/sponsors/Sundeepg98` now; apply after 50+ stars. Lighter traction bar than FLOSS/fund; could be the next-quickest after FOSS United. |
| **Rainmatter Capital** | Cold-blocked by warm-intro playbook. ₹50L–₹100Cr equity ticket — premature for our state (0 users, no Pvt Ltd). | **DEFER** | Post-FLOSS/fund-submitted + ≥50 stars + Pvt Ltd. Trigger explicit, DM-not-email. |
| **Rainmatter Foundation** | Climate-only. Wrong vertical. | **SKIP** | Never (wrong fund). |
| **IndiaFOSS conference CFP** | Drafted at `docs/drafts/indiafoss-2026-cfp.md`. Adjacent: a talk gives the "1 blog post / public mention" trigger condition + community signal for FLOSS/fund. | **CONSIDER** | Submit per CFP deadline (verify in draft); orthogonal to grants but compounds traction. |

### Sequencing recommendation

```
TODAY  → resolve <product-email> placeholder in FOSS-United-grant-email.md
         send to grants@fossunited.org
TODAY  → fix Fly stale funding.json (redeploy OR change embedded asset) — low priority but clean
+1 wk  → setup github.com/sponsors/Sundeepg98 (waitlist + profile)
+2 wk  → Show HN preparation (per .research/launch-path-execution-playbooks.md)
+4 wk  → Show HN post + r/algotrading + Twitter D1-T1 cluster
+6 wk  → expect ≥50 stars from launch cluster
+7 wk  → submit FLOSS/fund (paste GitHub raw URL at dir.floss.fund/submit)
+8 wk  → apply GitHub Secure Open Source Fund (rolling, $10k)
+10 wk → Rainmatter Capital warm-intro sequence (Shenoy DM via existing draft)
```

Risk-adjusted EV (rough):
- FOSS United: ~₹2-4L expected (50% prob × ₹4L ask × indianFOSSPrecedentBias)
- FLOSS/fund: ~$5-10k expected (15% prob × $35k ask × no-Indian-fintech-precedent penalty)
- GitHub Secure: ~$2-3k expected (20% prob × $10k × security-posture-strength bonus)
- Rainmatter: ₹0 near-term (warm-intro gate); equity round expected value not modelable until users exist

**Total non-dilutive expected ≈ ₹4-10L over 6 months.** That covers Pvt Ltd incorporation + first VAPT + 2-3 months runway. Strong-enough non-dilutive base to defer any equity conversation until traction firmly proves out.

---

## §6 — Algo2Go umbrella adjustments to funding.json

### Current state (per memory `session_2026-05-10_path-a-complete.md`)

- `algo2go` org created 2026-05-05, publicly visible 2026-05-11 (per dispatch context)
- 28 modules externalised at `algo2go/kite-mcp-{broker, money, decorators, ...}`
- Each external module is its own repo, 0 stars currently
- Host repo remains `Sundeepg98/kite-mcp-server` (orchestrator role)
- "Stop at 3/5 Tier-1+2 facade decomp" per memory; "ship under kite-mcp-server until trigger fires" per `kite-algo2go-rename.md`

### Implication: rebrand to `algo2go/kite-mcp-server`?

Memory says: **trigger-gated, not immediate**. The kite-mcp-server host repo stays under `Sundeepg98` until the algo2go umbrella has sufficient social proof to graduate. Today's state:
- algo2go org public: yes
- algo2go has stars: no (0 across 28 repos)
- Premature to transfer host repo to org

### Does `funding.json` need update?

**Today: no change required.** The manifest's `repositoryUrl.url` points to `https://github.com/Sundeepg98/kite-mcp-server` which is correct as of HEAD. `entity` is Sundeep-individual which is correct for a pre-incorporation individual maintainer.

**Future: if/when host repo transfers to `algo2go/kite-mcp-server`**, update:
1. `projects[0].repositoryUrl.url` → `https://github.com/algo2go/kite-mcp-server`
2. Possibly `entity.type` → `organisation` if Algo2Go Pvt Ltd incorporated (which is the $10k tier deliverable; chicken-and-egg)
3. Possibly `entity.webpageUrl.url` → `https://algo2go.com` (or wherever the brand site lives)
4. Re-trigger validator pass at `https://fundingjson.org/validate/`
5. Re-submit to FLOSS/fund? **No** — funding.json is a living manifest; the submit-once URL is what the directory tracks. Edits propagate automatically via re-crawl.

### Should application be filed as "Algo2Go" umbrella or "kite-mcp-server" specifically?

**File as kite-mcp-server specifically.** Rationale:
1. Algo2Go is currently just a holding org with no flagship use case beyond hosting decomposed modules
2. kite-mcp-server has the concrete value-prop, the security audit, the user-facing story
3. FLOSS/fund evaluates individual projects, not portfolios — a multi-project umbrella manifest dilutes signal
4. The `projects` array in funding.json supports multiple projects, but adding the 28 algo2go module repos as separate projects would look like padding (all at 0 stars, no public docs)
5. Memory explicitly stages this: "ship under kite-mcp-server until trigger fires" — the trigger isn't "org publicly visible", it's "umbrella has gravity"

When the umbrella does graduate, the funding.json grows naturally — additional entries in `projects[]` as each module accumulates standalone value.

### No-op for now

`funding.json` requires no algo2go-related edits today. Re-evaluate when Pvt Ltd registered (which is the $10k tier outcome) or when host repo transfers (separately decided).

---

## Appendix A — Pre-submission checklist update (vs prior 2026-05-02 doc)

15-item checklist from `.research/floss-fund-application-prep.md` re-checked at 2026-05-11. Status changes only:

| # | Item | Was (May 2) | Now (May 11) |
|---|---|---|---|
| 1 | `funding.json` at repo root reachable | OK | OK + still tracked at `master` |
| 2 | `wellKnown` URL matches default branch | **BROKEN** | **FIXED** (`252c460` 2026-05-03) and **removed entirely** at `25c9c8e` because repo and project share `github.com` host — wellKnown only required for cross-host manifests |
| 3 | Plan amounts conform to denomination rule | **VIOLATED** | **FIXED** (`252c460`) — $10k / $35k / $60k |
| 4 | `entity.email` is real product email | OK (`sundeepg8@gmail.com`) | OK |
| 5 | Validates clean at `fundingjson.org/validate/` | (untested then) | **PASS** (verified today via jsonschema lib) |
| 6 | ≥50 GitHub stars | **0/50** | **0/50** (unchanged) |
| 7 | Show HN posted | NO | NO (still not posted) |
| 8 | Blog post / writeup published | NO | NO (no blog/launch artifact in master) |
| 9 | `SECURITY_AUDIT_REPORT.md` in repo | YES | YES |
| 10 | `docs/floss-fund-proposal.md` placeholder resolved | **NO** (`<product-email-placeholder>` open) | (not re-checked; carry forward as still-open) |
| 11 | `FUNDING.json` duplicate removed | NO | NO (still duplicate; benign) |
| 12 | GitHub Sponsors profile live | NO | NO (no profile at `github.com/sponsors/Sundeepg98`) |
| 13 | Submission within 4 weeks of a quarter-end | (forward-look) | Q2 ends Jun 30; Q3 ends Sep 30. Target Q3 review. |
| 14 | Indian bank account capable of USD wire identified | (forward-look) | Sundeep individual account; verify FEMA LRS reverse-path with CA before submission |
| 15 | FOSS United email prepared but not sent | YES | YES — **but recommend sending NOW**, per §5 |

**Net progress May 2 → May 11**: Three blockers fixed (`wellKnown`, denominations, schema version). Three blockers unchanged (traction, Show HN, blog). One new blocker found (Fly stale).

---

## Appendix B — Sources cited (URLs probed today)

- [FLOSS/fund main](https://floss.fund/)
- [FAQ](https://floss.fund/faq/)
- [Submit](https://dir.floss.fund/submit)
- [Validate](https://fundingjson.org/validate/)
- [Schema v1.1.0](https://fundingjson.org/schema/v1.1.0.json) — probed directly via curl
- [Blog](https://floss.fund/blog/) — last post 2025-10-18
- [Progress update 2025-01](https://floss.fund/blog/progress-update/)
- [1st tranche announcement](https://floss.fund/blog/update-2025-may/)
- [2nd tranche announcement](https://floss.fund/blog/second-tranche-2025-anniversary/)
- [2025 disbursements](https://floss.fund/projects/2025/)
- [Funding manifest hub](https://floss.fund/funding-manifest/)
- [funding.json spec site](https://fundingjson.org/)
- [Zerodha 2025 OSS report](https://zerodha.com/open-source/2025-report/)
- [Zerodha OSS landing](https://zerodha.com/open-source/)
- [Rainmatter (Capital)](https://rainmatter.com/) — application Google Form `https://forms.gle/88D9cKMan27qa5R57`
- [FOSS United grants](https://fossunited.org/grants)
- [GitHub Secure OSS Fund](https://github.com/open-source/github-secure-open-source-fund)
- [The Drop Times: 1st-year retro](https://www.thedroptimes.com/55345/flossfund-allocates-1m-globally-in-first-year-calls-indias-sovereign-foss-strategy)

Plus internal sources:
- Prior research: `.research/floss-fund-application-prep.md` (2026-05-02)
- Audit/batch: `.research/audits/2026-05-11/research-batch-2026-05-11.md` §F
- Memory: `~/.claude/projects/D--Sundeep-projects/memory/kite-floss-fund.md`
- Memory: `~/.claude/projects/D--Sundeep-projects/memory/kite-rainmatter-warm-intro.md`
- Memory: `~/.claude/projects/D--Sundeep-projects/memory/session_2026-05-10_path-a-complete.md`
- Repo: `funding.json` (HEAD), `docs/rainmatter-onepager.md`, `docs/drafts/foss-united-grant-email.md`
- Empirical probes: `gh api repos/Sundeepg98/kite-mcp-server`, `gh api orgs/algo2go/repos --paginate`, `curl https://fundingjson.org/schema/v1.1.0.json`, `curl https://kite-mcp-server.fly.dev/funding.json`, `curl https://raw.githubusercontent.com/Sundeepg98/kite-mcp-server/master/funding.json`
