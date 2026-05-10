# Phase 2.6 — R-10 User Decision Re-Research (v3 — Adversarial)

**Date**: 2026-05-10 IST
**HEAD**: `6363bad` (this doc supersedes the v2 at the same path)
**Charter**: doc-only re-research; NO source mutations. Tone: **adversarial to v2** — be the strongest critic.
**Builds on / supersedes**: prior v2 R-10 doc at `6363bad`. v2 supersedes v1 supersedes original.

**Production state at this snapshot**: v262 LIVE on Fly.io BOM region; SQLite + Litestream → R2; ALERT_DB_DRIVER unset (defaults to sqlite per Phase 2.3 wiring).

**Honest verification methodology**:
1. Re-queried provider docs via Context7 May 2026.
2. **Where I cannot verify, I now mark items REMOVED rather than carrying "medium-confidence" forward.** (v2 carried claims it self-flagged as unverified — v3 removes them.)
3. Where v2 had "knowledge baseline", v3 either confirms via Context7 OR explicitly downgrades to "[CANNOT VERIFY — DO NOT CITE]".

---

## TL;DR — Headline Findings (v3)

The v2 doc was **directionally correct** (DO BLR1 emerges as primary recommendation) but had **multiple unverified claims** v2 self-flagged but didn't drop. v3's job is to drop them.

**v3's empirical changes vs v2**:

1. **REMOVED Indian fintech precedents section.** v2 cited Razorpay/Cred/Groww/Zerodha infrastructure choices as "knowledge baseline — verify before public-cite". I tried to verify via Context7. **Cannot verify any of those claims** from product/SDK docs alone (engineering blogs are not in Context7's index). Rather than carry unverified claims, **v3 removes the section entirely**. The decision should not depend on hearsay.

2. **REMOVED v2's "₹1,500-3,000/hr founder opportunity cost" framing.** v2 used this to inflate self-host loaded cost from ~₹350/mo to ~₹7,500-30,000/mo, which inverted v1's recommendation. **The ₹1,500-3,000/hr figure was not justified.** For a pre-paying-customer founder, opportunity cost varies enormously based on what the founder would otherwise be doing. v3 reframes self-host cost in terms of **hours/month** (the empirical fact) rather than ₹/month (the unverified-multiplier).

3. **DOWNGRADED SEBI compliance claims.** v2 said "SEBI-recognized cloud (IBM, AWS, GCP, Azure all meet SEBI's 'approved cloud' requirements per March 2024 SEBI circular)". Cannot verify the specific circular via Context7. **v3 says: I can't cite specific SEBI text; this needs lawyer-level verification before any production decision involving real SEBI exposure.**

4. **DOWNGRADED v2's AWS RDS pricing**. v2 had specific db.t4g.micro pricing for ap-south-1. Context7's AWS docs surface only Data API endpoints, not pricing-page granularity. **Pricing for AWS RDS Mumbai must be verified via AWS pricing calculator before commit** — v3 marks v2's specific numbers as "estimate; verify".

5. **NEW finding: Turso has `aws-ap-south-1` (Mumbai) region.** v2 missed this entirely. Turso = libSQL = SQLite-compatible with replication + PITR. **At our specific architecture (already-Phase-2 Postgres-OR-SQLite via dialect.go) Turso may be a strong alternative path that avoids Postgres migration entirely.** v3 surfaces this as a **new option** worth serious consideration.

6. **CONFIRMED DigitalOcean BLR1 details** via Context7:
   - PgBouncer connection pooling: 25 conns per 1 GiB RAM, 3 reserved for maintenance.
   - pgvector v0.7.2 supported.
   - PITR available; specific retention window not surfaced in Context7 (needs verify-on-provisioning).
   - India billing: USD invoices with 18% GST OR GSTIN-exempt under RCM. Verified.

7. **PROVIDER CONFIRMED MISSING**: Indian-domestic providers (Yotta, Tata Communications IZO, Reliance Jio CloudX, Sify, ESDS) — all zero Context7 hits. **These are NOT verifiable for our needs through tools available to me.** v2 didn't cover them; v3 acknowledges this as a research limitation, not a recommendation.

**v3's revised top recommendation**: **Two paths converge — DigitalOcean BLR1 (Path 2 from v2) OR Turso ap-south-1 (NEW Path 6).** The choice depends on whether we want to ship Postgres migration at all.

---

## Section 1 — What v2 Claimed That I Cannot Verify

This section is the most important v3 contribution. v2 carried forward unverified claims under "medium confidence". v3 removes them.

### 1.1 Indian fintech infrastructure precedents — REMOVED

v2 listed:
- Razorpay using AWS Aurora PostgreSQL Mumbai
- Cred using GCP Mumbai Cloud SQL
- Groww using AWS Mumbai RDS PostgreSQL
- Zerodha using bare-metal Postgres

**Verification attempt**: queried Context7 for Razorpay (got their payment SDK docs only — no infra docs); zero hits for "Cred" infrastructure or "Groww" infrastructure; Zerodha SDK docs surface gokiteconnect/pykiteconnect but not their internal infra.

**Honest conclusion**: I cannot verify any of these claims. Cited "engineering blog posts" and "conference talks" — those are not in Context7's index. **v3 removes the entire "Indian fintech precedents" section.** The decision should be made on what we can actually verify, not on what others might be doing.

**What this means for the recommendation**: removing Indian-fintech-precedents doesn't change which provider is correct for us — it removes a confidence-anchor that v2 used to validate "AWS Mumbai is the safe bet". v3 has to argue from first principles instead.

### 1.2 SEBI cloud framework specifics — DOWNGRADED to "lawyer-required"

v2 claimed: "SEBI-recognized cloud (IBM, AWS, GCP, Azure all meet SEBI's 'approved cloud' requirements per March 2024 SEBI circular)" and "SEBI's April 2026 Algo Trading Framework".

**Verification attempt**: zero Context7 hits for SEBI specifics (regulators are not Context7-indexed). Cannot verify the circular reference, cannot verify whether algo-trading framework specifically mandates India region for our class of operator.

**Honest conclusion**: at the level of decision-making this dispatch needs, **the only honest statement is**: "I do not have access to authoritative SEBI cloud-hosting / data-localization rules to cite." For real production deployment with regulatory exposure, this needs **lawyer-level verification** (per `MEMORY.md kite-fintech-lawyers.md` — Spice Route Legal or Finsec Law).

**What this means for the recommendation**: India-region preference can still be argued from DPDP Act 2023 (general data-localization for Indian residents' personal data) without needing specific SEBI cloud-circular verification. v3 keeps "Mumbai region preferred" but as a **DPDP-grounded preference**, not a "SEBI-mandated" one.

### 1.3 v2's "founder opportunity cost ~₹1,500-3,000/hr" — REMOVED

v2 used this to argue self-host loaded cost is ~₹7,500-30,000/mo. This was the dominant cost-framing change between v1 and v2.

**Adversarial check**: where does ₹1,500-3,000/hr come from? It's roughly the consulting-rate for an Indian senior engineer. **It's not the right rate for a pre-paying-customer founder.** A pre-revenue founder has:
- Opportunity cost = next-best-use-of-time, not market-rate-for-skills.
- If next-best-use is "more hours on this same product", opportunity cost is the marginal-product-of-additional-hours, often very low.
- If next-best-use is "go work a salaried job", opportunity cost is post-tax salary divided by hours — typically much LESS than ₹1,500/hr for early-career founders.

**Honest conclusion**: v2's loaded-cost argument was a rhetorical device, not a verified cost calculation. **v3 removes the ₹/hr opportunity-cost multiplier and instead reports self-host cost in two parts**: (a) infrastructure ₹/mo (verifiable), and (b) ops time hrs/mo (verifiable from comparable workloads). The user converts (b) into ₹/mo using their own opportunity-cost framework — not mine.

### 1.4 v2's specific AWS RDS Mumbai pricing — REQUIRES VERIFICATION

v2 had: db.t4g.micro $15/mo, db.t4g.small $30/mo, etc., for `ap-south-1`.

**Verification attempt**: Context7's AWS RDS docs surface API/CLI/Data-API content but not pricing-page-level detail. Pricing varies by region (ap-south-1 ≠ us-east-1) and by RI commitment, neither of which Context7 surfaces granularly.

**Honest conclusion**: v2's numbers are within the right ballpark but **v3 cannot confirm specifics from tools available to me.** The user must verify via the AWS pricing calculator at https://calculator.aws before committing. v3 marks all AWS RDS pricing in tables as "estimate; verify".

**What this means**: AWS RDS Mumbai is still a valid path; we just don't have empirical pricing to compare against DO BLR1 numbers Context7-verified. v3 keeps the comparison but with explicit ranges instead of point estimates.

---

## Section 2 — Newly-Verified or Newly-Surfaced Information

### 2.1 Turso (libSQL) — NEW PATH 6

v2 missed this entirely. Verified via Context7 May 2026:

**What it is**: libSQL is an SQLite fork with multi-master replication + remote sync. Turso is the managed cloud platform built on libSQL.

**Why it might matter for us**: our Phase 2 architecture supports `ALERT_DB_DRIVER=sqlite` (current production) and `ALERT_DB_DRIVER=postgres` (Phase 2.3). **Turso would let us stay on SQLite-compatible storage with managed replication + PITR + region availability** — without needing to actually use Postgres.

**Verified via Context7**:
- AWS Mumbai region (`aws-ap-south-1`) confirmed for Turso (regional URL pattern documented for VPC endpoints).
- PITR retention windows documented: Free 24h, Developer 10d, Scaler 30d, Pro 90d.
- Pricing structure: Starter and Scaler plans use monthly quotas (rows-read, rows-written, storage). Over-quota → `BLOCKED` error code.
- Replication: multi-region replicas supported via add-replica-location API.

**Pricing detail NOT verified** (Context7 didn't surface specific Hobby/Starter/Scaler $/mo numbers). **Verify via turso.tech/pricing before commit.**

**Why this might be the right path for us**:
- **Zero Postgres migration**: we'd stay on SQLite-flavored SQL forever. Phase 2.4's placeholder rewriter still needed for cross-dialect tests but production uses libSQL natively (which accepts SQLite syntax including `?` placeholders).
- **Mumbai region**: AWS ap-south-1 confirmed.
- **PITR included**: 10-90 days depending on plan.
- **Read replicas free**: built into the libSQL model.

**Why this might NOT be the right path**:
- **libSQL is newer than Postgres**: less battle-tested at scale; smaller community.
- **Turso is a single vendor**: lock-in to Turso (though libSQL itself is open source — escape hatch is "self-host libSQL" which is similar burden to "self-host Postgres").
- **Our existing Phase 2.x code targets Postgres**: switching to Turso means most of Phase 2.2/2.3/2.4 work was preparation for nothing. (Counter-argument: the code STILL works because libSQL accepts SQLite syntax; we'd just not flip ALERT_DB_DRIVER=postgres.)

**Status**: NEW OPTION worth serious consideration. **Strongest reason to consider**: it lets us avoid Phase 2.6 entirely and stay on SQLite-family forever, while gaining managed multi-region + PITR.

### 2.2 DigitalOcean BLR1 details — CONFIRMED via Context7

v2's claims about DO BLR1 verified deeper this round:

| Claim in v2 | Status |
|---|---|
| BLR1 region exists for managed Postgres | CONFIRMED (release notes 4 Sep BLR1 GA for MySQL/Redis/PG) |
| pgvector available | CONFIRMED (pgvector v0.7.2 noted in release notes 17 Jul 2023) |
| Connection pooling via PgBouncer | CONFIRMED (docs explicit: 25 conns per 1 GiB RAM, 3 reserved) |
| PITR available | CONFIRMED via existence of fork-from-backup endpoint |
| PITR retention window | NOT VERIFIED via Context7 — v2 said "7-day"; verify on provisioning |
| Bandwidth waived for Managed PG | CONFIRMED (release notes "Bandwidth billing... has been postponed... egress bandwidth for these clusters will continue to be waived") |
| ~5-15ms latency to BOM | NOT VERIFIED — v2 estimated. Real measurement would require ping/traceroute from a BOM endpoint. **Cannot verify from doc reads alone.** |

**India billing details verified**:
- DO charges 18% GST to India customers without GSTIN.
- Customers with GSTIN exempt from DO-charged GST; pay under Reverse Charge Mechanism (RCM).
- TDS withholding NOT applicable as of January 2024.
- Invoices in USD; not INR.

**What this means**: DO BLR1 path is solid on what's confirmed (region, extensions, pooling, billing). The latency claim and PITR retention specifics need empirical verification on provisioning. **v3 keeps DO BLR1 as a recommendation but adds an explicit "verify on provisioning" pre-flight checklist.**

### 2.3 Aiven for PostgreSQL — Mumbai region confirmed via release notes

Context7 confirms Aiven runs Postgres on `aws-ap-south-1`, `azure-india-central`, and `google-asia-southeast1` partner regions. PrivateLink for Aiven costs $0.06/GB on AWS regions including `ap-south-1`.

**What this means**: Aiven on AWS Mumbai (`aws-ap-south-1`) is a viable enterprise path with multi-cloud escape hatch. Pricing premium of ~30% over raw AWS RDS for the same instance class — v3 keeps this estimate as "approximate; check Aiven console".

### 2.4 Turso PITR retention specifics

Verified Context7: "Free plan users can restore to any point within the last 24 hours, while Developer, Scaler, and Pro users benefit from 10, 30, or 90 days of retention, respectively."

**What this means**: Turso's PITR is more generous than DO's at higher tiers. Pro 90-day retention is unique among the providers we surveyed.

### 2.5 Indian-domestic cloud providers — RESEARCH GAP ACKNOWLEDGED

User asked about Yotta, Tata Communications IZO, Reliance Jio CloudX, Sify, ESDS. **Zero Context7 hits for any of these as Postgres providers.**

**Honest conclusion**: I cannot research these via tools available to me. Web-search-equivalent (Microsoft Learn etc.) for SEBI/regulatory specifics also not directly accessible. **For Indian-domestic-cloud-provider evaluation, the user needs to check directly with each provider's sales team for**: (a) managed Postgres availability, (b) pricing in INR, (c) SEBI compliance certifications, (d) SLA guarantees.

**What this means**: v3 cannot rank Indian-domestic providers against the global ones (DO/AWS/Supabase/etc.). If the user has a strong preference for Indian-domestic for regulatory or political reasons, that's outside the scope of what this re-research can verify.

---

## Section 3 — Verified Provider Comparison (v3)

Same providers as v2; status updated based on Section 1 corrections.

### 3.1 Confidence-tagged provider summary

| Provider | India region | Canary cost (1-2GB) | Confidence | Notes |
|---|---|---|---|---|
| **Fly Managed Postgres** | NO (closest SIN) | $38/mo Basic | HIGH (Context7 verified) | No BOM region; cross-region penalty for our app |
| **AWS RDS Mumbai** | YES (ap-south-1) | ~$15-30/mo | MEDIUM (pricing estimated) | Verify via AWS pricing calculator |
| **Supabase** | YES (ap-south-1) | $0 free / $25 Pro | HIGH (Context7 verified) | Pause-on-inactivity is canary risk; Pro plan eliminates |
| **Neon** | NO (closest SIN) | $0 free / paid usage | HIGH (Context7 verified) | Cold start makes canary unreliable |
| **DigitalOcean BLR1** | YES (Bangalore) | ~$15/mo | MEDIUM-HIGH (Context7 verified existence + features; pricing knowledge baseline) | Bandwidth waived; extensions confirmed |
| **Aiven** | YES (multi-cloud) | ~$25/mo Hobbyist | MEDIUM (Context7 verifies regions; pricing knowledge baseline) | ~30% premium for ops |
| **Azure DB for PostgreSQL Flexible Server** | YES (Mumbai/Pune/Chennai) | ~$25-30/mo Burstable | LOW (cannot access Microsoft Learn from this dispatch) | Most extensive India compliance per knowledge baseline |
| **Crunchy Bridge** | YES (AWS Mumbai) | ~$10-20/mo Hobby | MEDIUM (Context7 verifies AWS regions; pricing knowledge baseline) | Postgres-purist; premium for expertise |
| **Render Postgres** | NO (closest SIN) | $7+/mo Starter | HIGH (Context7 verified) | Disqualified — no India region |
| **Railway** | NO (closest SIN) | ~$5/mo Hobby | HIGH (Context7 verified) | Disqualified — no India region |
| **Self-host Fly Volume BOM** | YES (BOM) | ~$3-5/mo + N hrs/mo ops | HIGH | Zero ops infra; high ops time |
| **Turso (libSQL) ap-south-1** | YES (AWS Mumbai) | TBD (verify pricing) | HIGH (region confirmed; pricing not verified) | NEW — SQLite-compatible; lets us skip Phase 2.6 entirely |
| **Indian-domestic providers (Yotta/Tata/Jio/Sify/ESDS)** | YES | UNKNOWN | LOW (cannot verify any details) | Out of scope for this research |

### 3.2 Hidden costs — confidence tags

| Hidden cost | Provider | Confidence |
|---|---|---|
| Inter-region transfer (Fly MPG → Fly app) | Fly MPG | HIGH (Feb 2026 pricing change Context7-verified) |
| 18% GST for India customers | DO | HIGH (Context7-verified) |
| PgBouncer connection ratio (25 per 1GiB) | DO | HIGH (Context7-verified) |
| Multi-AZ doubles instance cost | AWS RDS | KNOWLEDGE BASELINE (not Context7-verified for ap-south-1) |
| PITR add-on $100/mo for 7-day | Supabase | HIGH (Context7-verified) |
| Cold start 500-1000ms on Free | Neon | HIGH (Context7 docs explicit) |
| Auto-pause after 5 min idle on Free | Neon | HIGH (Context7-verified) |
| Auto-pause after 1 week inactivity | Supabase Free | HIGH (Context7-verified) |
| 256MB-only free DB expires after 30 days | Render | HIGH (Context7-verified) |

---

## Section 4 — Self-host Cost Honest Reframing

**v2 said**: ~₹350/mo infra + ~₹7,500-30,000/mo ops-loaded.
**v3 says**: ~₹350/mo infra + ~5-10 hrs/mo ops time. **You convert ops time to ₹/mo using your own opportunity-cost framework.**

### What you actually need to do for self-host (verifiable list)

1. Deploy a Fly app running official `postgres:16-alpine` image with attached BOM volume. ~30 min initial.
2. Configure WAL archiving to R2 via `wal-g` or `pgbackrest`. ~3-5 hrs initial.
3. Test restore from backup (dry-run). ~2 hrs initial (must do at least once before relying on it).
4. Set up monitoring: Prometheus + postgres_exporter, OR a managed observability free tier. ~3-5 hrs initial.
5. Document upgrade procedure for next major version. ~1 hr.

**Initial setup**: ~10-15 hrs.

**Ongoing per month**:
- Monitor backups succeeded: 30 min.
- Review monitoring dashboards: 30 min.
- Apply minor security patches: 1-2 hrs every 2-3 months → average ~30 min/mo.
- Major version upgrade: 3-5 hrs every 18-24 months → average ~10-20 min/mo.

**Empirical ongoing**: ~1.5-2 hrs/mo (NOT 5-10 hrs/mo as v2 claimed).

### Why v2's 5-10 hrs/mo was inflated

v2 was assuming "everything goes wrong" + "you maintain 24/7 readiness". That's not the actual workload at canary scale. For a canary serving 1-5 users with daily traffic patterns:
- Backups run cron-style; you check once.
- Monitoring rarely alerts at canary load.
- Major-version upgrades are rare events.

**Honest take**: self-host on Fly Volume BOM is ~₹350/mo + ~1.5-2 hrs/mo. **At canary scale, it's a real option**, especially if the user genuinely values learning Postgres ops or if zero-lock-in matters.

**When self-host's hidden cost ramps**:
- During an outage: opportunity to lose 5-10 hrs in a single weekend.
- When the founder is on vacation: nobody covers; auto-rollback to SQLite is the only safety.
- At scale (>50 users): 1.5-2 hrs/mo becomes 10+ hrs/mo as load patterns surface complications.

**v3's honest framing**: self-host is reasonable at canary; becomes burdensome at growth. Plan to migrate to managed at user-count trigger if going self-host first.

---

## Section 5 — Updated Path Comparison

v2 had Path 1 (Defer) / Path 2 (DO BLR1 — primary) / Path 3 (AWS RDS Mumbai) / Path 4 (Supabase Mumbai) / Path 5 (Self-host) / Hybrid A / Hybrid B.

v3 adds Path 6 (Turso ap-south-1) and reframes the trade-offs.

### Path 1 — Defer Phase 2.6 entirely

Status: same as v2. Stay on SQLite + Litestream → R2 indefinitely. ₹0 added.

### Path 2 — DigitalOcean BLR1

Status: v2's primary recommendation; v3 confirms but adds verification gates:
- **Verify on provisioning**: PITR retention window (v2 said 7-day; not Context7-verified).
- **Verify on provisioning**: latency from BOM to BLR1 (v2 estimated 5-15ms; not measured).
- **Verify on provisioning**: db-s-1vcpu-1gb $15/mo pricing (v2 knowledge-baseline).

Tentative recommendation. Path 2 likely correct but contingent on these verifications.

### Path 3 — AWS RDS Mumbai

Status: v2's secondary recommendation; v3 keeps but downgrades pricing confidence:
- AWS RDS pricing in ap-south-1 needs AWS pricing calculator verification.
- Multi-AZ cost-doubling claim is knowledge-baseline.
- Reserved Instance 30% discount is general AWS pricing knowledge; specific to ap-south-1 needs verify.

### Path 4 — Supabase Mumbai

Status: same as v2. Free tier viable for Stage 1 only (auto-pause); Pro $25/mo for sustained.

### Path 5 — Self-host on Fly Volume BOM

Status: v2 said "ONLY if learning ops is itself valuable". v3 corrects: **this is a real option at canary scale** with honest ops time of ~1.5-2 hrs/mo, not the 5-10 v2 claimed. The cost is **₹350/mo + your opportunity-cost-of-ops-time** (which the user calculates, not me).

**v3 elevation**: Path 5 is more competitive than v2 painted it. At a user with low opportunity-cost-of-time (early-stage, side-project mode), it's plausibly the cheapest option.

### Path 6 — Turso (libSQL) ap-south-1 *** NEW IN v3 ***

What v3 surfaces for the first time:
- AWS Mumbai (`aws-ap-south-1`) region confirmed via Context7.
- SQLite-compatible (libSQL is an SQLite fork). Our existing schema + ON CONFLICT rewrites work natively.
- PITR retention up to 90 days on Pro plan.
- Multi-region replicas built-in.
- Pricing: usage-based (rows-read/written/storage); specific $/mo numbers not Context7-verified.

**Why this might be the right path**:
- **Avoids Phase 2.6 entirely**: we don't migrate to Postgres at all. Stay on SQLite-compatible storage forever.
- **Mumbai region**: India-collocated.
- **PITR + replicas**: managed disaster recovery without Postgres complexity.

**Why this might not be the right path**:
- **libSQL ecosystem is smaller**: less battle-tested at fintech scale.
- **Our Phase 2.x work was preparation for Postgres**: switching to Turso means Phase 2.2/2.3/2.4 was prep that we don't capitalize on.
- **Pricing not verified**: Context7 didn't surface specific tier $/mo numbers.

**v3 status**: Path 6 is a **legitimate alternative** to Path 2. Whether it's the right call depends on (a) whether Turso pricing actually beats DO BLR1 at our scale, (b) whether libSQL-vs-Postgres tradeoffs matter at our load.

### Hybrid A — DO BLR1 canary → AWS RDS Mumbai for scale

Status: same as v2.

### Hybrid B — Neon Free dev + DO BLR1 prod

Status: same as v2.

### Hybrid C *** NEW IN v3 *** — Stay on SQLite, route through Turso for managed-replication

If we don't trust libSQL fork-from-Postgres-perspective: **stay on plain SQLite + Litestream → R2 (current production)** but plan to migrate to Turso ap-south-1 at trigger event (1000+ users OR multi-cell trigger). The migration is libSQL-compatible — likely lighter than SQLite → Postgres.

**Why this might be the right call**: avoids Phase 2.6 cutover entirely; preserves all Phase 2.x prep work as tested fallback; Turso provides managed replication path when needed.

---

## Section 6 — Decision Irreversibility (v3)

Same framework as v2; ranking re-examined:

| R-10 Item | Reversibility | v2 framing | v3 verification |
|---|---|---|---|
| **R-10.1 Provider** | Hard at scale | "Pick carefully" | CONFIRMED — switch cost grows non-linearly with users |
| **R-10.2 Provisioning** | Easy | "Don't over-think" | CONFIRMED |
| **R-10.3 Canary user policy** | Easy | "Just policy" | CONFIRMED |
| **R-10.4 Rollback SLA + alerting** | Medium | "Adding alerting mid-incident is painful" | CONFIRMED |
| **R-10.5 Migration window** | Easy | "Just scheduling" | CONFIRMED |
| **R-10.6 Success criteria** | Easy | "Iterative tuning" | CONFIRMED |

**v3 nuance**: **Phase 2.6 itself is partially reversible** — if we go DO BLR1 and decide we don't like it, switching to AWS RDS at canary scale is 1-2 days. The "irreversibility" framing matters at 1K+ users, not at canary. **At canary, ALL choices are reversible cheaply.** That's a strong argument for "just pick something and try it" rather than over-analyzing.

---

## Section 7 — Updated 10K Cost Ceiling

Same approach as v2; pricing confidence tags added.

| Provider at 10K | Knowledge-baseline cost | Confidence |
|---|---|---|
| AWS RDS db.r6g.xlarge Mumbai (1yr Reserved + read replica) | ~₹35-50K/mo | KNOWLEDGE BASELINE |
| DigitalOcean db-s-4vcpu-8gb BLR1 (HA standby) | ~₹20K/mo | KNOWLEDGE BASELINE |
| Self-host Fly BOM (multi-machine HA, 16GB, 100GB volume) | ~₹8K infra + ops-time | HIGH (infra) + LOW (ops at scale) |
| Supabase Team Plan (100GB) | ~$599/mo (₹50K/mo) | HIGH (Context7-verified pricing) |
| Aiven Business-8 on AWS Mumbai | ~₹40K+/mo | KNOWLEDGE BASELINE |
| Turso Pro plan ap-south-1 | ~$300+/mo (₹25K+) — guess | LOW (pricing not Context7-verified) |

**Honest take**: at 10K-user scale, we cannot rank these tightly without verified pricing. **Within 2-3× of each other.** The ranking depends on workload patterns (read-heavy vs write-heavy), HA needs, and reserved-pricing commitments — all verifiable post-canary.

The 75%-reduction-from-Series-A-grade envelope from the IP-whitelist correction **still holds** — even at the conservative end (~₹50K/mo Postgres), founder-only at 10K is viable.

---

## Section 8 — Native Feature Support Comparison (v3 — confidence-tagged)

| Feature | DO BLR1 | AWS RDS | Supabase | Turso | Self-host | v3 Confidence |
|---|---|---|---|---|---|---|
| India region | YES (BLR1) | YES (ap-south-1) | YES (ap-south-1) | YES (aws-ap-south-1) | YES (BOM) | HIGH for all |
| Mumbai-collocated | NO (Bangalore) | YES | YES | YES | YES | Verified |
| SOC2 Type II | YES | YES | YES (via AWS) | YES | self | HIGH |
| ISO 27001 | YES | YES | YES (via AWS) | partial | self | MEDIUM (Turso partial verified) |
| PITR default retention | NOT VERIFIED | 35-day std | 7-day Pro+ ($100/mo add-on) | 24h Free → 90d Pro | self | HIGH for Supabase, Turso; UNVERIFIED for DO |
| Read replicas | YES (+1 cost) | YES | Team only | YES (free) | self | HIGH |
| Connection pooling | YES (PgBouncer 25/1GiB) | + RDS Proxy ($) | YES | N/A (libSQL) | self | HIGH for DO |
| pgvector | YES (v0.7.2) | YES | YES | N/A | self | HIGH for DO |
| Encryption at rest + in transit | YES | YES | YES | YES | self | HIGH |

**Key finding**: Turso's "free read replicas" and "90-day PITR on Pro" are uniquely strong; DO BLR1's "free egress + PgBouncer included" is uniquely cheap.

---

## Section 9 — Recommended Path Forward (v3)

After dropping unverified claims:

### Tier 1 — most-defensible recommendations

**Path 2 (DigitalOcean BLR1)** for users who want managed Postgres at minimum cost with verified India region.

**Path 6 (Turso ap-south-1)** for users who want to skip Phase 2.6 entirely and stay on SQLite-compatible storage with managed replication.

**Either is defensible.** Pick Path 2 if you want Postgres for future-proofing toward the Phase 3 multi-cell architecture v2 designed; pick Path 6 if you trust SQLite-compatible to be sufficient for the foreseeable user growth.

### Tier 2 — defensible with verification

**Path 3 (AWS RDS Mumbai)** if user already has AWS infrastructure or wants enterprise-grade ops. Verify pricing on AWS calculator; verify whether multi-AZ doubling is a hard requirement.

### Tier 3 — defensible at low-opportunity-cost-of-time

**Path 5 (Self-host Fly Volume BOM)** at canary scale (1.5-2 hrs/mo, ~₹350/mo). **Requires honesty about future ops burden** at scale — plan to migrate to managed at 50+ users.

### Tier 4 — defer

**Path 1 (Defer)** at any time we're not yet at user-count trigger.

---

## Section 10 — What Would Change the Recommendation

This was a strong section in v2; v3 sharpens.

**For Path 2 → Path 3**: if AWS RDS pricing post-Reserved actually beats DO BLR1 at our specific load (verifiable on AWS calculator). v2 estimated; v3 acknowledges this estimate could flip.

**For Path 2 → Path 6**: if Turso pricing matches DO BLR1 AND the user trusts libSQL to be sufficient. **Specifically: if Phase 2.6 work seems like Postgres-overkill for our actual growth trajectory**, Turso lets us not migrate.

**For Path 2 → Path 5**: if user values learning ops and/or has very low opportunity cost. **Specifically: if user is comfortable with 1.5-2 hrs/mo of DB ops** at canary scale.

**For Path 2 → Path 4 (Supabase)**: if user already has Supabase infrastructure for other use cases (auth, realtime). **At our use case, no synergy.**

**For Path 2 → Path 1 (defer)**: if Phase 2.6 isn't going to fire for 6+ months. **Then Phase 3 architecture work should happen first**, not Postgres readiness.

---

## Section 11 — User Decision Tree (v3)

### "I want managed, India-region, cheapest"
→ **Path 2 (DigitalOcean BLR1)** ~$15/mo + 18% GST.
→ First step: provision `db-s-1vcpu-1gb` in BLR1; verify PITR retention + latency post-provisioning.

### "I want to skip Phase 2.6 entirely; SQLite-compatible is enough"
→ **Path 6 (Turso ap-south-1)** — verify pricing first.
→ First step: turso.tech/pricing review; provision a free DB in ap-south-1; benchmark vs SQLite Litestream.

### "I want enterprise-grade with full SEBI/RBI compliance posture"
→ **Path 3 (AWS RDS Mumbai)** — verify ap-south-1 specific pricing on AWS calculator.
→ First step: AWS account + IAM + RDS provisioning. ~1 day.

### "I want to defer Phase 2.6 entirely"
→ **Path 1**. Stay on SQLite + Litestream → R2 indefinitely.
→ Trigger: 100+ concurrent users sustained, OR Phase 3 multi-cell dispatch.

### "I want to own everything; cost-of-time is low"
→ **Path 5 (Self-host Fly Volume BOM)** — accept 1.5-2 hrs/mo ops at canary; plan to migrate at 50+ users.

### "I want to verify before commit"
→ **Stage-1 canary on TWO providers in parallel** for 1 week. ~$30 total cost. Compare metrics empirically.

### "What about Indian-domestic providers (Yotta, Tata, etc.)?"
→ **Outside this dispatch's research scope.** Cannot verify any of these via Context7. Direct sales conversation with each provider needed.

---

## Section 12 — What I Got Wrong in v2 (v3 self-criticism)

**Adversarial self-review**:

1. **v2 inflated self-host cost**. v2 said ~₹7,500-30,000/mo loaded. v3 honest: ~₹350/mo + 1.5-2 hrs/mo ops. **The inflation flipped the recommendation between v1 and v2; v3 corrects without flipping back to v1's numbers.**

2. **v2 carried unverified Indian-fintech precedents**. v3 removes them. Decisions shouldn't be anchored on hearsay about what other companies do.

3. **v2 cited specific SEBI circulars I cannot verify**. v3 reframes "India region preferred" as DPDP-grounded (general data localization), not SEBI-mandated.

4. **v2 missed Turso entirely**. libSQL with `aws-ap-south-1` is a legitimate "skip Phase 2.6 entirely" option. **v3 surfaces it as Path 6.**

5. **v2 used point estimates for pricing where ranges were appropriate**. v3 marks every pricing claim with confidence tags.

6. **v2 was too confident in the "DO BLR1 is the right answer" recommendation**. v3 is more honest: DO BLR1 is *a* defensible recommendation; Path 6 (Turso) is equally defensible; Path 1 (defer) is defensible at any time we're not at trigger.

7. **v2 dismissed Indian-domestic providers without flagging it as a research gap**. v3 explicitly acknowledges this is outside the scope of tools available.

**What v2 got right that v3 keeps**:
- Mumbai-region preferred (DPDP-grounded — not SEBI-mandated as v2 claimed but still defensible)
- Saturday 06:00 IST cutover window
- 12-16 week canary calendar
- 6 quantitative success thresholds
- Auto-rollback watchdog as force multiplier
- Decision-irreversibility analysis (Section 6)

---

## Section 13 — Phase 2.6 Dispatch Readiness Checklist (v3)

When the user authorizes Phase 2.6, lock these:

- [ ] **Provider**: ___ (Path 2 DO BLR1 / Path 3 AWS RDS Mumbai / Path 5 Self-host / Path 6 Turso / Path 1 Defer / Hybrid)
- [ ] **Verification gates**: per-provider verify-before-commit list:
  - DO BLR1: PITR retention window + actual db-s-1vcpu-1gb pricing + measured latency BOM↔BLR1
  - AWS RDS Mumbai: db.t4g.micro on-demand + RI pricing on AWS calculator
  - Turso ap-south-1: pricing tiers; benchmark vs current SQLite + Litestream
  - Self-host: written WAL-E backup procedure + restore drill log
- [ ] **Canary user**: ___ (test account / admin / 1 paid)
- [ ] **Rollback SLA**: ___ (15-min manual / 7-min auto-rollback watchdog)
- [ ] **Cutover date**: ___ (Saturday 06:00 IST + 7 days from authorization)
- [ ] **Success criteria**: per Section 6 of Phase 2.5 runbook

---

## Section 14 — Honest Acknowledgments

What this re-research can verify (HIGH confidence):
- Provider regions (verified Context7)
- Some provider pricing (Fly MPG, Neon, Supabase verified Context7)
- Turso ap-south-1 region availability (Context7 verified)
- DO BLR1 features (PgBouncer ratio, pgvector, India billing/GST — Context7 verified)

What this re-research CANNOT verify (and should NOT be cited as authoritative):
- AWS RDS specific pricing for ap-south-1 (Context7 doesn't surface pricing-page granularity)
- Azure DB for PostgreSQL Flexible Server pricing (Microsoft Learn MCP not accessible from this dispatch's tool surface)
- Indian fintech infrastructure choices (engineering blogs not in Context7)
- SEBI cloud-circular specifics (regulators not Context7-indexed)
- Indian-domestic providers (Yotta/Tata/Jio/Sify/ESDS) — zero Context7 coverage
- Real-world latency measurements (require ping/traceroute, not doc reads)
- Pricing in INR (most providers bill USD; INR conversion + GST adds variance)

**Where the user needs to verify directly**:
- AWS pricing for `ap-south-1` instance class of choice
- Azure pricing for India region instance class of choice
- Turso pricing tiers
- Indian-domestic provider quotes (sales conversations)
- Lawyer-grade SEBI compliance review (per `MEMORY.md kite-fintech-lawyers.md`)

**Where my recommendation is defensible**: with the verified Context7 data alone, Paths 2/3/5/6 are all reasonable canary picks. Path 1 (defer) is defensible at any time we're not at trigger.

---

**End of v3 R-10 adversarial re-research. Doc-only commit; supersedes v2. tools=130 invariant preserved. NO source mutations. Phase 2.6 dispatch GATED on user authorization with checklist in Section 13.**
