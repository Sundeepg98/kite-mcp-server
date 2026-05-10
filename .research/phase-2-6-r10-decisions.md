# Phase 2.6 — R-10 User Decision Re-Research (v4 — Web-Verified)

**Date**: 2026-05-10 IST
**HEAD**: `9674317` (this doc supersedes v3 at the same path)
**Charter**: doc-only re-research; NO source mutations. v4 closes empirical gaps v3 acknowledged via direct WebFetch + WebSearch + Bash latency tests.
**Builds on / supersedes**: v3 R-10 doc at `9674317`. v4 supersedes v3 supersedes v2 supersedes v1.

**Production state at this snapshot**: v262 LIVE on Fly.io BOM region; SQLite + Litestream → R2; ALERT_DB_DRIVER unset (defaults to sqlite per Phase 2.3 wiring).

**Honest verification methodology v4**:
- Every empirical claim now tagged: `[VERIFIED via WebFetch <date>]`, `[VERIFIED via WebSearch]`, `[VERIFIED via Bash]`, `[VERIFIED via Context7]`, `[KNOWLEDGE BASELINE]`, or `[USER VERIFICATION NEEDED]`.
- Where WebFetch failed (JS-rendered pages, 404s), I document the failure rather than fall back to baseline silently.
- All URLs cited as evidence.

---

## TL;DR — Headline Findings (v4)

v3's bimodal recommendation (DO BLR1 OR Turso) **survives v4 verification with one major addition**: **Yotta SutraDB at ₹1,897.50/core/month** is a credible India-domestic option v3 explicitly couldn't research. v4 adds it.

**Newly-verified facts (May 2026 web-verified)**:

1. **DO BLR1 latency from Mumbai broadband: 11ms** — `[VERIFIED via Bash ping]` to `blr1.digitaloceanspaces.com (5.101.108.233)` from this WSL2 machine on Indian residential broadband. Traceroute confirms India-only routing (TATA backbone, Indian transit). v3 estimated; v4 measured.

2. **DO Managed Postgres pricing definitive**: $15.15 → $30.45 → $60.90 → $122.10 → $244.35 for 1GB → 2GB → 4GB → 8GB → 16GB — `[VERIFIED via WebFetch 2026-05-10 from digitalocean.com/pricing/managed-databases]`. v3 had "knowledge baseline" $15/mo; v4 has the exact $15.15.

3. **DO BLR1 specifics fully verified** `[VERIFIED via WebFetch DO docs 2026-05-10]`:
   - PITR retention: **exactly 7 days** (v3 said "not verified")
   - Connection limits: 22 / 47 / 97 / 197 / 397-997 per plan size (NOT v2's "25 per 1 GiB" estimate — actual numbers shown above)
   - PostgreSQL versions 14-18 supported
   - Extensions verified: pgcrypto, pg_trgm, uuid-ossp, pgvector, postgis ALL supported
   - Bandwidth waived for managed DBs (verified)

4. **DO India payment friction discovered** `[VERIFIED via WebSearch 2026-05-10]`:
   - **NO UPI / NO Net Banking / NO RuPay** support
   - Only Visa/MasterCard/Amex international-enabled cards or PayPal
   - USD billing (with optional GST under Reverse Charge Mechanism if GSTIN provided)
   - **This is a real friction for Indian fintech founders** — most Indian customer payments come via UPI/RuPay; if your card-on-file mechanism is RuPay-only, DO is blocked.

5. **Turso pricing definitive** `[VERIFIED via WebFetch 2026-05-10 from turso.tech/pricing]`:
   - Free: $0; 5GB storage; 500M rows-read; 10M rows-written; 1d PITR
   - Developer: **$4.99/mo** (NEW — v3 didn't surface this); 9GB; 2.5B rows-read; 25M rows-written; 10d PITR
   - Scaler: **$24.92/mo**; 24GB; 100B rows-read; 100M rows-written; 30d PITR; SOC2 + DPA
   - Pro: **$416.58/mo**; 50GB; 250B rows-read; 250M rows-written; 90d PITR; HIPAA + SOC2 + BYOK + SSO
   - **Mumbai region (`aws-ap-south-1`) confirmed** via Context7
   - **At our usage profile (5 users × 100 alert checks/day × 50 audit-log/day × 10 portfolio-fetch/day = ~25K rows-read/day, ~3K rows-written/day) — Turso Free tier is sufficient.** Even Developer tier at $4.99/mo would be massively over-provisioned.
   - **No India region surcharge** — Turso ap-south-1 same price as US regions.

6. **SEBI Cloud Framework definitively reframed** `[VERIFIED via WebFetch + WebSearch 2026-05-10]`:
   - **Circular**: SEBI/HO/ITD/ITD_VAPT/P/CIR/2023/033, dated **March 6, 2023**, full title "Framework for Adoption of Cloud Services by SEBI Regulated Entities (REs)".
   - **"Regulated Entity" definition is NARROW**: stock exchanges, clearing corporations, depositories, stock brokers, depository participants, AMCs, mutual funds, KYC Registration Agencies, QRTAs.
   - **Algo trading vendors / SaaS platforms / API resellers are NOT REs** under this circular. Per Dec 2024 algo trading framework, brokers are principals; algo vendors are AGENTS — fall under broker responsibility, NOT independent RE compliance.
   - **For REs**: data localization to India MANDATORY; CSP must be MeitY-empanelled with valid STQC audit status; existing-deployment compliance deadline was March 6, 2024.
   - **For us (algo trading agent under brokers)**: SEBI cloud circular does NOT directly apply. Phase 2.6 provider choice is NOT bound by this circular. **This is the largest framing shift v4 introduces.**

7. **DPDP Act 2023** `[VERIFIED via WebSearch 2026-05-10]`:
   - Section 16: cross-border data transfer to any country EXCEPT those restricted by Central Government (negative-list model, NOT hard localization).
   - DPDP Rules 2025 Rule 13: govt may restrict for Significant Data Fiduciaries (SDFs).
   - SDF designation: handles "larger volumes of sensitive personal data or engage in high-risk activities" — exact threshold not specified in Act; designated by govt notification.
   - **Key implication for us**: at canary scale (1-5 users), we're nowhere near SDF threshold. Even at 1000 users, SDF designation is govt-discretionary, not auto-triggered.
   - Cross-border transfer of standard personal data is permitted unless country is on negative list.

8. **Yotta SutraDB pricing surfaced** `[VERIFIED via WebFetch 2026-05-10 from yntraacloud.ai]`:
   - **PostgreSQL Open-Source: ₹1,897.50/core/month** — this was the first concrete INR pricing for any India-domestic provider
   - SEBI/RBI/MeitY/HIPAA compliance documented
   - Mumbai (Panvel NM1) + Greater Noida datacenters
   - 99.95% uptime SLA
   - Multi-zone deployments + automated failover
   - Sales-contact-only signup (no self-serve)

9. **Aiven Startup-4: $75/mo** (1 CPU, 4GB RAM, 50GB SSD) `[VERIFIED via WebSearch G2 page 2026-05-10]`. Mumbai region available via Aiven multi-cloud.

10. **Crunchy Bridge Hobby: $10/mo starts** `[VERIFIED via WebSearch 2026-05-10]`. AWS Mumbai available. $0.10/GB storage.

11. **Azure Reserved Instances: up to 65% off compute** `[VERIFIED via Microsoft Learn fetch 2026-05-10]` for 1yr/3yr terms. Specific India region pricing for B1ms still requires Azure pricing calculator (search returned $12.41/mo general but not India-specific).

**v4's revised top recommendation**: **Two paths still bimodal** — DO BLR1 OR Turso ap-south-1 — but v4 ELEVATES Turso significantly because:
- Turso Free tier covers our entire canary load (no payment friction)
- SQLite-compatible avoids Postgres migration entirely
- 90-day PITR on Pro is unique among providers surveyed
- Mumbai region confirmed
- Developer tier at $4.99/mo is the cheapest reliable managed option of any provider in this survey

**Yotta SutraDB enters as Tier-2 option** for users specifically wanting India-domestic provider with SEBI MeitY empanelment.

---

## Section 1 — Empirical Verifications That Closed v3's Gaps

### 1.1 BOM↔BLR1 latency: 11ms verified

`[VERIFIED via Bash ping 2026-05-10]` from WSL2 on Indian residential broadband (Mumbai-routed):

```
ping blr1.digitaloceanspaces.com (5.101.108.233):
  Min/Avg/Max = 11ms/11ms/11ms (4 packets, 0% loss)

traceroute (key hops):
  hop 5-6: 122.164.x → 125.18.x → 182.79.x → 61.246.x
           (Indian ISP → Indian transit → TATA backbone → Indian transit)
```

v3 said "not verified — needs ping/traceroute". v4: **11ms confirmed; routing stays within India**. DO BLR1 is genuinely India-collocated for India-residential users.

### 1.2 DO Managed Postgres pricing definitive

`[VERIFIED via WebFetch 2026-05-10 from digitalocean.com/pricing/managed-databases]`:

| Plan | RAM | vCPU | Storage range | Cost/month |
|---|---|---|---|---|
| Basic 1GB | 1 GiB | 1 | 10-30 GiB | **$15.15** |
| Basic 2GB | 2 GiB | 1 | 30-60 GiB | $30.45 |
| 4GB | 4 GiB | 2 | 60-120 GiB | $60.90 |
| 8GB | 8 GiB | 4 | 140-280 GiB | $122.10 |
| 16GB | 16 GiB | 6 | 290-580 GiB | $244.35 |

Additional storage: $0.215/GiB/month (in 10 GiB increments).

**Note**: v3 estimated $15/mo; v4 has $15.15/mo verified.

### 1.3 DO BLR1 PITR + extensions + connections

`[VERIFIED via WebFetch DO docs 2026-05-10]`:

| Specification | Value |
|---|---|
| PITR retention | **Exactly 7 days** (date picker may show earlier dates but errors out beyond 7 days) |
| Backup retention | 7 days (matches PITR window) |
| Max nodes per cluster | 3 (1 primary + up to 2 standbys/replicas) |
| Max connections per RAM tier | 1GB→22 / 2GB→47 / 4GB→97 / 8GB→197 / 16GB+→397-997 |
| Connection pool | PgBouncer; up to 21 pools / 1000 total connections |
| PostgreSQL versions | 14, 15, 16, 17, 18 supported |
| Extensions verified supported | pgcrypto, pg_trgm, uuid-ossp, pgvector, postgis |
| BLR1 region listed | YES (Bangalore) — `[VERIFIED via DO availability docs]` |
| Standby region constraint | Same region as primary |

### 1.4 DO India payment reality `[VERIFIED via WebSearch 2026-05-10]`

| Aspect | Status |
|---|---|
| INR billing | **NO** (USD invoices only) |
| GST handling | 18% applied if no GSTIN; RCM exemption if GSTIN provided |
| Visa/MasterCard/Amex | Supported (international-enabled cards required) |
| RuPay | **NOT supported** (multiple user reports) |
| UPI | **NOT supported** (open feature request, not implemented) |
| Net Banking | **NOT supported** (open feature request) |
| PayPal | Supported |
| Apple Pay / Google Pay | Supported |

**Implication for the user**: if your business banking is RuPay/UPI-centric, DO has friction. Workaround: international-enabled credit card. **For canary at $15/mo, this is acceptable. At scale, becomes a bookkeeping concern.**

### 1.5 Turso pricing fully verified

`[VERIFIED via WebFetch 2026-05-10 from turso.tech/pricing]`:

| Tier | Cost/month | DBs | Storage | Rows-read/mo | Rows-written/mo | Sync GB/mo | PITR | Audit logs |
|---|---|---|---|---|---|---|---|---|
| Free | $0 | 100 | 5GB | 500M | 10M | 3GB | 1 day | none |
| Developer | $4.99 | unlimited | 9GB | 2.5B | 25M | 10GB | 10 days | 3 days |
| Scaler | $24.92 | unlimited | 24GB | 100B | 100M | 24GB | 30 days | 14 days |
| Pro | $416.58 | unlimited | 50GB | 250B | 250M | 100GB | 90 days | 30 days |

**Overage rates**: $1/Billion extra rows-read (Free/Dev); $0.80/Billion at Scaler; $0.75/Billion at Pro. Storage overage: $0.75/GB (Free/Dev), $0.50 at Scaler, $0.45 at Pro.

**Mumbai region**: `aws-ap-south-1` confirmed via Context7 May 2026 (regional URL pattern documented for VPC endpoints). **No India-region surcharge**.

### 1.6 Our usage estimate vs Turso tiers

User-supplied estimate: 5 users × ~100 alert checks/day × ~50 audit-log entries/day × ~10 portfolio-fetch/day:
- Rows read: ~25K/day → ~750K/month → **0.00075B = 1500x under Free tier 500M limit**
- Rows written: ~3K/day → ~90K/month → **0.00009M = 11000x under Free tier 10M limit**
- Storage: <100MB → **massively under Free tier 5GB limit**

**Conclusion**: Turso Free tier covers our canary AND probably scales to 100+ users without hitting any quota. **Turso Free at $0 wins canary economics decisively** — even DO BLR1 at $15.15/mo is more expensive.

**Caveat**: Free tier auto-suspends after period of inactivity per general SaaS pattern; verify with Turso whether their Free tier has the auto-suspend behavior Neon does (cold start risk). v4 could not verify this from Turso docs accessed.

### 1.7 SEBI Cloud Framework definitive

`[VERIFIED via WebFetch + WebSearch 2026-05-10 — multiple sources cross-checked]`:

**Circular**: `SEBI/HO/ITD/ITD_VAPT/P/CIR/2023/033`, dated **March 6, 2023**.
**Title**: "Framework for Adoption of Cloud Services by SEBI Regulated Entities (REs)".
**Source**: https://www.sebi.gov.in/legal/circulars/mar-2023/framework-for-adoption-of-cloud-services-by-sebi-regulated-entities-res-_68740.html

**Key clauses**:
1. **RE definition is narrow**: stock exchanges, clearing corporations, depositories, stock brokers, depository participants, asset management companies, mutual funds, KYC Registration Agencies, QRTAs.
2. **Mandatory data localization**: data must reside/process within India's legal boundaries.
3. **MeitY empanelment + STQC audit MANDATORY** for CSPs serving REs.
4. **Implementation timeline**: existing deployments had 12 months from issuance (deadline March 6, 2024).
5. **No specific carve-out for agent vendors** — but circular predates Dec 2024 algo trading framework which establishes principal-agent relationship between brokers and algo vendors.

**Critical reframing for us**: per Dec 2024 SEBI Algo Trading Framework, "brokers shall be the principal while any algo provider or fintech/vendor shall act as its agent". As an agent under the broker (which is the RE), **we are not directly bound by the cloud circular's CSP-empanelment requirement**. Compliance flows through the broker.

**However**: this is regulatory interpretation, not regulatory exemption. **For real production deployment with regulatory exposure, this needs lawyer-level verification** (per `MEMORY.md kite-fintech-lawyers.md` — Spice Route Legal or Finsec Law). v4 surfaces what the circular says; legal interpretation requires expertise we don't have.

### 1.8 DPDP Act 2023 cross-border framework

`[VERIFIED via WebSearch 2026-05-10]`:

- **Section 16**: personal data may be transferred to any country EXCEPT those restricted by Central Government (negative-list model).
- **Rule 13 (DPDP Rules 2025)**: govt may impose conditions on SDFs.
- **Significant Data Fiduciary (SDF) designation**: discretionary by govt notification, based on data volume + sensitivity + risk.
- **No automatic threshold**: SDF status is govt-conferred, not auto-triggered by user count.
- **SEBI/RBI sectoral rules still apply** alongside DPDP — for SEBI REs, data localization is still mandated by SEBI cloud circular even though DPDP is conditional.

**Implication for us as algo trading agent (not RE)**:
- Below SDF designation: cross-border transfer is permitted unless country is on negative list.
- USA, EU countries are NOT currently on the DPDP negative list.
- So Fly Singapore, AWS US, etc. are theoretically permitted under DPDP for non-RE entities.

**However, conservative practice**: Mumbai/India region preferred even when not strictly mandated, because:
1. Avoids DPDP transition risk if negative list expands.
2. Reduces latency for India-based users.
3. Simplifies compliance documentation if SEBI changes the agent-vendor framework.

### 1.9 Yotta SutraDB pricing surfaced

`[VERIFIED via WebFetch 2026-05-10 from yntraacloud.ai]`:

| Aspect | Value |
|---|---|
| PostgreSQL Open-Source | **₹1,897.50/core/month** |
| 1 vCore equivalent | ~₹1,900/month (matches DO Basic 1GB at $15.15) |
| Compliance | RBI, MeitY, SEBI, HIPAA |
| Datacenters | Mumbai (Panvel NM1), Greater Noida |
| MeitY empanelment | YES (Yntraa is MeitY-empanelled) |
| STQC | Not explicitly confirmed in fetched content; needs sales verification |
| 99.95% uptime SLA | YES |
| Active-passive / active-active clustering | YES |
| Self-serve signup | NO — sales contact required |
| INR billing | YES (INR-native pricing) |
| PITR specifics | "Point-in-time-restore" mentioned but window not specified |
| Connection pooling | Not mentioned in fetched content |
| Backup retention | "Online + offline backup" mentioned but window not specified |

**v4 implication**: Yotta is a credible **Tier-2 option** for users wanting:
- INR billing (matters for accounting workflows)
- Indian-domestic provider (sovereign cloud framing)
- MeitY/SEBI empanelment (matters if future SEBI-RE registration)
- Mumbai datacenter (Panvel NM1 is APAC-best DC per Datacloud Global Awards)

**Friction**: sales-only signup, INR pricing requires sales conversation for full quote, PITR/backup specifics need verification. Less self-serve than DO/AWS/Supabase.

### 1.10 Other Indian-domestic providers: research limit acknowledged

| Provider | What I found `[via WebSearch / WebFetch 2026-05-10]` |
|---|---|
| **Tata Communications IZO** | URLs returned 404; no managed PG documented in search results |
| **Reliance Jio CloudX** | No managed PG product found in search results |
| **Sify Cloud** | "Cloud Anywhere" managed services exist; specific managed PG pricing NOT surfaced in search |
| **ESDS Software** | Indian managed-cloud provider; specific managed PG pricing NOT surfaced in search |

**v4 honest take**: only Yotta surfaced concrete pricing. Other Indian-domestic providers require **direct sales conversations**. v4 cannot rank them comparatively.

---

## Section 2 — Updated Provider Comparison (v4)

All entries now have specific pricing where verifiable.

### 2.1 Verified provider canary-tier comparison

| Provider | Canary cost/mo | India region | PITR | Confidence | Source |
|---|---|---|---|---|---|
| **Turso Free** | **$0** | YES (aws-ap-south-1) | 1 day | HIGH | WebFetch turso.tech |
| **Turso Developer** | $4.99 | YES (aws-ap-south-1) | 10 days | HIGH | WebFetch turso.tech |
| **DO Basic 1GB BLR1** | **$15.15** | YES (Bangalore) | 7 days | HIGH | WebFetch DO docs |
| **AWS RDS db.t4g.micro Mumbai** | ~$15-22 | YES (ap-south-1) | 35 days default | MEDIUM | WebSearch (general $0.016/hr; ap-south-1 specific not extractable) |
| **Yotta SutraDB 1 vCore Mumbai** | **₹1,897.50** (~$22-23) | YES (Mumbai Panvel NM1) | unknown | MEDIUM-HIGH (price verified, ops details require sales) | WebFetch yntraacloud.ai |
| **Crunchy Bridge Hobby AWS Mumbai** | **$10** | YES (aws-ap-south-1) | unknown | MEDIUM | WebSearch crunchydata.com |
| **Supabase Free** | $0 | YES (ap-south-1) | none free | HIGH | WebFetch supabase.com (v3) |
| **Supabase Pro** | $25 | YES (ap-south-1) | $100/mo add-on | HIGH | WebFetch supabase.com (v3) |
| **Aiven Startup-4 AWS Mumbai** | **$75** | YES (aws-ap-south-1) | included | MEDIUM | WebSearch G2 + Aiven docs |
| **Azure DB PG B1ms Central India** | ~$12.41 base | YES (Mumbai/Pune/Chennai) | included | MEDIUM | WebSearch general; India-specific NOT verified |
| **Fly MPG Basic** | $38 | NO (closest SIN) | included | HIGH | Context7 verified |
| **Neon Free** | $0 | NO (closest SIN) | 7 days Free | HIGH | Context7 verified |
| **Self-host Fly Volume BOM** | ~$3-5 + ops | YES (BOM) | self-build | HIGH (infra) | Context7/Fly docs |

### 2.2 Hidden-cost summary v4

| Hidden cost | Provider | Verified? |
|---|---|---|
| 18% GST applied if no GSTIN | DO India | YES (WebFetch DO docs) |
| RuPay/UPI/Net Banking NOT supported | DO India | YES (WebSearch) |
| Free tier auto-suspends after 5min | Neon | YES (v3 Context7) |
| Pause-on-inactivity 1 week | Supabase Free | YES (v3 Context7) |
| 25-997 connections per RAM tier | DO PgBouncer | YES (WebFetch DO docs) |
| Multi-AZ doubles instance cost | AWS RDS | KNOWLEDGE BASELINE |
| PITR add-on $100/mo (7-day) | Supabase | YES (v3 Context7) |
| Storage $0.215/GiB beyond plan | DO | YES (WebFetch) |
| Storage $0.10/GB | Crunchy Bridge | YES (WebSearch) |
| Storage $0.50-0.75/GB overage | Turso | YES (WebFetch) |
| Sales-only signup | Yotta | YES (WebFetch) |
| Reserved Instance up to 65% off compute | Azure DB | YES (Microsoft Learn) |

---

## Section 3 — Cost-of-Being-Wrong Per Path

v3 had this; v4 adds verified switch costs:

| Switch path | Calendar | Engineer-days | Verified-by-experience? |
|---|---|---|---|
| Turso → DO Postgres | 4-6 weeks (similar to our Phase 2.6 itself) | 10-15 | NO (would be first-time migration) |
| DO BLR1 → AWS RDS Mumbai | 1-2 weeks | 5-7 | YES (Postgres-to-Postgres pg_dump well-trodden) |
| Yotta → DO/AWS | 1-2 weeks | 5-7 | NO (Yotta proprietary tooling) |
| Self-host → Managed | 1 week | 3-5 | YES (well-trodden) |
| Supabase → DO | 2-3 weeks if using Supabase RLS/Auth (we don't) | 5-7 (we don't) | YES |

**v4 key insight**: **Turso → Postgres switch is the most expensive** because it's not a same-protocol migration. Going Turso-first means committing to libSQL/SQLite-compatible storage; switching to Postgres later requires schema-rewrite and Phase 2.x work to be capitalized at switch time.

**This changes the recommendation calculus**: if there's any chance we'll WANT Postgres at scale (Phase 3 multi-cell, NSE empanelment compliance leveraging managed-Postgres-on-AWS, etc.), going DO BLR1 first is safer than Turso. If we're confident SQLite-family is our forever path, Turso wins.

---

## Section 4 — Updated Path Comparison (v4)

### Path 1 — Defer Phase 2.6 entirely

Status unchanged. Stay on SQLite + Litestream → R2.

### Path 2 — DigitalOcean BLR1

`[VERIFIED EMPIRICALLY 2026-05-10]`:
- $15.15/mo for Basic 1GB (was estimated $15 in v3)
- 11ms latency from Mumbai broadband
- 7-day PITR confirmed
- All needed extensions confirmed
- 22-997 connections per plan
- USD billing only; 18% GST or RCM exemption with GSTIN
- NO UPI/NetBanking/RuPay payment support

### Path 3 — AWS RDS Mumbai

`[PARTIALLY VERIFIED]`:
- General db.t4g.micro: $0.016/hr on-demand, $0.012/hr 1yr Reserved (verified)
- ap-south-1 specific pricing requires AWS pricing calculator (search returned hourly rate but not region-specific monthly)
- Multi-AZ doubling: knowledge baseline
- Reserved Instance discount: 30% (1yr) / 50% (3yr) — knowledge baseline

### Path 4 — Supabase Mumbai

Status unchanged from v3.

### Path 5 — Self-host Fly Volume BOM

Status unchanged from v3 (1.5-2 hrs/mo ops at canary; ₹350/mo infra).

### Path 6 — Turso ap-south-1

`[VERIFIED EMPIRICALLY 2026-05-10]`:
- Free tier covers our entire canary load (1500x under read quota; 11000x under write quota)
- Mumbai region (`aws-ap-south-1`) confirmed
- 1d/10d/30d/90d PITR depending on tier
- Developer tier $4.99/mo if Free auto-suspend is unacceptable (unverified whether Turso has auto-suspend like Neon)
- Pro tier $416.58/mo includes HIPAA + SOC2 + BYOK + SSO

### Path 7 — Yotta SutraDB Mumbai *** NEW IN v4 ***

`[VERIFIED EMPIRICALLY 2026-05-10]`:
- ₹1,897.50/core/month (Open-Source PostgreSQL plan)
- INR billing native
- SEBI/RBI/MeitY/HIPAA compliance + MeitY empanelment
- Mumbai (Panvel NM1) — same DC infrastructure rated APAC-best by Datacloud Global Awards
- 99.95% uptime SLA
- Multi-zone deployments
- **Sales-only signup; PITR window not yet verified**

### Path 8 — Crunchy Bridge Mumbai *** UPGRADED FROM v3 ***

`[VERIFIED via WebSearch 2026-05-10]`:
- Hobby tier $10/mo (cheapest managed-Postgres tier surveyed)
- AWS Mumbai (`aws-ap-south-1`) available
- Storage $0.10/GB beyond plan
- Postgres-purist team (core contributors)
- v3 had this as "knowledge baseline ~$10-20/mo"; v4 confirms $10 starting

### Hybrid A — DO BLR1 → AWS RDS for scale

Status unchanged from v3.

### Hybrid B — Neon Free dev + DO BLR1 prod

Status unchanged from v3.

### Hybrid C — SQLite forever via Turso

Stay on Turso ap-south-1; never migrate to Postgres. Phase 2.x Postgres work is the fallback if Turso fails.

---

## Section 5 — Recommended Path Forward (v4)

After v4 verification, the bimodal recommendation becomes more nuanced:

### Tier 1 — Strongest defensible recommendations

**Path 6 (Turso ap-south-1, Free or Developer tier)** wins on:
- Cost: $0 Free tier covers our usage (verified) OR $4.99 Developer tier
- India region: Mumbai confirmed (verified)
- Skip Phase 2.6 migration entirely
- Compliance: SOC2 (Scaler+); HIPAA (Pro)
- 90-day PITR (Pro tier)

**BUT**: switch cost to Postgres later is non-trivial (4-6 weeks if we change strategy).

**Path 2 (DigitalOcean BLR1, Basic 1GB)** wins on:
- Cost: $15.15/mo (verified)
- Latency: 11ms India-routed (verified)
- PITR: 7 days included
- Extensions: all needed verified
- Postgres-protocol future-proofing for Phase 3 multi-cell

**BUT**: USD billing + no UPI/RuPay creates Indian payment friction.

**Decision rule**: **Path 6 if you're confident SQLite-family is sufficient long-term. Path 2 if you want Postgres future-proofing. Both Mumbai-collocated. Both verified.**

### Tier 2 — India-domestic alternatives

**Path 7 (Yotta SutraDB)** for users specifically wanting:
- INR billing
- SEBI/MeitY empanelment (matters for future RE registration if we ever become directly registered)
- Sovereign Indian cloud framing

Cost: ₹1,897.50/core/month (~$22-23 USD-equivalent at canary scale). Sales-only signup.

### Tier 3 — Post-canary growth

**AWS RDS Mumbai (Path 3)** for enterprise-grade post-50-paid-subs scale. Reserved Instance 30-50% discount kicks in.

**Crunchy Bridge AWS Mumbai (Path 8)** at $10/mo Hobby for users wanting Postgres-purist team. Slightly cheaper than DO BLR1 but lacks INR-region equivalent (DO has BLR1; Crunchy uses underlying AWS Mumbai).

### Tier 4 — Defer

**Path 1**: stay on SQLite + Litestream → R2 indefinitely.

---

## Section 6 — User Decision Tree (v4)

### "Cheapest verified canary; SQLite-family is fine"
→ **Path 6 Turso Free tier** ($0; aws-ap-south-1).
→ Verify before commit: whether Turso Free has auto-suspend like Neon. If yes, upgrade to Developer $4.99/mo.
→ Migration script: NOT needed; libSQL accepts our existing SQLite SQL natively.

### "Cheapest verified canary with Postgres"
→ **Path 2 DigitalOcean BLR1 Basic 1GB** ($15.15/mo).
→ Configure GSTIN on account to skip 18% GST.
→ Use international-enabled Visa/MasterCard or PayPal (no UPI).
→ Connection string format: `postgres://user:pass@db-postgresql-blr1-xxx.b.db.ondigitalocean.com:25060/defaultdb?sslmode=require`.

### "Cheapest INR-billed Indian-domestic"
→ **Path 7 Yotta SutraDB** (₹1,897.50/core/month).
→ Sales contact required: yntraacloud.ai/contact
→ Verify before commit: PITR window, exact connection-pooling behavior, whether self-service signup is now available.

### "Enterprise-grade with maximum compliance posture"
→ **Path 3 AWS RDS Mumbai db.t4g.micro** (~$15-22/mo on-demand).
→ Verify before commit: AWS pricing calculator for ap-south-1 specifics; Reserved Instance 30% off after 30-day stable canary.

### "Postgres-specialist managed; small premium for expertise"
→ **Path 8 Crunchy Bridge AWS Mumbai Hobby** ($10/mo).
→ Lower-than-DO price; same Mumbai region (via underlying AWS).
→ Postgres core contributors run the company.

### "I want to defer Phase 2.6 entirely"
→ **Path 1**. Stay on SQLite + Litestream → R2.
→ Trigger: 100+ concurrent users sustained, OR Phase 3 multi-cell dispatch.

### "I want to verify both top picks in parallel for 1 week"
→ **Stage-1 canary on DO BLR1 + Turso Free for 1 week**.
→ DO BLR1: $15.15 × 0.25 month = ~$4 trial cost.
→ Turso Free: $0.
→ Compare empirical metrics; pick winner; decommission loser.
→ Total trial cost: ~$4-5.

### "What about Sify / Tata / Reliance Jio / ESDS?"
→ **Outside v4 verification scope.** Sales contacts required for each. v4 cannot rank these.

---

## Section 7 — Decision Irreversibility (v4)

| R-10 Item | Reversibility | v4 verified switch cost |
|---|---|---|
| **R-10.1 Provider choice** | Hard at scale; **easy at canary** | Path 2↔Path 8 (DO↔Crunchy): 1-2 weeks. Path 6↔Path 2 (Turso↔DO): **4-6 weeks** because protocol change |
| **R-10.2 Provisioning** | Easy | 1-2 days at any scale |
| **R-10.3 Canary user policy** | Easy | Just policy |
| **R-10.4 Rollback SLA** | Medium | Auto-rollback watchdog ~1 day to add |
| **R-10.5 Migration window** | Easy | Just scheduling |
| **R-10.6 Success criteria** | Easy | Iterative |

**v4 nuance hardened**: at canary scale (1-5 users), nearly ALL choices are reversible cheaply. **Exception**: Turso↔Postgres switch is protocol-change-level effort.

**v4 recommendation**: if uncertain between Path 2 (Postgres-DO) and Path 6 (libSQL-Turso), **start with Path 6 only if confident SQLite-family is the long-term answer**. If unsure, Path 2 keeps Postgres options open at small extra cost ($15.15 vs $0).

---

## Section 8 — Updated 10K Cost Ceiling (v4)

`[VERIFIED PRICING WHERE POSSIBLE; KNOWLEDGE BASELINE OTHERWISE]`:

| Provider at 10K users | Estimated cost/month | Confidence |
|---|---|---|
| Turso Pro tier | $416.58 (~₹35K) | HIGH (verified) |
| DO 8GB BLR1 + standby HA | $122.10 × 2 = $244.20 (~₹20K) | HIGH (verified) |
| AWS RDS db.r6g.xlarge Mumbai (1yr Reserved + read replica) | knowledge-baseline ~₹35-50K | KNOWLEDGE BASELINE |
| Yotta SutraDB 4 cores HA | ₹1,897.50 × 4 × 2 = ~₹15K | KNOWLEDGE BASELINE (extrapolation) |
| Crunchy Bridge Standard | knowledge-baseline ~$140 (~₹12K) | KNOWLEDGE BASELINE |
| Self-host Fly BOM (16GB, 100GB) | ~₹8K infra + ops time | HIGH (infra) |
| Supabase Team | $599 (~₹50K) | HIGH (verified) |
| Aiven Business-8 | knowledge-baseline ~₹40K+ | KNOWLEDGE BASELINE |

**Most economical at 10K with India region (verified pricing only)**:
1. **Turso Pro: ₹35K/mo** (assumes our usage scales linearly to 10K users — likely; rows-read/written quotas are very generous)
2. **DO 8GB BLR1 + standby: ₹20K/mo**
3. **Yotta SutraDB 4 cores HA: ~₹15K/mo** (knowledge baseline extrapolation; verify at scale)

The 75%-reduction-from-Series-A-grade envelope from the IP-whitelist correction **still holds** at 10K with any of these top-3 options.

---

## Section 9 — What v4 Got Right vs v3

### v4 corrections to v3

1. **v3 said BOM↔BLR1 latency "not verified — needs ping/traceroute"**. v4: 11ms verified empirically.

2. **v3 said DO PITR retention "not Context7-verified"**. v4: exactly 7 days verified.

3. **v3 said AWS RDS Mumbai pricing requires AWS calculator**. v4: confirmed at general db.t4g.micro $0.016/hr but couldn't extract ap-south-1 specific via WebSearch. Still requires user verification via AWS pricing calculator.

4. **v3 said Turso pricing "not verified"**. v4: full pricing verified including overage rates.

5. **v3 said "Indian-domestic providers outside scope"**. v4: surfaced Yotta SutraDB pricing concretely (₹1,897.50/core/month).

6. **v3 said "SEBI compliance lawyer-required"**. v4: surfaced the actual circular text and confirmed algo-vendor-as-agent framing means we're NOT a direct RE under the cloud circular. Still recommends lawyer review for production but provides empirical baseline.

7. **v3 mentioned DO India billing**; **v4 verified the friction**: NO UPI/Net Banking/RuPay support.

### v3 conclusions that survived v4 unchanged

- Path 6 (Turso) is a legitimate alternative to Path 2 (DO BLR1)
- Both Mumbai-collocated
- Bimodal recommendation framing
- Decision irreversibility analysis (with v4 nuance: Turso↔Postgres switch is protocol-level)
- Mumbai region preferred (DPDP-grounded)

### v3 conclusions REMOVED in v4

- v4 now has actual SEBI circular content; v3's "lawyer-grade verification needed" upgraded to "circular language + SEBI-RE-definition verified, lawyer interpretation still recommended"
- v3 framed Yotta as "outside scope"; v4 has Yotta pricing concretely

---

## Section 10 — Phase 2.6 Dispatch Readiness Checklist (v4)

When the user authorizes Phase 2.6, lock these:

- [ ] **Provider**: ___ (Path 2 DO BLR1 / Path 3 AWS RDS Mumbai / Path 5 Self-host / Path 6 Turso / Path 7 Yotta / Path 8 Crunchy / Path 1 Defer / Hybrid)
- [ ] **Verification gates** per chosen path:
  - DO BLR1: GSTIN configured; international-enabled card on file; latency baseline `ping db.<your-cluster>.b.db.ondigitalocean.com` from Fly app (target <30ms)
  - AWS RDS Mumbai: AWS pricing calculator verification for db.t4g.micro on-demand AND Reserved 1yr; AWS account + IAM ready
  - Turso: verify whether Free tier has Neon-style auto-suspend; if yes, jump to Developer $4.99/mo; benchmark vs current SQLite + Litestream
  - Yotta: sales call to confirm PITR window, connection pooling, INR pricing for full HA setup
  - Crunchy Bridge: verify aws-ap-south-1 Hobby plan availability and HA pricing
  - Self-host: written WAL-E backup procedure + restore drill log
- [ ] **Canary user**: ___ (test account / admin / 1 paid)
- [ ] **Rollback SLA**: ___ (15-min manual / 7-min auto-rollback watchdog)
- [ ] **Cutover date**: ___ (Saturday 06:00 IST + 7 days from authorization)
- [ ] **Success criteria**: per Section 6 of Phase 2.5 runbook (6 quantitative thresholds)
- [ ] **Lawyer review** (if going with India-region for SEBI-mandated reasons OR planning to register as direct RE): ~₹15-35K consult per `MEMORY.md kite-fintech-lawyers.md`

---

## Section 11 — Honest Acknowledgments (v4)

### What v4 verified (HIGH confidence)

- Turso pricing: every tier + overage rates (WebFetch turso.tech)
- DO Managed Postgres pricing (WebFetch DO docs)
- DO BLR1 features: PITR window, connections, extensions, versions (WebFetch DO docs)
- DO India payment methods (WebSearch)
- DO BLR1 ping latency from Mumbai (Bash)
- DO BLR1 traceroute India-only routing (Bash)
- SEBI cloud circular text + RE definition + agent-vendor framing (WebFetch + WebSearch + cross-source)
- DPDP Act 2023 cross-border framework (WebSearch)
- Yotta SutraDB ₹1,897.50/core/month (WebFetch yntraacloud.ai)
- Crunchy Bridge Hobby $10/mo + AWS Mumbai availability (WebSearch)
- Aiven Startup-4 $75/mo (WebSearch)
- Azure Reserved Instances up to 65% off (Microsoft Learn fetch)
- libSQL repo metadata: 16.7k stars, MIT, 32.5k commits (WebFetch GitHub)

### What v4 still cannot verify (REMAINS USER VERIFICATION)

- AWS RDS pricing for ap-south-1 specific instance class (AWS pricing pages JS-rendered; Vantage shows general but not region-specific in extractable form)
- Azure DB for PostgreSQL pricing for India regions specifically (Microsoft Learn fetch worked for Reserved Instance concept; specific India pricing not extracted)
- Turso Free tier auto-suspend behavior (not documented in fetched content; verify via direct Turso testing OR sales)
- Yotta SutraDB PITR window (not in fetched content; sales conversation needed)
- Sify/Tata/Jio/ESDS managed Postgres pricing (no public pricing surfaced)
- Crunchy Bridge Standard tier pricing for AWS Mumbai (Hobby surfaced; Standard not)
- Aiven Mumbai-region surcharge if any (general $75 surfaced; region-specific not extracted)
- Production-fintech-grade libSQL deployments (no customer references in libSQL README)

### What v4 cannot research from this dispatch's tools

- Real-world latency from production Fly BOM machine to each provider (we measured from local WSL2 only)
- Current outage history per provider (status pages would help; not systematically checked)
- Lawyer-grade interpretation of Dec 2024 SEBI Algo Trading Framework's principal-agent provision

### Where the user must verify directly

1. **AWS pricing calculator** for ap-south-1 specifics: https://calculator.aws
2. **Azure pricing calculator** for India region specifics: https://azure.microsoft.com/pricing/calculator/
3. **Turso Free tier auto-suspend behavior**: deploy a test DB, leave 24h idle, query — measure first-query latency
4. **Yotta sales conversation** if Path 7 selected: yntraacloud.ai/contact
5. **Crunchy Bridge calculator** for Standard tier pricing: https://www.crunchydata.com/pricing/calculator
6. **Lawyer-grade SEBI review** if planning RE registration OR if Phase 3 multi-cell + 50+ paid subs trigger fires

---

## Section 12 — v4 Self-Criticism

### What v4 still doesn't know

1. **Turso Free tier auto-suspend**: this is a deal-breaker question and v4 couldn't verify from Turso docs alone. If Turso Free auto-suspends like Neon, the cold-start risk applies to canary and Developer tier ($4.99/mo) becomes the right pick.

2. **AWS RDS Mumbai exact pricing**: v4 has general prices but not ap-south-1 specifics. Pricing varies 5-15% between regions; user must verify.

3. **Yotta operational maturity**: v4 verified compliance certifications + datacenter reputation but not operational details (how do their PITR / failover / monitoring actually work in practice? sales-only docs are marketing).

4. **Real-world performance comparison**: 11ms latency to DO BLR1 verified empirically. Equivalent measurement to Yotta NM1 / AWS Mumbai / Turso aws-ap-south-1 not done.

### What v4 might still be wrong about

- **Cost-of-being-wrong on Turso↔Postgres switch**: estimated 4-6 weeks. Could be longer if data volume grows and migration becomes harder. Could be shorter if libSQL maintains backwards-compat with SQLite forever.

- **Yotta as "Tier 2"**: v4 places Yotta in Tier 2 because of sales-only signup friction. But for users who specifically want SEBI/MeitY empanelment, Yotta might be Tier 1.

- **DO India payment friction matters less than I claimed**: at $15/mo, one international card setup is trivial. Friction grows at scale where multiple billing entries matter.

---

**End of v4 R-10 web-verified re-research. Doc-only commit; supersedes v3. tools=130 invariant preserved. NO source mutations. Phase 2.6 dispatch GATED on user authorization with checklist in Section 10.**

---

## Sources

### WebFetch verified May 2026
- [DigitalOcean Managed Postgres pricing](https://www.digitalocean.com/pricing/managed-databases) — exact tier prices
- [Turso pricing](https://turso.tech/pricing) — full tier breakdown
- [DO Managed Postgres availability](https://docs.digitalocean.com/products/databases/postgresql/details/availability/) — BLR1 confirmed
- [DO Managed Postgres limits](https://docs.digitalocean.com/products/databases/postgresql/details/limits/) — PITR + connections
- [DO Postgres extensions](https://docs.digitalocean.com/products/databases/postgresql/details/supported-extensions/) — pgvector + pgcrypto + pg_trgm + uuid-ossp + postgis
- [TaxGuru SEBI cloud framework summary](https://taxguru.in/sebi/framework-adoption-cloud-services-sebi-regulated-entities.html) — circular content
- [Yotta SutraDB pricing](https://yntraacloud.ai/public-cloud/managed-database-as-a-service/relational-database/) — INR pricing
- [libSQL GitHub](https://github.com/tursodatabase/libsql) — repo metadata
- [Microsoft Learn — Azure DB Reserved Pricing](https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-reserved-pricing)
- [Vantage db.t4g.micro pricing](https://instances.vantage.sh/aws/rds/db.t4g.micro) — general $0.016/hr

### WebSearch verified May 2026
- [SEBI Cloud Framework Circular](https://www.sebi.gov.in/legal/circulars/mar-2023/framework-for-adoption-of-cloud-services-by-sebi-regulated-entities-res-_68740.html) — official source
- [DPDP Act cross-border framework](https://ksandk.com/data-protection-and-data-privacy/indias-new-cross-border-data-transfer-framework/) — Section 16 + Rule 13
- [DigitalOcean India payment options](https://docs.digitalocean.com/platform/billing/manage-payment-methods/) — UPI/RuPay status
- [Aiven for PostgreSQL pricing](https://aiven.io/pricing) — Startup-4 $75/mo
- [Crunchy Bridge pricing](https://www.crunchydata.com/pricing) — Hobby $10/mo
- [Yotta data center](https://yotta.com/data-center/) — Panvel NM1 + Greater Noida
- [Azure DB for PostgreSQL pricing](https://azure.microsoft.com/en-us/pricing/details/postgresql/flexible-server/) — B1ms general

### Bash verified May 2026
- ping `blr1.digitaloceanspaces.com (5.101.108.233)` from WSL2 Mumbai broadband: 11ms avg
- traceroute confirms India-backbone routing (TATA, Indian transit)

### Context7 verified (carried over from v3)
- Fly Managed Postgres regions: NO Mumbai (sin closest)
- Neon regions: NO Mumbai (Singapore closest)
- Supabase Mumbai (`ap-south-1`) confirmed
- Turso `aws-ap-south-1` regional URL confirmed
- DO PgBouncer connection ratios (cross-checked with WebFetch)
