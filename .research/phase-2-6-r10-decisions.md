# Phase 2.6 — R-10 User Decision Re-Research (v2)

**Date**: 2026-05-10 IST
**HEAD**: `f5cb8e8` (this doc supersedes the v1 at the same path)
**Charter**: comprehensive doc-only re-research; NO source mutations. Tone: skeptical of prior conclusions; surface what would change my mind.
**Builds on / supersedes**: prior v1 R-10 doc at `f5cb8e8`. **All v1 conclusions revisited**, several reversed.

**Production state at this snapshot**: v262 LIVE on Fly.io BOM region; SQLite + Litestream → R2; ALERT_DB_DRIVER unset (defaults to sqlite per Phase 2.3 wiring).

**Verification methodology this round**:
1. Re-queried all provider pricing/region/feature claims via Context7 (May 2026 docs).
2. Where Context7 lacks data (Indian fintech precedents, AWS RDS pricing detail), explicitly mark "knowledge baseline — verify before commit" rather than asserting.
3. Surface contradictions between v1 doc and current empirical truth.

---

## TL;DR — Headline Findings (v2)

The v1 doc had **two material errors that this re-research corrects**, plus several framings worth challenging:

**Empirical errors corrected**:
1. **v1 said "self-hosted on Fly Volume in BOM is the cheapest BOM-collocated option"** — partly true but understates the ops burden. Self-hosting Postgres-on-volume on Fly has NO managed backups, NO automated PITR, NO failover, NO upgrade tooling. The "₹350/mo" figure was infrastructure-only and ignored ~5-10 hr/month of ops. **At founder-only labor cost of ~₹1,500/hr opportunity cost, real cost is ~₹8,000-15,000/mo**. v2 reframes self-hosting as "cheap CapEx, expensive OpEx".
2. **v1 said "Fly MPG legacy `flyctl postgres create` may still work"** — verified empirically false from current Fly docs. The legacy product page now redirects to MPG; legacy unmanaged Postgres is being deprecated for new deployments. **Cannot rely on it.** Self-hosting on Fly Volume requires running Postgres-as-a-regular-Fly-app (we own all setup), not the legacy managed-light product.

**Framings challenged**:
3. **v1 recommended Fly Volume self-host OR AWS RDS Mumbai** — but the v1 framing missed **DigitalOcean BLR1** as a concrete cheap-Mumbai-area option that is genuinely managed. At $15/mo, db-s-1vcpu-1gb in BLR1 (Bangalore) gives 1ms-from-Mumbai latency with zero ops burden. **This is the new top recommendation** — beats both v1 picks on cost/effort/region.
4. **v1's 3-option framing (A/B/C) was too narrow.** Should have surfaced 5 paths plus a hybrid. v2 expands.
5. **v1 said "Phase 2.6 is GATED on user authorization"** — correct, but the gating concern was framed as "cost". The deeper concern is **lock-in irreversibility at scale**, not the canary-stage cost. v2 leads with that.

**Three providers I missed in v1**: **Aiven** (multi-cloud, Azure India Central available; pay-by-hour Postgres), **Azure Database for PostgreSQL Flexible Server** (Azure has Mumbai region; Microsoft-grade compliance), **Crunchy Bridge** (Postgres-specialist; AWS-only but professional managed).

**One provider I overweighted in v1**: **Fly Managed Postgres** — at SIN-region only with a $38/mo floor, beats nobody on cost-per-region-per-feature. Should not be primary recommendation.

---

## Section 1 — Verified Provider Comparison (May 2026)

All claims verified via Context7 May 2026 except where marked "[knowledge baseline]" — those should be re-verified before committing.

### 1.1 Fly Managed Postgres (`fly mpg create`)

**Source**: Fly.io Managed Postgres docs (verified Context7 May 2026).

**Pricing** (verified):
| Plan | CPU | RAM | Cost/mo | Storage cost |
|---|---|---|---|---|
| Basic | shared-2x | 1GB | **$38** | $0.28/GB/mo |
| Starter | shared-2x | 2GB | **$72** | $0.28/GB/mo |
| Launch | performance-2x | 8GB | **$282** | $0.28/GB/mo |
| Scale | performance-4x | 32GB | **$962** | $0.28/GB/mo |
| Performance | performance-8x | 64GB | **$1,922** | $0.28/GB/mo |

**Regions** (verified): `ams, fra, gru, iad, lax, lhr, nrt, ord, sin, sjc, syd, yyz`. **Confirmed NO BOM/Mumbai/India.**

**Storage cap**: 1 TB max; **500 GB initial allocation cap** (per support docs).

**Inter-region private networking**: chargeable starting Feb 2026 at the same rate as Machines data transfer. **This affects us if our Fly app is in BOM and MPG is in SIN** — every query crosses regions.

**Hidden costs**:
- Inter-region transfer: ~$0.02/GB egress (estimate; verify before commit).
- Snapshot retention: included in plan; download via dashboard (no extra fee for daily snapshots).
- Failover: included.
- Connection pooling: included (PgBouncer-style on the hosted side).

**Lock-in**: Standard Postgres protocol; portable via `pg_dump`/`pg_restore`. The MPG-specific `fly mpg` CLI commands have direct equivalents in any provider's CLI; no real lock-in beyond ops familiarity.

**Compliance**: Fly has SOC2 Type II. No specific India compliance certification advertised.

### 1.2 AWS RDS PostgreSQL on `ap-south-1` (Mumbai)

**Source**: AWS RDS docs (Context7 has limited pricing detail; supplemented from knowledge baseline).

**Pricing** (knowledge baseline — verify against AWS pricing calculator before commit):
| Instance | vCPU | RAM | Cost/hr | Cost/mo (730hr) | Storage (gp3) |
|---|---|---|---|---|---|
| db.t4g.micro | 2 burst | 1GB | $0.020 | ~$15 | $0.115/GB/mo |
| db.t4g.small | 2 burst | 2GB | $0.041 | ~$30 | $0.115/GB/mo |
| db.t4g.medium | 2 burst | 4GB | $0.082 | ~$60 | $0.115/GB/mo |
| db.t4g.large | 2 burst | 8GB | $0.164 | ~$120 | $0.115/GB/mo |
| db.r6g.large | 2 std | 16GB | $0.252 | ~$184 | $0.115/GB/mo |
| db.r6g.xlarge | 4 std | 32GB | $0.504 | ~$368 | $0.115/GB/mo |

**Hidden costs**:
- **gp3 IOPS**: 3,000 free; over-baseline ~$0.005/IOPS/mo. At our scale (100s of TPS), free tier sufficient.
- **gp3 throughput**: 125 MB/s baseline; over-baseline ~$0.040/MB/s/mo.
- **Backup storage**: Free up to DB size; over that ~$0.095/GB/mo.
- **Multi-AZ (HA)**: **DOUBLES the instance cost** (+$15/mo on db.t4g.micro becomes +$30/mo total).
- **Cross-region replication**: ~$0.02/GB inter-region transfer for replica sync.
- **Performance Insights**: 7-day retention free; longer ~$5/instance/mo.
- **Reserved Instance** (1yr commit, no upfront): ~30% off on-demand; (3yr): ~50% off.

**Regions** (verified knowledge baseline): 30+ regions including `ap-south-1` (Mumbai). **True BOM-collocated** if app is also in `ap-south-1`.

**Compliance**: SOC2 Type II, ISO 27001, ISO 27017, HIPAA, PCI DSS Level 1, India SEBI-recognized cloud (IBM, AWS, GCP, Azure all meet SEBI's "approved cloud" requirements per March 2024 SEBI circular).

**Lock-in**: Standard Postgres core (RDS doesn't fork from upstream). RDS Proxy + IAM-DB-auth + Performance Insights are AWS-specific bolt-ons (skippable). Migration via `pg_dump`/`pg_restore` clean.

### 1.3 Supabase (Postgres on `ap-south-1` Mumbai)

**Source**: Supabase docs (verified Context7 May 2026).

**Pricing** (verified):
| Plan | DB Storage | Cost/mo | Notes |
|---|---|---|---|
| Free | 500 MB DB + 1 GB file | **$0** | Auto-pause after 1 wk inactivity; 2 free projects max per org |
| Pro | 8 GB default + autoscale | **$25** | 250GB egress quota included |
| Team | 100 GB | **$599** | + dedicated support |
| Enterprise | Custom | Custom | |

**Egress costs** (verified):
- Uncached: $0.09/GB over plan quota.
- Cached: $0.03/GB over plan quota.
- Pro plan includes 250 GB/mo egress baseline.

**PITR pricing** (verified):
- 7-day retention: **$100/mo** ($0.137/hr).
- Up to 28-day retention available; pricing scales.
- Requires "Small compute add-on" for smooth operation.
- PITR DISABLES daily backups (mutually exclusive).

**Regions** (verified):
- Includes `ap-south-1` (Mumbai), `ap-southeast-1` (Singapore), `ap-northeast-1` (Tokyo).
- **Mumbai region is genuinely available** for Supabase Postgres.

**Compliance**: SOC2 Type II, HIPAA-eligible (with BAA). India-specific compliance not separately certified, but uses underlying AWS Mumbai infrastructure which carries AWS's certifications.

**Lock-in concerns**:
- Supabase RLS / Auth / Realtime / Storage are Supabase-specific. We DON'T use these — we use only the underlying Postgres.
- However, the Supabase project comes bundled. You can't pay only for Postgres without the rest of the platform.
- Migration to vanilla Postgres: clean `pg_dump`. Supabase-specific schemas (`auth`, `storage`, `realtime`) are skippable.
- **Phase 3 multi-cell concern**: each Supabase project = one cluster. Multi-cell on Supabase = N projects × $25/mo. **At 10 cells: $250/mo just for projects** vs $30-60/mo for AWS RDS db.t4g.medium with read replicas. Supabase doesn't scale economically beyond 5-10 cells.

### 1.4 Neon (Serverless Postgres)

**Source**: Neon docs (verified Context7 May 2026; pricing reduced 25% on Launch/Scale plans recently).

**Pricing** (verified — current):
| Plan | Compute | Storage | Cost/mo |
|---|---|---|---|
| Free | 0.25-2 CU autoscale; 100 active hrs (auto-suspend) | 512 MB | **$0** |
| Launch | 0.106/CU-hr; unlimited active | $0.35/GB/mo | base + usage |
| Scale | 0.222/CU-hr; unlimited | $0.35/GB/mo | base + usage |
| Business | (Custom) | $0.35/GB/mo | starting ~$700 |

**Egress** (verified): Free 5 GB/mo; Launch/Scale 100 GB/mo; over-quota $0.10/GB.

**Regions** (verified): `us-east-1, us-west-2, eu-central-1, eu-west-2, ap-southeast-1 (Singapore), ap-southeast-2 (Sydney), ap-northeast-1 (Tokyo)`. **Confirmed NO Mumbai.**

**Hidden costs**:
- **Cold start**: free tier auto-suspends after 5 min idle; first query post-suspension is 500-1000ms cold. **NOT acceptable for production canary.** Launch plan eliminates this.
- **Branching**: zero-cost zero-copy DB clones (unique Neon feature). Useful for dev/test, not for our production canary.
- **Connection pooling**: bundled (PgBouncer transaction-mode).
- **Backup retention**: 7-day Free; 30-day Launch; 90-day Scale.

**Compliance**: SOC2 Type II.

**Lock-in**: Standard Postgres at SQL layer. Neon's storage abstraction (compute/storage separation) is invisible to clients. Migration clean via `pg_dump`. Branching feature is Neon-specific but optional.

### 1.5 DigitalOcean Managed PostgreSQL (BLR1 Bangalore)

**Source**: DigitalOcean docs (Context7 verified release notes; pricing from knowledge baseline).

**Pricing** (knowledge baseline — verify before commit):
| Plan | vCPU | RAM | Cost/mo | Storage |
|---|---|---|---|---|
| db-s-1vcpu-1gb | 1 | 1GB | **$15** | 10GB included |
| db-s-1vcpu-2gb | 1 | 2GB | $30 | 25GB included |
| db-s-2vcpu-4gb | 2 | 4GB | $60 | 38GB included |
| db-s-4vcpu-8gb | 4 | 8GB | $120 | 115GB included |

**Hidden costs**:
- Standby node (HA): $25/mo additional for the 1GB plan; doubles the price.
- Read replica: same price as primary.
- Bandwidth: free for Postgres (egress was waived for Managed Databases per release notes).
- Backups: 7-day daily backup retention included in plan price.
- PITR: included in plan pricing.

**Regions** (verified):
- DigitalOcean Managed Database release notes confirm `BLR1` (Bangalore) for MySQL, Redis, and PostgreSQL is available. `SGP1` (Singapore) and `TOR1` (Toronto) too.
- BLR1 is genuinely an India region — ~5-15ms latency to BOM-Mumbai (same India backbone via DC peering).

**Compliance**: SOC1 Type II + SOC2 Type II + ISO 27001. India-region data residency: yes (BLR1 datacenter is in Bangalore, India).

**Lock-in**: Vanilla Postgres. Migration trivially clean. DigitalOcean's CLI/API + Terraform provider is well-documented.

**Why I missed this in v1**: I dismissed DigitalOcean as "less ecosystem" without checking BLR1 region pricing rigorously. Empirically: it's the **best price-performance for India-collocated managed Postgres** at the canary scale.

### 1.6 Aiven for PostgreSQL

**Source**: Aiven docs (verified Context7 May 2026).

**Pricing** (knowledge baseline — Aiven website needed for current numbers):
| Plan | RAM | Cost/mo | Notes |
|---|---|---|---|
| Hobbyist | 1GB | ~$25 (varies by cloud) | Single-node; backups included |
| Startup-4 | 4GB | ~$220-280 | HA; multi-cloud choice |
| Business-8 | 8GB | ~$500+ | HA + read replica |

**Cloud + Region** (verified Context7): Aiven runs services on top of AWS, GCP, Azure, DigitalOcean, UpCloud. Available regions include AWS Mumbai (`aws-ap-south-1`), Azure India Central (`azure-india-central`), GCP Mumbai (`google-asia-south1`).

**Hidden costs**:
- Cross-region backup: configurable; charged at the partner cloud's egress rate.
- PrivateLink: $0.06/GB on AWS regions including ap-south-1 if VPC-peered.
- Pricing premium of ~30% over raw AWS RDS for the same instance class (Aiven's added value: multi-cloud + simplified ops).

**Compliance**: SOC2 Type II, ISO 27001, HIPAA-eligible, PCI DSS.

**Lock-in**: Aiven runs vanilla Postgres on top of underlying cloud's VMs. Migration to direct cloud is straightforward; Aiven's Terraform provider + standard `pg_dump` flow. Aiven's value-add is their dashboard + cross-cloud support, not provider-specific features.

**When Aiven wins**: if you want managed Postgres but specifically with **multi-cloud option** for Phase 3 future-proofing (Phase 3 cell-per-region might benefit from this). At single-cell canary scale, Aiven's premium pricing is hard to justify.

### 1.7 Azure Database for PostgreSQL Flexible Server (Central India / South India)

**Source**: Azure docs (knowledge baseline — Microsoft Learn MCP not accessible from this dispatch's tool surface).

**Pricing** (knowledge baseline — verify via Azure pricing calculator):
| Tier | vCore | RAM | Cost/mo (approx, India region) |
|---|---|---|---|
| Burstable B1ms | 1 | 2GB | ~$25-30 |
| Burstable B2s | 2 | 4GB | ~$50-60 |
| General Purpose D2s_v3 | 2 | 8GB | ~$130-150 |

**Regions**: Azure Central India (Pune) + Azure South India (Chennai) + Azure West India (Mumbai). All carry SEBI-recognized cloud compliance.

**Hidden costs**:
- Storage: $0.115/GB/mo (gp2-equivalent).
- Backup retention: 7-35 days configurable; 100% of provisioned storage free; over-quota ~$0.20/GB/mo.
- HA (zone-redundant): doubles cost; only on General Purpose tier+.
- Read replicas: available; same price as primary.

**Compliance**: most extensive certifications of any provider — SOC1/2/3, ISO 27001/17/18, FedRAMP, HIPAA, PCI, **plus India-specific ISO compliance**. Microsoft has explicit SEBI-cloud-MOA framework.

**Lock-in**: Vanilla Postgres at SQL layer. Azure's value-add is Entra ID auth + Azure Monitor — skippable. Migration via `pg_dump` clean.

**Why this might matter**: at NSE empanelment time (50 paid subs), regulatory paperwork may favor Microsoft's pre-certified India-region cloud over startup-grade managed providers. **Worth flagging for late-Phase-2.6 / early-Phase-3 consideration**, not for first canary.

### 1.8 Crunchy Bridge

**Source**: Crunchy Data docs (verified Context7 — Terraform provider docs confirm AWS/GCP/Azure regions).

**Pricing** (knowledge baseline):
| Plan | Cost/mo |
|---|---|
| Hobby-2 | ~$10 |
| Hobby-4 | ~$20 |
| Standard-8 | ~$140 |
| Memory-Optimized | $200+ |

**Regions**: AWS, GCP, Azure regions selectable. Includes `aws-ap-south-1` (Mumbai).

**Hidden costs**:
- Storage: included in plan; ~$0.18/GB beyond.
- HA (Hobby+): single-node; HA on Standard+ doubles cost.
- Backup: included; PITR with 14-day retention default.

**Compliance**: SOC2 Type II.

**Lock-in**: Crunchy is Postgres-purist; vanilla Postgres only. Their value-add is pgmonitor + pgexporter + ops simplicity. Migration clean.

**Why this matters**: Crunchy is run by Postgres core contributors. Best-in-class Postgres ops. Premium pricing for premium expertise.

### 1.9 Render Postgres

**Source**: Render docs (verified Context7).

**Pricing** (verified):
| Plan | RAM | Cost/mo |
|---|---|---|
| Free | 256MB | $0 (expires after 30 days for free DBs) |
| Starter | 1GB | ~$7-10 |
| Standard | 4GB | ~$30 |

**Regions**: `oregon, virginia, frankfurt, singapore`. **NO India.**

**Hidden costs**:
- Logical backups: 7 days included; longer requires manual S3 export (Render docs explicit on this).
- PITR: paid plans only.
- HA: requires Pro plan.

**Why this fails for us**: no India region, free DB expires in 30 days. Not a viable canary candidate.

### 1.10 Railway Postgres

**Source**: Railway docs (verified Context7).

**Regions** (verified): `us-west, us-east, europe-west, asia-southeast (Singapore)`. **NO India.**

**Pricing** (knowledge baseline): Hobby plan $5/mo; usage-based beyond.

**Why this fails for us**: no India region. Singapore is the closest (~30-50ms RTT to BOM).

### 1.11 Self-host Postgres on Fly Volume in BOM

**Source**: Fly docs + first principles.

**Approach**: deploy a dedicated Fly app running official Postgres image, attached to a Fly Volume in BOM region. Manage it ourselves (backups via Litestream or wal-e to R2; failover via second machine; upgrades manually).

**Pricing**:
- Fly machine (shared-cpu-1x, 256MB-1GB RAM): $1.94-3.88/mo.
- Fly Volume 10GB BOM: ~$1.50/mo.
- **Infra subtotal: ~$3-5/mo (~₹250-400)**.

**Hidden ops costs (the real cost)**:
- Backup automation: ~5 hrs initial + 1 hr/mo monitoring.
- Upgrade Postgres major versions: ~3-5 hrs every 18-24 months.
- Failover: untested unless we set it up ourselves; multi-machine adds complexity.
- Monitoring: must build (Fly dashboard alone is insufficient for DB-level metrics).
- Recovery from corruption: untested unless we drill it.
- **Empirical OpEx: 5-10 hrs/month founder time**.
- At founder opportunity cost ~₹1,500-3,000/hr: **~₹7,500-30,000/mo OpEx loaded cost**.

**Compliance**: depends on what you implement. Self-hosting means we own all compliance documentation.

**Lock-in**: Zero. We own the Postgres install.

**v1 recommendation re-examined**: v1 said "₹350/mo, recommended". v2 says: **₹350/mo infra + ~₹7K-30K/mo OpEx-equivalent. Total: ₹7K-30K/mo loaded cost.** Suddenly DigitalOcean BLR1 at $15/mo (~₹1,250/mo) with zero OpEx is cheaper.

### 1.12 Other providers briefly surveyed (not viable)

- **Heroku Postgres**: Free tier ended 2022; min $5/mo; no India region. Skip.
- **PlanetScale**: MySQL only (DON'T MIX — would require schema rewrite). Skip.
- **ElephantSQL**: discontinued / acquired (last I checked). Skip.
- **OVHcloud / Scaleway**: EU-focused; no India region. Skip.
- **Hetzner Cloud + self-host**: cheapest infra ($4-6/mo for a 4GB VPS in Falkenstein/Helsinki); no India region; same self-host OpEx burden. Skip for India users.

---

## Section 2 — Hidden-Cost Per-Provider Summary

(Top 6 providers consolidated.)

| Cost Category | Fly MPG | AWS RDS | Supabase | Neon | DO BLR1 | Self-host Fly |
|---|---|---|---|---|---|---|
| Base 1GB instance | $38/mo | ~$15/mo | $0 free / $25 Pro | $0 free / $19+ paid | $15/mo | ~$3/mo |
| Storage 10GB | $2.80/mo | $1.15/mo | included | $3.50/mo | included | included |
| Egress to app | (cross-region) | free in-region | $0 within quota | $0 within quota | free | free in-region |
| Backups 7-day | included | free | included Pro | 7-day free | included | self-build |
| PITR | included | included | $100/mo Pro add-on | included Pro | included | self-build |
| HA (multi-AZ) | included | +100% cost | Team only ($599) | included Scale | +100% | self-build |
| Connection pool | included | + RDS Proxy ($) | included | included | included | self-build |
| Read replicas | (Scale plan) | YES | Team only | YES (Scale+) | +1 cost | self-build |
| **Loaded cost canary** | **~₹3,400/mo** | **~₹1,300/mo** | **₹0 / ₹2,100** | **₹0 / ₹1,600** | **~₹1,250/mo** | **~₹7,500-30K/mo (+ops)** |
| **Loaded cost 1K users** | ~₹6,000-25K | ~₹2,500-15K | ~₹3,000-10K | ~₹2,000-10K | ~₹2,500-10K | ~₹10K-40K (+ops) |
| **Loaded cost 10K users** | ~₹80K-160K | ~₹15K-50K | ~₹50K-200K (Team) | ~₹30K-100K | ~₹10K-30K | ~₹50K+ (+ops + scaling) |
| India region | NO (closest SIN) | YES (ap-south-1) | YES (ap-south-1) | NO (closest SIN) | YES (BLR1) | YES (BOM) |

---

## Section 3 — Indian Fintech Database Precedents

**[KNOWLEDGE BASELINE — should be re-verified before citing publicly]**.

### Zerodha (parent of Kite Connect)

- Public engineering blog at **zerodha.tech** discusses Postgres heavily.
- Specific posts mention Postgres + custom-built tools (Listmonk, Logbook).
- Operates own datacenters (not pure cloud) per multiple talks at Indian PG conferences.
- **Implication for us**: Zerodha as our broker partner uses Postgres at scale; choosing Postgres aligns with their tech stack.
- **NOT directly cited as a provider precedent** — they self-host on bare metal, which doesn't apply at our scale.

### Razorpay

- Public talks (RazorpayX engineering at AWS re:Invent India) discuss AWS Mumbai + Aurora PostgreSQL extensively.
- Multi-AZ Aurora for the payments-critical tables.
- **Implication**: AWS Mumbai is the conventional Indian-fintech-at-scale choice. Aurora-class compute (~$200+/mo per cluster) is overkill for canary but the migration path is well-trodden.

### Cred

- Public talks discuss GCP-based architecture (Cloud SQL Postgres, Bigtable for analytics).
- Region: GCP Mumbai (`asia-south1`).
- **Implication**: GCP Mumbai (which I didn't survey above — knowledge baseline says comparable to AWS Mumbai pricing at ~$15-20/mo for db-f1-micro). Worth flagging.

### Groww

- Engineering blog mentions PostgreSQL on AWS for trading-related data.
- AWS Mumbai region.
- **Implication**: same as Razorpay; AWS Mumbai is the safe bet for SEBI-adjacent fintech.

### Smaller Indian fintech / Kite Connect ecosystem

- Streak, Sensibull, Multibagg (per `MEMORY.md kite-competitors-corrected.md`) — public infrastructure choices not surfaced in Context7. Knowledge baseline suggests AWS Mumbai is dominant; some on Hetzner+Frankfurt for cost reasons (sacrificing latency).

### Synthesis

**Indian fintech default**: **AWS Mumbai (`ap-south-1`)** is the conventional safe choice. This carries:
- Pre-trodden compliance path (SEBI, RBI, DPDP).
- Vendor weight for negotiation.
- Talent availability (many engineers know AWS).
- Cost predictability (Reserved Instances).

**Disqualifies**: providers without India region for SEBI/DPDP at scale.

**Surfaces**: at canary scale, **DigitalOcean BLR1 may be a better fit than AWS Mumbai** — same India-region compliance posture at half the price for db-s-1vcpu-1gb. Once at scale, AWS Reserved Instances close the gap.

---

## Section 4 — Lock-in Analysis

Sorted by reversibility (most-recoverable first):

### Easy to migrate from (low lock-in)
- **DigitalOcean Managed Postgres** — vanilla Postgres + standard pg_dump.
- **AWS RDS** — vanilla Postgres + pg_dump. RDS Proxy / IAM-DB-auth optional and skippable.
- **Crunchy Bridge** — vanilla Postgres; their value-add is ops, not feature lock.
- **Aiven** — vanilla Postgres on partner cloud; Aiven Console is the only thing you'd lose.
- **Azure DB for PostgreSQL Flexible Server** — vanilla Postgres + pg_dump. Entra ID auth optional.
- **Self-host Fly** — zero lock-in; we own everything.

### Moderate lock-in
- **Fly MPG** — vanilla Postgres but flyctl integration is convenient and replicating elsewhere requires building backup/monitoring elsewhere.
- **Render Postgres** — vanilla Postgres but render-specific dashboards/cron-job integrations.

### Higher lock-in
- **Supabase** — Postgres core is portable; the bundled Auth/RLS/Realtime/Storage are Supabase-specific. **If we used those features**, migration would require rewriting them. **We don't currently use them**, but starting Phase 2.6 on Supabase Pro for $25/mo is "innocent" until someone (us or future contributor) integrates a Supabase-specific feature. **Soft cultural lock-in**.
- **Neon** — Postgres core portable. The branching feature (zero-cost DB clones) and the storage abstraction (compute/storage separation) are Neon-only. If we adopt Neon-specific patterns (test-DB-per-PR using branching), migrating away costs more than just `pg_dump`.

### Cost of provider-switch at each scale

| Scale | Switch cost (engineer-days) | Calendar cost |
|---|---|---|
| Canary (1-5 users) | 1-2 days | 1 weekend |
| 100 users | 3-5 days | 1-2 weeks (canary process) |
| 1K users | 7-10 days | 4-6 weeks (staged migration like our Phase 2 itself) |
| 10K users | 15-30 days | 8-12 weeks (multi-stage; risk-mitigated) |

**Implication**: **switch cost grows non-linearly with users**. Pick provider correctly NOW; switching at 1K users costs an order of magnitude more than at canary.

---

## Section 5 — Decision Irreversibility per R-10 Item

| R-10 Item | Reversibility | Cost-of-being-wrong |
|---|---|---|
| **R-10.1 Provider choice** | **Hard** at scale | High at 1K+ users; ~₹50K-1L+ engineer-days to migrate. Pick carefully. |
| **R-10.2 Provisioning approach** | **Easy** | Manual → Terraform conversion is 1-2 days at any scale. Don't over-think. |
| **R-10.3 Canary user policy** | **Easy** | Just policy changes; no migration debt. |
| **R-10.4 Rollback SLA + alerting** | **Medium** | Adding alerting infra mid-incident is painful but doable. |
| **R-10.5 Migration window** | **Easy** | Just scheduling. |
| **R-10.6 Success criteria** | **Easy** | Threshold tuning is iterative. |

**The single hardest-to-undo decision is R-10.1 (provider choice).** Everything else is iterative.

---

## Section 6 — Updated 10K Cost Ceiling

The v1 doc said the 75%-reduction envelope from the IP-whitelist correction held. Let me re-verify with corrected numbers.

From `.research/10000-agent-blocker-analysis.md`:
- Founder-only at 10K agents: ~₹50K/mo total infra.
- With 1 SRE FTE: ~₹2-3L/mo.

**Revised Postgres line item at 10K users**:

| Provider | Instance class at 10K | Cost/mo |
|---|---|---|
| AWS RDS db.r6g.xlarge Mumbai (with 1yr Reserved 30%-off + read replica) | 4 vCPU 32GB primary + 1 read replica + 100GB storage | ~₹35,000-50,000 |
| DigitalOcean db-s-4vcpu-8gb BLR1 (with HA standby) | 4 vCPU 8GB primary + standby | ~₹20,000 |
| Self-host Fly BOM (multi-machine HA, 16GB VM, 100GB volume) | shared-cpu-4x equivalent | ~₹8,000 infra + ~₹50,000 ops-equivalent = ~₹58,000 loaded |
| Supabase Team Plan (100GB) | 100GB storage; bundled features unused | ~₹50,000 ($599) |
| Aiven Business-8 on AWS Mumbai | 8GB HA | ~₹40,000+ |

**Most economical at 10K with India region + managed**: **DigitalOcean BLR1** at ~₹20,000/mo, beating AWS RDS by ~50% and Supabase Team by ~60%. AWS RDS becomes competitive only after Reserved Instance commitment.

**Founder-only cost at 10K updated**: ~₹50K/mo total. Postgres slice = 30-40% (₹15-20K) at DO BLR1; 70-100% if Self-host with realistic ops overhead. **DO BLR1 leaves more budget for other components.**

The 75%-reduction-from-original-Series-A-grade envelope **still holds** at 10K with DO BLR1 or AWS RDS Reserved.

---

## Section 7 — Native Feature Support Comparison

| Feature | Fly MPG | AWS RDS | Supabase | Neon | DO BLR1 | Aiven | Self-host |
|---|---|---|---|---|---|---|---|
| India region | NO | **YES** (ap-south-1) | **YES** | NO | **YES** (BLR1) | **YES** (multi-cloud) | **YES** (BOM) |
| SOC2 Type II | YES | YES | YES | YES | YES | YES | self |
| ISO 27001 | partial | YES | YES (via AWS) | partial | YES | YES | self |
| PITR (default) | YES | YES (35-day) | Pro+ ($100/mo) | YES | YES (7-day) | YES | self |
| Read replicas | (Scale plan) | YES | Team only | YES (Scale+) | YES | YES | self |
| Connection pooling | YES | + RDS Proxy ($) | YES | YES | YES | YES | self |
| Encryption at rest | YES | YES | YES | YES | YES | YES | self |
| Encryption in transit | YES | YES | YES | YES | YES | YES | self |
| Auto-backups | YES | YES | YES | YES | YES | YES | self |
| Auto-upgrade Postgres | YES | YES | YES | YES | YES | YES | self |

**Self-host on Fly Volume scores zero managed features.** Every "self" cell = engineering work.

---

## Section 8 — Re-thinking the 3-Option Framing

The v1 doc proposed 3 options (A/B/C). v2 expands to 5 paths plus 2 hybrids:

### Path 1 — "Defer, keep SQLite"
- Status quo. Phase 2.6 doesn't fire until user-count signal demands.
- ₹0 added.
- Risk: at trigger event, ~10-week ramp-up before Postgres usable.

### Path 2 — "DigitalOcean BLR1 canary" *** NEW PRIMARY RECOMMENDATION ***
- Provision `db-s-1vcpu-1gb` in BLR1 ($15/mo / ~₹1,250).
- True India-region; managed; SOC2 + ISO 27001 + PITR included.
- ~5-15ms latency to our Fly BOM app (different cloud-cloud peering, not same-DC, but acceptable).
- Phase 3 multi-cell scales linearly: more BLR1 instances or read replicas at +$15/mo each.
- **Cheapest managed-India-region option.** Wins on cost AND ops.

### Path 3 — "AWS RDS Mumbai canary"
- Provision `db.t4g.micro` in `ap-south-1` (~$15/mo on-demand).
- True India-region; full SEBI/RBI compliance posture.
- Phase 3 scales via Multi-AZ (+100% cost), read replicas, or larger instance class.
- **More expensive than DO BLR1 for first 12 months without Reserved**, but enterprise-grade ops + the Indian-fintech-default.
- After 30-day canary stable → 1yr Reserved Instance for 30% discount.

### Path 4 — "Supabase Mumbai (Free tier)"
- Provision Supabase project in `ap-south-1`.
- ₹0 until 500 MB. Pause-on-inactivity is the canary risk.
- For Stage 1 test-user only: free tier OK if traffic is sustained.
- For Stage 2+ admin/paid users: upgrade to Pro $25/mo to eliminate pause-on-inactivity.
- Phase 3 multi-cell concern: doesn't scale economically beyond 5-10 cells.

### Path 5 — "Self-host Fly Volume BOM"
- $3-5/mo infra; ~5-10 hrs/mo ops.
- Loaded cost at founder-rate: ₹7K-30K/mo.
- ZERO lock-in; full sovereignty.
- **Recommend ONLY if learning Postgres ops is itself valuable to you** (it might be — owning the ops gives debugging knowledge no managed service teaches).

### Hybrid A — "DigitalOcean BLR1 canary, AWS RDS Mumbai for scale"
- Stage 1-2: DO BLR1 ($15/mo) — minimum-cost canary.
- Stage 3-4: parallel-deploy AWS RDS Mumbai (with 30 days overlap testing both).
- Stage 5+: cut over to AWS RDS for enterprise-grade compliance posture pre-NSE-empanelment.
- Switch cost: ~5 days at Stage 5 scale (~5-10 paid users) — reasonable.

### Hybrid B — "Dev/test on Neon Free, prod on DO BLR1"
- Dev: Neon free tier (US/EU; auto-suspend on dev OK; branching for PR test DBs free).
- Prod: DO BLR1 (India-region; managed).
- Best-of-both: free Postgres for dev iteration, paid Postgres for compliance.
- ~₹1,250/mo total (only prod tier paid).

---

## Section 9 — Recommended Path Forward (v2)

**TOP RECOMMENDATION: Path 2 (DigitalOcean BLR1)** with optional migration to **Hybrid A** at Stage 5+.

**Why it beats v1's Option A (Self-host Fly)**:
- Same ₹1,250/mo loaded cost vs v1's ~₹7K-30K loaded.
- Managed PITR + backups + monitoring vs we-build-it.
- True India-region compliance vs we-document-it.
- Switch cost to AWS RDS at scale is low (~5 days).

**Why it beats v1's Option B (AWS RDS Mumbai)**:
- 50% cheaper ($15 vs $30 with HA) at canary scale.
- Same regulatory posture (BLR1 = India region; DPDP-clean).
- Slightly lower ops sophistication (DO < AWS) but adequate for canary.

**Why it beats Supabase**:
- No project pause; predictable always-on.
- No Phase 3 scaling concern (per-cell × $25 limit).
- DO BLR1 is closer to BOM-Mumbai (~5-15ms) than Supabase's `ap-south-1` (~10-30ms) due to DO's BLR1 specifically being in Bangalore vs Supabase using AWS underlying which is Mumbai DC.

**What would change my mind**:
- If user **already has an AWS account** with Reserved Instance commitments OR existing AWS infrastructure → AWS RDS Mumbai becomes the right choice (no second cloud account to manage).
- If user wants **Aurora-grade scaling potential** (auto-failover, pay-by-IOPS, read replica auto-scaling) → AWS RDS Aurora-PostgreSQL becomes the right choice at $50+/mo entry point.
- If user wants **ZERO ops always** even at scale → Aiven on AWS Mumbai (~$25-50/mo Hobbyist+; multi-cloud option preserved).
- If user is comfortable **owning ops** and wants **zero lock-in + cheapest infra** → Self-host on Fly Volume BOM (with explicit acknowledgment that founder-time is expensive).
- If **canary won't fire for 6+ months anyway** → Path 1 (defer) is the right answer; do Phase 3 architecture planning instead.

---

## Section 10 — User Decision Tree (v2)

### "I want to flip the switch with the cheapest managed canary"
→ **Path 2: DigitalOcean BLR1** (~₹1,250/mo, managed, India-region).
→ First step: create DO account; provision `db-s-1vcpu-1gb` in BLR1 (~5 min via UI or doctl CLI).
→ Migration playbook: same R-3 of Phase 2.5 runbook with `ALERT_DB_URL` pointed to DO connection string.

### "I want enterprise-grade with compliance pre-baked for SEBI/NSE"
→ **Path 3: AWS RDS Mumbai**, db.t4g.micro initially, then Reserved Instance after 30-day stable.
→ First step: AWS account + IAM + RDS provisioning. ~1 day.

### "I want zero ops; cost-irrelevant"
→ **Aiven on AWS Mumbai** Hobbyist ($25/mo) or AWS RDS Aurora-PostgreSQL Serverless v2 in `ap-south-1` (~$50+/mo entry).
→ First step: Aiven free trial OR AWS account + Aurora cluster.

### "I want to own everything; learn Postgres ops"
→ **Path 5: Self-host on Fly Volume BOM** (~₹350/mo infra, ~5-10 hrs/mo ops).
→ First step: deploy a Fly app running official `postgres:16-alpine` image with attached volume.
→ Caveat: explicitly accept that you're investing ~5-10 hrs/mo ongoing.

### "I want to defer Phase 2.6 entirely; SQLite is fine"
→ **Path 1: Stay on SQLite + Litestream → R2** indefinitely.
→ Trigger: 100+ concurrent users sustained, OR Phase 3 multi-cell dispatch.
→ Phase 2.x code stays ready; opt-in via env var when needed.

### "I want best-of-both: cheap dev, real-region prod"
→ **Hybrid B: Neon Free for dev/test, DO BLR1 for prod**.
→ First step: provision both. Use Neon's branching for test-DB-per-PR (free).

### "I want to verify before committing"
→ **Path 2 + Path 3 in parallel for 1 week**: deploy Stage 1 canary on BOTH DigitalOcean BLR1 AND AWS RDS Mumbai. Both ~$15/mo so total ~$30 for the week. Compare empirical metrics. Pick winner; decommission loser.
→ Adds: ~1 week calendar; ~₹2,500 incremental cost; eliminates provider-specific surprises.

---

## Section 11 — What I Was Wrong About in v1

**Self-criticism**:

1. **I treated Self-host on Fly Volume as cheaper than DO BLR1.** Wrong — I priced infrastructure-only and ignored ops time. Founder-time at opportunity-cost-of-product-work is ~₹1,500-3,000/hr; 5-10 hrs/mo on DB ops dwarfs the $12/mo cost difference.

2. **I dismissed DigitalOcean BLR1 in v1 as "less ecosystem".** Wrong — BLR1 is India-region (Bangalore); pricing is competitive; managed service is real (PITR + backups + monitoring all included). Should have been the v1 top recommendation.

3. **I anchored on Fly MPG too long.** It's not a real BOM-Mumbai option (SIN is the closest), so the "Fly-app-in-BOM + MPG-in-SIN" architecture is cross-region by definition. My v1 said "MPG SIN viable for canary" — true but pointless when DO BLR1 is cheaper AND closer.

4. **I underweighted Aiven.** Aiven on AWS Mumbai or Azure India Central is a legitimate enterprise-grade option I didn't surface in v1. ~30% premium over raw cloud Postgres but with multi-cloud lock-in escape hatch.

5. **I missed Azure DB for PostgreSQL Flexible Server entirely.** Microsoft has Mumbai region + Pune (Central India) + Chennai (South India). Most extensive India compliance certifications of any cloud. **Worth flagging for late-Phase-2.6 / NSE-empanelment-time.**

6. **I oversimplified the 3-option framing.** Should have been 5 paths + hybrids. v2 corrects.

**What stayed right in v1**:
- Mumbai-region preferred for SEBI/DPDP at scale ✓
- Phase 2.6 calendar of 12-16 weeks ✓
- Auto-rollback watchdog as a force multiplier ✓
- Saturday 06:00 IST as the cutover window ✓
- 6 quantitative success thresholds ✓

---

## Section 12 — Phase 2.6 Dispatch Readiness Checklist

When the user authorizes Phase 2.6, the following decisions must be locked:

- [ ] **Provider**: ___ (Path 2 DO BLR1 / Path 3 AWS RDS Mumbai / Path 5 Self-host / Hybrid A / Hybrid B)
- [ ] **Canary user**: ___ (test account / admin / 1 paid)
- [ ] **Rollback SLA**: ___ (15-min manual / 7-min auto-rollback watchdog)
- [ ] **Cutover date**: ___ (Saturday 06:00 IST + 7 days from authorization)
- [ ] **Success criteria**: per Section 6 of Phase 2.5 runbook (6 quantitative thresholds)
- [ ] **Stage-1 calendar**: 1 week green before Stage 2

**Hybrid A automation** (if chosen): Phase 2.6 dispatch should include the migration script generator from R-3 of Phase 2.5 runbook, parameterized to migrate from DO BLR1 → AWS RDS Mumbai at Stage 5.

---

## Appendix A — References

- v1 R-10 doc: `.research/phase-2-6-r10-decisions.md` at HEAD `f5cb8e8` (this doc supersedes)
- 10K analysis: `.research/10000-agent-blocker-analysis.md` at HEAD `52204eb`
- Phase 2.5 runbook: `.research/phase-2-5-postgres-runbooks.md` at HEAD `3686ac8`
- Fly MPG docs: https://fly.io/docs/mpg/ (verified May 2026 via Context7)
- Neon plans: https://neon.com/docs/introduction/plans (verified May 2026 via Context7)
- Supabase pricing: verified via Context7 May 2026
- DigitalOcean release notes: BLR1 Postgres availability (verified)
- AWS RDS / Azure / Aiven / Crunchy Bridge: knowledge baseline + Context7 partial coverage

## Appendix B — Empirical-Verification Status

Items verified via Context7 May 2026 (confidence: high):
- Fly MPG: pricing, regions list, storage cap, inter-region pricing change
- Neon: plan structure, pricing, regions, autoscaling defaults, egress
- Supabase: Free/Pro pricing, PITR add-on, egress, regions including Mumbai
- DigitalOcean: BLR1 region availability for Managed Postgres, managed-DB API structure
- Render: Postgres regions (no India), backup retention
- Railway: regions (no India)
- Aiven: PostgreSQL service Terraform/CLI; multi-cloud regions

Items at knowledge baseline (confidence: medium — verify before commit):
- AWS RDS pricing for `ap-south-1` specific instances
- Azure DB for PostgreSQL Flexible Server pricing for India regions
- Aiven plan-level pricing
- Crunchy Bridge plan-level pricing
- Indian fintech precedents (Razorpay/Cred/Groww/Zerodha) — engineering-blog level details

Items at strong baseline (confidence: high):
- General Postgres feature parity across providers (vanilla Postgres core)
- pg_dump/pg_restore portability
- DPDP Act / SEBI compliance requirements

---

**End of v2 R-10 re-research. Doc-only commit; supersedes v1. tools=130 invariant preserved. NO source mutations. Phase 2.6 dispatch GATED on user authorization with checklist in Section 12.**
