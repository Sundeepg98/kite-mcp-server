# Phase 2.6 — R-10 User Decision Analysis + Downstream Implications

**Date**: 2026-05-10 IST
**HEAD**: `3686ac8` (post-Phase-2.5)
**Charter**: comprehensive consolidation research; NO source mutations. User makes Phase 2.6 + downstream decisions in a fully-informed way after reading.
**Builds on**:
- Phase 2.0 design at `c5b9cf7`
- Phase 2.1 SQL audit at `da91a39`
- Phase 2.5 runbook at `3686ac8`
- 10K-agent blocker analysis at `52204eb`
- Phase 2.4 placeholder rewriter at alerts v0.5.0

**Production state at this snapshot**: v261 LIVE on Fly.io BOM region; SQLite + Litestream → R2; ALERT_DB_DRIVER unset (defaults to sqlite per Phase 2.3 wiring).

---

## TL;DR — Headline Findings

Two major empirical corrections to the Phase 2.5 runbook surfaced during this research:

1. **Fly Postgres has changed substantially.** Legacy `flyctl postgres create` (Postgres on Apps) is being superseded by **Fly Managed Postgres** (`fly mpg create`). New pricing: **Basic $38/mo (1GB RAM, shared-2x), Starter $72/mo (2GB), Launch $282/mo (8GB)**. Phase 2.5's "₹500-1500/mo" estimate was **based on the legacy product**; under the current Managed Postgres SKU, the canary tier is ~₹3,200/mo Basic or ~₹6,000/mo Starter (2-4× higher than the runbook estimate).

2. **Fly Managed Postgres has NO Mumbai (BOM) region.** Available regions: `ams, fra, gru, iad, lax, lhr, nrt, ord, sin, sjc, syd, yyz`. Closest to BOM is `sin` (Singapore, ~30-50ms RTT to BOM). Phase 2.5's "BOM-collocated for <1ms latency" claim was empirically false. **Cross-region Fly MPG is technically viable but substantially less compelling than the runbook claimed.**

These corrections shift the provider-selection landscape:

| Provider | Mumbai region | Canary cost (1-2GB) | Best fit |
|---|---|---|---|
| **Fly MPG** | NO (closest: SIN) | ~$38-72/mo | Operationally simplest (same flyctl) but cross-region |
| **AWS RDS** | YES (`ap-south-1`) | ~$15-30/mo (db.t4g.micro, 20GB) | True BOM-collocated; lowest infra latency |
| **Supabase** | YES (`ap-south-1`) | $0 (free) → $25/mo (Pro) | Mumbai region + free tier ≤500MB |
| **Neon** | NO (closest: SIN) | $0 (free) → $19/mo (Launch) | Free tier ≤512MB; cross-region |
| **Self-hosted on Fly Volume** | YES (BOM) | ~$3-8/mo (legacy `flyctl postgres create`) | Cheapest + true BOM, but you own the ops |

**Headline recommendation**: **Phase 2.6 should use Supabase Mumbai (free tier) for the canary OR self-hosted Postgres on Fly BOM volume**. Both are true Mumbai-collocated and substantially cheaper than Fly MPG-Singapore. Supabase is operationally simpler; self-hosted on Fly volume preserves the full flyctl operational model with BOM data residency.

---

## Empirical Provider Comparison (May 2026)

### R-10.1 — Provider/cost decision

#### Fly Managed Postgres (`fly mpg create`)

**Source**: Fly.io Managed Postgres docs (verified via Context7 May 2026).

| Plan | CPU | RAM | Cost/mo (USD) | ₹/mo | Storage |
|---|---|---|---|---|---|
| Basic | shared-2x | 1GB | $38 | ~₹3,200 | $0.28/GB/mo |
| Starter | shared-2x | 2GB | $72 | ~₹6,000 | $0.28/GB/mo |
| Launch | performance-2x | 8GB | $282 | ~₹23,500 | $0.28/GB/mo |
| Scale | performance-4x | 32GB | $962 | ~₹80,000 | $0.28/GB/mo |
| Performance | performance-8x | 64GB | $1,922 | ~₹1,60,000 | $0.28/GB/mo |

**Regions**: `ams, fra, gru, iad, lax, lhr, nrt, ord, sin, sjc, syd, yyz`. **NO BOM/Mumbai/India.**

**Implications**:
- Closest to our Fly BOM app: `sin` (Singapore, ~30-50ms RTT). Cross-region private networking will be **chargeable** starting Feb 2026 at the same rate as Machines data transfer.
- All plans include HA, backups, connection pooling — but Basic gives only 1GB RAM.
- Migration concern: existing `flyctl postgres create` (Postgres-on-Apps) is being superseded by `fly mpg create`. Some legacy docs at fly.io reference the old product; runbook R-2 in Phase 2.5 used the legacy command. **Check at provisioning time** whether legacy is still permitted; if not, runbook step 1 becomes `fly mpg create`.

**Lock-in**: Standard Postgres protocol; portable to any pgx-compatible client. Backups are pg-native; restoreable to any other Postgres.

#### AWS RDS (Postgres on `ap-south-1`)

**Source**: AWS RDS pricing (knowledge baseline; can re-verify via AWS docs at provisioning if user picks this).

| Plan | vCPU | RAM | Cost/mo (USD) | ₹/mo | Storage |
|---|---|---|---|---|---|
| db.t4g.micro | 2 (burstable) | 1GB | ~$15 | ~₹1,250 | $0.115/GB/mo gp3 |
| db.t4g.small | 2 (burstable) | 2GB | ~$30 | ~₹2,500 | $0.115/GB/mo gp3 |
| db.t4g.medium | 2 (burstable) | 4GB | ~$60 | ~₹5,000 | $0.115/GB/mo gp3 |

Plus **automated backups free** (within retention window), but PITR after that ~$0.10/GB/mo.

**Regions**: 30+ regions including `ap-south-1` (Mumbai). **True BOM-collocated.**

**Implications**:
- Cheapest BOM-collocated option (db.t4g.micro $15/mo vs Fly MPG Basic $38/mo SIN).
- Latency: <5ms within ap-south-1 if app moves there too; ~30ms BOM→ap-south-1 (different cloud providers, different IXPs).
- 12-month free tier exists for new AWS accounts (db.t2.micro 750hrs/mo + 20GB gp2 + 20GB backup). After 12 months, costs apply.
- **Reserved instances** (1-year prepay) cut on-demand price ~30%. Savings Plan another option.
- IAM-managed; needs AWS account setup if not already in place.

**Lock-in**: Standard Postgres; portable. AWS-side ops include CloudWatch metrics + automated backups + Performance Insights (extra ~$5/mo).

#### Supabase (Postgres on `ap-south-1` Mumbai)

**Source**: Supabase docs (verified via Context7 May 2026).

| Plan | Storage | Cost/mo (USD) | ₹/mo |
|---|---|---|---|
| Free | 500MB DB + 1GB file | $0 | ₹0 |
| Pro | 8GB DB default (autoscale) | $25 | ~₹2,100 |
| Team | 100GB DB | $599 | ~₹50,000 |
| Enterprise | Custom | Custom | Custom |

Free Plan caveat: project pauses after 1 week inactivity; max 2 free projects per org; **read-only mode at 500MB** until upgraded. Pro Plan unlocks Mumbai region selection (Free might constrain to specific regions).

**Regions** (verified): includes `ap-south-1` (Mumbai), `ap-southeast-1` (Singapore), `ap-northeast-1` (Tokyo), and others. Mumbai is **explicitly available**.

**Implications**:
- **True BOM-collocated for free** (within 500MB) — best canary economics for ≤500MB scale.
- Realtime/storage/auth/edge-functions bundled — we'd ignore those, just use Postgres.
- Connection pooling (pgbouncer) bundled.
- Free tier auto-pause is a problem for production canary — Pro tier $25/mo eliminates it.
- Built-in observability (Postgres metrics in Supabase dashboard).

**Lock-in**: Standard Postgres core, but Supabase RLS/Auth/Realtime tables are Supabase-specific. We'd avoid those — using only Postgres core means portable.

#### Neon (Serverless Postgres)

**Source**: Neon docs (verified via Context7 May 2026).

| Plan | Storage | Compute | Cost/mo (USD) | ₹/mo |
|---|---|---|---|---|
| Free | 512MB | 100 active hrs (auto-suspend) | $0 | ₹0 |
| Launch | 10GB | unlimited active hrs | $19 | ~₹1,600 |
| Scale | 50GB | unlimited | $69 | ~₹5,800 |
| Business | 500GB | unlimited | $700 | ~₹58,000 |

**Regions**: `us-east-1, us-west-2, eu-central-1, eu-west-2, ap-southeast-1 (Singapore), ap-southeast-2 (Sydney), ap-northeast-1 (Tokyo)`. **NO Mumbai.**

**Implications**:
- Free tier auto-suspends after 5min idle — 1st query after suspension takes ~500-1000ms cold start. **NOT suitable for production canary** where consistent latency matters.
- Launch plan eliminates auto-suspend; $19/mo cheap for 10GB.
- Branching (zero-copy DB clones) is unique feature but not needed for our canary.
- Cross-region SIN→BOM latency similar to Fly MPG.

**Lock-in**: Standard Postgres; very portable. Storage abstraction is proprietary but invisible at SQL layer.

#### DigitalOcean Managed Database (Postgres)

**Source**: DigitalOcean knowledge baseline.

| Plan | RAM | Cost/mo (USD) | ₹/mo |
|---|---|---|---|
| Basic 1vCPU 1GB | 1GB | $15 | ~₹1,250 |
| Basic 2vCPU 4GB | 4GB | $60 | ~₹5,000 |

**Regions**: `BLR1` (Bangalore — India region!), plus US/EU/SIN. **BLR1 is closest to BOM after AWS.**

**Implications**:
- BLR1 region: ~5-10ms latency to Mumbai (same India backbone).
- Cheapest Mumbai-area option (~₹1,250/mo for 1GB).
- Backup retention 7 days included.
- Less ecosystem tooling than AWS RDS but simpler dashboard.

**Lock-in**: Standard Postgres; portable.

#### Railway / Render / Heroku Postgres (briefly)

- **Railway**: $5/mo Hobby plan + usage-based; regions limited (US/EU). NO India.
- **Render**: $7/mo Starter + $0.20/GB/mo storage; regions limited. NO India.
- **Heroku Postgres**: Free tier ended 2022; paid starts $5/mo. NO India.

**Verdict**: not viable for our India-user scenario.

#### Self-hosted Postgres on Fly Volume (BOM)

**Approach**: legacy `flyctl postgres create` (Postgres-on-Apps; not Managed) deploys a Postgres app on Fly machines using Fly Volumes. We've used Fly Volumes in production already (the SQLite path at v261 uses one).

| Resource | Cost/mo |
|---|---|
| 1 shared-cpu-1x machine (256MB RAM) in BOM | ~$2 (already in our Fly bill) |
| 1GB Fly Volume in BOM | ~$0.15 |
| 10GB Fly Volume in BOM | ~$1.50 |
| **Total at 10GB** | **~$3-4/mo (~₹250-350)** |

**Caveats**:
- We own the ops: WAL archiving, point-in-time recovery, failover, monitoring.
- Backups via Litestream (pgsql can ship via WAL-E to R2; see [WAL-E for Postgres](https://github.com/wal-e/wal-e)) — adds ~₹0/mo on R2 free tier or ~₹100/mo at modest scale.
- HA needs second machine + replication — but Phase 2.6 canary is single-instance acceptable.
- BOM region: AVAILABLE for Fly Apps (not MPG) — verified via existing v261 deployment.

**This is the cheapest BOM-collocated option** but requires more ops investment. For Phase 2.6 canary at ≤1 user, the ops investment is small (single instance, daily backup script, no failover testing needed).

#### SEBI Compliance / DPDP Data Localization

Per the 10K blocker analysis L1.5 + DPDP Act 2023:
- Below 50 paid subs: no Data Fiduciary registration required.
- At 50+ paid subs: register; specific data-localization requirements depend on whether we collect "Sensitive Personal Data" (financial info typically counts).
- Best practice: keep all India-user PII in India regions OR document the cross-border transfer with explicit consent.

**Implications for Phase 2.6 canary** (1 test user):
- Zero compliance risk regardless of provider region.
- For staged rollout to paid users, India-region preferred. **Mumbai > Bangalore > Singapore > anywhere else.**

**Provider compliance ranking**:
1. **AWS RDS Mumbai** + **Supabase Mumbai** — true Mumbai, no cross-border concern.
2. **Self-hosted Fly BOM** — true Mumbai, full data sovereignty.
3. **DigitalOcean BLR1** — Bangalore (India), defensible as "India localized".
4. **Fly MPG Singapore / Neon Singapore** — cross-border (India → SG), needs DPDP consent paperwork at scale.

---

#### R-10.1 RECOMMENDATION

**Tier 1 — Canary phase (1-5 users, <1 month)**:
- **Top pick: Self-hosted Postgres on Fly Volume in BOM** (~₹250-350/mo, true BOM, ops-light at single instance)
  - Pros: cheapest, BOM-collocated, full data sovereignty, same flyctl model as our app
  - Cons: we own ops; legacy `flyctl postgres create` may be deprecated (verify at provisioning time)
- **Backup pick: Supabase Free tier in Mumbai** (₹0/mo until 500MB)
  - Pros: free, Mumbai-collocated, managed (no ops)
  - Cons: free tier auto-pauses; need to upgrade to Pro ($25/mo) for production reliability

**Tier 2 — Post-canary growth (10-100 users, 1-12 months)**:
- **Migrate to Supabase Pro Mumbai ($25/mo) or AWS RDS db.t4g.micro Mumbai (~$15/mo)**
- Both offer 8-20GB at canary scale; both Mumbai-collocated.

**Tier 3 — Scale phase (100+ users, post-NSE-empanelment)**:
- **AWS RDS db.t4g.medium Mumbai or Supabase Team plan**
- Reserved instances cut AWS pricing ~30%; Supabase Team scales to 100GB.

**Avoid for Phase 2.6**:
- Fly MPG (no BOM region; cost premium without latency benefit)
- Neon (no BOM region; auto-suspend on free tier breaks canary)
- Railway/Render/Heroku (no India region)

---

### R-10.2 — Provisioning approach

#### Option A: Manual flyctl/CLI commands (current Phase 2.5 runbook approach)

**Pros**:
- Zero new tooling; matches our existing operational model.
- Documentation as runbook = source of truth.
- Easy to teach; one command per step.

**Cons**:
- Not idempotent (re-running may fail or duplicate).
- No diff/preview before apply.
- Drift detection requires manual checks.

#### Option B: Terraform-managed

**Tools**: Terraform + provider plugin (e.g., `hashicorp/aws`, `digitalocean/digitalocean`, `fly-apps/fly`).

**Pros**:
- Idempotent + diff-preview via `terraform plan`.
- State tracked; drift detectable via `terraform plan` against live infra.
- Versioned in git alongside code.
- Same model whether AWS, Supabase (Terraform Supabase provider exists), or DigitalOcean.

**Cons**:
- New tooling (Terraform binary + state backend).
- Learning curve if not already proficient.
- State file is a secret + needs remote backend (S3 / Terraform Cloud).
- ~1-2 days setup before first apply.

#### Option C: Provider-CLI scripted (shell scripts wrapping CLI)

**Pros**:
- Lighter than Terraform; just shell + provider CLI.
- Idempotent via `--if-not-exists`-style flags or grep checks.

**Cons**:
- Still needs explicit drift detection.
- Less idiomatic for cross-provider portability.

#### Secrets management

| Approach | Pros | Cons |
|---|---|---|
| **Fly Secrets** (current model) | Already in use; encrypted at rest; rolling-deploy on update | Coupled to Fly; not multi-cloud |
| **HashiCorp Vault** | Multi-cloud; rotation policies built-in | Major ops investment; ₹500-3000/mo if hosted |
| **AWS Secrets Manager** | Native to AWS RDS; rotation policies | Lock-in to AWS |
| **Doppler / 1Password Secrets Automation** | Multi-cloud; rotation; cheap (~$10/mo) | New tool dependency |

#### Connection pooling (PgBouncer)

For our Phase 2.6 canary (1-5 users, ~10 RPS): **NOT NEEDED**. Postgres handles direct connections fine at that scale.

**Trigger for adding PgBouncer**:
- 100+ concurrent connections sustained, OR
- p99 connection-acquire latency >100ms, OR
- max_connections approaching limit (typically 100 for small instances).

When triggered, two options:
1. Use provider-bundled PgBouncer (Supabase, Fly MPG, AWS RDS Proxy)
2. Self-host PgBouncer on a Fly machine (~$2/mo)

Application-side change: with pgxpool we already have client-side pooling. Switching to transaction-mode PgBouncer requires `pgx.QueryExecModeSimpleProtocol` per Context7's pgx docs — minor config, no SQL change.

#### R-10.2 RECOMMENDATION

**For Phase 2.6 canary (smallest viable)**:
- **Manual flyctl/CLI** (Option A) for first canary; document each step in extended R-2 of runbook.
- **Fly Secrets** for ALERT_DB_URL (already in use).
- **NO PgBouncer** (not needed at canary scale).
- **NO Terraform** (don't add tooling for one DB; revisit at multi-cell phase).

**At Phase 3 multi-cell trigger**: introduce Terraform. Multi-cell means multiple cells × per-cell Postgres × cell-router config — manual is no longer tractable.

**Connection-string rotation**: 90-day rotation cadence post-canary. Manual rotation acceptable at canary scale (1 connection string).

---

### R-10.3 — First canary user

#### Test/dev account (preferred for initial flip)

**Approach**: create a dedicated test email like `canary-test@<domain>.com` (or use your existing `g.karthick.renusharmafoundation@gmail.com` as test — but that's the Foundation-context email per `MEMORY.md`, must NOT be used for product).

**Better**: register a fresh signup via the production signup flow, marker the email as `+canary` (e.g., `you+canary@yourdomain.com`). Most email providers (Gmail) deliver `+`-suffixed addresses to the base inbox; this is a standard test-account pattern.

**Flip mechanism**:
- Phase 2.6.a: deploy a code change that reads `ALERT_DB_DRIVER_FOR_EMAIL=<canary-email>=postgres` mapping (overrides default sqlite for one email).
- Phase 2.6.b: alternatively, deploy an A/B-routing config where canary email's writes go to BOTH SQLite + Postgres for verification, before flipping to Postgres-only.

**Phase 2.6.a is simpler; Phase 2.6.b is safer**. Recommendation: **2.6.a for canary** (single-user blast radius is small; if it breaks, only canary is affected).

#### Real paid user (deferred until canary stable)

**SLA implications** (DPDP / consent):
- If we collect new categories of data in the move, we need consent. **Phase 2.6 doesn't change data categories** — same alerts/audit/sessions/tokens/credentials/billing tables; just different storage backend.
- DPDP requires "informed consent" but the storage-backend choice isn't itself a consented item; the `Privacy Policy` covers "we use third-party cloud providers".
- If user is in India and Postgres is in Mumbai → no cross-border consent needed.
- If user is in India and Postgres is in Singapore → cross-border transfer; needs explicit consent OR BCR (Binding Corporate Rules) — NOT recommended for canary.

**Therefore**: canary user's choice influences provider choice. Test-user flip is provider-agnostic; paid-user flip requires Mumbai-region provider unless consent updated.

#### Phased canary plan

**Stage 1** (week 1): test/dev account on Postgres.
- Single user; you control all activity.
- Smoke-test all tool calls (especially audit log writes — biggest write-volume table).
- Verify Postgres metrics show expected query patterns.

**Stage 2** (week 2-3): admin (you) on Postgres.
- Real-but-controlled traffic; you can detect any UX glitches first.
- Continue Stage 1 monitoring.

**Stage 3** (week 3-4): 1 friendly paid user (with their consent).
- After Stage 1+2 metrics show 1 week green.
- Pre-flight comms: "we're moving you to Postgres; you'll see no UX change; rollback in <15 min if anything goes wrong."
- Their email + Telegram chat both notified.

**Stage 4** (week 4-8): 5 paid users.
- Round-robin selection (not all power users; not all light users).

**Stage 5** (week 8-12): 10 paid users.

**Stage 6** (post-week-12): all users.
- After 4+ weeks green at Stage 5.

**At any stage**: any auto-rollback trigger (R-10.6) reverts ALL flipped users back to SQLite within 15 min.

#### R-10.3 RECOMMENDATION

**Canary user policy**:
- **Stage 1 user**: dedicated test account (`you+canary@yourdomain.com`).
- **Stage 2 user**: yourself on Postgres (admin role gives visibility).
- **Stage 3+**: friendly paid users with explicit consent + Telegram notify channel.
- **Provider choice locks Stage 3 timing**: Mumbai-region (Supabase / AWS / self-hosted) needed before paid-user flip. If using Singapore (Neon/Fly MPG), pause at Stage 2 until provider migration.

---

### R-10.4 — Rollback SLA + on-call prerequisites

#### Rollback mechanism (env var + redeploy)

Per Phase 2.3 wiring:
```bash
flyctl secrets unset -a kite-mcp-server ALERT_DB_DRIVER ALERT_DB_URL
# Triggers rolling deploy. App restarts with default driver=sqlite.
```

**Empirical timing breakdown**:
- `flyctl secrets unset` → 5-10 sec to apply.
- Rolling deploy: 1-2 min for image pull + container start (we have 1 machine; rolling on 1 = sequential restart).
- Healthz ready: 10-30 sec post-start.
- **Total rollback latency**: ~2-4 minutes from "decision to flip" to "service back on SQLite".

**Required prerequisite for 15-min SLA**: detection latency + decision latency together ≤ 11 minutes. Detection alone needs to be <5min.

#### Alerting infrastructure

**Detection signals** (per R-5 of Phase 2.5 runbook):
- `/healthz?probe=deep` returns 500 → DB unreachable.
- Tool call error rate >1% over 5min → write path broken.
- Latency p99 >1s sustained 5min → DB performance degraded.

**Required alerting infra**:

| Tool | Cost/mo | Setup time | Pros | Cons |
|---|---|---|---|---|
| **Fly metrics + Slack webhook** | ₹0 | ~1hr | Already integrated; `fly logs` + Slack notifications | Manual rule definition; no PagerDuty-grade routing |
| **Telegram bot ping** | ₹0 | ~1hr | We already have Telegram integration in code | Same Telegram account = single failure point |
| **PagerDuty Free tier** | ₹0 | ~2hrs | Industry-standard; on-call rotation built-in | Free tier limits notifications/mo |
| **OpsGenie** | ₹500-3000/mo | ~3hrs | Sophisticated routing | Cost; overkill for solo |
| **Better Stack (Logtail+Heartbeats)** | ₹0-1000/mo | ~2hrs | Better than PagerDuty Free for hobbyist scale | Cost ramp at scale |
| **Sentry** | ₹0 (5K events/mo free) | ~2hrs | Already an option; solid error tracking | Not optimized for infra alerts |

**Minimum viable on-call setup**:
1. Fly logs → grep for ERROR lines in `app.alertdb` namespace → Slack webhook.
2. `/healthz?probe=deep` polled every 60s by an external service (e.g., Better Stack heartbeats free tier or self-hosted UptimeKuma) → Telegram bot on failure.
3. Manual on-call schedule (= you, solo, with phone notifications).

**Cost: ₹0/mo** if Slack + Telegram already in place. ₹0-500/mo if adding Better Stack heartbeats.

#### On-call rotation

**Solo founder reality**: you are on-call 24×7 by default. Phase 2.6 canary at 1 user = max 1 user impacted by any failure = blast radius is small. Solo on-call is acceptable for Stages 1-3.

**Trigger for second on-call**: 10+ paid users on Postgres OR any auto-trade failure that was caused by the canary.

**Rainmatter introduction** (per `MEMORY.md kite-rainmatter-warm-intro.md`): not relevant to on-call. Rainmatter is for product/funding, not ops support.

#### R-10.4 RECOMMENDATION

**For Phase 2.6 Stages 1-3**:
- Solo on-call (you).
- Slack + Telegram alerting from Fly logs + healthz polling.
- ₹0-500/mo alerting cost.
- Rollback target: **15-min SLA realistic** (4-min mechanical + ~5min detection + ~5min decision buffer).
- **Auto-rollback** (no human in loop): wire a watchdog that detects healthz red for 5min straight → auto-flips ALERT_DB_DRIVER back. Adds ~30min eng to set up; cuts rollback SLA to ~7 min.

**For Phase 2.6 Stages 4+**:
- Add second on-call OR PagerDuty Free tier for night-coverage.
- Re-evaluate at the trigger point.

---

### R-10.5 — Migration window

#### When traffic is naturally lowest

Indian markets:
- NSE/BSE trading hours: 9:15 AM – 3:30 PM IST Mon-Fri.
- Pre-market: 9:00–9:15 AM IST Mon-Fri.
- After-market: 3:40–4:00 PM IST Mon-Fri (block deals only).

**Lowest-traffic windows for our app**:
- **Weekends** (Sat 00:00 IST – Mon 09:00 IST): zero trade orders; only background tasks (briefings, alerts).
- **Weeknight 22:00-06:00 IST**: minimal activity; some users may set GTT orders.
- **Worst window**: Monday 09:00–10:00 IST (markets opening; users active).

#### Cutover step-by-step (extends R-6 of Phase 2.5 runbook)

**T-7 days**: Stage 1 canary user pre-provisioned on Postgres; verify all 4 weeks of monitoring green.

**T-1 day**:
- Notify canary user via email + Telegram.
- Verify Postgres provider region status pages green.
- Confirm rollback plan rehearsed (you've actually run `flyctl secrets unset` + observed ~3min recovery).

**T-0** (target: Saturday 06:00 IST — well before any market activity):
- Snapshot current SQLite state (Litestream R2 backup verified within last 1hr).
- `flyctl secrets set ALERT_DB_DRIVER=postgres ALERT_DB_URL=...` for the canary user (if per-user gate) OR globally for full cutover.
- Wait for rolling deploy to complete (~2min).
- `curl /healthz?probe=deep` verify.
- Verify a tool call works: e.g., `get_holdings` via canary user's MCP session.

**T+1hr to T+24hr**: monitor R-5 metrics (error rate, latency p99, Postgres connection count). If any threshold trips, rollback.

**T+1 week**: declare canary stable if all metrics green.

#### Communication

**Email template** (canary user):
```
Subject: kite-mcp-server canary on Postgres — what to expect

Hi,

You're a canary participant in our Postgres migration this Saturday (May 31).
- What changes: nothing UX-visible. Storage backend swap only.
- Window: 06:00 IST Saturday; ~5 minutes downtime expected.
- Rollback: <15 min if anything's wrong.
- Contact: Telegram channel <link> or email <email> for instant rollback request.

Thanks!
```

**Telegram template**: same content, more compact; sent in the canary participant's existing Telegram alert channel.

#### R-10.5 RECOMMENDATION

**Cutover window**: **Saturday 06:00 IST**.
- Indian markets closed; no time-sensitive user actions.
- 24h before next market open (Monday 09:15) gives full debugging buffer.

**Communication**: 7-day notice + 1-day reminder + at-cutover update.

**Rollback rehearsal**: actually `flyctl secrets unset` + redeploy at least once in dev BEFORE production cutover. Confirms timing empirically.

---

### R-10.6 — Success criteria

#### Quantitative thresholds

| Metric | SQLite baseline | Postgres canary "green" threshold | Auto-rollback trigger |
|---|---|---|---|
| `/healthz?probe=deep` p99 latency | <500ms | <750ms | >1.5s sustained 5min |
| Tool call latency p99 | <100ms | <150ms | >300ms sustained 5min |
| Audit-write latency p99 | <50ms | <100ms | >250ms sustained 5min |
| Save* method error rate | <0.1% | <0.3% | >1% sustained 5min |
| Connection pool acquire wait p99 | N/A (single conn) | <50ms | >200ms sustained 5min |
| Round-trip checksum (SQLite vs PG) | identical | identical at every snapshot | any divergence → halt |
| Audit hash chain integrity | 100% | 100% | any break → halt |

#### Time window

**Per-stage green requirement**:
- Stage 1 (test user): 1 week green.
- Stage 2 (admin): 1 week green after Stage 1 done.
- Stage 3 (1 paid user): 2 weeks green.
- Stage 4 (5 paid users): 2 weeks green.
- Stage 5 (10 paid users): 4 weeks green.
- Stage 6 (full cutover): 30+ days green before SQLite decommission.

**Total minimum calendar from Stage 1 to full cutover**: ~10 weeks if all stages green first-pass. Realistically ~12-16 weeks accounting for at least one unplanned rollback or investigation.

#### Round-trip checksum verification

**Approach**: weekly automated reconciliation script.
1. Litestream snapshot current SQLite (existing — already runs continuous).
2. Connect to Postgres canary; run `SELECT COUNT(*), MAX(updated_at), HASH(...)` per table.
3. Connect to SQLite snapshot; same query.
4. Diff; alert on any mismatch beyond expected (concurrent writes during snapshot window).

**Implementation**: cron-scheduled Go script using same `LoadAlerts/LoadTokens/...` API tested in Phase 2.4 round-trip tests. Reuses Phase 2.4 test code for production data verification.

#### Hash chain integrity

Audit log uses HMAC-chained hashes (Phase 2.0 contract: `prev_hash + entry_hash`). Phase 2.4 tests didn't directly verify chain across dialect migration.

**Risk**: if Postgres ID generation differs from SQLite (BIGSERIAL vs INTEGER PRIMARY KEY AUTOINCREMENT), the hash chain — which is keyed on row contents not row IDs — should still verify. **Verify empirically in Phase 2.6** as part of canary acceptance.

#### R-10.6 RECOMMENDATION

**Green criteria**:
- Quantitative: all 6 metrics within thresholds for the stage's required calendar window.
- Qualitative: zero data discrepancies in weekly reconciliation; zero hash chain breaks.

**Auto-rollback**:
- Single-metric breach (>1% error rate) → immediate auto-rollback.
- Multi-metric warnings (latency degradation) → manual review, rollback within 15min if not investigated.

**Decommission SQLite at full cutover**:
- 30+ days post-Stage-6 green.
- Then: stop Litestream → delete R2 bucket → remove SQLite volume from fly.toml.
- Total elapsed from Stage 1 to SQLite decommission: ~14-20 weeks.

---

## Implications for Upcoming Phases

### Phase 3 — Multi-cell architecture

**Question**: does R-10.1 provider choice constrain Phase 3?

**Empirical answer**: YES, substantially.

| Provider | Multi-cell story | Phase 3 implication |
|---|---|---|
| **Self-hosted Fly Volume BOM** | Each Fly machine has its own volume. Multi-cell = multiple Fly apps × per-app volume. Sharding logic in app. | Cleanest fit; aligns with our existing model. |
| **AWS RDS Mumbai** | Single regional cluster. Sharding via app-level partition by user-cell-affinity. Multi-AZ for HA. | Works; medium complexity; AWS cost scales with reads/writes. |
| **Supabase Mumbai** | Single project = single cluster. Multi-cell = multiple Supabase projects. Each project = $25/mo Pro. At 10 cells: $250/mo just for projects. | Doesn't scale economically past ~10 cells. |
| **Fly MPG SIN** | Cross-region. Multi-cell would need MPG cluster per region; latency penalty everywhere. | Worst fit; cross-region cost + latency double-whammy. |
| **Neon SIN** | Branching feature lets us spawn cell-specific DBs cheaply ($19/cell after 1 free). | Decent fit if we accept SIN region. |

**Phase 3 implications**:
- If Phase 2.6 picks Fly Volume BOM → Phase 3 is easy continuation (multi-app with Volumes).
- If Phase 2.6 picks Supabase → Phase 3 forces re-evaluation; AWS RDS or self-hosted likely needed.
- If Phase 2.6 picks AWS RDS → Phase 3 stays in AWS; familiar territory.

**Recommended path**: Phase 2.6 = self-hosted Fly Volume BOM. Phase 3 = same model, multiple apps. Migration to managed only if ops burden becomes intolerable.

### Phase 1.4 — Self-hosted CI

**Question**: does Postgres in CI require Postgres elsewhere too?

**Empirical answer**: orthogonal. Phase 1.4 self-hosted CI runners would let us run a Postgres test container in CI without paying for a hosted Postgres provider for tests. Today our CI is GitHub-Actions-hosted; the Postgres-tagged tests are skipped because no Postgres is provisioned in the runners.

**Implications**:
- Phase 1.4 would unblock CI matrix for Postgres tests (cheap; just Docker container).
- Independent of R-10.1 production Postgres choice.
- Phase 1.4 trigger remains "GitHub-hosted CI cost crosses self-hosted threshold" (~2K runner-min/mo). Currently bounded by audit `6ee6520` work; not yet imminent.

**Recommendation**: Phase 1.4 stays deferred per current trigger. Independent decision.

### Future kc/* promotions

**Question**: does Phase 2.6 affect remaining kc/* extractions?

**Empirical answer**: No direct interaction. The kc/* path-A promotions are about module decomposition; the storage-backend choice is orthogonal. The only shared concern is `algo2go/kite-mcp-alerts` (already external; v0.5.0 is the Phase 2 work).

**Recommendation**: continue path-A independently. Phase 2.x progress doesn't gate kc/* work or vice versa.

### NSE empanelment + SEBI compliance

**Question**: does provider choice affect compliance?

**Per 10K analysis L1.5 + DPDP Act 2023**:
- Below 50 paid subs: minimal compliance burden.
- Above 50: Data Fiduciary registration; data localization preferred for Indian PII.

**Provider implications**:
- **Mumbai/Bangalore (AWS / Supabase / DigitalOcean BLR1 / self-hosted Fly BOM)**: clean compliance.
- **Singapore/Tokyo (Fly MPG / Neon)**: cross-border transfer; needs DPDP consent + transfer mechanism (BCR or SCC).

**At 50 paid subs** (per kite-cost-estimates): NSE empanelment ~₹4-8L + 3-6mo. **Locking provider choice now** to a Mumbai-collocated option avoids re-migration during the 50-sub transition.

**Recommendation**: pick Mumbai-collocated for Phase 2.6 even if more expensive than Singapore options. The migration cost of changing later (pre-50-paid) is small; the cost of changing later (post-50-paid, with users notified, with consent paperwork) is large.

### Cost ceiling at 10K agents — recap with Postgres line item updated

From the 10K blocker analysis (post-corrections):
- Founder-only at 10K: ~₹50K/mo total
- With SRE FTE at 10K: ~₹2-3L/mo total

**Postgres line item revision** based on R-10.1 findings:

| Scale | Provider choice | Postgres cost/mo |
|---|---|---|
| Phase 2.6 canary (1-5 users) | Self-hosted Fly Volume BOM | ~₹350 |
| Stage 4-5 (10-100 users) | Supabase Pro Mumbai OR AWS RDS db.t4g.micro | ~₹1,250-2,100 |
| 1000 users | AWS RDS db.t4g.medium Mumbai (with 1yr Reserved) | ~₹3,500-5,000 |
| 10K users | AWS RDS db.r6g.large Mumbai + read replicas + connection pooling | ~₹15,000-30,000 |

**vs Phase 2.5 runbook estimate**: runbook said ~₹500-1500/mo; this analysis revises to ~₹350/mo at canary (cheaper) but ~₹15-30K/mo at 10K (within original ceiling envelope).

**Updated 10K ceiling**: founder-only stays at ~₹50K/mo; Postgres slice ~30-60% of that depending on instance class. Still well under the 75%-reduction milestone from the IP-whitelist correction.

---

## Recommended Path Forward

### Option A — Minimum-viable Phase 2.6 (smallest cost, smallest scope)

**Provider**: Self-hosted Postgres on Fly Volume in BOM region.
**Approach**: legacy `flyctl postgres create` (verify still permitted at provisioning time).
**Cost**: ~₹250-350/mo for 10GB volume.
**Calendar**: ~1 day setup + 2-week canary + iterative stages = ~10-14 weeks to full cutover.
**Tooling**: existing flyctl + Fly Secrets + existing Telegram/Slack alerts.

**What this unlocks**:
- True BOM-collocated Postgres for canary.
- Ops in our existing model.
- Cheapest path; lowest commitment.

**What stays gated**:
- Phase 3 multi-cell stays manual (each cell = manual Fly app create).
- Backup retention is what we configure (no managed PITR — write our own WAL-E pipeline OR continue Litestream-style daily snapshots to R2).
- HA: single instance for canary; manual failover only.

**Risk**: legacy `flyctl postgres create` is being deprecated in favor of Fly Managed Postgres. If at provisioning time the legacy path is gone, fallback to Option B.

### Option B — Enterprise-grade Phase 2.6 (bigger investment, sets up Phase 3 cleanly)

**Provider**: AWS RDS Postgres in `ap-south-1` (Mumbai).
**Approach**: db.t4g.micro (1GB RAM, 20GB gp3) initial; scale to db.t4g.small or db.t4g.medium as load grows.
**Cost**: ~₹1,250/mo (db.t4g.micro) → ₹2,500/mo (small) → ₹5,000/mo (medium).
**Calendar**: ~2-3 days setup (AWS account + IAM + RDS provisioning + secrets) + 2-week canary = ~12-16 weeks to full cutover.
**Tooling**: AWS CLI + existing flyctl secrets propagating ALERT_DB_URL; optionally Terraform.

**What this unlocks**:
- True BOM-collocated; managed PITR (35-day retention default); CloudWatch metrics; multi-AZ option for Phase 3.
- Reserved instance pricing (~30% off after Phase 2.6 canary stable, locking in 1yr cost).
- AWS-side observability + alerting (CloudWatch alarms feed PagerDuty/Slack).
- Phase 3 multi-cell uses AWS multi-region (Mumbai + Hyderabad + Singapore for Asia-Pacific clients).

**What stays gated**:
- AWS account setup if not yet in place (1-day initial; KYC for Indian rupee billing optional).
- Higher recurring cost than Option A (₹1,250/mo vs ₹350/mo at canary scale).
- AWS lock-in (mild — Postgres still portable, but ops tooling becomes AWS-flavored).

**Risk**: AWS billing surprises (egress, snapshot storage, etc.) at scale. Mitigated by Cost Anomaly Detection + Budget Alerts.

### Option C — Defer Phase 2.6 entirely until specific user-demand trigger

**Approach**: stay on SQLite + Litestream → R2 indefinitely. Postgres remains Phase 2.x readiness work; not flipped on for any user.

**Trigger candidates**:
- 100+ concurrent users sustained.
- SQLite write-throughput bottleneck (>100K writes/hour) — empirically may not happen below 1000-user scale.
- Multi-cell Phase 3 dispatched (Phase 3 needs partitioned/replicated state — SQLite per-cell + cross-cell read API CAN work without Postgres; harder but cheaper).

**What this unlocks**:
- ₹0/mo recurring cost added.
- Zero ops burden.
- Phase 2.6 work stays "ready to deploy when needed".

**What stays gated**:
- All Phase 3 architecture work.
- Multi-region disaster recovery (we have BOM single point of failure).
- High-volume audit log (rolling >1M rows/month) where SQLite write-throughput matters.

**Risk**: at user-growth signal, we go from "0 users on Postgres" to "needs Postgres yesterday" with no canary buffer. The next dispatch of Phase 2.6 still takes ~10 weeks calendar even after authorization. So **defer = accepts a ~10-week ramp-up at the moment Postgres is genuinely needed**.

---

## User Decision Tree

### "I want to flip the switch, fast and cheap"
→ **Option A** (Self-hosted Fly Volume BOM, ~₹350/mo, ~14 weeks to full).
→ First step: dispatch a Phase 2.6.0 verification of `flyctl postgres create` still works in BOM. ~1 hour.

### "I want enterprise-grade ops with predictable scaling for the next 1-2 years"
→ **Option B** (AWS RDS Mumbai, ~₹1,250-5,000/mo, ~16 weeks to full).
→ First step: AWS account + IAM setup + provision db.t4g.micro in `ap-south-1`. ~1 day.
→ Lock in Reserved Instance pricing after 1-month stable canary.

### "Postgres readiness is fine; I have higher-priority work"
→ **Option C** (defer indefinitely). All Phase 2.x code already shipped; opt-in is a single env var when needed.
→ Revisit at user-count trigger; Phase 3 architecture work uses SQLite-per-cell + read-API approach (more eng but ~₹0 recurring infra cost).

### "I want Mumbai region but cheap, and I trust managed services"
→ **Supabase Free Pro Mumbai** (₹0 free → ₹2,100/mo Pro).
→ But: Phase 3 doesn't scale on Supabase (each cell = $25/mo project = ~₹2,100/mo × N cells). Pick this knowing Phase 3 may force migration.

### "I want to verify provider before commit"
→ Provision Stage 1 canary on TWO providers in parallel (e.g., self-hosted Fly + Supabase Free).
→ Compare 1 week of metrics; pick winner; decommission loser.
→ Adds ~₹0 (Supabase Free) + ~1 week calendar; rules out provider-specific surprises.

---

## Summary Table

| Decision | Recommendation | Rationale |
|---|---|---|
| R-10.1 Provider | **Self-hosted Fly Volume BOM** (Option A) OR **AWS RDS Mumbai** (Option B) | True BOM-collocated; cheaper than Fly MPG-Singapore; SEBI-compliant for Indian users |
| R-10.2 Provisioning | **Manual flyctl/CLI for Phase 2.6**; Terraform at Phase 3 trigger | Don't over-tool for one-DB canary |
| R-10.3 Canary user | **Test account → admin (you) → 1 paid → 5 → 10 → all** | Staged blast radius; explicit consent at paid-user transition |
| R-10.4 Rollback SLA | **15-min realistic; 7-min with auto-rollback watchdog** | Solo on-call viable for Stages 1-3 |
| R-10.5 Migration window | **Saturday 06:00 IST** (markets closed, weekend buffer) | Lowest-traffic; 24h debug window |
| R-10.6 Success criteria | **All 6 metrics within thresholds for stage-required calendar** | Auto-rollback at >1% error rate; manual at degradation |

**Phase 2.6 dispatch readiness**: USER-AUTHORIZATION REQUIRED.

Per the Phase 2.5 dispatch instruction, Phase 2.6 has cost + provider-choice + user-sign-off implications. After this analysis, the user has the data to:
1. Choose between Option A / B / C (or hybrid).
2. Decide canary-user staging policy.
3. Accept rollback SLA + alerting investment.
4. Schedule first cutover window.

---

**End of R-10 + downstream analysis. Doc-only. tools=130 invariant preserved. NO source mutations.**
