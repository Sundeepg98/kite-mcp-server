# Phase 2.6 — R-10 User Decision Re-Research (v5 — Strategic Synthesis)

**Date**: 2026-05-10 IST
**HEAD**: `db368a8` (this doc supersedes v4 at the same path)
**Charter**: doc-only synthesis; NO source mutations. v5 steps back from v1-v4's empirical drilling to **strategic context**: convergence analysis across all rounds, alternative architectures, and the meta-question — should Phase 2.6 even fire now?
**Builds on / supersedes**: v4 R-10 doc at `db368a8`. v5 supersedes v1→v4. Tone: synthesis over verification.

**Production state**: v262 LIVE on Fly.io BOM region; SQLite + Litestream → R2; ALERT_DB_DRIVER unset; **0 paid users**.

---

## Section 0 — TL;DR (v5)

After 5 research rounds, the decision tree has crystallized:

**The convergent recommendation across v1-v4** (most-confident pick after 4 rounds of skeptical re-examination): **EITHER stay on SQLite + Litestream → R2 indefinitely (Path 1) OR provision Turso Free tier (Path 6) as a "test the waters" zero-cost step.** Both options preserve all Phase 2.x prep work as future fallback.

**The strategic reframe**: at 0 paid users, **Phase 2.6 has no user-visible benefit**. The opportunity cost of the 12-16 weeks Phase 2.6 calendar is launch-path execution + NSE empanelment prep + feature shipping — work with much higher zero-user-state ROI than Postgres readiness. Phase 2.6 is **infrastructure investment ahead of demand**; demand isn't here yet.

**v5's primary recommendation is therefore "decide not to decide yet"**: keep Phase 2.6 ready (we already shipped the driver factory at v262), don't actually flip it. Revisit when a concrete trigger fires (50+ paid subs OR Phase 3 multi-cell dispatch OR explicit user demand).

**If user wants to validate the architecture path empirically**: Path E (Try-Before-Buy) — sign up Turso Free + DO BLR1 trial in parallel for 1 week, spend ~$5, gather real-world data. Lower-effort than Phase 2.6 dispatch; resolves "is libSQL enough OR do I need Postgres" empirically.

---

## Section 1 — Convergence Analysis Across v1-v5

### 1.1 What stayed STABLE across all 5 rounds

These are the most-confident conclusions because they survived 4 rounds of skeptical re-examination:

| Conclusion | v1 | v2 | v3 | v4 | v5 | Confidence |
|---|---|---|---|---|---|---|
| Mumbai region preferred for India users | ✓ | ✓ | ✓ | ✓ | ✓ | HIGHEST |
| Saturday 06:00 IST cutover window | ✓ | ✓ | ✓ | ✓ | ✓ | HIGHEST |
| 12-16 week canary calendar | ✓ | ✓ | ✓ | ✓ | ✓ | HIGHEST |
| 6 quantitative success thresholds | ✓ | ✓ | ✓ | ✓ | ✓ | HIGHEST |
| Auto-rollback watchdog as force multiplier | ✓ | ✓ | ✓ | ✓ | ✓ | HIGHEST |
| At canary scale, all R-10 decisions reversible cheaply | – | ✓ | ✓ | ✓ | ✓ | HIGH |
| Decision irreversibility ranking: R-10.1 hardest | – | ✓ | ✓ | ✓ | ✓ | HIGH |
| Path 1 (Defer) is defensible until trigger | ✓ | ✓ | ✓ | ✓ | ✓ | HIGH |

**The 5-round survivors are the load-bearing conclusions.** If user disagrees with ANY of these, restart conversation; otherwise treat as locked-in.

### 1.2 What CHANGED between rounds (and why)

These are the conclusions that flipped or sharpened — useful to track because they reveal what's still uncertain:

| Conclusion | v1 → v2 → v3 → v4 → v5 | Why it changed |
|---|---|---|
| Top recommendation | Self-host Fly → Self-host Fly → DO BLR1 → DO BLR1 OR Turso → "Don't decide yet" | New empirical data each round (DO BLR1 surfaced in v2, Turso in v3, web-verified prices in v4, strategic context in v5) |
| Self-host loaded cost | ₹350/mo → ₹7-30K/mo (loaded) → ₹350/mo + 1.5-2 hrs/mo → ₹350/mo + ops | v2 inflated via unjustified opportunity-cost multiplier; v3 corrected; v4-v5 stable |
| Indian fintech precedents | "Razorpay = Aurora-Postgres" → same → REMOVED (unverifiable) → REMOVED → **CORRECTED**: Razorpay actually uses MySQL (web-verified v5) | v3 honestly removed; v5 web-search found the truth |
| Indian-domestic providers | "Out of scope" → "Out of scope" → "Out of scope" → Yotta SutraDB ₹1,897.50/core (verified) → SAME | v4 web-fetched Yotta pricing concretely |
| SEBI cloud framework applicability | "SEBI mandates India region" → SAME → "Can't verify circular" → "Algo vendors are AGENTS not REs" → SAME | v3 honestly downgraded; v4 web-fetched circular text |
| Number of "viable paths" | 3 → 5+2 hybrids → 5+3 hybrids → 8+3 hybrids → 8+4 (Path 9 rqlite added) | More research surfaced more options |

**v5 lesson from convergence**: more research rounds added options without changing the core recommendation. Diminishing returns are real.

### 1.3 What v1-v4 missed that v5 surfaces

**v1-v4 anchor on "Postgres OR SQLite-compat at canary scale"**. v5 adds:
- **Path 9 — rqlite** (Raft-replicated SQLite, single binary): production-proven, fault-tolerant, deployable as 3-node cluster on existing Fly machines. Trades write performance for HA. Could be Phase 3 multi-cell foundation.
- **Path 10 — Cloudflare D1** (managed SQLite-compat at edge): per-tenant isolation, ~500-2K writes/sec ceiling, 10GB cap per database. **Fits our pattern** since we're <1K writes/day at canary.
- **Path 11 — Litestream-only optimization** (current path with provider variations): R2 (free egress; current) vs Tigris (Fly-native, geo-distributed) vs Backblaze B2 ($0.01/GB egress). All work; switch is config-only.

**The empirical correction v5 makes**: **Razorpay uses MySQL, not Aurora-Postgres**. v1-v3 cited "Razorpay = Aurora-Postgres" as knowledge baseline; v3 honestly removed it; v5 web-verified the correction. Razorpay's actual stack: MySQL primary + TimescaleDB for analytics + Kubernetes-deployed.

---

## Section 2 — Strategic Context: Should Phase 2.6 Even Fire Now?

### 2.1 The honest cost-benefit at 0 paid users

| Phase 2.6 cost | Estimate | Source |
|---|---|---|
| Provider canary cost | $5-20/mo | v4-verified (Path 6 Free–Path 2 $15) |
| Calendar | 12-16 weeks (Stage 1 → full cutover) | v1-v4 stable |
| Engineering time | 1-2 days per stage × 6 stages = ~12 engineer-days | v4-extrapolated |
| Risk surface | Each stage has rollback path; auto-rollback watchdog mitigates | v1-v4 stable |
| Cognitive overhead | Monitoring 2 backends in parallel for 12-16 wks | qualitative |

| Phase 2.6 benefit at 0 paid users | Estimate |
|---|---|
| User-visible latency improvement | None (SQLite local is faster than any network DB) |
| User-visible feature unlock | None (all features work on SQLite today) |
| Compliance posture improvement | None (we're not an RE per SEBI cloud circular per v4 finding) |
| Disaster recovery | Marginal (Litestream → R2 already works) |
| Phase 3 multi-cell readiness | Yes — but Phase 3 itself isn't dispatched |
| Future-proofing | Yes — but optionality value depends on Phase 3 timing |

**Net at 0 paid users**: Phase 2.6 is pure infrastructure investment ahead of demand. The "user-visible benefit" column is empty.

### 2.2 Opportunity cost of 12-16 weeks

What ELSE could happen in the same calendar?

| Alternative | Calendar | User-visible benefit |
|---|---|---|
| **Launch path execution** (per `MEMORY.md kite-launch-blockers-apr18.md`) | 4-8 weeks | High — gets first paid users |
| **NSE empanelment prep** (per `kite-cost-estimates.md`) | 3-6 months calendar; ₹4-8L | High at 30+ paid sub trigger |
| **Phase 3 multi-cell architecture** (research first) | 4-6 weeks design | Strategic — unblocks 1K+ user trajectory |
| **More features** (per `kite-trade.md`) | continuous | Variable; depends on which feature |
| **Audit log + observability hardening** | 2-4 weeks | Operational — helps when paid users arrive |
| **Path A continuation** (more module promotions) | continuous | Modest — code-org improvement, no user-visible |

**Honest take**: at 0 paid users, **launch path execution > Phase 2.6**. NSE empanelment prep also outranks Phase 2.6 because it has a 3-6 month regulatory calendar that runs concurrently with engineering, whereas Phase 2.6 needs concentrated engineering attention.

**v5 recommendation**: **defer Phase 2.6** until either:
1. **50+ paid users** (NSE empanelment trigger; provider choice now matters for compliance)
2. **Phase 3 multi-cell dispatch** (architectural prerequisite)
3. **SQLite write-throughput becomes a real bottleneck** (empirical signal, not anticipated)

Until any of those triggers fires, **the right thing is to KEEP Phase 2.6 ready** (which we DID — Phase 2.0-2.5 driver factory shipped at v262) and **don't flip it yet**.

### 2.3 Three-tier strategic timeline

| Now (0 paid users) | Trigger fires | Post-trigger |
|---|---|---|
| Path 1 (Defer) | 50+ paid users OR Phase 3 OR write bottleneck | Phase 2.6 dispatch (which option?) |
| Phase 2.x ALREADY READY | + at trigger time, ALSO research v6 with current state | + canary stages 1-6 |
| Cost: ₹0 added | Cost: $5-25/mo + 12-16 wks calendar | + may switch provider mid-rollout |

**v5 nuance**: by the time the trigger fires, the provider landscape will have changed. Doing Phase 2.6 now locks us in to today's provider; deferring lets us pick at-trigger-time with then-current data.

---

## Section 3 — Cost-of-Being-Wrong Sensitivity Analysis

What's the actual cost if each R-10 decision is wrong?

### R-10.1 — Provider choice wrong

| Scenario | Cost if wrong |
|---|---|
| Pick DO BLR1, want AWS RDS later | 1-2 weeks + ~$5K of canary data migrated. **Low.** |
| Pick Turso, want Postgres later | 4-6 weeks + protocol-level rework. **Medium.** |
| Pick Yotta, want managed-cloud later | 1-2 weeks + sales-conversation termination. **Low-medium.** |
| Pick Self-host, become enterprise customer demanding managed | 1 week migration + lots of "why" docs. **Low.** |

**Probability of switching**: at canary (1-5 users), low (we're small enough to absorb whatever we pick). At 100+ users, switching is real engineering work. At 1K+ users, switching is multi-month. **The "wrong now" cost is small; the "wrong at scale" cost is large — but we don't reach scale without first crossing the trigger thresholds, where we'd revisit anyway.**

### R-10.4 — Rollback SLA wrong

If our rollback mechanism doesn't work as designed:
- **One incident worth of downtime** = ~3-4 minutes per `flyctl secrets unset` cycle
- **Lost writes during that window** = at canary 1-5 users, ~0-5 transactions
- **Reputation cost** = small (1-5 canary users = controlled blast radius)

**Cost-of-wrong R-10.4 = ~₹0** at canary. Becomes meaningful at 100+ paid users.

### R-10.2 — Provisioning approach wrong

Manual flyctl now → Terraform later: 1-2 days conversion. **~₹0 cost-of-being-wrong.**

### R-10.3 / R-10.5 / R-10.6 — Policy/scheduling/criteria wrong

All iterative; cost-of-being-wrong is "we adjust next stage". **~₹0.**

### Sensitivity ranking (highest cost-of-wrong first)

1. **R-10.1 Provider** (medium-high if Turso↔Postgres path mismatch; low otherwise)
2. **R-10.4 Rollback SLA** (low at canary; high at scale — but we're at canary)
3. R-10.2-3-5-6 (all near-zero cost-of-wrong)

**Implication**: spending more research effort on R-10.1 makes sense; it's the only decision where being wrong costs real money/time. Everything else is iterative.

---

## Section 4 — Alternative Architectures NOT in v1-v4

v1-v4 anchored on "Postgres at managed providers OR keep SQLite". v5 surfaces three more options:

### Path 9 — rqlite (Raft-replicated SQLite)

**What it is**: open-source distributed SQLite using Raft consensus. Single self-contained Go binary; deploy 3 nodes for HA.

**Source verified**: rqlite.io docs + GitHub.

**Why it might fit us**:
- **SQLite-compatible**: zero migration from current stack.
- **HA built-in via Raft**: no Litestream, no PITR-via-snapshots needed.
- **Single-binary deploy on Fly machines**: ~3 instances × $2/mo = $6/mo total.
- **Fault-tolerant**: any node can fail without taking DB offline.

**Why it might NOT fit us**:
- **Reduced write performance** (Raft round-trips) — but at our <1K writes/day load, irrelevant.
- **Smaller ecosystem than Postgres or even Turso** — fewer Stack Overflow answers.
- **Not as "managed"** — we own all upgrades, monitoring, etc.

**Cost**: ~$6/mo infrastructure (3 Fly machines BOM region). Ops time similar to self-host Fly Volume but with HA.

**v5 status**: legitimate Path 9 if user wants HA without managed-service vendor lock-in. **Could be Phase 3 multi-cell foundation — each cell = 3-node rqlite cluster.**

### Path 10 — Cloudflare D1 (managed SQLite-compat at edge)

**Source verified**: developers.cloudflare.com + InfoQ.

**Specs**:
- 10GB max per database (hard cap; manual sharding for more)
- ~500-2K writes/sec ceiling (vs 10K-50K for local SQLite WAL)
- Per-database isolation (no extra cost per database)
- Edge-distributed (low read latency globally)

**Fit for us**: at <1K writes/day canary, we're 1000x under D1's write ceiling. Per-database isolation could be Phase 3 multi-cell pattern (one D1 per cell or per user). 10GB cap is fine for 5+ years of user data growth at our pattern.

**Why NOT a fit**: Cloudflare lock-in (D1 is CF-Workers-native; running our Go app on Fly + D1 on CF means cross-vendor architecture). India region: D1 doesn't have an explicit Mumbai DC but CF's edge is globally distributed (low latency from anywhere India).

**v5 status**: niche fit. Mentioned for completeness; not a primary recommendation.

### Path 11 — Litestream provider variations (within current SQLite path)

**Source verified**: litestream.io/alternatives.

Current state: SQLite + Litestream → R2 (Cloudflare R2 free egress).

Alternatives if R2 ever fails:
- **Tigris** (Fly.io-native, S3-compatible, geo-distributed CDN-like caching)
- **Backblaze B2** ($0.01/GB egress; cheapest paid option)
- **AWS S3** (most expensive; works fine with Litestream)
- **Self-hosted MinIO** (free; we own ops)

**Cost**: R2 free tier handles our backup volume; alternatives all <$5/mo at our scale.

**v5 status**: not really a "Path" — it's variations within Path 1. Mentioned because if user wants disaster-recovery improvement WITHOUT moving to Postgres, switching backup target is easier than switching DB.

### Path 12 — DuckDB analytics + SQLite OLTP split

**Verified via Context7**: DuckDB is in-process analytical (OLAP), not transactional (OLTP).

**Why this DOESN'T fit us**: our workload is 100% OLTP (small writes, point-lookup reads). DuckDB excels at large analytical queries over columnar data. **Wrong tool for our pattern.**

**v5 status**: not recommended. Mentioned because the user asked.

---

## Section 5 — Real Fintech Database Patterns (v5 Web-Verified)

v3 honestly removed the Indian fintech precedents section because v3 couldn't verify via Context7. v5 retried via WebSearch; here's what verified:

### Razorpay
- **Primary database: MySQL** (NOT Aurora-Postgres as v1-v3 hearsay claimed)
- **Analytics: TimescaleDB** (Postgres + timeseries extension)
- **Infrastructure**: Kubernetes-deployed across all components
- **Source**: Razorpay engineering blog at razorpay.com/blog/data-classification-real-time-highway/

**v5 correction to v1-v3**: the "Razorpay uses Aurora-Postgres" claim was wrong. They're MySQL-primary. **This means our anchoring on Postgres because "that's what fintech does" was based on misinformation.**

### Groww
- Mentioned indirectly via cockroachlabs.com customer references; specific RDBMS choice not surfaced
- Likely AWS-based (general Indian fintech pattern) but specific DB engine NOT verified

### Stripe / Revolut / Nubank
- Use Postgres extensively per enterprisedb.com + cockroachlabs blogs
- ACID transactions for money safety
- These are at scale (millions of users); not directly comparable to canary

### Form3 (UK fintech, similar pattern to us)
- Started on AWS RDS PostgreSQL
- Migrated to CockroachDB at scale
- Source: cockroachlabs blog

**v5 honest synthesis**: there's no Indian-fintech-default database pattern that automatically applies to our small-scale algo trading vendor. Postgres works for big fintechs; MySQL works for Razorpay. **Database choice at canary scale is governed more by ops convenience and switch cost than by "what big-fintech-X uses".**

---

## Section 6 — Lock-in Days-to-Migrate (v5 Empirical)

v1-v4 estimated; v5 pins down concrete migration steps:

### Path 1 → Path 6 (Current SQLite → Turso)

**Steps**:
1. Sign up Turso Free (10 min, $0)
2. Create database in `aws-ap-south-1` (5 min)
3. Set `ALERT_DB_DRIVER=turso`, `ALERT_DB_URL=libsql://...` (1 min)
4. Modify alerts.OpenDB to accept libsql:// URLs (already does — libSQL accepts SQLite syntax, just different driver)
5. Verify all 5 round-trip tests pass against Turso (1-2 hours)
6. Phase 2.6.a: deploy + canary user with `ALERT_DB_DRIVER=turso` for that user (1 hour)

**Total: 4-6 hours from sign-up to canary user on Turso.** Not 4-6 weeks. The "phase" framing was overweight for this specific path.

**Implication**: Turso testing is cheap and fast. **User could literally try this today** without the full Phase 2.6 staged rollout, because the migration is so light.

### Path 6 → Path 2 (Turso → DO BLR1 Postgres)

**Steps**:
1. DO account + GSTIN setup (1 day if no AWS-style ops familiarity)
2. Provision DO BLR1 Basic 1GB ($15.15/mo)
3. Adapt Phase 2.4 round-trip migration test to libSQL→Postgres (vs SQLite→Postgres)
4. Run round-trip migration; verify (1-2 days)
5. Switch ALERT_DB_DRIVER + ALERT_DB_URL (1 hour)
6. Canary stage rollout (1-2 weeks)

**Total: 1-2 weeks**, NOT v4's "4-6 weeks". v4 over-estimated because it assumed Phase 2.6 full process; in reality, libSQL→Postgres is just like SQLite→Postgres which we've already designed.

### Path 2 → Path 3 (DO BLR1 → AWS RDS Mumbai)

**Steps**:
1. AWS account + IAM (~1 day)
2. Provision RDS PostgreSQL ap-south-1 (1 hour)
3. pg_dump from DO + pg_restore to AWS (depends on data volume; ~1-2 hours at canary)
4. Update ALERT_DB_URL (1 minute)
5. Verify (1 day)

**Total: 2-3 days.** Postgres-to-Postgres migration is well-trodden.

### Path 1 → Path 9 (Current SQLite → rqlite)

**Steps**:
1. Deploy 3 Fly machines BOM with rqlite binary (~2 hours)
2. Migrate SQLite to rqlite cluster (rqlite has SQLite-import path)
3. Update connection logic to talk to rqlite HTTP API instead of local SQLite
4. Test (~1 day)

**Total: 1-2 days for migration; bigger commitment for ops.**

### v5 implication

**Migrations between SQLite-family options are HOURS-DAYS, not weeks.** v1-v4 conflated "Phase 2.6 full staged rollout" (12-16 weeks) with "actually swap the database backend" (hours-days). The 12-16 weeks is staging + monitoring + risk-mitigation, not the technical migration itself.

**This means try-before-buy is genuinely cheap**: actually deploying Turso for a day and seeing if it works is ~half a day of work, not a week of risk.

---

## Section 7 — Try-Before-Buy: Path E (NEW)

v5 introduces a path v1-v4 didn't make explicit: **research-by-deployment**.

### Path E — 1-week parallel canary

**Steps**:
1. Sign up Turso Free (10 min)
2. Sign up DO BLR1 Basic 1GB trial (10 min, $4 prorated for 1 week)
3. Configure dev environment to point at Turso
4. Configure another dev environment to point at DO BLR1
5. Run synthetic load matching our usage profile (30 min to write a script)
6. Measure for 1 week:
   - Latency p50/p99 from Fly BOM machine to each
   - Failure modes (cold starts, rate limits, connection drops)
   - Backup/restore drill (each provider)
   - Subjective ops experience (dashboard quality, error messages)

**Cost**: ~$4-5 total for 1 week of empirical data.

**Calendar**: 1 week real-time; ~4-6 hours hands-on engineering.

**What this resolves that v1-v4 couldn't**:
- Turso Free tier auto-suspend behavior (the deal-breaker question)
- Real BOM↔BLR1 latency from production-like Fly machine (not just local WSL2 ping)
- Real BOM↔Turso ap-south-1 latency
- Subjective developer experience (can't be researched from docs)

**v5 status**: **strongly recommend Path E as a precursor to any Phase 2.6 dispatch decision.** It costs less than continuing to research-by-paper.

---

## Section 8 — "Don't Decide Yet" — The Honest Option

After 5 rounds, the user has substantially complete data. The remaining unknowns require user-side action (Path E try-before-buy, lawyer consultation, sales calls). **At some point more research yields nothing new.**

### When does Phase 2.6 become forced?

| Trigger | Probability of firing within 6 months | What changes |
|---|---|---|
| 50+ paid users | LOW (currently 0; unclear ramp) | NSE empanelment + Phase 3 prep needed; provider choice matters for compliance |
| 100+ concurrent users | VERY LOW | SQLite write throughput becomes real concern |
| Phase 3 multi-cell dispatch | UNDETERMINED | Multi-cell architectural design needed first |
| SQLite corruption / disaster recovery test fails | LOW | Forced migration as recovery |
| Rainmatter / Z-Connect partnership requires Postgres | LOW | External pressure |
| Specific feature requires Postgres-only capability (e.g., LISTEN/NOTIFY for pub/sub) | LOW | Engineering-driven |

**At 0 paid users with no near-term ramp signal**: NONE of these triggers are firing. Phase 2.6 is **purely speculative infrastructure investment**.

### What "Don't decide yet" looks like operationally

- [x] Phase 2.x driver factory shipped at v262 (DONE — Phase 2.0-2.5 work)
- [x] go.mod allows easy Postgres swap (DONE — alerts v0.5.0)
- [x] dialect.go helper for cross-DB compatibility (DONE — Phase 2.1.6)
- [x] Round-trip migration test framework (DONE — Phase 2.4)
- [ ] Actually flip ALERT_DB_DRIVER for any user (NOT DONE — and this is the gated step)

**v5's honest recommendation**: leave the last checkbox unchecked. The infrastructure investment was worth it (Phase 2.0-2.5 prep is defensive optionality). The actual flip is premature.

---

## Section 9 — v5's Final Recommendation (Crystal-Clear)

### Tier 1 — Strongly Recommended

**Path 1 (Defer)** + **Path E (Try-Before-Buy when convenient)**:
- Now: stay on SQLite + Litestream → R2 (current production at v262)
- Within 3-6 months at hobby pace: spend ~$5 on Path E to empirically validate Turso vs DO BLR1
- At trigger event: revisit with then-current data; recommend Path 6 (Turso) OR Path 2 (DO BLR1) per which Path E favored

### Tier 2 — Defensible If User Wants Forward Motion Now

**Path 6 (Turso Free)**:
- Zero-cost migration (free tier covers 1500x our load)
- 4-6 hours engineering to deploy
- Reversible in <1 hour (revert ALERT_DB_DRIVER)
- Caveat: verify Turso Free auto-suspend behavior FIRST (deal-breaker question)

If Turso Free auto-suspends like Neon, switch to **Turso Developer at $4.99/mo** (still cheapest paid managed option in our entire 12-provider survey).

### Tier 3 — Wait For Trigger

**Path 2 (DO BLR1 $15.15/mo)** at trigger event (50+ paid subs OR Phase 3 dispatch).

**Path 7 (Yotta SutraDB ₹1,897.50/core)** at SEBI-RE-registration trigger (would need direct registration, not agent status).

**Path 3 (AWS RDS Mumbai)** at enterprise-customer trigger (someone asks for AWS-grade compliance posture).

### Tier 4 — Not Recommended For Us

**Path 4 (Supabase)**: Phase 3 scaling concern (per-project pricing × N cells).
**Path 5 (Self-host)**: ops burden grows with users; managed beats self-host post-canary.
**Path 8 (Crunchy Bridge)**: $10/mo Hobby beats DO BLR1 $15.15 marginally; not worth switching for $5/mo.
**Path 9 (rqlite)**: ops-heavy; only reconsider for Phase 3 multi-cell.
**Path 10 (Cloudflare D1)**: cross-vendor architecture (CF Workers + Fly app); not worth complexity at canary.
**Path 11 (Litestream alternatives)**: switch only if R2 fails us empirically.
**Path 12 (DuckDB)**: wrong tool (OLAP, not OLTP).

---

## Section 10 — Diminishing Returns Acknowledgment

After 5 rounds, the verifiable surface is exhausted. Further research without user-side action will yield diminishing returns.

### What further research COULD verify (with user actions)

| Item | User action required | Information value |
|---|---|---|
| Turso Free auto-suspend behavior | Sign up free + leave 24h idle + measure first-query latency | HIGH (deal-breaker) |
| BOM↔Turso ap-south-1 latency from Fly BOM | Deploy a probe to existing Fly machine | HIGH |
| Yotta SutraDB PITR window | Sales call | MEDIUM |
| AWS RDS ap-south-1 specific pricing | AWS pricing calculator | MEDIUM (general within 10% known) |
| Sify/Tata/Jio/ESDS managed PG | Sales calls × 4 | LOW (probability they fit our needs is low) |
| Lawyer-grade SEBI compliance review | Lawyer consultation | LOW unless we register as direct RE |

### What further research CAN'T verify (regardless of action)

| Item | Reason |
|---|---|
| Future-state provider pricing changes | Markets move; today's pricing isn't tomorrow's |
| Future-state SEBI/DPDP regulatory changes | Regulators evolve |
| What Phase 3 actually looks like in 12 months | Depends on user growth + technology landscape |
| Whether libSQL ecosystem will mature | Speculative |

**v5 honest take**: any v6 doc would be smaller than v5 because the marginal-research-yields curve is steep. The user has substantially complete data; further effort is incrementally less informative.

**The honest action item from v5**: either commit to Tier 1 (Defer + Path E when convenient) OR commit to Tier 2 (Path 6 Turso Free) OR commit to user-side actions (sales calls, lawyer review). More research-by-paper is unproductive.

---

## Section 11 — What v5 Got Wrong vs v4

### v4 conclusions v5 keeps

- DO BLR1 latency 11ms (Bash-verified)
- DO Managed Postgres pricing $15.15/$30.45/...
- Turso pricing tiers $0/$4.99/$24.92/$416.58
- SEBI cloud framework: algo vendors are agents, not REs
- DPDP Act 2023 conditional negative-list model
- Yotta SutraDB ₹1,897.50/core
- 6 stable conclusions across all rounds

### v4 framings v5 corrects

1. **v4 said Turso↔Postgres switch is 4-6 weeks**. v5 narrows this to 1-2 weeks (mostly migration test adaptation; the actual technical work is hours).

2. **v4 said Path 6 wins on cost; Path 2 wins on Postgres future-proofing**. v5 says: at 0 paid users, neither matters yet. Path 1 (defer) wins because both Path 6 and Path 2 are premature commitments.

3. **v4 didn't address opportunity cost of Phase 2.6**. v5 explicitly: launch path > Phase 2.6 at 0 paid users.

4. **v4 carried 8 paths + 3 hybrids without a "don't decide yet" path**. v5 makes "don't decide" the primary recommendation.

5. **v4 cited Razorpay vaguely as fintech-database example**. v5 web-verified: Razorpay uses MySQL primarily, not Aurora-Postgres. Anchoring on "fintech defaults" is unreliable.

### v3-v4 pattern v5 surfaces

v1→v2→v3→v4 progressively added empirical detail without changing the core decision: Phase 2.6 stays GATED. The fact that 4 rounds of escalating verification still leaves the decision GATED is a signal — **the decision doesn't need making yet**.

---

## Section 12 — Phase 2.6 Dispatch Readiness Checklist (v5)

If user authorizes Phase 2.6 NOW, lock these (unchanged from v4):

- [ ] **Provider**: ___ (Path 6 Turso Free / Path 2 DO BLR1 / Path 7 Yotta / Path 1 Defer / Path E Try-Before-Buy)
- [ ] **First step verification gate**: ___ (Path E recommended before Tier 2 commitment)
- [ ] **Canary user**: ___
- [ ] **Rollback SLA**: ___
- [ ] **Cutover date**: ___
- [ ] **Success criteria**: per Phase 2.5 runbook Section 6

If user picks **Path 1 (Defer)** or **Path E (Try-Before-Buy)**: Phase 2.6 dispatch is NOT needed. The decision is "no decision yet" + "validate when convenient".

---

## Section 13 — Recommended Next Action

### If user still wants Phase 2.6 to fire

→ **Path E first**, then commit to Tier 2 winner.
→ Calendar: 1 week + 4-6 hours engineering.
→ Cost: ~$5.
→ Outcome: empirical validation of Turso vs DO BLR1 from real BOM → resolves the bimodal recommendation by data.

### If user agrees Phase 2.6 is premature

→ **Path 1 (Defer) + bookmark**.
→ Phase 2.x infrastructure investment was worth it (defensive optionality).
→ Revisit at trigger event with then-current data.
→ Free up 12-16 weeks of calendar for higher-ROI work.

### If user wants more confidence before deciding

→ **Lawyer consultation** on SEBI compliance for our agent-vendor framing (~₹15-35K, 1-2 weeks calendar).
→ This resolves the "are we sure we're not REs?" question more authoritatively than v1-v5 can.

### If user wants to never revisit this

→ **Pick Tier 2 Path 6 Turso Free**. Done. Worst case: switch to DO BLR1 in 1-2 weeks at any future trigger event.

---

## Section 14 — Honest Acknowledgments (v5)

### What v5 verified beyond v4

- Razorpay uses MySQL primarily (v3-v4 honestly removed; v5 web-corrected)
- rqlite production-proven for HA + single-binary-deploy (Path 9)
- Cloudflare D1 specs: 10GB cap, 500-2K writes/sec (Path 10)
- Litestream backup-target alternatives: R2 / Tigris / B2 / S3 / MinIO

### What v5 still cannot verify (HIGH-IMPACT, USER-ACTION-REQUIRED)

- Turso Free auto-suspend behavior — DEAL-BREAKER QUESTION
- BOM↔Turso ap-south-1 latency from production Fly machine
- Yotta SutraDB PITR window
- Lawyer-grade SEBI agent-vendor interpretation

### What further rounds (v6+) would yield

After 5 rounds, the marginal-information-per-round curve is steeply diminishing. **v6 without user-side actions would be largely repackaging existing data.**

The next high-information action is NOT v6; it's:
1. **Path E try-before-buy** (1 week, $5) — resolves Turso auto-suspend + real latency
2. **Lawyer consultation** (~₹15-35K) — resolves SEBI agent-vendor question
3. **Yotta sales call** (~30 min) — resolves their PITR + ops details if user wants Path 7

These are user-decisions, not research-decisions.

---

## Section 15 — Sources (v5 New)

### WebSearch verified May 2026 (v5-specific)
- [Razorpay engineering blog — data architecture](https://razorpay.com/blog/data-classification-real-time-highway/) — confirms MySQL primary, TimescaleDB analytics, Kubernetes infra
- [rqlite GitHub](https://github.com/rqlite/rqlite) — production-proven, Raft-replicated SQLite
- [rqlite features](https://rqlite.io/docs/features/) — single-binary, HA, simple deployment
- [Cloudflare D1 limits](https://developers.cloudflare.com/d1/platform/limits/) — 10GB cap, 500-2K writes/sec
- [Cloudflare D1 scaling](https://medium.com/@tristantrommer/scaling-cloudflare-d1-from-10-gb-to-500-gb-with-manual-database-sharding-4e95d6deb742) — manual sharding pattern
- [Litestream alternatives](https://litestream.io/alternatives/) — R2 / Tigris / B2 / S3 backup target options
- [Form3 fintech case study (cockroachlabs)](https://www.cockroachlabs.com/blog/fintech-companies-scaled-distributed-sql/) — RDS PostgreSQL → CockroachDB migration pattern at scale

### Carried over from v4 (HIGH confidence)
- DigitalOcean Managed Postgres pricing (WebFetch)
- Turso pricing all tiers (WebFetch)
- DO BLR1 PITR/connections/extensions (WebFetch)
- DO India payment friction (WebSearch)
- Yotta SutraDB ₹1,897.50/core (WebFetch)
- SEBI Cloud Framework Circular SEBI/HO/ITD/ITD_VAPT/P/CIR/2023/033 (WebFetch + WebSearch)
- DPDP Act 2023 cross-border framework (WebSearch)
- BOM↔BLR1 latency 11ms (Bash ping/traceroute)
- Microsoft Learn Azure DB Reserved Pricing (Microsoft Docs MCP)

---

**End of v5 R-10 strategic synthesis. Doc-only commit; supersedes v4. tools=130 invariant preserved. NO source mutations. Phase 2.6 dispatch GATED on user authorization with primary recommendation: Path 1 (Defer) + Path E (Try-Before-Buy) when convenient. Diminishing-returns ceiling reached for research-by-paper; further information requires user-side action.**
