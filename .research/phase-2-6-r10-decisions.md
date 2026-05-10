# Phase 2.6 — R-10 User Decision Re-Research (v7 — Falsification Reckoning + Binary)

**Date**: 2026-05-10 IST
**HEAD**: post-`67d1d7f` (this doc supersedes v6 after Track 2 falsification of DO BLR1 reachability)
**Charter**: doc-only synthesis; NO source mutations. v7's job: reckon with what Track 2 falsification means for v1-v6 confidence, audit "WebFetch verified" claims, collapse 8 paths to a BINARY decision.
**Builds on / supersedes**: v6 R-10 doc at `67d1d7f` + Track 2 falsification finding (UI showed only NA/EU regions; BLR1 not surfaced for fresh account despite docs claiming availability).

**Production state**: v266 LIVE; SQLite + Litestream → R2; ALERT_DB_DRIVER unset; **0 paid users**.

---

## Section 0 — TL;DR (v7 — crispest of all rounds)

**The decision is binary**: **adopt Path 6 (Turso ap-south-1 Free)** OR **stay Path 1 (SQLite + Litestream → R2)**.

All other paths are eliminated by empirical evidence:
- Path 2 (DO BLR1) — **FALSIFIED**. Docs say BLR1 supports managed Postgres; Track 2 UI did not surface BLR1 for our fresh account. Region picker showed ONLY NA/EU. **Paper-truth ≠ UI-truth.** Cannot verify Path 2 without account-tier escalation OR sales contact.
- Path 3 (AWS RDS Mumbai) — Higher friction (AWS account creation, IAM setup); not yet validated; same "paper might not equal UI" risk.
- Path 5 (Self-host Fly Volume BOM) — Defensible but ops-heavy; v6 estimated 1.5-2 hrs/mo at canary; not validated.
- Path 7 (Yotta SutraDB) — Sales-only signup; cannot validate without phone call.
- Paths 4, 8, 9, 10, 11, 12 — already excluded in v3-v6 for various reasons.

**v7's recommendation**: **adopt Path 6 NOW** — Track 1 empirically validated it works at Mumbai region with Free tier; the engineering work is ~4-6h to wire libSQL driver into `app/providers/alertdb.go` factory; reversible to Path 1 in <5 min.

**v7's methodology lesson**: WebFetch + Context7 verification is **paper-truth**. Provisioning-attempt verification is **UI-truth**. v4 conflated them. Track 1 succeeded because Turso UI matched docs; Track 2 failed because DO UI did NOT match docs. **Future verification claims must distinguish "documented availability" from "actually-provisionable for this account".**

---

## Section 1 — Track 2 Falsification: What Actually Happened

### 1.1 Empirical sequence

1. v4 doc cited Context7-verified DO release notes: "Managed databases for MySQL and Redis are now available in the SGP1, BLR1, and TOR1 regions" (release note dated "4 September").
2. v4 ALSO cited DO availability docs: BLR1 listed for managed PostgreSQL.
3. v4 conclusion: "DO BLR1 PostgreSQL = $15.15/mo with 11ms latency to Mumbai" (the latency number from a separate Bash ping to `blr1.digitaloceanspaces.com`, NOT from a real provisioned DO Postgres in BLR1).
4. v6 carried this forward as Path 2's grounding.
5. Track 2 attempted actual provisioning: signup → onboarding questionnaire → Create Database page with PostgreSQL engine selected → region picker.
6. Region picker showed **only 12 NA/EU options**: NYC1/2/3, SFO2/3, TOR1, LON1, AMS3 (active) + SFO1, ATL1, RIC1, AMS2 (disabled).
7. DOM-search for "BLR1", "Bangalore", "SGP1", "Singapore", "SYD1", "Sydney", "Mumbai", "BOM", "Frankfurt", "FRA1": **0 hits across entire rendered page**.

### 1.2 Cross-checking after Track 2

v7 re-fetched DO docs to verify v4's claim:
- `docs.digitalocean.com/products/databases/postgresql/details/availability/` (last edited 23 Apr 2026): explicitly lists BLR1 alongside SGP1, SYD1, FRA1 for managed PostgreSQL.
- `docs.digitalocean.com/platform/regional-availability/`: confirms PostgreSQL Managed Databases available in all 14 datacenters including BLR1.
- **No documented account-tier restriction.**

### 1.3 The paper-vs-UI gap

| Source | BLR1 PostgreSQL? |
|---|---|
| DO availability docs | YES (paper-truth) |
| DO regional-availability matrix | YES (paper-truth) |
| Context7 release notes archive | YES for MySQL/Redis (4 September); v4 extrapolated to PG |
| DO Create Database UI (our fresh account) | **NO** (UI-truth) |

### 1.4 Possible explanations for the gap

1. **Account-tier gating** (undocumented): fresh accounts limited to NA/EU.
2. **Capacity-constrained**: BLR1 at temporary capacity limit; UI hides unavailable regions.
3. **Engine-specific**: DO offers PostgreSQL in SOME regions but not BLR1 for this engine; release-notes archive only confirmed MySQL+Redis.
4. **Fraud-prevention**: new accounts with first payment method may face rolling-trust restrictions.

**v7 cannot resolve which explanation is correct without DO support contact.** What v7 CAN say: **BLR1 PostgreSQL is NOT empirically reachable for our specific account at this specific moment**.

### 1.5 Why this matters

If we had committed to Path 2 (DO BLR1) based on v4's "verified" claim, we'd have hit this UI block at production time, post-engineering-investment, with deploy timeline pressure. **The paper-verification was a near-miss.** Track 2 caught it pre-commitment.

---

## Section 2 — Verification Confidence Audit (Re-tagging All v4-v6 Claims)

v4-v6 used "Context7 verified" / "WebFetch verified" / "Knowledge baseline" tags. v7 introduces a stricter tier:

| Tier | Definition | Examples |
|---|---|---|
| **REAL-EMPIRICAL** | Provisioned + queried successfully on actual account | Track 1 Turso ap-south-1 |
| **PAPER-VERIFIED** | Docs/release-notes confirm but not provisioning-tested for OUR account | Most v4 claims |
| **KNOWLEDGE-BASELINE** | Common knowledge, not explicitly verified this round | AWS RDS pricing details |
| **FALSIFIED** | Paper-claimed but Track-attempt failed | DO BLR1 PostgreSQL availability |
| **NOT-TESTABLE-WITHOUT-ACTION** | Requires user-side action (sales call, lawyer, phone) | Yotta operational details, SEBI compliance |

### 2.1 Re-tagged v4-v6 claims

| Claim | v4 tag | v7 tag |
|---|---|---|
| DO Managed PG pricing $15.15/mo Basic 1GB | WebFetch verified | **REAL-EMPIRICAL** (Track 2 saw the price in UI even though couldn't provision in BLR1) |
| DO BLR1 PostgreSQL availability | WebFetch verified | **FALSIFIED** (Track 2 UI didn't show BLR1) |
| DO BLR1 latency 11ms from Mumbai broadband | "Bash ping verified" | **PAPER-VERIFIED** (the ping was to `blr1.digitaloceanspaces.com` Cloudflare-edged URL, NOT a provisioned DB in BLR1; latency to actual DO BLR1 Postgres unknown) |
| DO BLR1 PITR 7 days | WebFetch verified | **PAPER-VERIFIED** (docs say 7 days; couldn't confirm in UI without provisioning) |
| DO BLR1 connection limits 22-997 per RAM tier | WebFetch verified | **REAL-EMPIRICAL** (Track 2 UI showed exact "Connection limit: 22" for 1GB plan) |
| Turso pricing (Free $0, Developer $4.99, Scaler $24.92, Pro $416.58) | WebFetch verified | **REAL-EMPIRICAL** (Track 1 confirmed Free tier; paid tiers still PAPER-VERIFIED) |
| Turso Mumbai region | Context7 verified | **REAL-EMPIRICAL** (Track 1 dashboard showed AWS AP South Mumbai option, provisioned successfully) |
| Yotta SutraDB ₹1,897.50/core/month | WebFetch verified | **PAPER-VERIFIED** + **NOT-TESTABLE-WITHOUT-ACTION** (sales-only signup) |
| AWS RDS ap-south-1 db.t4g.micro pricing | WebSearch general | **KNOWLEDGE-BASELINE** (Vantage shows general; ap-south-1 specific never extracted) |
| Azure DB India region pricing | WebSearch general | **KNOWLEDGE-BASELINE** (general only) |
| SEBI cloud framework circular text | WebFetch verified | **PAPER-VERIFIED** (cited but not lawyer-interpreted) |
| Aiven Startup-4 $75/mo AWS Mumbai | WebSearch G2 | **PAPER-VERIFIED** (third-party listing; not provisioning-tested) |
| Crunchy Bridge Hobby $10/mo AWS Mumbai | WebSearch | **PAPER-VERIFIED** (similar caveat to Aiven) |

### 2.2 The 11ms latency claim — re-examined

v4 said: "DO BLR1 latency from Mumbai broadband: 11ms verified via Bash ping to `blr1.digitaloceanspaces.com (5.101.108.233)`".

**v7 correction**: that ping was to **DO Spaces** in BLR1, not to a provisioned managed Postgres in BLR1. Spaces uses different network paths (object storage CDN-fronted) than Managed Databases (private VPC-routed). **The 11ms number is suggestive but not the actual managed-PG latency.**

For Track 1 Turso, we DID measure actual DB latency:
- Warm INSERT 54-86ms from same Mumbai broadband to `aws-ap-south-1.turso.io`
- That's the only **REAL-EMPIRICAL** managed-DB-from-Mumbai latency we have.

### 2.3 What this means for v6's recommendations

v6 said "Path 2 wins on Postgres future-proofing" — **partially based on PAPER-VERIFIED Path 2 reachability that Track 2 falsified**. v6's bimodal Path 6 vs Path 2 framing collapses when Path 2 turns out to be UI-blocked.

**v7 honest take**: **only Path 6 is REAL-EMPIRICAL for our account.** Everything else is paper.

---

## Section 3 — Methodology Lesson

### 3.1 Why v4's "WebFetch verified" missed the new-account-tier restriction

WebFetch reads marketing/docs pages — they describe the **product capability**, not the **per-account-state availability**. Documentation is correct in aggregate; UI behavior is account-specific.

This is a structural limitation of paper-verification:
- Docs: "Postgres available in BLR1"
- UI: "your account, today, can or cannot create Postgres in BLR1"

**These can diverge** for reasons including: account age, payment history, tier, capacity, fraud signals, region rollout phase, engine-region pairings.

### 3.2 What v4 should have said

Instead of "WebFetch verified — DO BLR1 supports managed Postgres", v4 should have said:

> "**Documented**: DO BLR1 supports managed Postgres per official docs.
> **Empirically reachable for our account**: NOT YET TESTED. Requires Track-style provisioning attempt to confirm."

The two statements differ. v4 collapsed them.

### 3.3 Updated verification framework (v7)

For future R-10-style decisions:

| Verification step | What it confirms | What it does NOT confirm |
|---|---|---|
| Read official docs | Product can do X | Whether YOUR account can do X today |
| WebFetch pricing pages | Listed price $Y | Whether you'll be charged $Y (taxes, regional surcharges, account-specific discounts/penalties) |
| Context7 release notes | Feature was launched | Whether it's currently rolled out to your tier/region |
| Search user forums | Others have used it | Whether it works for your specific account-state |
| **Provisioning attempt (Track-style)** | UI-truth: actually reachable for this account | Production behavior under load (Track 3 work) |
| **Hello-world test** | Connection works + basic ops succeed | Sustained behavior over hours/days/weeks |
| **1-week sustained load** | Production-grade reliability | Long-tail edge cases (multi-month) |

**Verification effort scales with stakes.** For zero-paid-user canary, Track-style attempt is the right level. For 100+ user production, sustained load + drill-tested rollback is needed.

### 3.4 Implications for future R-10 / Phase 2.6 dispatches

When user reaches 50+ paid subs trigger and re-engages Phase 2.6:
- Don't trust docs alone. Test provisioning each candidate first.
- Prioritize providers with self-serve UI > sales-only providers (Yotta is now demoted)
- Latency claims from secondary endpoints (Spaces, marketing CDNs) are NOT proxies for managed-DB latency
- Do parallel provisioning trials for top-2 candidates BEFORE committing engineering time

---

## Section 4 — Path Hierarchy Reset (Post-Falsification)

### 4.1 v7 tier system

**Tier 1 — REAL-EMPIRICAL (provisioning-validated)**:
- Path 6 (Turso ap-south-1 Free) — Track 1 success
- Path 1 (SQLite + Litestream → R2 — current production)

**Tier 2 — PAPER-VERIFIED (docs say it works; not Track-tested)**:
- Path 5 (Self-host Postgres on Fly Volume BOM) — Fly volumes work; Postgres install + WAL-E backup is engineering work, not paper-questionable
- Path 11 (Litestream alternatives — Tigris / Backblaze / S3 / MinIO) — backup-target swap; trivially testable

**Tier 3 — FALSIFIED for our account-state**:
- Path 2 (DO BLR1 PostgreSQL) — Track 2 UI didn't surface BLR1

**Tier 4 — NOT-TESTABLE-WITHOUT-USER-ACTION**:
- Path 3 (AWS RDS Mumbai) — needs AWS account creation, IAM setup; high friction
- Path 7 (Yotta SutraDB) — sales-only signup; needs phone call
- Path 4 (Supabase Mumbai) — could be Track-tested but never was; same risk as Path 2 of paper-vs-UI gap

**Tier 5 — Eliminated in earlier rounds**:
- Path 8 (Crunchy Bridge), Path 9 (rqlite), Path 10 (Cloudflare D1), Path 12 (DuckDB)

### 4.2 The binary that remains

After tier-pruning:
- **Action**: Path 6 (adopt Turso Free) — Track 1 validated
- **Status quo**: Path 1 (defer; stay on SQLite) — production at v266

These are the only two paths with REAL-EMPIRICAL grounding for our zero-paid-user state.

### 4.3 What about Path 5 (Self-host)?

Self-host on Fly Volume BOM is paper-defensible (we already use Fly volumes for SQLite production; running Postgres-on-volume is similar mechanics). But it adds ops burden (~1.5-2 hrs/mo per v6) for zero immediate user-visible benefit.

**v7 keeps Path 5 as a fallback option** in case user wants Postgres-protocol-future without managed-service vendor dependency. But it's not the primary recommendation.

---

## Section 5 — Recommendation: BINARY

### 5.1 Path 6 (Turso Free) — adopt now

**Why this is the recommendation**:
1. Track 1 empirically validated at Mumbai region
2. Free tier covers 1500x our usage with no payment-method-on-file required
3. Engineering work ~4-6h to wire libSQL driver into `app/providers/alertdb.go` factory (extending Phase 2.3 driver-switching work)
4. Reversible to Path 1 in <5 min via `ALERT_DB_DRIVER` env var revert
5. PITR 1-day on Free; 10/30/90-day on paid tiers (Track 1 confirmed PITR built into Free tier UI)
6. Mumbai region collocated; warm latency 35-86ms (acceptable for our access pattern per v6 analysis)

**Engineering steps** (TDD per `.claude/CLAUDE.md`):
1. Write `providers_test.go` test that `Driver="turso" + valid URL` returns non-nil DB
2. Run test → confirm RED (Driver enum doesn't have "turso")
3. Add `case "turso": return alerts.OpenLibSQL(cfg.URL, cfg.Token)` to `ProvideAlertDB` factory
4. Add `OpenLibSQL` constructor to external `algo2go/kite-mcp-alerts` repo (similar pattern to `OpenPostgresDB`)
5. Tag alerts repo v0.6.0; bump kite-mcp-server's go.mod
6. Test on test/dev Fly machine first; flip when comfortable
7. Document in Phase 2.5 runbook

**Expected total effort**: 4-6 hours engineering + 1-2 days observation before flipping primary backend.

### 5.2 Path 1 (Defer SQLite) — defensible alternative

**Why this might be right**:
1. 0 paid users → 0 user-visible benefit from Path 6 adoption today
2. SQLite + Litestream → R2 already battle-tested across v189-v266 production
3. Phase 2.x infrastructure already shipped at v262 (driver-switching factory + Phase 2.4 round-trip tests) — defensive optionality preserved
4. Engineering effort = 0; mental overhead = 0

**Cost of staying Path 1**: at trigger event (50+ paid subs OR Phase 3 dispatch), we re-engage Phase 2.6 dispatch, repeat verification (DO BLR1 might be available by then, or might not), eat ~10-week ramp-up.

### 5.3 The choice between the two

This is genuinely an **incremental optionality investment** decision:
- Path 6 adoption = small upfront cost, accumulated optionality (multi-region read replicas, managed PITR)
- Path 1 stay = zero cost, no new optionality, fallback to SQLite-everything-forever

**Both are defensible.** v7's recommendation: **default to Path 6** because the 4-6h engineering cost is small relative to the optionality gained, AND Track 1's empirical success has already eliminated most of the risk. But if user wants minimal-moving-parts posture, Path 1 is fine.

---

## Section 6 — What If User Wants to Validate Path 3 (AWS RDS Mumbai) Anyway?

If user, despite v7's recommendation, wants to test Path 3 to be thorough:

**Effort**:
- AWS account creation (~30-60 min including KYC for Indian customers)
- IAM setup (~15-30 min)
- RDS provisioning in `ap-south-1` (~20-30 min — RDS is slow to provision)
- Hello-world test (~15 min)
- Total: ~2-3 hours, plus ~$5-10 prorated trial cost
- **Risk**: same paper-vs-UI gap could surface (e.g., new AWS accounts have stricter region/instance limits)

**v7 says**: probably not worth the investment given Track 1 success. But if user does this and Path 3 works, the recommendation flips to **either Path 3 OR Path 6** (Postgres-protocol-with-AWS-Mumbai vs libSQL-with-Turso-Mumbai) — and the v6-style bimodal framing returns.

---

## Section 7 — What If User Wants to Investigate Path 2 (DO BLR1) Mystery?

DO BLR1 falsification is a research question, not a blocker for the canary decision. If user wants to resolve:

**Options**:
1. **Wait 24-48h and retry**: capacity / fraud-rolling-trust restrictions may clear automatically
2. **Add ~$10 of credit to DO account, leave 1 week, retry**: payment-history threshold theory test
3. **Contact DO support**: ask "why doesn't BLR1 show in my managed PG region picker?" — direct answer
4. **Switch to MongoDB engine, see if BLR1 shows**: if MongoDB lists BLR1 but PostgreSQL doesn't, it's engine-specific

**v7 doesn't recommend pursuing this** unless user specifically wants Path 2 as the canary backend. If Path 6 works, the DO mystery is interesting but not decision-relevant.

---

## Section 8 — Cross-Round Convergence (v1 → v7)

### Conclusions stable across all 7 rounds (highest confidence)

1. Mumbai region preferred for India users (DPDP-grounded)
2. Saturday 06:00 IST cutover window (if Phase 2.6 staged rollout fires)
3. R-10.1 (provider) is the only HIGH-cost-of-wrong decision
4. At canary scale, all R-10 decisions reversible cheaply
5. Phase 2.x driver factory at v262 was the right defensive investment

### Conclusions that EVOLVED across rounds

| Round | Top recommendation |
|---|---|
| v1 | DO BLR1 / Self-host Fly bimodal |
| v2 | Self-host elevated; DO BLR1 secondary |
| v3 | Adversarial — DO BLR1 primary; Self-host with caveats |
| v4 | Web-verified DO BLR1 + Yotta surfaced |
| v5 | "Don't decide yet" — Path 1 defer or Path E try-before-buy |
| v6 | Track 1 success → Path 6 Turso primary; Path 2 DO BLR1 secondary |
| **v7** | **Path 2 falsified → BINARY: Path 6 OR Path 1** |

The arc reflects increasing empirical grounding. v6 was bimodal because both Path 6 (Turso) and Path 2 (DO BLR1) seemed reachable. v7 is binary because only Path 6 is actually reachable.

### Lessons across the arc

1. **Paper-truth ≠ UI-truth**. v4's "Context7 verified" was technically correct (the docs DO list BLR1) but operationally misleading (UI didn't surface BLR1).
2. **More research rounds added options**, but did NOT change the core recommendation until empirical attempt forced it.
3. **The actual Track 1 + Track 2 attempt revealed more in 1 day than 6 rounds of paper analysis.** Future similar decisions should compress to 1-2 paper rounds + immediate provisioning trial.

---

## Section 9 — Phase 2.6 Closure Recommendation

Phase 2.6 was originally framed as a 12-16 week canary dispatch with 6 stages (R-10.1 through R-10.6). v6 already noted this ceremony was overkill at 0 paid users.

**v7 closes Phase 2.6 with this resolution**:

If user picks Path 6: Phase 2.6 dispatch reduces to ~4-6h engineering integration + smoke test + flip-when-ready. **Not 12-16 weeks**. Not 6 stages. Just integration of an empirically-validated driver into the factory we already shipped at v262.

If user picks Path 1: Phase 2.6 stays GATED but the gate is now well-understood. Re-engage when trigger fires; provisioning trials happen at that time with then-current data.

**Phase 2.6 is no longer "decide between 8 paths". It's "do this small engineering task OR don't, your call".**

---

## Section 10 — Self-Criticism (v7)

### What v7 might still be wrong about

1. **"Path 2 falsified" might be temporary**. Track 2 was on day 1 of the new DO account. 24-48h trust-rolling could surface BLR1. Without retry, can't distinguish "permanent" from "temporary" account-tier restriction. **v7 treats the falsification as decision-relevant signal regardless** because it shifted the friction-balance toward Path 6.

2. **Track 1's 4 runs is small sample**. Production-grade confidence needs Track 3 (1-week sustained). Path 6 recommendation is canary-grade, not production-grade.

3. **The "11ms ping" misframing affects Path 5 too**. If we self-host Postgres on Fly Volume BOM, our latency to it is sub-ms (same Fly machine). But if we considered self-host on a different cloud, the same paper-vs-UI gap could apply.

4. **v7 didn't actually verify Path 6 paid-tier claims** (Developer $4.99, Scaler $24.92, Pro $416.58). Track 1 only validated Free tier. If user grows past Free quotas (very unlikely at 0 paid users), upgrade behavior + cost could differ from paper.

5. **The methodology framework in Section 3.3 is normative, not yet validated**. v7 introduces a verification-tier system but hasn't tested whether it would have prevented v4's mistake in retrospect. Future R-10-style dispatches should validate the framework.

### What v7 explicitly cannot answer

- Does DO BLR1 work for established accounts (>30 days, positive payment history)? Possibly — but verifying takes account-aging.
- Does AWS RDS Mumbai work for our account? Untested; could have its own paper-vs-UI gap.
- Will Turso Free auto-suspend after 24h+ idle? Track 1 didn't test (Track 3 work).
- Will libSQL ecosystem maturity hold for 12+ months? Speculative.

---

## Section 11 — Recommended Next Action (v7)

### Default v7 path

**Adopt Path 6 (Turso Free aws-ap-south-1) via 4-6h engineering**:

1. Phase 2.6.1 (engineering): extend `app/providers/alertdb.go` driver-switching to support `Driver="turso"`. TDD per CLAUDE.md.
2. Phase 2.6.2 (external repo): add `OpenLibSQL(url, token) (*DB, error)` constructor to `algo2go/kite-mcp-alerts`. Tag v0.6.0.
3. Phase 2.6.3 (config): set `ALERT_DB_DRIVER=turso`, `ALERT_DB_URL=libsql://phase-2-6-canary-sundeepg98.aws-ap-south-1.turso.io`, `ALERT_DB_TOKEN=<from ~/.path-e-tryout/turso-creds.env>` on test/dev Fly machine.
4. Phase 2.6.4 (smoke test): admin login + record_audit work end-to-end through Turso backend.
5. Phase 2.6.5 (defer flip on production): keep `ALERT_DB_DRIVER=sqlite` on production until comfortable.
6. Phase 2.6.6 (closure): mark Phase 2.6 done; Phase 2.7 (production canary) GATED on first-paid-user trigger.

### Alternative if user prefers minimal-action

**Stay Path 1**: do nothing. v262 production continues on SQLite + Litestream. Phase 2.x infrastructure stays as defensive optionality.

### What v7 does NOT recommend

- Investigating DO BLR1 mystery (low ROI; Track 1 success already provides path forward)
- Setting up AWS account for Path 3 trial (high friction; unclear if worth the effort given Track 1)
- Sales call to Yotta (only relevant if SEBI-direct-RE-registration path becomes likely; not at 0 paid users)
- Track 3 (1-week sustained load) yet — wait until Path 6 actually integrated and running on test/dev

---

## Section 12 — Sources (v7 New)

### WebFetch verified (v7-specific, May 2026)
- [DO PostgreSQL availability docs](https://docs.digitalocean.com/products/databases/postgresql/details/availability/) — last edited 23 Apr 2026; lists BLR1 for managed PG
- [DO regional availability matrix](https://docs.digitalocean.com/platform/regional-availability/) — confirms PG in BLR1 with no documented account-tier restriction
- [DO managed PostgreSQL marketing page](https://www.digitalocean.com/products/managed-databases-postgresql) — no specific regions enumerated
- [DigitalOcean status](https://status.digitalocean.com/) — BLR1 operational as of 9 May 2026

### Empirical (Track 1 + Track 2)
- Track 1 results: `.research/path-e-try-before-buy-results.md` at HEAD `31e2638`
- Track 2 falsification: this commit (no separate doc; surfaced in v7 directly)
- Track 2 screenshot: `D:\Sundeep\projects\kite-mcp-server\.playwright-mcp\path-e-track2-do-region-picker-no-blr1.png`

### Context7 (re-queried v7)
- DO release notes archive (4 September) — explicitly mentions MySQL+Redis in BLR1; v4 extrapolated to PG without separate confirmation

### Carried forward from v1-v6
All sources from v6's Section 12 unchanged — except DO BLR1 reachability claim is now FALSIFIED.

---

**End of v7 R-10 falsification reckoning. Doc-only commit; supersedes v6. tools=130 invariant preserved. NO source mutations.**

**v7's primary recommendation**: **adopt Path 6 (Turso Free aws-ap-south-1) via 4-6h engineering integration** OR stay Path 1 (defer SQLite). The 8-path hierarchy has collapsed to a binary; the binary has clear default.

**v7's methodology lesson**: WebFetch + Context7 verification is paper-truth. Track-style provisioning attempt is UI-truth. The two can diverge undocumentedly. For future R-10-style decisions, compress paper analysis (~1-2 rounds) and prioritize provisioning trials early.
