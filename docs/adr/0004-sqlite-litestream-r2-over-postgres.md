# ADR 0004: SQLite + Litestream → Cloudflare R2 Over Postgres

**Status**: Accepted (2026-04-26, retrospective — original decision Apr 3 2026)
**Author**: kite-mcp-server architecture
**Decision drivers**: Single-node Fly.io deployment; SEBI 5-year audit
trail durability requirement; ₹0 storage budget for Y1; need for
auto-restore on volume loss.

---

## Context

The server stores five things that must survive a Fly.io machine
rebuild or volume loss:

1. **Audit trail** — every MCP tool call (`tool_calls` table). SEBI
   requires this preserved for **5 years** (NSE/INVG/69255 Annexure I).
2. **Encrypted Kite credentials** — per-user `KiteCredentialStore`
   (AES-256-GCM); rebuilding from scratch forces every user to re-do
   developer-app setup.
3. **OAuth client registrations** — DCR clients persisted by
   `ClientStore`; loss breaks already-installed MCP clients.
4. **MCP session registry** — `SessionRegistry` (commit `268ab4f`); loss
   forces every connected client to re-authenticate.
5. **Price alerts** — user-set price triggers (`AlertStore`); loss
   silently breaks the entire alerts subsystem.

All five live in the same SQLite database at `/data/alerts.db`,
mounted on a Fly.io volume. The volume is replicated 1×; a hardware
failure or accidental `flyctl volumes destroy` loses everything.

The deployment posture also matters:
- Single Fly.io machine, 512 MB RAM, `bom` region.
- One operator, no DBA.
- Y1 revenue ₹0 (pre-revenue), Y1 storage budget effectively ₹0.
- ARM64 not in scope.

## Decision

Stay on **SQLite**. Add **Litestream continuous replication** to
**Cloudflare R2**. No Postgres migration. R2's free tier
(10 GB storage, 10M Class A ops/month, no egress fees) covers our
projected Y1 volume comfortably; storage cost is **$0/month**.

Implementation in commit `763aa24` (2026-04-03):

- `Dockerfile:11-13` pulls Litestream `0.5.10` static binary into the
  builder stage and copies it into the runtime image at
  `Dockerfile:22`.
- `etc/litestream.yml` configures replication of `/data/alerts.db` to
  R2 with 10-second sync interval; bucket / endpoint / credentials
  injected via Fly.io secrets (`LITESTREAM_BUCKET`,
  `LITESTREAM_R2_ACCOUNT_ID`, `LITESTREAM_ACCESS_KEY_ID`,
  `LITESTREAM_SECRET_ACCESS_KEY`).
- `scripts/run.sh` is the container entrypoint: on cold start it runs
  `litestream restore -if-replica-exists` to rehydrate the DB if the
  volume is empty, then `exec litestream replicate -exec
  "kite-mcp-server"` so Litestream supervises the app process.

Validation: GitHub Actions cron at `.github/workflows/dr-drill.yml`
runs `scripts/dr-drill.sh` on the 1st of each month
(09:00 IST), exercising the full restore chain against R2 and
asserting expected schema/row-count. Added in commit `43cc844`
(2026-04-26) per NIST CSF 2.0 PR.IP-9 / RC.RP.

## Alternatives considered and rejected

**A. Postgres on Fly.io managed cluster.** Rejected on cost: Fly.io
managed Postgres starts at ~$15/month for the smallest cluster, plus
high-availability setup adds another $30+/month. At Y1 revenue ₹0,
this is the entire monthly server budget. SQLite + Litestream is
$0/month for equivalent durability at our scale.

**B. Postgres on Neon / Supabase free tier.** Considered. Rejected
because (i) free tiers add a network hop from `bom` to a US/EU region
adding 100-300 ms latency to every audit write, and the audit hot
path runs on every tool call; (ii) free tier of either has a cold-pause
behavior that would push the first request after idle into 1-3
seconds — visible to users; (iii) they lock us to a vendor's free-tier
ToS, while R2 is just S3-compatible storage we can lift to any
provider in an hour.

**C. SQLite without backup, accept volume-loss risk.** Rejected on SEBI
grounds — losing 5-year audit trail is a regulatory event, not a
"oh well" event. Even if we self-host generously, the audit trail is
non-negotiable.

**D. Manual periodic SQLite dumps to R2 (cron-based).** Rejected because
the RPO (recovery point objective) is at best the cron interval. With
trading data, an hourly cron means up to 60 minutes of orders lost on
restore. Litestream's continuous WAL shipping gets RPO to roughly
10 seconds (the configured `sync-interval` plus network).

**E. Postgres later, SQLite now (kick the can).** Considered. Rejected
because the SQLDB port (ADR 0002, `kc/alerts/db.go:13`) already
captures the dialect-portable subset; future migration is bounded
work, not architectural rewrite. The decision to migrate can land when
demand signals (multi-region, multi-writer, large team) actually appear.

**F. DynamoDB or Firestore.** Rejected — schema-flexible NoSQL is the
wrong shape for SEBI audit queries (`SELECT * FROM tool_calls WHERE
email = ? AND ts BETWEEN ? AND ?` is the dominant workload). Adding
secondary indexes per query pattern in NoSQL is more complexity than
SQLite delivers for free.

## Consequences

**Positive**:
- $0/month storage cost. R2 has no egress fees, so monthly DR drills
  are free.
- 10-second RPO on regional volume loss (Litestream WAL-shipping
  cadence).
- Auto-restore on cold start: `scripts/run.sh:11` runs
  `litestream restore -if-replica-exists` before `litestream replicate`.
  No operator intervention on machine recreate.
- Single SQLite file simplifies local-dev: every developer's box is
  identical to production storage shape.
- Litestream supervises the app process (`exec litestream replicate
  -exec "kite-mcp-server"`), so app crash + restart is observable to
  Litestream and replication continues uninterrupted.

**Neutral**:
- ARM64 deploys would need a different Litestream binary; not in
  scope but documented.
- 512 MB RAM ceiling means the SQLite file plus working set must stay
  under ~300 MB. At Y1 we project ~50 MB. Acceptable for Y1.

**Negative**:
- **Single writer**: SQLite + WAL mode + Litestream is fundamentally
  single-writer. Horizontal scaling beyond one Fly.io machine requires
  a Postgres migration. ADR 0002 documents the port readiness for
  this future move.
- **Restore window**: cold-start restore from R2 takes ~10-30 seconds
  for the first 1-10 MB. During that window the app is not serving
  traffic. Acceptable because Fly.io machine recreate is a rare event.
- **R2 vendor lock**: not really — R2 is S3-compatible, Litestream
  works against any S3 endpoint. Migrating to AWS S3, Backblaze B2,
  Wasabi is a config change.
- **Litestream is one developer's project**: dependency on
  `benbjohnson/litestream` (active but small maintainer pool).
  Mitigation: the binary at `/usr/local/bin/litestream` is pinned to
  a specific version (`Dockerfile:11`: `LITESTREAM_VERSION=0.5.10`),
  and the underlying SQLite file remains independently restorable
  even if Litestream itself disappears tomorrow.

## References

- `Dockerfile:11-13,22-23` — Litestream binary install + config copy
- `etc/litestream.yml` — replica config (R2 endpoint, 10s sync
  interval)
- `scripts/run.sh:11,15` — restore-then-replicate entrypoint
- `.github/workflows/dr-drill.yml` — monthly R2 restore validation
  (commit `43cc844`)
- `scripts/dr-drill.sh` — restore-validation script
- Commit `763aa24` (2026-04-03) — "feat: add Litestream SQLite backup
  to Cloudflare R2"
- Commit `268ab4f` (earlier) — "feat: persist MCP sessions to SQLite —
  survive server restarts" (earlier durability work that this ADR
  builds on)
- ADR 0002 — SQLDB port for future Postgres adapter
- MEMORY note: "Litestream backup: SQLite WAL → Cloudflare R2 bucket
  `kite-mcp-backup` (APAC). 10s sync. Auto-restore. $0/month."
