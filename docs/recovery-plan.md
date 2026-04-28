# Recovery Plan — kite-mcp-server

*Last reviewed: 2026-04-26*
*Maps to NIST CSF 2.0: RC.RP-1 (Recovery plan executed), RC.IM (Improvements), RC.CO (Communications), PR.IP-9 (Resilience plan), PR.IP-10 (Recovery test).*
*Companion to: [`incident-response.md`](incident-response.md), [`incident-response-runbook.md`](incident-response-runbook.md), [`monitoring.md`](monitoring.md), [`change-management.md`](change-management.md), [`asset-inventory.md`](asset-inventory.md).*

This document is the operational policy for **recovering from incidents** — what gets restored, in what order, with what RTO/RPO targets, and how we validate the recovery before declaring service restored.

[`incident-response-runbook.md`](incident-response-runbook.md) Phase 4 hands off to this document; this is the destination, not a duplicate.

---

## 1. Recovery objectives (RTO / RPO)

| Asset | RTO (Recovery Time) | RPO (Recovery Point) | Justification |
|---|---|---|---|
| **Fly.io machine** (clean restart) | 5 min | N/A — stateless | `flyctl restart` cycle |
| **SQLite DB** (Litestream restore from R2) | 10 min | ~10 seconds | Litestream sync interval = 10s; restore = ~5 min download + sanity query |
| **Audit hash chain** (continuity) | Same as DB | ~10 seconds | Chain reseed on startup; gap marked with `__chain_break` row |
| **Encrypted credentials** | Same as DB | ~10 seconds | Encrypted-at-rest in same SQLite |
| **MCP sessions** | 30 min | N/A — re-issued on demand | `mcp-remote` re-auths automatically |
| **OAuth client registrations** | Same as DB | ~10 seconds | Encrypted in `oauth_clients` table; replicated |
| **Cloudflare R2 bucket** | 30 min | Last successful sync | Bucket re-create + Litestream re-sync from local DB |
| **Static egress IP** | Manual (Fly.io support) | N/A | Fly.io re-provision; users re-whitelist |
| **Telegram bot binding** | 24h | N/A | Token rotation requires user side too if bot URL changes |
| **Stripe billing state** | Per Stripe SLA | N/A | Stripe is source-of-truth; we sync via webhooks |

**Service-level targets**:
- **Tier 1 outage** (full service offline): RTO 30 min, RPO 10 seconds.
- **Tier 2 outage** (degraded — e.g., Telegram down): no RTO target; degrade gracefully.
- **Tier 3 outage** (data loss only): RTO 1 hour for re-creation of read-only state from upstream sources.

These targets are aspirational — actuals validated monthly via DR drill (§4).

---

## 2. Backup architecture

### 2.1 Primary persistence

- **SQLite database**: `/data/alerts.db` on Fly.io persistent volume `kite_data` (mounted at `/data`).
- **WAL journal**: in same directory; Litestream reads it.

### 2.2 Continuous replication (Litestream)

`etc/litestream.yml`:

```yaml
dbs:
  - path: /data/alerts.db
    replicas:
      - type: s3
        bucket: ${LITESTREAM_BUCKET}
        path: alerts.db
        endpoint: https://${LITESTREAM_R2_ACCOUNT_ID}.r2.cloudflarestorage.com
        region: auto
        sync-interval: 10s
```

Properties:
- **Sync interval**: 10 seconds (the RPO floor).
- **Target**: Cloudflare R2, APAC region (per [`MEMORY.md`](../MEMORY.md)).
- **Retention**: Litestream default 24h WAL window. Restore beyond 24h not supported via Litestream alone.
- **Cost**: $0/month at current scale (R2 free tier 10 GB egress; we're well under).
- **Encryption-in-transit**: TLS to R2.
- **Encryption-at-rest**: R2 SSE-S3 + application-layer AES-256-GCM (T1 tables).

Process: Litestream runs as a sidecar inside the same container as the Go binary. The entrypoint script (`Dockerfile`) supervises both.

### 2.3 Audit hash-chain external publication (opt-in, off by default)

Per [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) §3.11 / §4.1:

- Configured via `AUDIT_HASH_PUBLISH_*` env vars (see [`env-vars.md`](env-vars.md)).
- When enabled: publishes `HashTipPublication{tip_hash, entry_count, timestamp, signature}` to S3-compatible bucket every hour.
- Provides external anchor that an attacker rewriting the in-DB chain cannot forge.
- **Status**: opt-in; not enabled on the production deployment.

When enabled, this becomes a secondary backup surface for the hash chain only (not the full DB).

### 2.4 What is NOT backed up

- **Application logs** (stdout / Fly.io tail) — Fly.io's default log retention applies; logs are not separately archived.
- **Browser local storage** on `/dashboard` — user-side concern; per [`data-classification.md`](data-classification.md) §"Out of scope".
- **Stripe billing state** — Stripe is source of truth; webhooks resync.
- **Kite-side session state** — owned by Zerodha; ~24h refresh on their side.

---

## 3. Recovery procedures

### 3.1 Recovery Tier 1: Application restart (5 min)

Causes: panic without persistent corruption, OOM, transient network issue.

```bash
flyctl machine list -a kite-mcp-server
flyctl machine restart <machine-id> -a kite-mcp-server
```

Verification:

```bash
curl -s https://kite-mcp-server.fly.dev/healthz?format=json | jq
# Expect: status: ok; components: audit ok, riskguard ok
flyctl logs -a kite-mcp-server --limit 100 | grep -iE 'error|panic'
# Expect: no panics post-restart
```

If healthcheck still red after 60s: rollback per [`change-management.md`](change-management.md) §5.

### 3.2 Recovery Tier 2: Code rollback (5-10 min)

Causes: bad deploy with logic error.

```bash
flyctl releases -a kite-mcp-server
# Identify last-known-good version vN
flyctl rollback vN -a kite-mcp-server
```

Fly.io re-deploys the prior image. SQLite state is preserved (Litestream replica is unchanged — we only changed binary).

### 3.3 Recovery Tier 3: Data restore from R2 (10-30 min)

Causes: SQLite corruption, accidental delete, schema migration that broke data.

**Step 1 — Take service offline**:

```bash
flyctl scale count 0 -a kite-mcp-server
```

**Step 2 — Snapshot current (corrupted) state for forensics**:

```bash
flyctl ssh sftp get /data/alerts.db ./evidence/alerts.db.corrupt
sha256sum ./evidence/alerts.db.corrupt > ./evidence/alerts.db.corrupt.sha256
```

**Step 3 — Restore from R2 via Litestream**:

```bash
# On a workstation (with Litestream installed + R2 secrets in env):
litestream restore -o /tmp/restored.db -config etc/litestream.yml /data/alerts.db
sha256sum /tmp/restored.db
```

**Step 4 — Validate the restored DB**:

```bash
sqlite3 /tmp/restored.db "SELECT COUNT(*) FROM kite_tokens;"
sqlite3 /tmp/restored.db "SELECT COUNT(*) FROM tool_calls;"
sqlite3 /tmp/restored.db "PRAGMA integrity_check;"
```

`integrity_check` must return `ok`. Any other output = corrupted restore; halt and investigate.

**Step 5 — Push restored DB back to volume**:

```bash
# Stop machine first; volume not writable while machine is up
flyctl machine stop <id> -a kite-mcp-server
flyctl ssh sftp shell -a kite-mcp-server
# In sftp: put /tmp/restored.db /data/alerts.db
flyctl machine start <id> -a kite-mcp-server
```

**Step 6 — Verify hash chain continuity**:

The audit chain has a `__chain_break` marker for retention deletes ([`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) §3.10). Genuine corruption + restore creates a similar gap. Document this gap in `docs/evidence/incident-YYYY-MM-DD/timeline.md` so post-mortem cross-references it.

```bash
flyctl logs -a kite-mcp-server | grep -i 'chain'
# Expect: SeedChain successfully resumed at <hash>
```

### 3.4 Recovery Tier 4: Full re-deploy (30-60 min)

Causes: Fly.io app deletion, region migration, severe infrastructure compromise requiring fresh start.

1. **Recreate Fly.io app**: `flyctl apps create kite-mcp-server-v2` (new slug if `kite-mcp-server` is gone).
2. **Re-deploy**: `flyctl deploy -a kite-mcp-server-v2 --remote-only` from local clone of repo at last-known-good commit.
3. **Re-create persistent volume**: `flyctl volumes create kite_data --region bom --size 1`.
4. **Restore SQLite**: per §3.3 from R2 replica.
5. **Re-set all secrets**: see [`config-management.md`](config-management.md) §4.2 baseline list.
6. **Re-point DNS / OAuth callbacks**: update `EXTERNAL_URL`; update OAuth provider URLs; update Stripe webhook URL.
7. **Communicate** to users that the service URL has changed (one-time disruption — users re-authenticate via mcp-remote).

This is the worst-case path. Prevented by Litestream + Fly.io app stability.

### 3.5 Recovery Tier 5: Self-host fork takeover (manual, days)

Causes: Fly.io ban, financial inability to continue, regulator shutdown of hosted instance.

In this scenario: the operator publishes the source (already public) and instructs users to self-host. Migration guide: [`byo-api-key.md`](byo-api-key.md) + [`client-examples.md`](client-examples.md).

User responsibility:
1. Spin up own Fly.io / Render / VPS instance.
2. Build the binary from `master`.
3. Set their own `OAUTH_JWT_SECRET`, `EXTERNAL_URL`, `ADMIN_EMAILS`.
4. Re-register their Kite developer app callback at the new URL.
5. Re-enrol their Telegram chat IDs (if used).

**No data migrates** in this path — each user's encrypted data was on the hosted instance, which they cannot access. They re-bootstrap from Kite-side state. Annoying but not catastrophic.

---

## 4. DR drill (continuous validation)

### 4.1 Monthly automated drill

`.github/workflows/dr-drill.yml` runs `scripts/dr-drill.sh` on the 1st of each month at 03:30 UTC. The script:

1. Validates required env vars are set.
2. Restores the latest R2 replica to a scratch DB.
3. Verifies the file is non-empty.
4. Runs a sanity query (`SELECT COUNT(*) FROM kite_tokens`) — expects non-zero in production.
5. Optionally pings Telegram on success.

Exit codes:
- `0` — success
- `2` — missing env
- `3` — restore failed
- `4` — empty file
- `5` — sanity query failed

A failed drill turns the workflow red, surfacing in GitHub Actions and the operator's monitor. The NIST CSF 2.0 RC-function expectation is "periodic evidence that backups are recoverable" — the monthly drill is that evidence.

### 4.2 Quarterly DR tabletop

In addition to the automated drill, every quarter the operator runs a "what-if" tabletop:

| Quarter | Scenario | Walkthrough |
|---|---|---|
| 2026-Q2 | "Fly.io bom region is down for 4 hours." | Walk §3.4 mentally; identify any secret / DNS / OAuth-callback that would change |
| 2026-Q3 | "SQLite corruption discovered at 14:00 IST during market hours." | Walk §3.3 timeline; verify users see correct messaging |
| 2026-Q4 | "Cloudflare R2 bucket inaccessible." | Walk fallback — what happens to RPO if Litestream can't sync for 6 hours? |
| 2027-Q1 | "Operator laptop stolen with active Fly.io session." | Walk credential rotation sequence; verify 2FA prevents lateral movement |

Output: brief markdown note appended to `docs/evidence/dr-tabletop-YYYY-Qn.md` documenting any gaps found.

### 4.3 Annual full DR drill (recovery validation)

Once per year (typically Q1): execute §3.3 end-to-end on a NON-PRODUCTION clone of the app. Validates the full restore path including:

1. New Fly.io app spin-up.
2. Litestream restore from R2.
3. Schema integrity check.
4. Smoke test against the restored instance.
5. Tear down.

Budget: 2-3 hours of operator time + minimal Fly.io cost.

---

## 5. Recovery validation checklist

Before declaring recovery complete after any incident, verify:

- [ ] `/healthz?format=json` top-level `status: "ok"`.
- [ ] All `components.*.status` are `"ok"` or `"unknown"` (not `"disabled"`/`"dropping"`/`"defaults-only"`).
- [ ] `/healthz?format=json` `version` matches expected git SHA (per `server_version` MCP tool).
- [ ] Audit hash chain verifies clean (server log on startup).
- [ ] Litestream replication is current (WAL freshness <1 min).
- [ ] At least one full read tool succeeds end-to-end (e.g., `get_profile` from a test account).
- [ ] At least one write tool that's gated by RiskGuard returns expected behaviour (e.g., `place_order` with too-large value should be REJECTED, proving RiskGuard is wired).
- [ ] No errors in `flyctl logs --limit 500 | grep -iE 'error|panic|fatal'` post-recovery.
- [ ] If incident triggered notifications: confirmation that affected users received the breach notification (per [`incident-response.md`](incident-response.md) DPDP Rule 7).
- [ ] Forensic snapshot preserved with SHA-256 hash.
- [ ] Timeline document updated through recovery completion.

Recovery is NOT declared complete until ALL checks pass.

---

## 6. Communication during recovery

Per NIST CSF 2.0 RC.CO, recovery requires coordinated communication.

### 6.1 During an incident (Phase 4 of [`incident-response-runbook.md`](incident-response-runbook.md))

Status banner on `/dashboard`:

```
[BANNER] Recovering from incident YYYY-MM-DD HH:MM IST.
Estimated restoration: HH:MM IST. Updates: <link>.
```

Update banner at major milestones (containment → eradication → recovery → resolved).

### 6.2 During recovery

If RTO is exceeded materially (e.g., DB restore takes >30 min):

- Update users via Telegram (if bot is alive) or via the dashboard banner.
- Email the affected users from the grievance officer address with a brief status.
- Post a 1-line update on Twitter / Z-Connect / GitHub README — avoid technical jargon.

### 6.3 After recovery

- Email affected users: "service restored; what we did, what to verify on your side."
- Public post: 1 sentence acknowledging the incident and linking the post-mortem (when published).
- Update the incident timeline document with "RECOVERY COMPLETE: YYYY-MM-DD HH:MM IST".

Do NOT use the recovery email to announce new features or solicit feedback — keep it factual and incident-scoped.

---

## 7. Post-recovery actions

Within 30 days of recovery:

| Action | Owner | Output |
|---|---|---|
| Post-mortem | Maintainer | `docs/post-mortems/YYYY-MM-DD-<slug>.md` (per [`incident-response.md`](incident-response.md) §"Post-incident") |
| Independent review | External security engineer | Appendix to post-mortem (~₹15-25k budget) |
| Threat-model update | Maintainer | Add adversary / surface row to [`threat-model-extended.md`](threat-model-extended.md) §1/§2 |
| Risk register update | Maintainer | Adjust likelihood / impact in [`risk-register.md`](risk-register.md) |
| Process improvement | Maintainer | Update relevant runbook (this file, [`incident-response-runbook.md`](incident-response-runbook.md), [`continuous-monitoring.md`](continuous-monitoring.md)) |
| Public post-mortem | Maintainer | Personal blog + GitHub README link |
| CHANGELOG entry | Maintainer | Note the incident date + fix commits |
| Re-submit closure | Maintainer | CERT-In closure report; DPB closure when portal accepts (per [`incident-response.md`](incident-response.md)) |

---

## 8. Recovery dependencies

This section enumerates what we depend on — IF these are also down during the recovery, RTO inflates.

| Dependency | Failure scenario | Mitigation |
|---|---|---|
| Fly.io control plane | `flyctl` commands fail | Wait; Fly.io status page; community.fly.io |
| Cloudflare R2 | Restore from replica blocked | If local SQLite is intact, no impact; if not, RPO extends to last successful snapshot |
| GitHub | CI / source pull blocked | Use local clone; deploy from local |
| Maintainer's network connection | Operator can't issue commands | Multi-factor: phone hotspot; coffee shop wifi; etc. |
| Maintainer themselves | Solo operator unavailable | This is the structural risk of single-maintainer projects ([`incident-response.md`](incident-response.md) §4.5) |

The maintainer-availability risk is documented; not yet mitigated. Future: deputy operator + shared admin credentials.

---

## 9. Capacity / scale recovery considerations

If the incident is caused by a scale event (sudden user growth), recovery includes scale-up:

| Symptom | Scale action |
|---|---|
| Memory >80% sustained | `flyctl scale memory 1024 -a kite-mcp-server` (1GB) |
| CPU >70% sustained | `flyctl scale vm performance-1x -a kite-mcp-server` |
| Disk >80% on `/data` volume | `flyctl volumes extend <volume-id> --size 5` (5GB) |
| Audit dropped_count climbing | Larger volume + investigate Litestream throughput |
| Connection pool exhaustion | Investigate; SQLite is single-writer; CGo-free `modernc.org/sqlite` is the bottleneck under high write |

These are SCALE-fixes, not RECOVERY-fixes. Recovery restores baseline; scale prevents recurrence.

---

## 10. Out of scope

- **Full geographic disaster recovery** (different continent backup) — gated on second broker per [`fly.toml`](../fly.toml) annotation.
- **Multi-tenant sharded architecture** — out of scope at current scale.
- **Disaster recovery for self-host operators** — they own their own RTO/RPO; we provide procedure documentation, not infrastructure.
- **Cyber insurance claim filing** — operator handles per insurance contract; no project-level pre-arrangement.

---

## 11. Cross-references

- [`incident-response.md`](incident-response.md) — incident response scenarios + DPDP/CERT-In timelines
- [`incident-response-runbook.md`](incident-response-runbook.md) — Phase 4 (Recovery) handoff to this doc
- [`monitoring.md`](monitoring.md) §"Daily ops checklist" — ongoing posture verification
- [`continuous-monitoring.md`](continuous-monitoring.md) §3 — alerts that trigger recovery
- [`change-management.md`](change-management.md) §5 — code/config rollback procedures
- [`config-management.md`](config-management.md) §3 — secret rotation
- [`asset-inventory.md`](asset-inventory.md) §8 — asset criticality (RTO ranking)
- [`vendor-management.md`](vendor-management.md) §6 — vendor incident response
- [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) §3.18 — Litestream backup
- [`RETENTION.md`](RETENTION.md) §5 — Litestream retention details
- [`scripts/dr-drill.sh`](../scripts/dr-drill.sh) — automated DR drill
- [`.github/workflows/dr-drill.yml`](../.github/workflows/dr-drill.yml) — monthly cron
