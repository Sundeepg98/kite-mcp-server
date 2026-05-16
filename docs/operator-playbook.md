# Operator Playbook

Day-2 operations for Kite MCP Server. Written for a single operator
(Sundeep) running the Fly.io deployment, or a future self-hoster
running the same Docker image.

Runbook, not tutorial. Assumes you can read Go logs, know `flyctl`
basics, and have `./scripts/smoke-test.sh` on hand.

Release-day steps live in [release-checklist.md](release-checklist.md).
Endpoint and env-var reference: [env-vars.md](env-vars.md) and
[SECURITY_POSTURE.md](SECURITY_POSTURE.md).

---

## 1. Morning routine (5 minutes)

Before opening Claude. If any check fails, jump to the matching
section below.

1. **Component health**
   ```bash
   curl -s https://kite-mcp-server.fly.dev/healthz?format=json | jq .
   ```
   Expect top-level `status: ok` and `components.audit.status: ok`,
   `components.riskguard.status: ok`. `kite_connectivity` and
   `litestream` will be `unknown` (neither probed in-process).

2. **Kite token refreshed**
   Daily refresh window is ~7:35 AM IST. Run any read-only tool
   (`get_profile` is fine) — success means your session is good.
   Failure with "Kite token expired" triggers seamless re-auth via
   mcp-remote — click through Kite login once, done.

3. **Audit buffer drop count**
   From healthz JSON, `components.audit.dropped_count` must be `0`.
   - 1–10 drops: acceptable burst, no action.
   - 10–100 drops: inspect SQLite / Litestream throughput:
     `flyctl logs -a kite-mcp-server | grep -iE 'audit|litestream'`.
   - 100+: sustained write problem — this is a compliance gap. Escalate
     via § 6 step 4.

4. **Recent errors**
   ```bash
   flyctl logs -a kite-mcp-server --limit 200 | grep -iE 'panic|error|fatal' | head
   ```
   Third-party warnings are fine. App-layer ERRORs are not.

If any of these are red, **do not place orders** until resolved. A
silent audit gap is worse than a missed trade.

## 2. When tools fail — decision tree

### HTTP 401 from `/mcp`
MCP bearer JWT rejected, or the Kite token under it expired.

- MCP bearer expired (24h lifetime, `oauth/config.go:31`) — mcp-remote
  re-auths automatically on the next call. Nothing to do.
- Kite token expired at the ~6 AM IST window — middleware `RequireAuth`
  returns 401 on purpose so mcp-remote triggers a silent re-auth. User
  clicks through Kite login once, fresh token caches.
- 401 persists through manual re-auth — the OAuth client record is
  stale. Ask the user to run `login` again to re-register their Kite
  API key/secret.

### HTTP 429 from any tool
Rate limiter tripped. Two scopes, distinguishable by the
`X-RateLimit-Scope` response header (added in commit `0b1724d`):

- `ip` — shared IP limit (auth 2/sec, token 5/sec, MCP 20/sec). Too
  many callers from one egress. Wait and retry.
- `user` — per-email limit. A single user hammering the server. If
  it's not you, someone is abusing your self-hosted instance.

Both include `Retry-After`. Respect it.

### HTTP 500 from any endpoint
Something threw. The smoke test explicitly requires `/mcp` to return
401/405 and never 500 — a 500 there means middleware is broken.

```bash
flyctl logs -a kite-mcp-server | grep -A 40 panic | head -60
flyctl logs -a kite-mcp-server --limit 500 | grep -iE 'ERROR|panic|500' | head
```

Common causes:
- CQRS duplicate handler (now returns error at startup instead of
  panicking at request time — commit `4a37f10`).
- Event-sourcing subscribe gap (e.g. the `family.member_removed`
  bug, commit `95ce99f` — symptom: events vanish from audit).
- Broker adapter retry exhaustion (`retryOnTransient` tries 3 times;
  3rd failure surfaces to user).

A persistent 500 > 5 min warrants rollback — do not hot-fix on master.

## 3. Daily: Kite token refresh (~7:35 AM IST)

Kite tokens expire daily at ~6 AM IST (`kc/expiry.go`). Users log in
once per trading day, typically 7:30–9:00 AM IST.

- The landing page advertises this:
  `"Daily refresh: Kite sessions auto-refresh at ~7:35 AM IST... takes 10 seconds."`
  (`kc/templates/landing.html:320`.)
- Dashboard shows a session-expired banner when the token is stale.
- Morning Telegram briefing (9 AM IST) still sends status/alerts when
  the token is stale, but skips order-sensitive content.
- First question when a user reports morning order failures: "have
  you logged in today?"

You cannot refresh tokens on the user's behalf — Kite's OAuth flow
requires them to click through `kite.zerodha.com`. No workaround.

## 4. Weekly

Do this Monday morning after Dependabot's batch lands (scheduled 04:00
IST Monday — `.github/dependabot.yml`).

- [ ] **Audit drop trend.** Compare this week's cumulative
      `dropped_count` to last week's. More than ~1,000 drops in a
      week means the async writer needs tuning.
- [ ] **R2 backup sync.** Litestream replicates `/data/alerts.db`
      every 10 seconds (`etc/litestream.yml`). Most-recent WAL
      segment under `s3://<LITESTREAM_BUCKET>/alerts.db/` should be
      under a minute old during trading hours. Older than an hour
      during active use → restart the Fly machine and monitor.
- [ ] **Stale sessions.** Call `list_mcp_sessions` (commit `ee345e0`).
      Any session older than 7 days with `recent_tool_calls = 0` is
      abandoned — revoke with `revoke_mcp_session`.
- [ ] **Activity timeline.** `/dashboard/activity` — look for
      repeated tool failures (often reveals a deprecated Kite API
      or a changed symbol).
- [ ] **Dependabot PRs.** Minor/patch Go + GH Actions bumps are
      grouped one-PR-per-ecosystem. Review, `go test ./... -count=1`,
      merge. Major bumps come individually — closer look on
      `gokiteconnect` and `mcp-go` especially.

## 5. Monthly

- [ ] **Dependency sweep.** Pick up any Dependabot PRs you skipped
      weekly. For majors, read the upstream changelog before merge.
- [ ] **SEBI compliance re-read.** [SECURITY_POSTURE.md](SECURITY_POSTURE.md)
      end-to-end. Refreshes mental model and surfaces drift (retention
      window, encryption scheme, audit chain config).
- [ ] **Audit table size.** 90-day retention was bumped to 5 years
      for SEBI. Check the `tool_calls` row count isn't approaching
      tens of millions on SQLite — plan a Postgres migration before
      you get to hundreds of millions. See § 7 for scale signals.
- [ ] **OAUTH_JWT_SECRET rotation — quarterly cadence.**
      **Recommended cadence: every 90 days, on the 1st Monday of
      Jan/Apr/Jul/Oct, ~04:00 IST (low-traffic maintenance window).**
      Aligns with NIST SP 800-57 Part 1 guidance for symmetric keys
      protecting authentication tokens. Calendar reminder owns the
      cadence; rotation itself is the gated activity.

      **Why not "breach-only"?** Breach-only is a defensible stance
      but requires a robust leak-detection signal we don't currently
      have (no SIEM integration, no canary tokens, no automated
      anomaly alerting on the audit table). Quarterly cadence gives
      the same forward-secrecy benefit with a predictable
      maintenance cost. Switch to breach-only when leak-detection
      is wired and proven. **Until then, quarterly is the safer
      default** — committed to by this playbook.

      **Use Option B (re-encrypt-during-grace) — zero forced
      re-login.** Procedure (full runbook at
      `.research/decisions/rotate-key-runbook-2026-05-11.md`):
      ```bash
      OLD=$(flyctl secrets list -a kite-mcp-server | grep OAUTH_JWT_SECRET | head -1)  # paste current
      NEW=$(openssl rand -hex 32)
      # Step 1: install PREVIOUS so existing JWTs keep verifying
      flyctl secrets set OAUTH_JWT_SECRET_PREVIOUS=$OLD -a kite-mcp-server
      # Step 2: offline re-encrypt all encrypted columns
      flyctl ssh sftp get /data/alerts.db ./alerts.db
      go build -o rotate-key ./cmd/rotate-key
      ./rotate-key -db ./alerts.db -old-secret $OLD -new-secret $NEW
      flyctl ssh sftp put ./alerts.db /data/alerts.db
      # Step 3: promote NEW; PREVIOUS keeps grace window alive
      flyctl secrets set OAUTH_JWT_SECRET=$NEW -a kite-mcp-server
      # Step 4: after 7-day grace window, drop PREVIOUS
      flyctl secrets unset OAUTH_JWT_SECRET_PREVIOUS -a kite-mcp-server
      ```
      The two-secret graceful pattern (`OAUTH_JWT_SECRET_PREVIOUS`)
      means existing MCP bearers + dashboard cookies keep verifying
      through the 7-day grace window. **Zero forced re-login** if
      the runbook is followed end-to-end. (Skipping the grace forces
      every user to re-authenticate on next request — annoying but
      not data-loss; the encryption rotation itself is complete.)

      **Breach-triggered supplement**: rotate IMMEDIATELY (skipping
      the grace window — re-login is acceptable when integrity is
      uncertain) if any of: leaked-secrets scan hits, unexpected
      tool calls from foreign egress IP, mysterious DB writes.
      See § 6 Incident Response.

## 6. Incident response

If compromise is suspected (unexpected tool calls, foreign egress IP,
mysterious DB modifications), do these **in order** — no parallelising.

1. **Kill switch.** From your MCP client, call `admin_freeze_global`
   with `confirm: true`. Flips the riskguard kill switch; blocks all
   place/modify/GTT orders on the next tool call, no deploy required.
   (`mcp/admin_risk_tools.go:215`.) If your MCP client is itself
   suspect, use `/admin/ops` in the browser — protected by
   `ADMIN_ENDPOINT_SECRET_PATH` and `ADMIN_EMAILS`.

2. **Rotate every secret.**
   - `OAUTH_JWT_SECRET` (see § 5) — forces all clients to re-auth.
   - Kite API key + secret on kite.trade/console — invalidates the
     static-egress-whitelisted app. Re-whitelist `209.71.68.157`
     under the new app.
   - `TELEGRAM_BOT_TOKEN` via `@BotFather`.
   - R2 access key on the Cloudflare console — Litestream stops
     restoring until you update `LITESTREAM_ACCESS_KEY_ID` /
     `LITESTREAM_SECRET_ACCESS_KEY`.
   - `ADMIN_ENDPOINT_SECRET_PATH` — pick a new random path.

   Roll all onto Fly in one `flyctl secrets set` to minimise
   restarts.

3. **Alert users.** Pinned GitHub Discussion + Telegram DM. Include
   what happened, what they need to do (log in again; rotate their
   own Kite key/secret if per-user credentials were stored), and
   whether the audit trail is intact.

4. **Audit log investigation.** The audit log is append-only with a
   hash chain (commit `3591cc6` adds external publishing). If the
   chain is intact you can prove which events were authentic.
   ```bash
   # Human-readable
   open https://kite-mcp-server.fly.dev/dashboard/activity?days=30
   # Scriptable — CSV or JSON via the dashboard export endpoints
   ```
   Look for calls from unknown IPs, emails you don't recognise, or
   write-tool bursts from a single session. `list_mcp_sessions`
   output tells you which sessions to revoke.

5. **Post-mortem.** Timeline, scope, root cause, fix, prevention.
   Even solo, the writing discipline catches what memory smooths.

## 7. Scale signals

None currently apply. Flag early if any get close.

- **Fly machine (currently 512MB shared 1 CPU).** Bump to
  Performance-1x (2GB, 1 dedicated vCPU) when CPU sustains > 70%
  during market hours, memory regularly crosses 400MB
  (`flyctl metrics -a kite-mcp-server`), or ticker connections
  start dropping.
- **Postgres migration.** Stay on SQLite until `tool_calls` crosses
  ~50M rows and activity dashboard queries exceed 100ms, or you
  need multi-writer / read replicas. Fly has managed Postgres;
  keep Litestream running during the cutover for rollback safety.
- **Multi-region.** Skip until you add a non-Kite broker. Kite's own
  API is India-only so egress still flows through BOM regardless.
- **Multi-broker.** The `broker.Client` port is already abstracted;
  adding Upstox or Groww is a `broker/<name>/` adapter. Triggers:
  user demand, Kite dependency reduction (₹500/month/app, pricing
  could change), or regulatory arbitrage.
- **External alerting.** Currently none. When self-hosted by a team,
  wire `/healthz?format=json` into the team's on-call system. Solo
  operation: Telegram briefing + manual healthz is enough.

---

## Useful one-liners

```bash
flyctl logs -a kite-mcp-server
flyctl status -a kite-mcp-server
flyctl secrets list -a kite-mcp-server                 # names only
flyctl releases -a kite-mcp-server
flyctl releases rollback <VERSION> -a kite-mcp-server

./scripts/smoke-test.sh                                 # 9 checks, ~10s
curl -s https://kite-mcp-server.fly.dev/healthz?format=json | jq .
# In your MCP client: run `test_ip_whitelist` to verify Kite IP whitelist.
```
