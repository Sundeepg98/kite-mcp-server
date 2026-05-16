<!-- secret-scan-allow: docs-cite-public-flyctl-deployment-and-image-tags -->

---
as-of: 2026-05-11
re-verify-by: 2026-08-11
prior-doc: .research/day-1-launch-ops-runbook.md (2026-05-03 at HEAD `14a188e`)
master-head-at-write: 652e848
verification-method: live `/healthz` curl + fly MCP `fly-status`/`fly-ips-list` empirical probes + git log of operational deltas since 2026-05-03
dispatch: refresh Day-1 launch ops runbook given 12 days of MCP/automation gains
status: READ-ONLY; doc-only; single commit
---

# Day-1 Launch Ops — 2026-05-11 Refresh

> Refresh of `.research/day-1-launch-ops-runbook.md` (2026-05-03) given today's operational deltas: fly MCP installed (60 tools), dr-decrypt-probe binary shipped (closes the HKDF verification gap that was a known TODO), H1 secret-scan hook in maintenance-OS design (mostly user-side), and the falsified egress-IP "staleness" investigation. Cloudflare Code Mode + Bitwarden MCP install plan is on the bench (not yet installed). All claims dated; all probes empirical.

---

## Lead summary — what changed in 12 days

Six operational deltas affect Day-1 launch ops, dated 2026-05-11 from the prior runbook at 2026-05-03. Each cited:

1. **Fly MCP installed** (`9a0079b`, 2026-05-16): 60 structured-JSON tools across 9 namespaces replace ~20 of the `flyctl` shell-outs in the prior runbook. `fly-status`/`fly-ips-list`/`fly-apps-releases`/`fly-secrets-list`/`fly-secrets-set`/`fly-machine-clone`/`fly-machine-restart` are the most-touched on launch day. The MCP server is built into `flyctl` itself (v0.4.14, `flyctl mcp server`) — Fly first-party, not a third-party wrapper. Targets Claude Desktop by default; Claude Code wired via project-scope `.mcp.json`.
2. **dr-decrypt-probe binary shipped** (`14a215d`, 2026-05-10): `cmd/dr-decrypt-probe/` exists with 7 tests passing. Exit codes 0/1/2/5/6 map to success/generic/short-secret/missing-salt/auth-tag-fail respectively. **Closes the "restore drill is honestly TODO" caveat in §5.2 of the prior runbook.** Disaster-recovery verification is now agent-doable end-to-end.
3. **DR drill executed** (`25b201a`, 2026-05-10): R2 backup chain confirmed healthy on production — Litestream PID 645 actively replicating, sync-interval 10s, restore byte-equivalent to live DB, `hkdf_salt` 32 bytes survived restore. **PARTIAL PASS** historically because the probe binary didn't exist yet; now closed by item 2 above. Repo GitHub Actions secrets (4 R2 + 2 Telegram) **still not provisioned** — `dr-drill.yml` monthly cron continues to fail at the env-var gate.
4. **Static egress IP claim FALSIFIED-then-RECONFIRMED** (`7559133`, 2026-05-16): the fly-MCP audit's truncated `fly-ips-list` response shipped a false "no `209.71.68.157` anywhere" finding. Live `flyctl ips list -a kite-mcp-server --json` (this dispatch + 3 peer audits 2026-05-11) confirms **`209.71.68.157` IS the dedicated `egress_v4` in `bom`, created 2026-04-01, unchanged.** Prior runbook's reliance on this IP for SEBI Kite-developer-app whitelisting is **correct**. No patch needed to user-shippable docs.
5. **H1 secret-scan PreToolUse hook designed** (`.research/maintenance-strategy/maintenance-model.md` §H1, 2026-05-11): planned `~/.claude/hooks/validators/pre-write-secret-scan.py`, fail-closed PreToolUse on `Write|Edit|MultiEdit`. **Status: designed not implemented.** Today's runbook authors are inserting `<!-- secret-scan-allow: ... -->` directives in research docs anticipating the hook landing — five docs already carry the allow header. **Day-1 implication**: if H1 lands before launch, accidental secret-paste during incident response is structurally prevented. If not, the discipline is still in the doc convention.
6. **Cloudflare Code Mode + Bitwarden MCP install plans drafted** (`652e848`, 2026-05-16): two-page concrete install plans on the bench. **Not yet installed.** Code Mode would close R2 ops via 2 tools wrapping the 2,500+ Cloudflare API endpoints (R2 token rotation, DNS, bucket inspection) — useful for post-launch ops but NOT Day-1 critical. Bitwarden MCP would resolve the I10/I11 plaintext-credentials-in-memory problem structurally; same — not Day-1 critical.

Production state at this writing (empirical `curl /healthz`, 2026-05-11):
- `status: ok`, `version: v1.3.0`, `uptime_s: 467947` (≈5.4 days continuous), `anomaly_cache.status: ok` (new field since prior runbook), `audit.status: ok`, `riskguard.status: ok`.
- `kite_connectivity` and `litestream` report `unknown` by design — neither probed in-process, matches `docs/monitoring.md` § 1.

---

## TL;DR — three critical pre-Submit items (refreshed)

These remain the launch-day go/no-go. Updated commands to use the fly MCP tool surface where available.

1. **Pre-stage a second `bom` machine 10 min before submission.** Now via fly MCP, not shell-out:
   - **`fly-status({app: "kite-mcp-server"})`** — capture current machine id (e.g., `2863d22b7eee18`), image tag (e.g., `deployment-01KR9FPJC88YA80VWS7VMTWTY7`), and version (e.g., `273`) into a scratch file. Returns structured JSON, strictly superior to `flyctl status` shell-out.
   - **`fly-machine-clone({app: "kite-mcp-server", id: "<machine-id>"})`** — clones the existing machine in the same region (`bom`). Egress IP `209.71.68.157` shared (re-confirmed by the IP-staleness sweep) — SEBI Kite-developer-app whitelist unaffected.
   - **`fly-status` again** — verify machine count = 2. Cost: ~$0.30–0.60/day extra; tear down via `fly-machine-stop` post-launch.

2. **Capture last-known-good release snapshot via fly MCP** instead of `flyctl releases list`:
   - **`fly-apps-releases({name: "kite-mcp-server"})`** — returns full release history as structured JSON (15KB+ for our app). The top entry's `ID` + `Version` + `ImageRef` is the rollback target. Paste into a scratch sticky note visible all day.
   - **No `flyctl deploy` between snapshot and post-launch + 24h.** Code freeze. Day-0 diff = "zero new code shipped."

3. **Validate `/healthz?format=json` is green AND run dr-decrypt-probe AT LEAST ONCE pre-launch.** This is the meaningful upgrade vs the prior runbook:
   - **Smoke test**: `./scripts/smoke-test.sh https://kite-mcp-server.fly.dev` — 13 checks, all must pass.
   - **Litestream WAL freshness**: `flyctl ssh console -a kite-mcp-server -C 'ls -la /data/alerts.db-wal'` (no fly MCP equivalent — `fly-machine-exec` is the closest but no current install of it has been live-tested for `ssh console`-class probes; shell-out still the right tool here).
   - **dr-decrypt-probe (NEW, not in prior runbook)**: run the binary against a restored scratch DB to confirm the HKDF→AES-256-GCM chain decrypts. Exact procedure:
     ```bash
     # In WSL2, ~2 minutes:
     # 1. Restore R2 backup to scratch path
     mkdir -p /tmp/dr-launch-day && cd /tmp/dr-launch-day
     litestream restore -o /tmp/dr-launch-day/restored.db -if-replica-exists \
        -config <(envsubst < /mnt/d/Sundeep/projects/kite-mcp-server/etc/litestream.yml) \
        /data/alerts.db

     # 2. Probe the decryption chain
     export OAUTH_JWT_SECRET="$(flyctl secrets list -a kite-mcp-server | grep OAUTH_JWT_SECRET)"   # paste the real value here (32+ bytes)
     /tmp/dr-decrypt-probe -db /tmp/dr-launch-day/restored.db
     # Exit 0 = chain works end-to-end. Exit 5 or 6 = HALT LAUNCH.

     # 3. Cleanup
     rm -rf /tmp/dr-launch-day
     ```
     Exit codes from `cmd/dr-decrypt-probe/main.go`:
     - `0` — success, every encrypted column decrypted, AES-GCM auth-tag verified.
     - `1` — generic error (bad -db path, file open).
     - `2` — `OAUTH_JWT_SECRET` unset OR <32 bytes.
     - `5` — `hkdf_salt` missing from `config` table; catastrophic restore loss.
     - `6` — AES-GCM auth-tag failure (wrong secret OR salt corrupted).
   - **NEW go-criterion**: dr-decrypt-probe exit 0 within 2 min of pre-launch. If exit 5 or 6, defer launch.

If any of these three is red, **defer the launch by 24–48 hours**. HN re-submission is allowed; a botched launch is harder to recover from.

---

## Simulated incident walkthrough — "user reports 502 from /mcp at 10:00 AM"

The prior runbook's Phase 4a covered "`/healthz` 5xx" in the abstract. Walk through it with today's tooling to find the friction.

**Scenario**: HN front-page hour 1.5; a commenter posts "tried to wire up Claude Desktop, getting 502 from `/mcp`." Five other comments seconding it.

### Step 1 (00:00–00:30) — Triage: real or false positive?

**Prior runbook**: `curl -s -o /dev/null -w "%{http_code}" https://kite-mcp-server.fly.dev/healthz` returns 5xx for >2 min, OR `flyctl status` shows machine red.

**Today's tools**:
- **Empirical `curl`** stays — fastest, agent-callable via Bash. Result this dispatch: `status: ok, uptime_s: 467947, version: v1.3.0`.
- **NEW `fly-status({app: "kite-mcp-server"})` via fly MCP** — returns structured JSON with machine state, image tag, region, full release history reference. Strictly superior to shell-out `flyctl status` for parseable signals.

**Friction**: zero. fly MCP `fly-status` returns the same data as `flyctl status` plus more (machine name like `purple-darkness-3572`, full image_ref including digest). Agent can parse the JSON without regex on shell output. **WIN over prior runbook.**

### Step 2 (00:30–02:00) — Identify the cause

**Prior runbook**: `flyctl logs -a kite-mcp-server --limit 500 | grep -A 20 panic | head -80`.

**Today's tools**:
- **fly MCP `fly-logs({app: "kite-mcp-server"})`** — exists but **not load-tested by us on a real 502 scenario yet**. Per the install audit (§3 of `fly-mcp-empirical-install-2026-05-11.md`), `fly-logs` is in the 60-tool surface but its exact response shape (streaming? snapshot? line-limit?) wasn't probed during install verification.
- **Shell-out `flyctl logs` remains the load-bearing fallback** if `fly-logs` MCP behaves strangely under stress.

**Friction surfaced**: `fly-logs` is an unknown-quantity tool for incident response. **Recommendation: pre-launch, dry-run `fly-logs({app: "kite-mcp-server"})` once and verify the response shape.** ~5 minutes of friction-mitigation. If response is paginated/cursor-based or has a 2-second timeout for long logs, the prior runbook's `--limit 500 | grep` shell-out beats it on raw operator speed.

### Step 3 (02:00–05:00) — Decide: rollback or scale?

**Prior runbook**:
```bash
flyctl releases -a kite-mcp-server                 # find prior release vN
flyctl rollback vN -a kite-mcp-server               # ETA <5 min
```

**Today's tools**:
- **fly MCP `fly-apps-releases({name: "kite-mcp-server"})`** — returns 15KB+ structured JSON history. Strictly superior. Top entry's `Version` (e.g., `273`) and `ImageRef` (e.g., `registry.fly.io/kite-mcp-server:deployment-01K...`) are the rollback target.
- **There is NO `fly-rollback` MCP tool** (intentional — deploys are destructive per Fly's design). The actual rollback is still `flyctl deploy --image <prior-ImageRef>` OR `flyctl releases rollback` shell-out. Per `fly-mcp-empirical-install-2026-05-11.md` §3.2, this is the **only confirmed gap** in the fly MCP surface for our workflow.

**Friction**: medium. Identifying the rollback target is faster (structured JSON); executing the rollback is unchanged. **Net win** because the bottleneck is "which release was last good?" and that's exactly what `fly-apps-releases` answers.

### Step 4 (05:00–10:00) — Recovery and post-mortem stub

**Prior runbook**: Post a single GitHub Discussion + one HN reply: "Hosted demo briefly down — investigating."

**Today's tools (delta)**:
- **No automation change for the comms step.** GitHub MCP would help (it's in the Track 3 install queue but not installed); for now, `gh issue create` and HN web-form. Unchanged.
- **H1 secret-scan hook**, if landed by launch day, prevents accidentally pasting a real `OAUTH_JWT_SECRET` or `Fly-API-Token` into an incident-response GitHub comment under stress. This is the structural win mentioned in the lead summary.

**Friction**: unchanged, but the H1 hook reduces a Day-1 footgun (paste-a-secret-into-comment-under-stress) if it's live.

### Net assessment

For a 502 incident, the fly MCP gains:
- **+1 win**: `fly-status` and `fly-apps-releases` return structured JSON, faster parse.
- **+1 unknown**: `fly-logs` response shape not pre-verified.
- **+1 H1 mitigation** (if landed): structural prevention of comment-paste secret leaks.

**Single biggest friction-mitigation action before launch**: dry-run `fly-logs` once. Five minutes of effort to know its behavior. If it doesn't work for the use-case, stick to shell-out `flyctl logs`. Don't discover its quirks during a live incident.

---

## Phase-by-phase delta from prior runbook

### Phase 1 — Rate-limit and capacity posture

**Unchanged** in mechanism. Rate-limit defaults (auth 2/sec, token 5/sec, MCP 20/sec — layered per-IP AND per-user) verified at `app/ratelimit.go:182-197` in the prior runbook; no commit since then has touched `ratelimit.go`. The capacity-stage second-machine recommendation from prior TL;DR is now executable via `fly-machine-clone` (cleaner than shell-out).

**New consideration**: production uptime is now empirically `~5.4 days continuous` (`uptime_s: 467947`). That's a useful baseline — at HN-surge time the machine should still report uptime in the same range UNLESS a deploy or restart intervenes. Sudden `uptime_s` reset during launch = machine crash-loop signal.

### Phase 2 — First 90-min HN comment triage

**Unchanged** in workflow. The minute-by-minute breakdown (0-15 wait, 15-30 triage, 30-60 cadence, 60-90 freeze, 90+ step-back) and prepared replies live in `.research/show-hn-redteam-rehearsal.md` and `docs/show-hn-post.md`. No new comment-content delta in 12 days.

**Minor delta**: `gh` CLI is **the only blessed way** to interact with GitHub Issues / PR comments on the day (per the global `.claude/CLAUDE.md` rule "use gh CLI for data ops, Chrome for visual"). GitHub MCP is on the install bench (rank #2 in Track 3) but **not installed today**. Don't pivot to it mid-launch.

### Phase 3 — Day-1 metrics dashboard

Refreshed commands (replace shell-outs with fly MCP where available):

```bash
# /healthz — unchanged, still the truth.
curl -s https://kite-mcp-server.fly.dev/healthz?format=json | jq .
# Healthy: status=ok, components.audit.status=ok, components.riskguard.status=ok,
#          components.anomaly_cache.status=ok, audit.dropped_count=0 (if exposed).
# NEW since prior runbook: anomaly_cache component is now reported.

# Smoke test (unchanged)
./scripts/smoke-test.sh https://kite-mcp-server.fly.dev

# Machine state — UPGRADED from shell-out
# Old: flyctl status -a kite-mcp-server
# New: fly-status({app: "kite-mcp-server"}) via fly MCP — returns structured JSON

# Release history — UPGRADED from shell-out
# Old: flyctl releases -a kite-mcp-server
# New: fly-apps-releases({name: "kite-mcp-server"}) via fly MCP

# Logs — STILL shell-out (fly-logs MCP not load-tested)
flyctl logs -a kite-mcp-server | grep '/mcp '
flyctl logs -a kite-mcp-server --limit 500 | grep -iE 'error|panic|fatal' | head -50

# OAuth completions — unchanged (still flyctl ssh sqlite)
flyctl ssh console -a kite-mcp-server -C 'sqlite3 /data/alerts.db \
  "SELECT COUNT(DISTINCT user_email) FROM tool_calls \
   WHERE ts > datetime(\"now\", \"-2 hours\");"'

# Memory / CPU — shell-out remains (fly-status returns machine state, not metrics)
flyctl metrics -a kite-mcp-server
```

### Phase 4 — Incident response decision trees

**4a (hosted demo crashes)**: above walkthrough. Mostly unchanged; `fly-status`/`fly-apps-releases` upgrade.

**4b (`/mcp` traffic surge causes session-store DOS)**: unchanged. Fly.io edge-block via dashboard remains the move; no MCP tool covers edge-rules today.

**4c (Zerodha C&D email)**: unchanged. `docs/drafts/zerodha-compliance-email.md` remains the template; `docs/incident-response.md` Scenario 4 the formal procedure.

**4d (SEBI-adjacent hostile voice)**: unchanged.

**4e (HN top-voted unfair criticism)**: unchanged. Prepared replies in `.research/show-hn-redteam-rehearsal.md`.

**4f (RiskGuard false-positive)**: unchanged. Riskguard check count is now empirically 11 per `.claude/CLAUDE.md` (vs the prior runbook's reference of 8–9). The threshold-tightening procedure remains via env vars.

**NEW Phase 4g — credentials-suspected compromise mid-launch**: if a credential leak is suspected during launch (e.g., a screenshot of `flyctl secrets list` accidentally tweeted, or H1 hook flags a paste attempt), the rotation procedure is:

```
1. fly-secrets-list({app: "kite-mcp-server"}) — confirm which secret is suspected
2. Rotate OAUTH_JWT_SECRET first (highest blast radius):
   - Old prior-runbook: flyctl secrets set OAUTH_JWT_SECRET=$(openssl rand -hex 32) -a kite-mcp-server
   - New via fly MCP: fly-secrets-set({app: "kite-mcp-server", keyvalues: "OAUTH_JWT_SECRET=<new>"})
3. Machine auto-restarts. /healthz uptime_s resets — expected.
4. Affected users re-auth via mcp-remote (transparent OAuth refresh).
5. Run dr-decrypt-probe to confirm the NEW secret decrypts the EXISTING DB:
   /tmp/dr-decrypt-probe -db /tmp/dr-launch-day/restored.db
   (exit 0 = key chain works with rotated secret + existing salt; exit 6 = HALT)
6. Post one HN reply: "Rotated a credential out of caution; service restored."
```

**Key point**: dr-decrypt-probe makes credential rotation testable in <2 min instead of "redeploy and hope." This wasn't possible in the prior runbook.

### Phase 5 — Disaster recovery (Litestream) — MAJOR REFRESH

**Prior runbook**: "Restore drill itself is honestly TODO — the chain has not been demonstrated end-to-end against this deployment's encryption keys; deferred to post-launch weekend."

**Today**:
- DR drill executed 2026-05-10 (`25b201a`). R2 backup chain confirmed healthy. Restore-from-R2 byte-equivalent to live DB. `hkdf_salt` survives restore.
- dr-decrypt-probe binary shipped (`14a215d`). 7 tests pass on WSL2 Go 1.25.0.
- The end-to-end "restore → decrypt → smoke-test encrypted columns" chain is **agent-doable in <5 min**. No longer a TODO.

**Refreshed pre-launch validation** (replaces §5.1 of prior runbook):

```bash
# 1. Is Litestream actively running on the prod machine?
flyctl ssh console -a kite-mcp-server -C 'pgrep -af litestream'
# Healthy: returns process tree (PID 645 in DR drill on 2026-05-10).

# 2. WAL freshness
flyctl ssh console -a kite-mcp-server -C 'ls -la /data/alerts.db-wal'
# Healthy: -wal mtime within last 60s during business hours.

# 3. R2 snapshot list
flyctl ssh console -a kite-mcp-server -C 'litestream snapshots -config /etc/litestream.yml /data/alerts.db'
# Healthy: at least one snapshot in the last 24h.

# 4. NEW: dr-decrypt-probe full chain test
# WSL2-side:
# (See TL;DR item 3 for exact commands.)
# Exit 0 within 2 minutes = chain works end-to-end including AES-GCM auth-tag verification.

# 5. KNOWN OPEN: GitHub Actions secrets for dr-drill.yml workflow
# Per .research/dr-drill-results-2026-05-11.md §2 finding 4: the 4 R2 + 2 Telegram secrets
# at GitHub → repo Settings → Actions are NOT provisioned. dr-drill.yml monthly cron has
# never successfully run. User action required: paste secrets.
# Day-1 implication: the synthetic CI drill is not running, but the manual drill above
# covers the same chain. Provision the secrets post-launch for ongoing automated cron coverage.
```

### Phase 6 — Post-90-min stretch goals

**Unchanged.** Twitter at min 60-90, Reddit Day 2, awesome-mcp-servers PRs. MCP Registry already published.

### Phase 7 — Standing rules

**Updated**:
- WSL2 (`/mnt/d/`) for reads/probes — unchanged.
- `git commit -o -- <path>` path-form — unchanged.
- NO `git add -A`, NO `--rebase`, NO worktrees, NO `git stash` — unchanged.
- DOC ONLY on Day 0 — unchanged. `flyctl deploy` forbidden except emergency rollback (Phase 4a).
- **NEW: fly MCP first for read-only ops**; shell-out `flyctl` for destructive ops (deploy, rollback). Structured JSON > regex on shell output.
- **NEW: dr-decrypt-probe is the proof-of-recovery test** — run pre-launch + after any secret rotation.
- **NEW: H1 hook may or may not be live**. If live, accidental secret-paste is structurally blocked. If not, lean on `<!-- secret-scan-allow: ... -->` directives in any research docs touched on launch day.
- Caffeine, water, ONE screen at a time — unchanged.

---

## New sections added since prior runbook

### A. Cloudflare Code Mode (planned, not installed)

Per `.research/research/cloudflare-bitwarden-install-plan-2026-05-11.md`: a single-URL HTTP MCP at `https://mcp.cloudflare.com/mcp` exposing 2 tools (`search`, `execute`) that wrap 2,500+ Cloudflare API endpoints via V8-isolate sandbox. **99.9% token reduction vs naive MCP**. OAuth in-browser.

**Day-1 implication**: NONE. Not installed. If installed pre-launch (~3 minutes for OAuth handshake), it would:
- Make R2 token rotation agent-doable in ~5 min (vs ~30 min of manual dashboard clicking).
- Enable live R2 bucket inspection during incident response (verify the WAL segment count, recent generation, etc.).

**Recommendation**: install Cloudflare Code Mode **after launch**, before the first post-launch DR drill. Day-1 is wrong-time for new MCP integrations.

### B. Bitwarden MCP (planned, not installed)

Per same doc: `npx @bitwarden/mcp-server` (v2026.2.0). Local-only by design. Reuses existing `bw login`+`bw unlock --raw` session via `BW_SESSION` env. 30+ tools.

**Day-1 implication**: NONE. Not installed. If installed pre-launch, would close the I10/I11 plaintext-credentials-in-memory problem structurally (BUT migration is one-time ~13 min wall-clock — wrong time to do it on Day 0).

**Recommendation**: install Bitwarden MCP **post-launch**, week 2.

### C. fly MCP — first-party operational use

Per `.research/fly-mcp-empirical-install-2026-05-11.md`: 60 tools, KEEP recommendation, project-scope `.mcp.json` entry. Agent-callable.

**Day-1 implication**: USE on launch day for read-only ops. Confirmed live tool calls from the install audit:
- `fly-status({app: "kite-mcp-server"})` — superset of `flyctl status`.
- `fly-apps-releases({name: "kite-mcp-server"})` — full release history JSON.
- `fly-ips-list({app: "kite-mcp-server"})` — confirms `209.71.68.157` as `egress_v4` in `bom`.

**Untested for incident-response use**: `fly-logs`, `fly-machine-restart`, `fly-machine-clone` (clone known via Track 1 doc, not load-tested for cold-start latency under stress).

**Recommendation**: pre-launch dry-run of `fly-logs` and `fly-machine-clone` once each. ~10 min total. Validate response shape before relying on under-stress.

---

## Friction inventory — what's still painful on Day 1

From the walkthrough above, ordered by likelihood × pain:

1. **`fly-logs` MCP response shape is unverified for incident-response use.** ~5 min fix: dry-run pre-launch.
2. **No `fly-rollback` MCP tool.** Rollback remains shell-out. Confirmed gap per fly MCP audit. Not blocking; well-understood.
3. **GitHub Actions secrets for `dr-drill.yml` not provisioned.** Doesn't affect Day 1 (the manual probe in TL;DR §3 covers the same chain). Provision post-launch.
4. **H1 secret-scan hook designed-not-implemented.** If a secret is pasted by accident during incident comms, nothing structural stops it on Day 1. Mitigation: don't paste secrets into comments. Operationally manageable but not zero-risk.
5. **Cloudflare Code Mode + Bitwarden MCP not installed.** Day-1 has zero leverage from these; they're week-2 work.
6. **`flyctl ssh console` calls** remain shell-out (e.g., for `litestream snapshots`, `pgrep`, `ls /data/`). No fly MCP equivalent for arbitrary commands beyond `fly-machine-exec` which we haven't load-tested.

**Net assessment**: the largest Day-1 friction was the "restore drill is honestly TODO" caveat in the prior runbook. **That is now closed.** dr-decrypt-probe + `25b201a` DR drill = end-to-end backup-and-decrypt is provable in <5 min. Every other friction item is operationally manageable on Day 1.

---

## Cross-references (refreshed)

- `.research/day-1-launch-ops-runbook.md` — prior (2026-05-03) at HEAD `14a188e`. This doc is the delta.
- `.research/fly-mcp-empirical-install-2026-05-11.md` — fly MCP 60-tool surface + tested calls.
- `.research/research/egress-ip-stale-sweep-2026-05-11.md` — `209.71.68.157` empirically confirmed live.
- `.research/dr-drill-results-2026-05-11.md` — R2 chain healthy; salt survives restore.
- `cmd/dr-decrypt-probe/main.go` — HKDF→AES-256-GCM verification binary. 7 tests pass.
- `scripts/dr-drill-prod-keys.sh` — script that calls dr-decrypt-probe with exit-code semantics.
- `.research/maintenance-strategy/maintenance-model.md` — H1 hook design.
- `.research/research/cloudflare-bitwarden-install-plan-2026-05-11.md` — install plans for the 2 deferred MCPs.
- `.research/research/mcp-ecosystem-audit-2026-05-11.md` — top-10 MCP install/build candidates.
- `app/ratelimit.go:182-197` — rate-limit defaults (unchanged).
- `fly.toml` — single-machine `bom` posture (unchanged).
- `etc/litestream.yml` — Litestream R2 config (unchanged).
- `scripts/smoke-test.sh` — 13-check post-deploy validation (unchanged).
- `docs/incident-response.md` / `docs/operator-playbook.md` / `docs/monitoring.md` — formal procedures.

---

*End of refresh. READ-ONLY. Doc only. Single commit + push per brief.*
