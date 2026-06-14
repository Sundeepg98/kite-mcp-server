# Scale-to-zero safety audit — kite-mcp-server hosted Fly app (2026-06-14)

**Decision: KEEP scale-to-zero, with the cheap mitigations below applied. One real code follow-up deferred (instruments-async).**

## What changed
The hosted Fly app `kite-mcp-server` (bom, read-only `ENABLE_TRADING=false`) was flipped for cost:
`auto_stop_machines: false -> "stop"`, `min_machines_running: 1 -> 0` (shipped config-only, image unchanged `deployment-01KRRG6EE4009WSKM16ZF8X6QD`). When idle the machine stops; an inbound request auto-starts it. Saves ~$2.5-3/mo of always-on compute; the ~$2/mo dedicated egress IP remains (irreducible — SEBI).

This contradicted several repo docs that asserted always-on (most pointedly `docs/config-management.md:215` "Don't suspend — audit chain needs continuity"), so a 6-lens adversarial audit ran before making it durable. The hosted app is SEBI-regulated, hence the rigor.

## Empirical findings (measured against live prod)
- **Cold start ~11–12s** (two clean measurements), NOT the "~1-2s" originally claimed. Dominated by a **synchronous `api.kite.trade/instruments.json` fetch** (~6-10MB) during boot, before the port binds.
- Warm: `/healthz` 0.19s, `/` 0.20s, `/mcp` 401 (correct — OAuth-gated). The earlier root `000/187s` was a **local DNS blip**, not the app.
- **Egress IP `209.71.68.157` persists across a full stop->start cycle** — SEBI allow-list safe (confirmed empirically, not just inferred).
- Live secrets: `OAUTH_JWT_SECRET`, `LITESTREAM_BUCKET`, `LITESTREAM_R2_ACCOUNT_ID` set. **No `TELEGRAM_BOT_TOKEN`.** Live boot log: `Telegram not configured, skipping briefing tasks`; `Scheduler started tasks=[pnl_snapshot(15:40) audit_cleanup(03:00)]`.

## The 6 lenses (verdicts)

| Lens | Severity | Verdict |
|------|----------|---------|
| **1. Audit-chain continuity** | **none** | **SAFE.** Prev-hash re-seeds from the DB's last row on every boot (`kite-mcp-audit/store.go:203-220 SeedChain`, wired at `audit_init.go:194-213`, unit-tested `TestStore_SeedChain_ResumesFromDB`). A clean restart = zero chain discontinuity; the verifier sees a contiguous chain. SIGKILL mid-write can't corrupt (atomic single-statement insert, hashes precomputed). The doc claim "audit chain needs continuity [requires always-on]" is **factually wrong**. Only real stop-time concern: flush the async write-buffer (`writeCh` cap 1000) — a SIGKILL before drain loses un-persisted entries but leaves NO chain gap. → fixed by `kill_timeout`. |
| **2. Data durability** | low | **SAFE.** DB on persistent Fly volume `kite_data` (survives stop/start); WAL crash-safe; S3 restore only on volume LOSS (`run.sh:7-12` restores only if file absent), not normal wake. Worst case on abrupt stop = R2 replica stale ≤10s, never primary loss. → `kill_timeout` hardens it. |
| **3. Scheduler correctness** | medium | Exact-wall-clock-minute firing, no catch-up (`kite-mcp-scheduler/scheduler.go:205`). `pnl_snapshot@15:40 IST` missed ~daily under scale-to-zero — but **analytics-only** (DailyPnLEntry from live holdings; only users with valid Kite tokens). `audit_cleanup@03:00` = harmless over-retention no-op for ~5yrs (SEBI wants MIN 5y; first deletable row ~2031). No compliance break. |
| **4. Session / OAuth / cold start** | low | **keep-as-is.** All state DB-backed; cold-start rehydration explicitly engineered (`kite-mcp-kc/session_service.go:215-237` rebuilds Kite client when `Data.Kite==nil` after restart). MCP auth = stateless JWT (`OAUTH_JWT_SECRET`, identical across restarts). OAuth state/PKCE stateless (signed, round-tripped). A wake == the restart that already happens on every deploy. |
| **5. Regulatory + always-on sweep** | high→**overstated** | No SLA/SEBI/DPDP **uptime** duty (TERMS.md disclaims uptime; retention duties satisfied by the persistent volume). Agent flagged Telegram briefings + price alerts breaking — but **live verification disproved the briefings part**: `TELEGRAM_BOT_TOKEN` is unset, so morning_briefing/mis_warning/daily_summary are **not wired** on hosted. `set_alert` price-alerts need a per-user WebSocket ticker (user-driven; idle demo = none active). Net real impact ≈ the pnl_snapshot gap (Lens 3). The "always-on" doc assertions are STALE-CAUTION, safe to re-document. |
| **6. Cold-start + smoke-canary** | high | **Real.** (a) ~12s cold start; **worst-case ~96s then boot exit 1 (crash-loop)** if `api.kite.trade` is unreachable at wake (`kite-mcp-instruments/manager.go` RetryAttempts=3×~30s, returns err → `RunServer` exits). Self-heals when Kite recovers. (b) `smoke-test.sh` check 1 uses `curl --max-time 5` with no warmup → a cold wake returns 000 → **false canary failure**. (c) No Fly-side `[checks]` block, so no health-check flapping. |

## Mitigations APPLIED (this session — deploy repo only, no algo2go module changes)
1. `fly.toml`: added top-level `kill_timeout = "15s"` (HTTP drain 10s + litestream final WAL sync + audit buffer flush before SIGKILL). Corrected the cold-start comment to ~12s + the instruments-fetch caveat.
2. `fly_toml_test.go`: `TestFlyToml_HasMinMachinesRunning` → `TestFlyToml_ScaleToZeroConfigured` (asserts `min=0`, `auto_stop="stop"`, `kill_timeout="15s"`). Unbreaks CI. Other 3 fly.toml tests untouched. All 4 pass.
3. `scripts/smoke-test.sh`: added a cold-start warm-up before check 1 (`curl --max-time 90 --retry 2 ... /healthz || true`) so a sleeping machine isn't a false outage.
4. Docs corrected to scale-to-zero reality: `config-management.md` (incl. the false "audit chain continuity" rationale), `asset-inventory.md`, `incident-response.md`, `callback-deep-dive-13-levels.md`, `mcp-registry-prepublish-checklist.md`.
5. `CLAUDE.md`: cold start ~12s; residuals 4 (crash-loop) + 5 (pnl/briefings); audit-verdict block.

## DEFERRED (real code change — operator's "leave Fly for now"; flag for a future pass)
- **Make the boot-time instruments load async / non-fatal** (`algo2go/kite-mcp-instruments`): start with an empty map + let the background scheduler populate, instead of a synchronous fetch that gates port-bind and can crash-loop boot. This is the single highest-value follow-up — it shrinks the ~12s cold start AND removes the Kite-down-at-wake crash-loop. Lower-effort interim: drop RetryAttempts/Delay for the hosted build so worst-case boot can't reach ~96s.
- (Optional) scheduler catch-up-on-boot + persist `lastRun` to fix the pnl_snapshot daily miss. Low priority (near-zero impact on the idle demo).

## If the operator prefers to REVERT instead
`fly.toml`: `auto_stop_machines = false`, `min_machines_running = 1` (drop or keep `kill_timeout`), then `flyctl deploy -a kite-mcp-server --image registry.fly.io/kite-mcp-server:<current> --config fly.toml -y`. Revert the test + docs. Cost returns to ~$3/mo for the machine. Reasonable if the ~12s demo cold start / crash-loop exposure isn't worth ~$2.5/mo before the instruments-async fix lands.

## Provenance
Workflow `wf_8afb6f56-67a` (5/6 lenses; lens-1 re-run as a standalone agent after a StructuredOutput miss). Pinned to kite-mcp-server master @ `18a388f` + the uncommitted scale-to-zero edits. Live probes against `kite-mcp-server.fly.dev` v277.
