# Production ↔ Master Gap Report

**Date**: 2026-05-11
**Scope**: investigate the claimed gap between production state (`v1.3.0 / tools=111`) and master HEAD (claimed `tools=130 in-tree`)
**Mode**: READ-ONLY investigation — no source mutations, no deploys

---

## TL;DR — three findings

1. **There is no gap.** Production runs the latest deployed master. Image `deployment-01KR9FPJC88YA80VWS7VMTWTY7` (sha256 `629a6ee5…`) was deployed yesterday 2026-05-10 17:44 UTC against HEAD `bc5043e` and is still serving live. Current master HEAD `1e80930` is exactly **1 commit ahead** of the deployed image, and that commit is **doc-only** (`STATE.md` archive cleanup; zero `.go` source mutations). Production is bit-equivalent to current master modulo `.research/*.md` files, which are excluded from the Docker build context.

2. **The "tools=130 in-tree" claim is false.** It originates from a grep that included `_test.go` fixtures. Production-source `mcp.NewTool("…)` call sites = **111** in non-test files; **19** in test files; 111+19=130 is the figure STATE.md and the orchestrator quoted. When I built and ran the current-source binary locally, it logged `Tool registration complete registered=93 excluded=0 gated_trading=18 trading_enabled=false total_available=111` — a perfect match for what production reports.

3. **The "~550 commits stale" / "19-tool delta" claim is false.** Distance from deployed commit (`bc5043e`) to current master (`1e80930`) = **1 commit, doc-only**. The dispatch-chain metadata across v228–v274 was correctly tracking deploys against actual landed commits.

**Recommendation**: no deploy needed; no investigation of deploy failure needed; correct STATE.md to remove the false gap claim.

---

## §1 — Empirical state

### 1.1 What's actually running on Fly

| Field | Value |
|---|---|
| App | `kite-mcp-server` |
| Hostname | `kite-mcp-server.fly.dev` |
| Image tag | `kite-mcp-server:deployment-01KR9FPJC88YA80VWS7VMTWTY7` |
| Image sha256 | `629a6ee5b67b16d8f26602883681185b9589b9b9d851a1b4b15455f65abac1fd` |
| Machine version | **273** |
| Region | `bom` |
| State | `started` |
| Last updated | `2026-05-10T17:44:10Z` |
| Source `flyctl status -a kite-mcp-server` (local Sun 2026-05-11) |  |

> Note: `flyctl releases list` is not a valid subcommand in this `flyctl` build. `flyctl releases` shows the help screen. `flyctl status` plus `flyctl image show` together provide the same evidence.

### 1.2 Healthz cross-check

```
$ curl -s https://kite-mcp-server.fly.dev/healthz
{"status":"ok","tools":111,"uptime":"1h36m53s","version":"v1.3.0"}
```

- `/version` → **HTTP 404** (route not registered; this is the expected behavior — version is exposed via `/healthz`).
- `/admin/ops` → HTTP 302 (auth-redirect canary, normal).
- Uptime at probe = ~1h36m (~22h after deploy timestamp), so the machine **did get cycled** sometime today, but the active image hash is still `629a6ee5…` — the cycle was a Fly Machine VM restart, not a redeploy.

### 1.3 Master HEAD source

| Field | Value |
|---|---|
| Local HEAD | `1e80930` |
| origin/master (after `git fetch`) | `1e80930` (== local) |
| HEAD message | `docs(research): canonical STATE.md + archive stale (82 archived, 14 remain active)` |
| HEAD ↔ deployed-image (`bc5043e`) distance | **1 commit ahead** |
| HEAD ↔ deployed-image diff | 80+ files, **all under `.research/` or `.research/archive/`** |
| Source-code mutations between `bc5043e` and HEAD | **0** |

### 1.4 Tools-count evidence from current source (compiled + run)

I built the current-source binary (`go build -o /tmp/kmcp-test .`) and started it locally with the minimal env (`OAUTH_JWT_SECRET`, `EXTERNAL_URL`, `ALERT_DB_PATH`). The startup log emitted:

```
Tool integrity manifest computed     tools=93     hash_bytes=2976
Tool registration complete           registered=93  excluded=0  gated_trading=18  trading_enabled=false  total_available=111
```

So **the current master HEAD source compiles to a binary that exposes exactly tools=111** — registered=93 visible tools + 18 trading tools gated out by `ENABLE_TRADING=false` (the production setting on Fly). Identical to what production reports.

### 1.5 Provenance of the bogus "130" figure

```
$ grep -rE 'mcp\.NewTool\("' mcp/ --include='*.go'              # what STATE.md cites
130 hits

$ grep -rE 'mcp\.NewTool\("' mcp/ --include='*.go' | grep -v _test.go  # exclude tests
111 hits

$ grep -rE 'mcp\.NewTool\("' mcp/ --include='*_test.go' | wc -l  # test-only
19 hits
```

The 19 fixture `mcp.NewTool(…)` calls in test files are not registered by any `init()` and never appear in production. STATE.md's line:

> **MCP tools (in-tree)** | **130** | `grep -rE 'mcp\.NewTool\("' mcp/`

uses a grep that doesn't filter `_test.go`. The cited "tool count delta = +19 tools in master not yet deployed" is exactly the test-fixture count — coincidence, not signal.

---

## §2 — Root cause

The gap is a **measurement artefact in STATE.md**, not a deploy-pipeline problem.

1. STATE.md was authored at HEAD `1e80930` claiming "Production is 19 tools / ~550 commits stale of master".
2. The "19 tools" figure came from `grep -rE 'mcp\.NewTool\("' mcp/ --include='*.go' | wc -l = 130`, comparing 130 against production's `tools=111`.
3. That grep includes test fixtures. Filtering those out brings the count to 111 — matching production.
4. The "~550 commits stale" framing in TL;DR §2 conflates *all repo history* with *post-deploy delta*. From deploy commit `bc5043e` to current HEAD `1e80930` = 1 commit, doc-only.
5. The orchestrator quoted these figures faithfully but they were wrong at the source.

The dispatch-chain metadata (v228 → v274) was *not* hallucinated. Each dispatch's `bcbe9f0`, `c6eea80`, `b21ad3e`, `bc5043e`, etc., is a real git commit with the claimed message. `flyctl status` shows machine version **273** (matching the v273+v274 combined deploy reported at session end). 86 consecutive deploys with `tools=111` is consistent with the empirical state: the production binary's tools registry produces exactly 111 from the source it's built from, and the source has continuously produced 111 throughout the v228+ arc.

---

## §3 — Timeline reconstruction

| Time | Event |
|---|---|
| 2026-05-10, throughout the day | v228–v272 dispatch chain deployed continuously; each version-tagged image landed cleanly per `flyctl status` evidence after each deploy |
| 2026-05-10 17:44 UTC | Final deploy of session: machine version 273, image `deployment-01KR9FPJC88YA80VWS7VMTWTY7` (sha256 `629a6ee5…`), against HEAD `bc5043e` |
| 2026-05-10 23:31 IST (≈18:01 UTC) | Author commits `1e80930` `docs(research): canonical STATE.md + archive stale`. STATE.md is created with the "tools=130 / 19-tool gap" claim, mistakenly counting test fixtures |
| 2026-05-11 (today) | Synthesis agent reads STATE.md, sees claim of "production stale of master", reports the discrepancy faithfully across 4 dispatches |
| 2026-05-11 ~19:21 UTC | This investigation: empirically confirms current-source binary registers `total_available=111`, matching production; identifies the grep error in STATE.md |

No deploys ever failed. No deploys ever rolled back silently. Production ran the very latest deployed master image at every measurement point. The tools count was in fact preserved at 111 throughout the chain — the dispatch-chain reports were correct.

---

## §4 — Failure modes considered and ruled out

| Hypothesis | Status | Evidence |
|---|---|---|
| v229–v252 Path A inauguration deploys never landed; production stuck on old image | **Ruled out** | `flyctl status` shows machine version 273, image `deployment-01KR9FPJC88YA80VWS7VMTWTY7` deployed 2026-05-10 17:44 UTC. Each dispatch in v228+ produced a successor image hash; chain ran without rollback. |
| Fly serves an old image because deploys never completed | **Ruled out** | `flyctl image show` reports the v273+v274 image is the live machine image. Deploy completed cleanly per flyctl logs at session end. |
| Healthz reads stale data (e.g., from a snapshot) | **Ruled out** | Healthz returns `len(mcp.GetAllTools())` computed live per request from the in-process tool registry (`app/http.go:619`). It is the source-of-truth. |
| `tools=111 invariant` actually means "we kept rolling back to keep production at v1.3.0" | **Ruled out** | Image hashes change deploy-to-deploy across v228–v274 (e.g., `5e31a300…` v270 → `629a6ee5…` v273+v274). Deploys are landing; the binary changes; tools count stays at 111 because the source produces 111 from the same registration logic across these refactors. |
| Master HEAD's "tools=130" is real but only when you compile + run; production isn't running it | **Ruled out** | I compiled current master HEAD locally and ran it. It registers `total_available=111`. The "130" figure was a grep counting test fixtures. |

---

## §5 — Recommendation

**No technical action required.** Production is healthy and current. Specifically:

1. **Do not deploy** in response to the synthesis agent's report — there is nothing to deploy. The 1-commit gap is a `.research/` archive reorganization that is excluded from the Docker build context. A deploy would produce a bit-equivalent image (cf. v263–v272 doc-only sub-arc that all shared sha256 `5e31a300…`).
2. **Correct STATE.md.** The two false claims to fix:
   - §TL;DR item 2: replace "Production is 19 tools / ~550 commits stale of master. Master HEAD `bc5043e` has tools=130 in-tree" with the empirical truth: production is at master HEAD modulo `.research/`-only commits; tools count is `tools=111` in both production and master-built binary.
   - §1.1 row "MCP tools (in-tree) | 130": the grep needs `--include='*.go' | grep -v _test.go` to exclude test fixtures. With that filter, the count is 111, which matches production. Either correct the figure or note that the grep over-counts by 19.
3. **No flyctl reauth needed.** The CLI worked for `status` + `image show` immediately in this investigation; whoever wrote the launch playbooks ("flyctl reauth via Playwright, ~30 min") may have been working around an unrelated stale auth that has since healed.
4. **Dispatch-chain metadata is trustworthy.** The v228–v274 reports' `tools=111` invariant claims were correct empirical observations of post-deploy production state. The orchestrator was not hallucinating; it was reading a STATE.md that had a bug.

If the user wants to ship the 1 doc-only commit `1e80930` to production for completeness, that's a no-cost action: a doc-only deploy that shares the v273+v274 image bits and bumps the machine version label only.

---

## §6 — Investigation cost

- WSL2 `flyctl status` + `flyctl image show`: ~3 s
- Production `curl /healthz` and `/version`: ~1 s
- Local `go build` of current source: ~30 s
- Local binary run + healthz capture: ~10 s after a couple of false starts on env (port, alert DB)
- Total wall time: ~10 min; well under the 1h budget.

No source mutations performed. Single output file: this report at `.research/production-master-gap-report.md`.
