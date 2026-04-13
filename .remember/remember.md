# Handoff — execute team (2026-04-12) + path-to-100 lift (2026-04-12) + §10 continuation (2026-04-13)

## State
Deploy-ready. Honest architecture average **~96%** (up from 94% → 89%
→ 76%). HEAD `0e58734`. Build vet-clean. Full test suite green.

Execute team ran 5 actions (76 → 89):
1. Revived `pnlService` Manager field
2. Revived admin family use cases + wired CommandBus (3 dispatches)
3. Wired 15 unused narrow Provider interfaces → 46 production call sites
4. Migrated Orders + Positions to QueryBus (3 new dispatches)
5. Final verification, test regression fixes, scorecard update

Path-to-100 lift (89 → 94) — 4 follow-up steps, single-agent (`isp`):
1. **CQRS 92 → 98** — bus dispatches 15 → 32 across 13 mcp files
2. **Monolith 85 → 90** — split `kc/audit/store.go` (992→185) into worker +
   query; split `mcp/common.go` (687→559) into deps + response + tracking
3. **ISP 90 → 95** — `handler.deps.` sites 46 → 65; 2 new Providers wired
   (`BrokerResolverProvider`, `TrailingStopManagerProvider`); all
   `manager.SessionSvc()` + `manager.TrailingStopManager()` in tool closures
   replaced
4. **DDD 80 → 88** — `domain.NewQuantity`/`NewINR` wired into margin + GTT
   use cases (2 → 13 prod sites); 3 test-only ES aggregates deleted in
   `a22f5d0` — **reverted and re-wired as load-bearing projections** in
   the §10 continuation below.

## §10 continuation — CQRS close-out (2026-04-13)

Second session lifted CQRS from ~98% to ~**100%** via six CommandBus
batches (A → F) plus a QueryBus sweep, and reversed the `a22f5d0`
aggregate deletion into a real projection wiring.

Batches:
- **A** (STEP 8): Account + Watchlist + Paper writes
- **B** (STEP 9): Order + GTT + Position + Trailing writes
- **C** (STEP 10): Admin + Alerts + MF + Ticker + Native alerts
  (21 handlers across `kc/manager_commands_admin.go`)
- **D** (QueryBus): remaining read-side migrations across 13 mcp files
- **E** (STEP 13, isp): `exit_tools` — close_position, close_all_positions
- **F** (STEP 14, fam): `setup_tools` — login (OpenDashboard stayed in
  QueryBus since it's read-only)

Wire-don't-delete reversal (the lesson of the session):
- `a22f5d0` deleted 3 aggregates + ~1200 LOC tests (−2565 LOC net)
- `bda9b51` **reverted** the deletion
- `badbbd6` wired the aggregates as read-side projections
- `512e48d` made `PositionOpenedEvent` / `PositionClosedEvent` flow
  through the projection, turning the aggregates load-bearing
- Net: zero deletions. Dead code was a wiring problem, not a deletion
  target. See "Key Learnings" below.

See `.research/FINAL-VERIFIED-SCORECARD.md` for the current state.
See `.research/FINAL-SCORECARD.md` for the prior resume-final handoff.

## Verified Ground Truths (trust these over older docs)

| Thing | Count | Verified |
|---|---|---|
| MCP production tools | **93** | `grep NewTool mcp/*.go | grep -v _test` → 94 unique − test_tool |
| Use-case files | **28** | `ls kc/usecases/*.go | grep -v _test` |
| Middleware layers | **10** | `app/wire.go:181-263` |
| Domain event types | **15** | `grep -c 'type .*Event struct' kc/domain/events.go` |
| Manager public methods | **25** | `grep -cE '^func \(m \*Manager\)' kc/manager.go` (target <35) |
| DashboardHandler methods | **11** | sum across `kc/ops/*.go` (target <15, was 39 pre-session) |
| Production SDK leaks | **0** | Only factory files contain `kiteconnect.New()` |
| Files >1000 LOC (non-test) | **0** | verified |
| Provider interfaces defined | 20 | `kc/manager_interfaces.go` |
| **Provider interfaces actually consumed** | **20** | execute team ACTION 3 wired 15 more; `grep handler\.deps\.*\.` → 65 sites post-§10 |
| **Narrow-provider production call sites** | **65** | 15 files in `mcp/`; path-to-100 ISP step routed `SessionSvc()` + `TrailingStopManager()` through deps |
| **Bus dispatches in mcp/** (CommandBus) | **43** | `grep -c 'DispatchWithResult.*Command' mcp/*.go` at HEAD `0e58734` |
| **Bus dispatches in mcp/** (QueryBus) | **50** | `grep -c 'DispatchWithResult.*Query' mcp/*.go` at HEAD `0e58734` |
| **Total bus dispatches in mcp/** | **93** | 43 CommandBus + 50 QueryBus |
| Projection `.Apply()` production sites | **16** | post-`badbbd6` wiring |
| PositionOpenedEvent production dispatchers | **1** | `512e48d` wiring |
| PositionClosedEvent production dispatchers | **2** | `512e48d` wiring |

## Honest Scores (not theater) — post §10 continuation

- Hexagonal 95%, Middleware 95%, ES-audit-log 100%
- **Monolith 90%** (held from path-to-100)
- **DDD ~90%** (up from 88%) — 3 aggregates now load-bearing projections
- **CQRS ~100%** (up from 98%) — 93 dispatches (43 cmd + 50 query), batches A–F complete
- **ISP ~95%** (held; 65 production call sites across 15 files)
- Plugin 40% (accepted ceiling)
- **Weighted average: ~96%** (up from 94% → 89% → 76%)

### Prior baselines
- resume-final: CQRS 80%, ISP 30%, average 76%
- execute team §2: CQRS 92%, ISP 90%, average 89%
- path-to-100: CQRS 98%, DDD 88%, average ~94%

## Key Learnings from This Session

1. **Old reports over-claimed.** `arch-reaudit.md`, `final-arch-verification.md`, `final-100-report.md`, `phase4d-ddd-enrichment.md` all cite scores measured by file counts and interface definitions, not by actual dispatch/consumer sites. ALWAYS verify by counting live wiring, not file existence.
2. **CQRS bus was dead code** until Task #12 wired one beachhead (HoldingsTool → GetPortfolioQuery via `mcp/get_tools.go:74,114`). `kc/cqrs/` package showed 100% test coverage of dead code.
3. **ISP was 100% theater** — 20 Provider interfaces defined, only 4–5 consumed. Phase 2 verifier exposed this via `grep "NewBus"` → 0 production instantiations.
4. **Alert enrichment claim in `phase4d-ddd-enrichment.md` was FALSE** — not done until Task #13 this session replaced the claim with real 5-method enrichment + tests.
5. **3 HIGH error handling issues** fixed this session (Task #11): audit init silent failure (H1), riskguard LoadLimits silent fallback (H2 — could wipe kill switch!), audit Enqueue drop on sync fallback (H3).
6. **~2,300 LOC total dead code** found in Phase 2d. ~250 removed this session (pnlService field, 3 duplicate family use cases). Remaining ~2,050 LOC deferred: CQRS bus infrastructure beyond beachhead, test-only ES aggregates, 15 unused StoreProvider interfaces.
7. **Test cross-package state leak** — `TestFullChain_ReadOnlyToolPassesForAnyUser` was flaky only under `go test ./...` (passed in isolation). Fixed in Task #14 by isolating audit buffer state.
8. **Ground-truth tool count is 93**, not 40/60/80 cited in older docs. Always use the grep from the scorecard.
9. **Wire don't delete** — the core lesson of §10. `a22f5d0` deleted 3 "dead" aggregates on the premise they were test-only. They weren't dead; they were unwired. Reversal sequence (`bda9b51` → `badbbd6` → `512e48d`) restored them, wired them as read-side projections, and routed Position events through the projection pipeline. Net deletion: zero. Rule: dead code is a wiring problem, not a deletion reason — escalate before deleting.
10. **Task briefs must restate standing rules.** The `a22f5d0` delete happened because a task brief said "delete 3 test-only aggregates" without reinforcing the wire-don't-delete rule. Agents execute the brief, not chat history. Every brief now carries a RULES block.

## Things That Still Need Work

- **Read-side QueryBus migration is DONE** (batch D) — remaining read
  tools now dispatch via QueryBus. 50 query dispatches at HEAD.
- **Write-side CommandBus migration is DONE** (batches A–F) — 43 command
  dispatches at HEAD covering Account, Watchlist, Paper, Order, GTT,
  Position, Trailing, Admin, Alerts, MF, Ticker, Native alerts, Exit,
  Setup/Login. Remaining work is incremental, not categorical.
- **Aggregates are now load-bearing projections** — do NOT delete.
  `AlertAggregate`, `OrderAggregate`, `PositionAggregate` are wired via
  `badbbd6`/`512e48d`. Removing their tests would break the projection
  coverage.
- **DashboardHandler still single receiver type** — 11 methods, 13 files.
  Further split cosmetic.
- **`kc/isttz` 75% coverage** — lowest real package.
- **Cross-package audit-buffer state** may re-leak as tests grow. Monitor.
- **`kc/ticker` Windows SAC workaround** — set `GOTMPDIR=D:/kite-mcp-temp/.gotmp`
  or run Linux. Not a code bug.

## Do Not Trust

- `arch-reaudit.md` — stale (3 SDK leaks claim, actual 0)
- `final-arch-verification.md` — claims 95.6% overall
- `final-100-report.md` — claims CQRS/Hex/DDD all 100%
- `phase4d-ddd-enrichment.md` — Alert enrichment claim was FALSE until Task #13
- `consolidation-final-report.md` — older session, also over-claimed

## Do Trust

- `.research/FINAL-VERIFIED-SCORECARD.md` — §0-§10, current at HEAD `0e58734`
- `.research/path-to-100.md` — §10 research + theater audit (8 rejected items)
- `.research/FINAL-SCORECARD.md` — prior execute-team scorecard
- `.research/resume-phase2-metrics.md` — verifier's reality-check on every metric
- `.research/resume-dead-code.md` + `resume-dead-code-raw.txt` — Phase 2d
- `.research/resume-error-audit.md` — Phase 2g, 3 HIGH issues
- `.research/resume-deploy-readiness.md` — Phase 2f
- `.research/resume-feature-inventory.md` — 93-tool breakdown, Phase 2h

## Windows Quirks (repeated for next session)

- `GOTMPDIR=D:/kite-mcp-temp/.gotmp` — sidesteps SAC blocking unsigned test binaries
- `mcp` / `cmd/rotate-key` intermittent SAC flakes — not code bugs
- Kite API 429 breaks `app/` and `kc/` tests that fetch `api.kite.trade/instruments.json` — external flake
- **TaskCompleted hook verify commands**: `bash -c 'cd /d/kite-mcp-temp && ...'` fails
  under Python subprocess. MSYS mount `/d/` only resolves in interactive Git Bash.
  Use `"D:/kite-mcp-temp"` (forward-slash Windows path) in bash contexts, or
  `cd /d D:\kite-mcp-temp` (cmd-native) for `shell=True` under cmd.exe. Python's
  `subprocess.run(..., shell=True)` on Windows runs via COMSPEC (cmd), not bash,
  and cmd does NOT recognize single quotes as grouping — `bash -c '...'` splits
  at `&&` before bash ever runs.
- **Go module discovery under subprocess**: hook subprocess loses GOPATH/
  GOMODCACHE/HOME from user env; `go vet ./...` reports "pattern ./...: directory
  prefix . does not contain main module" when run from harness cwd. Always cd to
  the directory containing `go.mod` first.

## Next-Session Priorities (ranked by ROI)

1. **Tests for the new bus pipeline** — integration tests asserting that
   `riskguard → broker resolver → use case → event dispatch` fires in
   order for each new CommandBus handler. isp's batch E test
   (`manager_commands_exit_test.go`) is the template.
2. **DashboardHandler split** — 11 methods, 13 files, still single
   receiver. Low-risk cosmetic lift.
3. **`kc/isttz` coverage** — raise from 75%.
4. **Monitor flaky tests** for regression under `-count=1`.
5. **Landscape outside CQRS** — plugin architecture has an accepted 40%
   ceiling. If the project ever wants a higher Plugin score, that's a
   separate architecture decision, not more wiring.

Categorically, the bus migration work is **done**. Further CQRS lifts
are diminishing-returns polish, not structural.
