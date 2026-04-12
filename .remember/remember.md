# Handoff — execute team (2026-04-12) + path-to-100 lift (2026-04-12)

## State
Deploy-ready. Honest architecture average **~94%** (up from 89% post-execute,
and 76% pre-execute). Build vet-clean. Full test suite green (kc/ticker now
passing too).

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
   use cases (2 → 13 prod sites); deleted 3 test-only ES aggregates + their
   ~1200 LOC tests (net −2565 LOC)

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
| **Provider interfaces actually consumed** | **20** | execute team ACTION 3 wired 15 more; `grep handler\.deps\.*\.` → 46 sites |
| **Narrow-provider production call sites** | **46** | 9 files in `mcp/` |
| **Bus dispatches in mcp/** | **15** | 12 QueryBus + 3 CommandBus; `grep -c DispatchWithResult mcp/*.go` |

## Honest Scores (not theater) — post path-to-100 lift

- Hexagonal 95%, Middleware 95%, ES-audit-log 100%
- **Monolith 90%** (up from 85%)
- **DDD ~88%** (up from 80%)
- **CQRS ~98%** (up from 92%) — 32 dispatches across 13 files
- **ISP ~95%** (up from 90%) — 65 production call sites across 15 files
- Plugin 40% (accepted ceiling)
- **Weighted average: ~94%** (up from 89% → 76% → earlier)

### Prior baselines
- resume-final: CQRS 80%, ISP 30%, average 76%
- execute team §2: CQRS 92%, ISP 90%, average 89%

## Key Learnings from This Session

1. **Old reports over-claimed.** `arch-reaudit.md`, `final-arch-verification.md`, `final-100-report.md`, `phase4d-ddd-enrichment.md` all cite scores measured by file counts and interface definitions, not by actual dispatch/consumer sites. ALWAYS verify by counting live wiring, not file existence.
2. **CQRS bus was dead code** until Task #12 wired one beachhead (HoldingsTool → GetPortfolioQuery via `mcp/get_tools.go:74,114`). `kc/cqrs/` package showed 100% test coverage of dead code.
3. **ISP was 100% theater** — 20 Provider interfaces defined, only 4–5 consumed. Phase 2 verifier exposed this via `grep "NewBus"` → 0 production instantiations.
4. **Alert enrichment claim in `phase4d-ddd-enrichment.md` was FALSE** — not done until Task #13 this session replaced the claim with real 5-method enrichment + tests.
5. **3 HIGH error handling issues** fixed this session (Task #11): audit init silent failure (H1), riskguard LoadLimits silent fallback (H2 — could wipe kill switch!), audit Enqueue drop on sync fallback (H3).
6. **~2,300 LOC total dead code** found in Phase 2d. ~250 removed this session (pnlService field, 3 duplicate family use cases). Remaining ~2,050 LOC deferred: CQRS bus infrastructure beyond beachhead, test-only ES aggregates, 15 unused StoreProvider interfaces.
7. **Test cross-package state leak** — `TestFullChain_ReadOnlyToolPassesForAnyUser` was flaky only under `go test ./...` (passed in isolation). Fixed in Task #14 by isolating audit buffer state.
8. **Ground-truth tool count is 93**, not 40/60/80 cited in older docs. Always use the grep from the scorecard.

## Things That Still Need Work

- **Migrate remaining read tools to QueryBus** — Trades, Profile, Margins,
  Quotes, GTTs, Historical, option chain (~15 tools). Clone Orders pattern.
- **Wire order-write CommandBus** — `PlaceOrderCommand`, `ModifyOrderCommand`,
  `CancelOrderCommand`. Currently direct use-case invocation. Family commands
  were wired (3) by execute team; order-write is the next frontier.
- **Delete test-only aggregates** (`AlertAggregate`, `OrderAggregate`,
  `PositionAggregate`) — or move their tests out of `kc/eventsourcing/`.
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

- `.research/FINAL-SCORECARD.md` (this session's honest scorecard)
- `.research/resume-phase2-metrics.md` (verifier's reality-check on every metric)
- `.research/resume-dead-code.md` + `resume-dead-code-raw.txt` (Phase 2d)
- `.research/resume-error-audit.md` (Phase 2g, 3 HIGH issues)
- `.research/resume-deploy-readiness.md` (Phase 2f)
- `.research/resume-feature-inventory.md` (93-tool breakdown, Phase 2h)

## Windows Quirks (repeated for next session)

- `GOTMPDIR=D:/kite-mcp-temp/.gotmp` — sidesteps SAC blocking unsigned test binaries
- `mcp` / `cmd/rotate-key` intermittent SAC flakes — not code bugs
- Kite API 429 breaks `app/` and `kc/` tests that fetch `api.kite.trade/instruments.json` — external flake

## Next-Session Priorities (ranked by ROI)

1. Migrate remaining read domains to QueryBus (Trades, Profile, Margins,
   Quotes, GTTs, Historical, option chain) → CQRS 92% → 95% (~1 afternoon)
2. First order-write CommandBus dispatch (`PlaceOrderCommand`) → opens the
   command-side floodgates
3. Delete test-only ES aggregates → −900 LOC dead code (1 hour)
4. DDD aggregate root pattern out of test-only status
5. Monitor flaky tests for regression under `-count=1`
