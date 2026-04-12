# Task #18 — Remaining monolith / god-object / fat-interface scan

Independent audit run while refactoring is in progress. All numbers are grep-backed and reproducible.

## 1. Structs with >20 methods (non-test files)

Counted via `grep -rhn "^func (\w+ \*<Type>)" --include="*.go" | grep -v _test.go | wc -l`, disambiguated per package where type names collide.

| Rank | Receiver (package) | Methods | File | Status |
|-----:|-------------------|--------:|------|--------|
| 1 | `*Client` (`broker/mock`) | 53 | `broker/mock/client.go` (971 LOC) | Test harness — low priority, but `broker.Client` interface itself has 31 methods (see §3). Shrinking the interface will trim this too. |
| 2 | `*Handler` (`oauth`) | 47 | `oauth/handlers.go` (1255 LOC) | Being split by **split-fix** (Task #15, in_progress). |
| 3 | `*DashboardHandler` (`kc/ops`) | 46 | `kc/ops/dashboard_handler.go` | **NEW FINDING**. Still god-like even after the #12 / #16 split work. Recommend further functional split: portfolio / orders / activity / admin subhandlers as separate structs behind a small routing shim. |
| 4 | `*DB` (`kc/alerts`) | 40 | `kc/alerts/db.go` + splits | Task #11 split this into persistence + crypto + queries but receivers still hang off the one struct. Consider `DB` → `QueryStore`, `CommandStore`, `Crypto` as separate types with narrow interfaces. |
| 5 | `*Handler` (`kc/ops`) | 37 | `kc/ops/handler.go` | Split by Task #12 (completed). Receiver count is inherent to package; acceptable. |
| 6 | `*Client` (`broker/zerodha`) | 37 | `broker/zerodha/client.go` | Mirrors `broker.Client` interface surface. Shrink the interface first. |
| 7 | `*BotHandler` (`kc/telegram`) | 31 | `kc/telegram/bot.go` (453 LOC) | Acceptable cohesion — each method is a telegram command. Low priority. |
| 8 | `*Guard` (`kc/riskguard`) | 30 | `kc/riskguard/guard.go` (750 LOC) | **Medium finding**. 8 checks × 2-3 methods each. Recommend one checker struct per check behind a `Check` interface with a single `Run(ctx, order)` method; `Guard` becomes a composite. |
| 9 | `*App` (`app`) | 26 | `app/http.go` (827 LOC) | **Medium finding**. App wires routes + owns HTTP server + holds deps. Split route registration into `routes.go` (free functions), keep `App` as the dep container. |
| 10 | `*Store` (`kc/users`) | 26 | `kc/users/store.go` | Acceptable — CRUD + query methods on a user store. |
| 11 | `*Store` (`kc/audit`) | 23 | `kc/audit/store.go` (955 LOC) | **Medium finding**. File nearing 1000 LOC; split read vs. write responsibilities behind `AuditReader` / `AuditWriter` already exposed in `kc/interfaces.go`. |
| 12 | `*StoreRegistry` (`kc`) | 22 | `kc/broker_services.go` | Acceptable — this IS a registry. |
| 13 | `*SessionService` (`kc`) | 21 | `kc/session_service.go` | Acceptable post-decomposition. |
| 14 | `*SessionRegistry` (`kc`) | 20 | `kc/session.go` | Acceptable. |

`*Manager` (`kc`) still shows 144 methods via grep because method receivers are spread across 14+ files. Task #14 marked completed; if the round-2 `SchedulingService` extraction landed, the number on `Manager` itself should now be <45 — the 144 count aggregates every `(m *Manager)` receiver in the package regardless of file. Needs a finer re-count after the build stabilizes.

## 2. Non-test files still >700 lines

```
1255 ./oauth/handlers.go              (Task #15 in_progress — split-fix)
1176 ./kc/ops/dashboard_templates.go  (Task #16 in_progress — mock-fix; currently broken: duplicate decls with dashboard_*.go splits)
 986 ./kc/ops/user_render.go          NEW FINDING — not in any active task
 971 ./broker/mock/client.go          mock file, low priority
 955 ./kc/audit/store.go              NEW FINDING — CRUD + query; split with existing AuditReader/AuditWriter
 874 ./kc/manager.go                  being decomposed (Tasks #7/#14)
 827 ./app/http.go                    NEW FINDING — wiring + server + routes
 816 ./mcp/options_greeks_tool.go     acceptable — one tool, one file; Greeks math
 805 ./mcp/post_tools.go              acceptable — modify/cancel/exit order tools grouped
 750 ./kc/riskguard/guard.go          NEW FINDING — 8 checks in one file
 719 ./kc/papertrading/engine.go      acceptable — one engine
```

**Actionable new findings** (not covered by any existing task):
- `kc/ops/user_render.go` (986) — likely SSR render helpers. Split by page.
- `kc/audit/store.go` (955) — apply existing `AuditReader`/`AuditWriter` ISP split at type level.
- `app/http.go` (827) — extract `routes.go`.
- `kc/riskguard/guard.go` (750) — one checker struct per check behind a `Check` interface.

## 3. Interfaces still >10 methods (ISP violations)

Counted by regex-parsing `type X interface { ... }` bodies for method signatures.

| Methods | Interface | File | Verdict |
|--------:|-----------|------|---------|
| **31** | `Client` | `broker/broker.go:403` | **HIGH**. Kitchen-sink broker interface. Every consumer of `broker.Client` depends on all 31 methods (go's implicit interface satisfaction). Split into focused interfaces (ProfileReader, OrderPlacer, OrderReader, HoldingsReader, MarginsReader, HistoricalReader, GTTWriter, etc.) — the same pattern that's been applied in `kc/interfaces.go` for user/audit/registry readers/writers. This is the single biggest ISP violation left in the codebase. |
| **18** | `StoreAccessor` | `kc/manager_interfaces.go:75` | **HIGH**. A grab-bag "give me any store" interface. Split by consumer: most callers only need 1-2 accessors. |
| **12** | `PaperEngineInterface` | `kc/interfaces.go:501` | **MEDIUM**. Consider splitting into `OrderSubmitter` + `PositionReader` + `CashReader`. |
| **12** | `InstrumentManagerInterface` | `kc/interfaces.go:501` | **MEDIUM**. `LookupSymbol` vs. `Refresh` vs. `Search` — different call sites need different subsets. |
| **11** | `WatchlistStoreInterface` | `kc/interfaces.go:381` | **LOW**. Borderline; a CRUD store is naturally 6-10 methods. Split only if it causes test-mock bloat. |
| **10** | `AlertStoreInterface` / `UserReader` | `kc/interfaces.go` | Acceptable at the boundary. |
| ≤9 | all others | — | Acceptable. |

Everything in `kc/manager_interfaces.go` other than `StoreAccessor` is healthy (4-9 methods each).

## 4. Circular imports

`go build ./...` currently fails with method-redeclaration errors in `kc/ops/dashboard_*.go` (Task #16 in-progress), but these are duplicate-symbol errors, not import cycles. No cycles surfaced in `go mod graph` or build output. Rerun after Task #16 stabilizes to confirm clean.

## 5. Package coupling (highest incoming edges)

Non-test files importing each internal package:

| Incoming | Package | Notes |
|---------:|---------|-------|
| 57 | `kc/cqrs` | Query/command DTOs — wide use is expected and healthy. |
| 52 | `kc` | Root Manager — expected high coupling; decomposition in flight. |
| 41 | `oauth` | Auth is a cross-cutting concern. Acceptable. |
| 38 | `broker` | Same — cross-cutting. Worth watching because of the 31-method `Client` interface. |
| 29 | `kc/alerts` | Acceptable. |
| 33 | `kc/usecases` | Application layer — healthy. |
| 29 | `kc/domain` | Entities — healthy. |
| 18 | `kc/audit` | Healthy. |

No package is "structurally central" beyond what the hexagonal layering justifies. `kc` root and `broker` are the two coupling hotspots, and both already have decomposition tasks (#7, #14, or recommended new work on `broker.Client`).

## 6. Test files >3000 lines (candidates for splitting)

| Lines | File | Comment |
|------:|------|---------|
| 7402 | `mcp/tools_devmode_test.go` | **HIGH — split**. By tool group (orders, quotes, holdings, etc.). |
| 5941 | `app/server_test.go` | **HIGH — split**. By endpoint group. |
| 5705 | `oauth/handlers_test.go` | **HIGH — split**. By flow (authorize, token, refresh, revoke, discovery). |
| 4054 | `kc/ops/admin_edge_test.go` | **HIGH — split**. |
| 3572 | `kc/ops/handler_edge_test.go` | **HIGH — split**. |
| 3380 | `mcp/tools_validation_test.go` | **MEDIUM**. |
| 3371 | `kc/alerts/db_test.go` | **MEDIUM**. |
| 3211 | `mcp/tool_handlers_test.go` | **MEDIUM**. |
| 3115 | `mcp/tools_pure_test.go` | **MEDIUM**. |
| 3102 | `kc/papertrading/engine_edge_test.go` | **MEDIUM**. |

## Summary: NEW findings (not covered by any existing task)

Severity legend: H = high, M = medium, L = low.

1. **H** `broker/broker.go:Client` interface has 31 methods. Biggest ISP violation left. Recommend splitting into ~8 focused interfaces.
2. **H** `kc/manager_interfaces.go:StoreAccessor` has 18 methods. Grab-bag interface; split per consumer.
3. **M** `kc/ops/dashboard_handler.go:DashboardHandler` — 46 methods. Further split into per-section handlers.
4. **M** `kc/audit/store.go` — 955 LOC, 23 methods. Apply existing `AuditReader`/`AuditWriter` ISP split at type level.
5. **M** `app/http.go` — 827 LOC, 26 methods on `*App`. Extract a `routes.go` free-function file.
6. **M** `kc/riskguard/guard.go` — 750 LOC, 30 methods. Composite of per-check structs behind a `Check` interface.
7. **M** `kc/ops/user_render.go` — 986 LOC. Split by page.
8. **M** 5 test files over 3500 lines (see §6) should be split by responsibility.

Tasks already in flight cover the other big-ticket items (#14, #15, #16).

## Verification commands

```bash
# methods per receiver type (non-test)
grep -rhn "^func (\w\+ \*Manager)\|^func (\w\+ \*Store)\|^func (\w\+ \*Handler)\|^func (\w\+ \*Client)" --include="*.go" | grep -v _test.go | awk -F: '{print $1}' | awk -F/ '{OFS="/"; $NF=""; print}' | sort | uniq -c | sort -rn

# files >700 LOC (non-test)
find . -name "*.go" -not -name "*_test.go" -not -path "./vendor/*" | while read p; do l=$(wc -l<"$p"); [ "$l" -gt 700 ] && echo "$l $p"; done | sort -rn

# interface method counts
python script (see task output) or manually inspect each `type X interface` body

# test files >3000 LOC
find . -name "*_test.go" -not -path "./vendor/*" | while read p; do l=$(wc -l<"$p"); [ "$l" -gt 3000 ] && echo "$l $p"; done | sort -rn

# package coupling
grep -rhn '"github.com/zerodha/kite-mcp-server/' --include="*.go" | grep -v _test.go | sed 's/.*"\(github.com[^"]*\)".*/\1/' | sort | uniq -c | sort -rn

# circular imports
go build ./...   # currently broken by in-flight Task #16 duplicate-decls; no cycles reported
```

## Caveats

- `go build ./...` fails because of in-progress Task #16 duplicate declarations in `kc/ops/dashboard_*.go`. Re-running after #16 completes is required to confirm no import cycles.
- `(m *Manager)` receiver count of 144 aggregates across all `kc/*.go` files; Task #14 (completed) targeted a smaller subset. After build stabilizes, rerun `grep "^func (.*\*Manager)" kc/*.go | grep -v _test.go | wc -l` for the authoritative post-decomposition number.
