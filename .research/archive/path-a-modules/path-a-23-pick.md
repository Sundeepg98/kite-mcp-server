# Path A.23 Pick: kc/usecases

## Selection rationale

State at start: master HEAD `32fb61c`, v247 LIVE (chain agent in flight on
v248 of A.22). algo2go: 23 modules; 6 in-tree remaining.

User dispatch: kc/usecases — confirms strategic recommendation from
A.22 close-out (highest fan-in unlock since audit + riskguard cleared
its 2 internal blockers in A.21 + A.22).

## Empirical scan

```
ls kc/usecases/*.go        => 57 .go files
                              (account, admin, alert, cancel,
                               close_all_positions, close_position,
                               consent, context, convert_position,
                               create_alert, create_composite_alert,
                               data_export, family, get_orders,
                               get_portfolio, gtt, margin, mf,
                               modify_order, native_alert,
                               oauth_bridge, observability, options_strategy,
                               paper_trading, place_order, pnl, ports,
                               pretrade, queries, saga, session,
                               setup, telegram, ticker, trailing_stop,
                               usecases_edge_test, usecases_read_test,
                               usecases_test, usecases_write_test,
                               watchlist, widget — many _test.go
                               variants, mocks_test.go)

grep github.com/algo2go/ in kc/usecases/*.go
  => 11+ deps:
       alerts, broker, cqrs, domain, eventsourcing, logger,
       money, riskguard, ticker, users, watchlist
       (plus broker/mock + broker/zerodha subpkgs)

grep github.com/zerodha/kite-mcp-server in kc/usecases/*.go (NOT _test.go):
  => ZERO hits

grep github.com/zerodha/kite-mcp-server in kc/usecases/*_test.go:
  => ZERO hits

grep github.com/zerodha/kite-mcp-server/testutil in kc/usecases/*.go:
  => ZERO hits (no testutil-strip pattern needed)

grep -rl 'github.com/zerodha/kite-mcp-server/kc/usecases'
       --include='*.go' .
  => 38 consumer .go files
```

## Why kc/usecases is the right next pick

1. **Zero internal monolith imports** — same clean shape as kc/audit
   (A.21) and kc/cqrs (A.19). No testutil-strip needed.
2. **All 11 algo2go deps already external** (cqrs A.19,
   eventsourcing A.20, audit A.21, riskguard A.22 all just landed).
   No remaining edges.
3. **38 consumer fan-in** + 57 module-internal files = ~95-110
   total Phase A sweep, comparable to A.21 (82 files for kc/audit)
   and smaller than A.10 (kc/domain 161 files).
4. **High-leverage user-facing impact**: kc/usecases is the
   write-side CQRS layer (place/cancel/modify orders, portfolio,
   alerts, oauth bridge, sessions, tickers) — externalizing it
   completes the "ports & adapters" architecture migration along
   the most user-visible axis.
5. The user's hand-off anticipated 100+ file sweep — actual will
   be ~95-110 (within range), well inside the 4-hour budget per
   prior promotion timing.

## go.mod artifacts to drop (stale workspace lines)

```
require (
    ...
    github.com/zerodha/kite-mcp-server v0.0.0-... // indirect (line 37)
)
replace (
    github.com/zerodha/kite-mcp-server => ../..
)
```

Both lines drop cleanly. Stale carrying-cost from the in-tree
workspace days. No actual root imports in source.

## Type-identity safety

All 11 algo2go deps already external. Use cases operate on domain
types (Order, Position, Alert, Holding, OAuth, Session) defined in
github.com/algo2go/kite-mcp-domain — single-module identity since
A.10. CQRS commands/queries flow through external
github.com/algo2go/kite-mcp-cqrs (since A.19). Event aggregates
flow through external kite-mcp-eventsourcing (since A.20). No
co-existence problem.

## Stop conditions / halt-rules

- Stop ~3-4h. Halt at ~5h.
- Watchdog: any 600s no-progress -> commit + push immediately + surface.
- Hard rules unchanged (no `git stash`; WSL2 for `go test`; agent
  brief stays scoped to own packages; `git add -- <paths>` not `-A`).
