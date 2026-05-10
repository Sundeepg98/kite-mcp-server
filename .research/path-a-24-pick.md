# Path A.24 Pick: kc/papertrading

## Selection rationale

State at start: master HEAD `d32b2a2`, v248 LIVE (chain agent in flight on
v249 of A.23). algo2go: 24 modules; 5 in-tree remaining.

User dispatch: kc/papertrading — confirms strategic recommendation from
A.23 close-out (just unblocked by kc/riskguard A.22; high signal as
end-user feature).

## Empirical scan

```
ls kc/papertrading/*.go    => 17 .go files
                              (engine + 5 engine edge tests +
                               middleware + monitor + store +
                               store_fk + money_test + order_id +
                               leak_sentinel + papertrading_test +
                               riskguard_integration_test)

grep github.com/algo2go/ in kc/papertrading/*.go
  => 6 deps:
       alerts, broker (incl. /mock subpkg), domain, logger,
       oauth, riskguard

grep github.com/zerodha/kite-mcp-server in kc/papertrading/*.go:
  => ZERO hits in source (only stale go.mod replace artifacts)

grep github.com/zerodha/kite-mcp-server/testutil in kc/papertrading:
  => ZERO source imports (stale go.mod replace artifact only)

grep -rl 'github.com/zerodha/kite-mcp-server/kc/papertrading'
       --include='*.go' .
  => 18 consumer .go files
```

## Why kc/papertrading is the right next pick

1. **Zero internal monolith imports** in any .go source — same clean
   shape as kc/audit (A.21), kc/cqrs (A.19), kc/usecases (A.23)
2. **All 6 algo2go deps already external** (alerts A.11, broker
   early-A, domain A.10, logger A.7, oauth A.13, riskguard A.22 just
   landed) — no remaining edges
3. **18 consumer fan-in** + 17 module-internal files = ~37 total
   Phase A sweep, comparable to A.20 (kc/eventsourcing 32 files)
4. **High user-visible signal**: paper trading is an end-user
   feature (virtual portfolio mode). Externalizing it lets future
   non-Kite consumers wire paper trading into their own MCP servers
   without depending on the full monolith
5. **Strategic unlock**: clears the riskguard dep edge for
   kc/telegram. After A.24: kc/telegram becomes single-feasible
   (papertrading was its sole blocker)

## go.mod artifacts to drop (stale workspace lines)

```
replace (
    github.com/zerodha/kite-mcp-server => ../..
    github.com/zerodha/kite-mcp-server/testutil => ../../testutil
)
```

Both lines drop cleanly. Same shape as kc/audit (A.21) and kc/usecases
(A.23) — stale carrying-cost from the in-tree workspace days. No
actual root or testutil imports in source.

## Type-identity safety

All 6 algo2go deps already external. Paper trading engine operates on
domain types (Order, Position, Holding) defined in
github.com/algo2go/kite-mcp-domain — single-module identity since
A.10. The riskguard_integration_test.go reaches the just-landed
algo2go/kite-mcp-riskguard — verified working in A.22 standalone test.
No co-existence problem.

## Stop conditions / halt-rules

- Stop ~3h. Halt at ~4h.
- Watchdog: any 600s no-progress -> commit + push immediately + surface.
- Hard rules unchanged (no `git stash`; WSL2 for `go test`; agent
  brief stays scoped to own packages; `git add -- <paths>` not `-A`).
