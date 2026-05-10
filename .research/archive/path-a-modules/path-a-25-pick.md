# Path A.25 Pick: kc/telegram

## Selection rationale

State at start: master HEAD `191ab09`, v249 LIVE (chain agent in flight on
v250 of A.24). algo2go: 25 modules; 4 in-tree remaining.

User dispatch: kc/telegram — confirms strategic recommendation from
A.24 close-out (just unblocked by kc/papertrading; Telegram /buy /sell
/quick /setalert + briefings).

## Empirical scan

```
ls kc/telegram/*.go        => 15 .go files
                              (bot, bot_edge_test, cleanup_test,
                               commands, commands_test, disclaimer,
                               disclaimer_test, handler_auth_test,
                               handler_portfolio_test, handler_test,
                               handler_trading_test, plugin_commands,
                               plugin_commands_test, trading_commands,
                               trading_fuzz_test)

grep github.com/algo2go/ in kc/telegram/*.go
  => 8 deps:
       alerts, broker (incl. /ticker + /zerodha subpkgs),
       domain, instruments, papertrading (just landed A.24!),
       riskguard, ticker, watchlist

grep github.com/zerodha/kite-mcp-server in kc/telegram/*.go:
  => ZERO hits in source (only stale go.mod replace ../.. artifact)

grep github.com/zerodha/kite-mcp-server/testutil in kc/telegram:
  => ZERO hits (no testutil-strip pattern needed; no replace
              testutil line in go.mod either)

grep -rl 'github.com/zerodha/kite-mcp-server/kc/telegram'
       --include='*.go' .
  => 3 consumer .go files (app/http.go, app/app.go, app/adapters.go)
```

## Why kc/telegram is the right next pick

1. **Zero internal monolith imports** — same clean shape as kc/audit
   (A.21), kc/cqrs (A.19), kc/usecases (A.23), kc/papertrading (A.24)
2. **All 8 algo2go deps already external** (papertrading A.24 just
   landed; riskguard A.22; instruments A.16; watchlist A.15; ticker
   A.18) — no remaining edges
3. **Smallest consumer fan-in remaining**: only 3 files (app/* glue),
   simplest cutover
4. **High user-visible signal**: Telegram is an end-user feature
   surface (mobile-friendly trading via /buy /sell /quick /setalert,
   morning briefings, daily P&L). Externalizing it lets future
   algo2go consumers wire Telegram bot integration without depending
   on the full monolith
5. **Simpler go.mod**: only 1 stale workspace artifact (replace ../..),
   no replace testutil line — cleanest rewrite-dryrun yet

## go.mod artifacts to drop (stale workspace lines)

```
require (
    ...
    github.com/zerodha/kite-mcp-server v0.0.0-... // indirect (line 25)
)
replace (
    github.com/zerodha/kite-mcp-server => ../..
)
```

Both lines drop cleanly. Single-replace shape (no testutil) — simpler
than the dual-replace audit/usecases/papertrading shape.

## Type-identity safety

All 8 algo2go deps already external. Telegram bot operates on domain
types (Order, Position, Holding, Alert) defined in
github.com/algo2go/kite-mcp-domain — single-module identity since
A.10. Trading commands flow through external riskguard for safety
checks (verified working in A.22) and external papertrading for
paper-mode interception (verified working in A.24). No co-existence
problem.

## Stop conditions / halt-rules

- Stop ~3h. Halt at ~4h.
- Watchdog: any 600s no-progress -> commit + push immediately + surface.
- Hard rules unchanged (no `git stash`; WSL2 for `go test`; agent
  brief stays scoped to own packages; `git add -- <paths>` not `-A`).
