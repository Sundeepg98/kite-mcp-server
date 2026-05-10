# Path A.26 Pick: kc/sectors — FINAL extractable kc/* module

## Selection rationale

State at start: master HEAD `f77b9ad`, v250 LIVE (chain agent in flight on
v251 of A.25). algo2go: 26 modules. Only kc/sectors with own go.mod
remains in tree.

User dispatch: kc/sectors — confirms FINAL pick. Closes the entire
kc/* externalization arc.

## Empirical scan

```
ls kc/sectors/         => sectors.go, sectors_test.go, go.mod
                          (only 2 .go files — trivial leaf)

cat kc/sectors/go.mod  => zero replace directives (NO ../.. AND
                          NO ../../testutil); only stretchr/testify
                          require; pure stdlib leaf

grep github.com/algo2go/ in kc/sectors/*.go
  => ZERO algo2go imports (pure stdlib leaf — sector mapping data
     + NormalizeSymbol + Lookup helpers only)

grep github.com/zerodha/kite-mcp-server in kc/sectors/*.go:
  => ZERO hits (only the module declaration line in go.mod)

grep -rl 'github.com/zerodha/kite-mcp-server/kc/sectors'
       --include='*.go' .
  => 4 consumer .go files
       mcp/portfolio/sector_tool.go
       kc/ops/scanner.go
       kc/ops/dashboard_render_test.go
       kc/ops/api_portfolio.go
```

## Why this is the perfect finisher

1. **Smallest module by every metric**: 2 .go files, zero algo2go deps
2. **Cleanest go.mod possible**: NO `replace` directives at all (no
   `../..`, no `../../testutil`) — first such case in the entire
   Path A arc
3. **Tiny consumer fan-in**: 4 files (mcp/portfolio/sector_tool.go +
   3 kc/ops files)
4. **Pattern reference per its own go.mod narration**: "Pattern matches
   kc/isttz precedent (zero internal deps; only testify in test deps)"
   — kc/isttz was promoted in Path A.6 with the same shape
5. **Closes the arc**: After this Phase A + Phase B, every kc/*
   subdirectory with its own go.mod will be external in algo2go.
   Remaining in-tree kc/* code (kc/ops handlers, kc/ports interfaces,
   root-level kc/manager_*.go runtime wiring, kc/options.go,
   kc/config.go, etc.) lives inside the root module by design and
   does NOT have its own go.mod — those are not promotable.

## go.mod artifacts to drop

**NONE.** This is the first kc/* module in the entire arc with no
stale workspace artifacts. Just rewrite the module path. The
rewrite-dryrun script can keep its standard sed lines as no-ops
(harmless when they don't match).

## Type-identity safety

Zero algo2go deps; zero monolith deps. Pure stdlib + testify leaf.
The only data type exported is the in-memory sector map + 2 helper
funcs (NormalizeSymbol + Lookup). No co-existence problem possible.

## Stop conditions / halt-rules

- Stop ~2h. Halt at ~3h (per user dispatch).
- Watchdog: any 600s no-progress -> commit + push immediately + surface.
- Hard rules unchanged (no `git stash`; WSL2 for `go test`; agent
  brief stays scoped to own packages; `git add -- <paths>` not `-A`).

## Arc closure note

After A.26 lands:
- 27 algo2go modules total (broker, money, decorators, i18n,
  legaldocs, isttz, scheduler, logger, templates, aop, domain,
  alerts, users, oauth, billing, watchlist, instruments, registry,
  ticker, cqrs, eventsourcing, audit, riskguard, usecases,
  papertrading, telegram, sectors)
- 0 in-tree kc/* modules with own go.mod
- The kite-mcp-server repo becomes the orchestrator: imports all 27
  external modules, hosts root-level kc/manager_*.go runtime wiring,
  kc/ops/ handlers, kc/ports/ interfaces, mcp/ tool layer, app/
  HTTP+wiring, plugins/, testutil/, cmd/
- Path A inauguration COMPLETE for promotable kc/* modules
