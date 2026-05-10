# Path A.22 Pick: kc/riskguard

## Selection rationale

State at start: master HEAD `aac5af9`, v246 LIVE (chain agent in flight on
v247 of A.21). algo2go: 22 modules; 7 in-tree remaining.

User dispatch: kc/riskguard — confirms strategic recommendation from
A.21 close-out (high-leverage unblock for kc/usecases + kc/papertrading).

## Empirical scan

```
ls kc/riskguard/*.go              => 38 .go files (with subpkg checkrpc/)
grep github.com/algo2go/          => 5 deps:
  alerts, domain, i18n, oauth, logger
grep github.com/zerodha/kite-mcp-server in kc/riskguard/*.go (NOT _test.go):
  => 1 hit, intra-module:
       kc/riskguard/subprocess_check.go:15:
         "github.com/zerodha/kite-mcp-server/kc/riskguard/checkrpc"
grep github.com/zerodha/kite-mcp-server/testutil in kc/riskguard/*.go:
  => 0 hits (stale go.mod artifact only)

ls kc/riskguard/checkrpc/         => README.md, types.go, types_test.go
                                    (3 files, intra-module subpkg)

grep -rl 'kite-mcp-server/kc/riskguard' --include='*.go' .
  => 53 consumer .go files
```

## Why kc/riskguard is the right next pick

1. **Self-only internal dep**: only ref is to its own subpackage
   `checkrpc`, which moves with it during subdirectory-filter
2. **53 consumer fan-in** — meaningful unblock value
3. **All 5 algo2go deps already external** (alerts A.11, domain A.10,
   i18n A.4, logger A.7, oauth A.13); no remaining edges
4. **Unblocks 2 modules**:
   - kc/usecases (had audit + riskguard as 2 internal deps; audit
     extracted A.21; this clears the second)
   - kc/papertrading (had riskguard as sole internal dep)
5. After A.22: kc/telegram becomes single-blocker on papertrading;
   one more after that is fully unblockable

## go.mod artifacts to drop (stale workspace lines)

```
replace (
    github.com/zerodha/kite-mcp-server => ../..
    github.com/zerodha/kite-mcp-server/testutil => ../../testutil
)
```

Both lines drop cleanly. Same shape as A.21 (audit) — the single
intra-module ref to `checkrpc` rewrites in-place during the
extracted-tree rewrite-dryrun phase, not through a replace.

## Type-identity safety

All 5 algo2go deps already external. Riskguard checks operate on
domain types (Order, OrderRequest, Margin) defined in
github.com/algo2go/kite-mcp-domain — single-module identity since
A.10. No co-existence problem.

## Stop conditions / halt-rules

- Stop ~3-4h. Halt at ~5h.
- Watchdog: any 600s no-progress -> commit + push immediately + surface.
- Hard rules unchanged (no `git stash`; WSL2 for `go test`; agent
  brief stays scoped to own packages; `git add -- <paths>` not `-A`).
