# Path A.21 Pick: kc/audit

## Selection rationale

State at start: master HEAD `0446f84`, v245 LIVE (chain agent in flight on
v246 of A.20). algo2go: 21 modules; 8 in-tree remaining.

User dispatch surfaced 5 candidates: kc/audit (4 deps) +
kc/papertrading + kc/usecases + kc/riskguard + kc/telegram.

**Pick: kc/audit.**

## Scoring table for all in-tree candidates

| Module | Files | algo2go deps | Internal deps (prod) | Internal deps (test) | Verdict |
|---|---|---|---|---|---|
| **kc/audit** | 30 | 4 (alerts/domain/logger/oauth) | **0** | **0** | **PICK — clean** |
| kc/papertrading | 17 | 6 | 1 (riskguard) | 1 (riskguard) | Blocked by riskguard |
| kc/riskguard | 38 | 5 | 1 (own subpkg) | 0 | Self-only — possible |
| kc/sectors | 2 | 0 | 0 | 0 | Trivial — but only 2 files |
| kc/telegram | 15 | 8 | 2 (papertrading + riskguard) | 2 | Blocked by 2 modules |
| kc/usecases | 57 | 11 | 2 (audit + riskguard) | 2 | Blocked by audit + riskguard |

## Why kc/audit is the right next pick

1. **Zero internal monolith imports** in source — same shape as kc/cqrs/eventsourcing
2. **75 consumer files** in master reach kc/audit — large fan-in, biggest unblock
3. **All 4 algo2go deps already external** (alerts A.11, domain A.10,
   logger A.7, oauth A.13); no remaining edges
4. **Unblocks kc/usecases** for next promotion (audit + riskguard combo)
5. The user explicitly mentioned kc/audit at A.20 dispatch as the
   alternative-deferred-to-A.21 candidate

## Empirical scan

```
ls kc/audit | wc -l                        => 30 .go files
grep 'github.com/algo2go/' kc/audit/*.go   => 4 deps
  alerts, domain, logger, oauth
grep 'github.com/zerodha/kite-mcp-server'
       in kc/audit/*.go                    => ZERO refs (clean)
grep 'kite-mcp-server/testutil'
       in kc/audit/*.go                    => ZERO refs (clean)
grep -rl 'kite-mcp-server/kc/audit'
       --include='*.go' .                  => 75 consumer files
```

## go.mod artifacts to drop

```
replace (
    github.com/zerodha/kite-mcp-server => ../..
    github.com/zerodha/kite-mcp-server/testutil => ../../testutil
)
```

Both lines drop cleanly. The testutil replace is a stale artifact —
no actual testutil import exists in any kc/audit/*.go file. Both removed
in path-a-audit-rewrite-dryrun.sh.

## Type-identity safety

All 4 algo2go deps already external. Audit log records flow through
domain types (AuditEvent, ToolCallRecord) defined in
github.com/algo2go/kite-mcp-domain — single-module identity since A.10.
No co-existence problem.

## Stop conditions / halt-rules

- Stop ~3-4h. Halt at ~5h.
- Watchdog: any 600s no-progress -> commit + push immediately + surface.
- Hard rules unchanged (no `git stash`; WSL2 for `go test`; agent
  brief stays scoped to own packages; `git add -- <paths>` not `-A`).
