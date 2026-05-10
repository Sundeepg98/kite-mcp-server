# Path A.20 Pick: kc/eventsourcing

## Selection rationale

State at start: master HEAD `17c0fca`, v244 LIVE (chain agent in flight on
v245 of A.19). algo2go: 20 modules; 9 in-tree remaining.

User dispatch surfaced 2 candidates: kc/eventsourcing (3 deps) OR kc/audit (4 deps).

**Pick: kc/eventsourcing.**

### Empirical scan

```
ls kc/eventsourcing | wc -l       => 18 files
grep -rln 'kc/eventsourcing' --include='*.go' .   => 26 consumer files
grep -rh 'github.com/' kc/eventsourcing/*.go      => 3 algo2go imports:
  - github.com/algo2go/kite-mcp-alerts
  - github.com/algo2go/kite-mcp-broker
  - github.com/algo2go/kite-mcp-domain
  + stretchr/testify, google/uuid (external libraries)

Internal monolith imports:
  github.com/zerodha/kite-mcp-server/* in kc/eventsourcing/*.go = ZERO
```

### Why kc/eventsourcing over kc/audit

| Property | kc/eventsourcing | kc/audit |
|---|---|---|
| Internal `zerodha/kite-mcp-server/*` imports in src | 0 | 0 (probably) |
| algo2go .go imports | 3 (alerts+broker+domain) | 4 (alerts+domain+logger+oauth) |
| Module file count | 18 | ~31 |
| Replace lines in own go.mod | 1 (root) | 2 (root + testutil) |
| Workspace artifact | `replace ../..` only | `replace ../..` + `replace ../../testutil` |
| testutil dep | None observed in scan | Possible (oauth dep chain) |

eventsourcing's go.mod narration explicitly notes "moderate-fan-in,
single-PR-extractable" and was prepared for extraction in a 4-commit
batch. All blockers (kc/alerts, kc/domain, broker, kc/isttz, kc/logger,
kc/money) are now external. No remaining edges.

audit has potential testutil dep via oauth chain (testutil-strip pattern
from A.11 may apply). Defer to A.21+.

### Type-identity safety

All 3 algo2go .go imports are already external (Phase B canary done for
alerts at A.11, broker at A.6, domain at A.10). No type-identity risk:
events flowing through alerts/broker/domain are already single-module
identity — no co-existence problem.

### Workspace artifact to drop

```
replace (
    github.com/zerodha/kite-mcp-server => ../..
)
```

Same shape as kc/cqrs (A.19), kc/ticker (A.18), and 17 prior. Standard
sed pattern via `sed -i '/^replace (/,/^)/d'`.

### Stop conditions / halt-rules

- Stop ~3-4h. Halt at ~5h.
- Watchdog: any 600s no-progress -> commit + push immediately + surface.
- All hard rules unchanged (no `git stash`; WSL2 for `go test`; agent
  brief stays scoped to own packages; `git add -- <paths>` not `-A`).
