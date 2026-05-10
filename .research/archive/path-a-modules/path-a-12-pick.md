# Path A.12 Pick — kc/users (billing-chain step 2)

**Date**: 2026-05-10
**Selected**: `kc/users` -> `algo2go/kite-mcp-users`
**Master HEAD at dispatch**: `8094ecc` (= production v236 + Path A.11 kc/alerts external)

## Decision: kc/users (single promotion, billing-chain step 2)

Per orchestrator dispatch authorizing Path A.12 in the billing
unblocking chain. **13th** algo2go module promotion, **step 2 of 4**
in chain (alerts ✓ → users → oauth → billing).

### Empirical scoring

| Module | Files | LOC | Internal deps in .go | Consumer files | Tests |
|---|---:|---:|---|---:|---|
| **kc/users** | 8 | 3947 | 1 (algo2go/kite-mcp-alerts — already external) | 63 (253 occurrences) | yes |

### Pick rationale

- **Single algo2go .go dep**: only `github.com/algo2go/kite-mcp-alerts`
  imported. kc/alerts shipped at Path A.11 (`fd9d9fb`); resolves
  cleanly via GOPROXY.
- **Stale go.mod artifact**: `require zerodha/kite-mcp-server` +
  `replace ../..` in go.mod despite zero actual root imports in
  source. This is a leftover workspace artifact — needs cleanup
  during rewrite (drop both lines).
- **Test infrastructure clean**: zero testutil imports. No A.11-style
  inline-replace pattern needed.
- **Strategic value**: kc/users Phase B unblocks oauth (depends on
  users). After oauth: kc/billing single-feasible.

### Stale go.mod artifact handling

kc/users/go.mod has:
```
require github.com/zerodha/kite-mcp-server v0.0.0-...
...
replace github.com/zerodha/kite-mcp-server => ../..
```

But `grep github.com/zerodha/kite-mcp-server kc/users/*.go` returns
ZERO matches. The require + replace are dead workspace artifacts.

**Resolution**: drop both lines during rewrite. `go mod tidy` will
verify the require is unnecessary and won't re-add it.

### Type-identity safety

kc/users public API:
- `Store` — user CRUD with `*alerts.DB` field (alerts is external — same module path everywhere)
- `User` struct, role constants (RoleAdmin, RoleTrader, RoleViewer)
- TOTP MFA helpers (`ProvisioningURI`, `VerifyTOTP`, etc.) — pure stdlib + crypto
- Password helpers (bcrypt) — pure stdlib

`*alerts.DB` is the only cross-module type, and alerts is external.
After cutover, all consumers will import via algo2go path — single
module identity. **No type-identity blocker.**

## Stop-rule observations

- ~3-4h budget — comfortable
- No expected halts (single algo2go dep, all production-clean)

## Forward-looking impact

After kc/users ships, the future-candidates table updates:

| Module | Status after kc/users external |
|---|---|
| **oauth** | **Single-promotion candidate** (last in-tree dep cleared) |
| kc/billing | Still needs oauth external |

Path A.13 most viable: oauth (billing-chain step 3 of 4).

## Cross-session domain

`Path A inauguration owner` — broker DONE, money DONE, decorators
DONE, i18n DONE, legaldocs DONE, isttz DONE, scheduler DONE, logger
DONE, templates DONE, aop DONE, domain DONE, alerts DONE,
**users IN FLIGHT (billing chain step 2)**.
