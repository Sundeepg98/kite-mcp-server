# Path A.13 Pick — oauth (billing-chain step 3)

**Date**: 2026-05-10
**Selected**: `oauth` -> `algo2go/kite-mcp-oauth`
**Master HEAD at dispatch**: `10a1f5f` (= production v237 + Path A.12 kc/users external)

## Decision: oauth (single promotion, billing-chain step 3)

Per orchestrator dispatch authorizing Path A.13 in the billing
unblocking chain. **14th** algo2go module promotion, **step 3 of 4**
in chain (alerts ✓ → users ✓ → oauth → billing).

### Empirical scoring

| Module | Files | LOC | algo2go deps in .go | Consumer files | Tests |
|---|---:|---:|---|---:|---|
| **oauth** | 33 | 15880 | 2 (kite-mcp-templates + kite-mcp-users — both external) | 104 (609 occurrences) | yes |

### Pick rationale

- **All real deps external**: oauth's only production .go imports
  are `algo2go/kite-mcp-templates` + `algo2go/kite-mcp-users` —
  both already at v0.1.0 on algo2go (Path A.8' and A.12 respectively).
- **Zero testutil imports**: cleaner than kc/alerts (no helpers_test.go
  inline-replace + no MockKiteServer strip needed).
- **Stale go.mod artifacts**: oauth/go.mod has dead `replace ../`
  (root) + `replace ../testutil` — workspace artifacts to drop
  during rewrite (verified: zero actual root imports in oauth source).
- **Strategic value**: oauth Phase B is the LAST blocker for
  kc/billing's single-promotion. After oauth ships, kc/billing
  becomes single-feasible (Path A.14 = final billing-chain step).
- **Larger sweep than kc/users**: 104 consumers vs 63 — comparable
  to mid-tier kc/* extractions (between kc/users and kc/alerts/domain
  in scale).

### Type-identity safety verification

Per orchestrator brief, deeper checks:

**Q1: Does oauth import kc/users / kc/alerts (now external)?**
- Direct .go imports: only `algo2go/kite-mcp-templates` + `algo2go/kite-mcp-users`.
- kc/alerts is INDIRECT (via kc/users which uses *alerts.DB).
  Both kc/alerts and kc/users are external, so type-identity holds.

**Q2: Does oauth expose JWT/session types as cross-package values?**
- `oauth.Session`, `oauth.JWTConfig`, `oauth.ClientStore` — all
  intra-module types. Consumers use them via `oauth.X` references.
- After cutover, all consumers will import `algo2go/kite-mcp-oauth`,
  resolving to the same upstream types. No identity split.

**Q3: OAuth callback URL hardcoded references?**
- Callback URLs are runtime config (env vars + per-user stored in
  ClientStore). Not embedded in source paths. No mechanical impact
  from extraction.

**Q4: ClientStore + per-user encrypted client secrets?**
- ClientStore is a Go type backed by SQLite (alerts.DB). The
  encryption logic uses `crypto/aes` + HKDF from `golang.org/x/crypto`.
  No path-specific dependencies. After cutover, ClientStore moves
  with the package — same SQLite tables, same encryption keys
  (HKDF derived from OAUTH_JWT_SECRET env var, runtime-bound).

**Verdict: structurally clean.** No type-identity blocker. Will
verify empirically via scratch viability test before applying
Phase B on master.

## Stop-rule observations

- ~4h budget — comfortable
- Halt-at-first-surfacing per kc/billing methodology if any
  unexpected dep-graph issue surfaces

## Forward-looking impact

After oauth ships, the future-candidates table updates:

| Module | Status after oauth external |
|---|---|
| **kc/billing** | **Single-promotion-feasible** (last blocking dep cleared) |

Path A.14 = kc/billing (final billing-chain step).

## Cross-session domain

`Path A inauguration owner` — broker DONE, money DONE, decorators
DONE, i18n DONE, legaldocs DONE, isttz DONE, scheduler DONE, logger
DONE, templates DONE, aop DONE, domain DONE, alerts DONE, users DONE,
**oauth IN FLIGHT (billing chain step 3)**.
