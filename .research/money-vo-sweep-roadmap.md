# Money VO Full Sweep — Sprint Roadmap

Goal: elevate the DDD `Money` value object from a domain-only convenience
type to the canonical representation of all monetary fields in the codebase.
Eliminates the silent INR↔USD coercion class of bugs and pushes DDD score
from 99 → 100.

## Sliced approach

Five independent slices, each shippable as a standalone commit. Each slice
maintains JSON wire-format compatibility via the `Money.Float64()` accessor
at the serialization boundary, so external dashboards and the OAuth widget
host see no behavioural change.

## Slice 1 — UserLimits.Max*INR (DONE — current commit)

Status: shipped.

Surface area:
- `kc/riskguard/limits.go` — `UserLimits` struct fields (Max*INR are Money)
- `kc/riskguard/guard.go:23-31` — SystemDefaults values
- `kc/riskguard/internal_checks.go:65-90, 200-225` — currency-aware
  `Money.GreaterThan()` comparisons in checkOrderValue + checkDailyValue
- `kc/usecases/admin_usecases.go:184` — headroom subtraction at boundary
- `mcp/admin_user_tools.go`, `mcp/admin_risk_tools.go` — `.Float64()` at JSON boundary
- `mcp/compliance_tool.go`, `mcp/ext_apps.go` — widget JSON outputs
- `kc/ops/api_handlers.go`, `kc/ops/dashboard_safety.go` — dashboard JSON
- 60+ test sites updated

New API: `Money.Float64()` accessor + `Money.GreaterThan(other) (bool, error)`.

## Slice 2 — OrderCheckRequest.Price + cascade

Surface area (~130 sites):
- `kc/riskguard/types.go` — `OrderCheckRequest.Price float64` → `domain.Money`
- All 18 order-tool middleware paths that construct OrderCheckRequest
- Plugin RPC wire format (`kc/riskguard/checkrpc/*.go`) — the JSON-encoded
  request crosses a process boundary, so the proto must keep float64 at
  rest; conversion at the marshalling seam
- All 130+ test sites that build OrderCheckRequest with raw price floats

Risk: high. Plugin RPC compat is non-trivial (subprocess plugins consume
the JSON shape). Suggest a parallel-safe path: keep `Price float64` on the
proto struct, add a `Money() domain.Money` helper, gradually migrate
callers to read via the helper.

## Slice 3 — UserTracker.DailyPlacedValue + position/PnL

Surface area:
- `kc/riskguard/guard.go` — `UserTracker.DailyPlacedValue float64` → Money
  (line 478 increment becomes Money.Add)
- `kc/riskguard/types.go` — `UserStatus.DailyPlacedValue` (JSON-exposed,
  needs `.Float64()` boundary)
- Holdings/positions value computations (`mcp/portfolio_*.go`,
  `kc/usecases/portfolio_*.go`)
- Telegram briefings P&L formatting

Risk: medium. JSON wire format (`UserStatus`) is consumed by the dashboard
SSE feed and admin tools. Same Float64() boundary pattern as Slice 1.

## Slice 4 — Billing tier amounts

Surface area:
- `kc/billing/billing.go` — tier price fields, MRR computations
- All tier-config tests
- Admin dashboard tier display

Risk: medium. Coordinate with whoever's actively working in `kc/billing/*`
(check for in-flight agents before starting).

## Slice 5 — Paper trading cash + portfolio value

Surface area:
- `kc/papertrading/portfolio.go` — `Cash float64` field on PaperPortfolio
- All deposit/withdraw/PnL computations within the paper-trading engine
- `kc/papertrading/store.go` SQL persistence (REAL → REAL, but rebuild
  Money on Scan)
- Background LIMIT-fill monitor that adjusts portfolio cash

Risk: lowest (self-contained package, no external clients).

## Conventions established by Slice 1

1. **Boundary accessor pattern**: `.Float64()` at JSON serialization,
   SQLite REAL bind, log fields. Comments at boundary explain "why
   crossing out of domain layer".

2. **Zero-Money sentinel**: `Money.IsZero()` is the "no per-user override"
   indicator in `GetEffectiveLimits`. Constructors that leave money fields
   unset rely on this.

3. **Currency-aware comparison**: `Money.GreaterThan(other) (bool, error)`
   returns the comparison + currency-mismatch error. Callers treat the
   error as "unable to verify, allow" (fail-open at the boundary, not
   silent coercion).

4. **Test convention**: `domain.NewINR(N)` in struct literals everywhere
   instead of bare floats. Reflective `assert.Equal` works on Money values.

5. **Persistence convention**: SQLite stores REAL (float64), reconstructs
   via `domain.NewINR(scanned)` on Load. DDL types unchanged.

## Pre-existing issues out of scope

- `kc/riskguard/market_hours.go:28` — `marketHoursISTOverride` is a global
  test seam without sync; race detector flags it when running parallel
  tests with `-race`. Pre-existing, unrelated to Money sweep.
