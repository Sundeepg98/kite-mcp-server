# Port-Adapter Framework Design — empirical re-frame for multi-broker horizon

**Date**: 2026-05-04
**HEAD**: `28169b6` (post 3/5 module decomposition)
**Charter**: read-only research; commit + push doc only.
**Predecessor**: `.research/100-pct-decomposition-strategy.md`
recommended pivot to port-adapter framework as alternative to
ceremonial 5/5 grind.

---

## Q1 — Current port-adapter state (empirical)

**`broker/broker.go` is 635 LOC of clean port surface** — the
heaviest investment is already done. Surface inventory:

- **DTO types (200 LOC)**: `Profile`, `Margins`, `Holding`,
  `Position`, `Order`, `Trade`, `OrderParams`, `LTP`, `OHLC`,
  `Quote`, `Depth`, `HistoricalCandle`, `GTT*`, `MF*`,
  `OrderMargin*`, `OrderCharges*`, `NativeAlert*`. All
  broker-agnostic — no `kiteconnect.*` types in the port.
- **`Factory` interface**: `Create`, `CreateWithToken`, `BrokerName`.
- **`Authenticator` interface**: `GetLoginURL`, `ExchangeToken`,
  `InvalidateToken` + `AuthResult` struct.
- **Composite `Client` interface** + 9 ISP-segregated sub-interfaces:
  `BrokerIdentity`, `ProfileReader`, `PortfolioReader`,
  `OrderManager`, `MarketDataReader`, `GTTManager`,
  `PositionConverter`, `MutualFundClient`, `MarginCalculator`.
- **`NativeAlertCapable`**: optional sub-interface for brokers
  that support server-side alerts (currently Zerodha-only). Type
  assertion gates the capability — clean precedent.

**`broker.PortContract` (commit `55d1a17`)** is genuinely reusable.
Three sub-tests: `satisfies_broker_Client` (compile-time interface
checks via `var _ broker.X = c`), `BrokerName_non_empty`,
`read_methods_callable_no_panic` (10 read methods + 3 market-data
methods callable without panic). Works on any broker via
`PortContract(t, factory)`. NOT a one-off — explicitly designed for
reuse with a worked Upstox stub example in the file's docstring.

**Gap from "Zerodha-only" to "framework hosting N adapters"**:
**smaller than expected**. The port surface is 95% adapter-ready.
Three concrete leaks remain:

1. **`kc/ticker/service.go` leaks `kiteticker.Mode`** as a public
   type alias (`type Mode = kiteticker.Mode`). The `broker.Client`
   interface has NO ticker/websocket methods. Ticker is a separate
   port that hasn't been abstracted.
2. **`mcp/alert_tools.go:179` + `mcp/watchlist_tools.go:407`** still
   use `kiteconnect.QuoteLTP` directly inside `RetryBrokerCall`
   wrappers. Two callsites; trivial fix.
3. **`kc/alerts/briefing.go`** defines a custom `BrokerProvider`
   interface returning `kiteconnect.Holding` etc. (lines 26-32)
   — a parallel, broker-specific port that should re-use
   `broker.PortfolioReader`.

---

## Q2 — Multi-broker adoption blockers

| Concern | Status | Class |
|---|---|---|
| Auth flow shape | `broker.Authenticator` already abstracts OAuth-redirect; `AuthResult` is a clean DTO | (a) easily abstracted — done |
| Order-type vocabulary | `OrderParams.OrderType` is a string; brokers map to their own SDK | (a) done via `convertOrderParamsToKite` |
| OHLC / Quote shape | `broker.OHLC`, `broker.Quote`, `broker.Depth` are common-denominator types | (a) done |
| Instrument identifier format | "EXCHANGE:TRADINGSYMBOL" string convention (e.g. `NSE:RELIANCE`) — Zerodha + Upstox + Dhan all use; Angel One uses symbol_token | (b) needs adapter shim per-broker |
| GTT support | `GTTManager` interface exists; only Zerodha implements; Upstox doesn't yet | (b) optional sub-interface like `NativeAlertCapable` (precedent set) |
| Mutual fund support | Same as GTT — Zerodha-specific today; ICICIDirect/Groww may differ | (b) wrap in optional interface |
| Server-side alerts | `NativeAlertCapable` precedent | (a) done |
| **Websocket / live ticks** | `kc/ticker/` directly imports `kiteticker.Mode` + `kiteticker.Ticker` | **(c) leaks through — every ticker consumer is broker-specific** |
| Historical-data interval vocab | `interval string` parameter; broker-specific values like "5minute", "day" | (b) needs canonical interval enum + per-broker map |
| Margin response shape | `MarginCalculator` returns `any` (Raw pass-through) | (b) intentional escape hatch — fine for v1 framework |

**The (c) blocker is the framework's reason-to-exist**. Ticker
abstraction would be a new port (`broker.Ticker` or `broker.LiveStream`
with `Subscribe`, `Unsubscribe`, `SetMode`, `OnTick` methods)
matching the Zerodha kiteticker shape — this is the genuine
multi-broker debt.

---

## Q3 — Framework design (3-axis)

**Port surface**: keep current 9 sub-interfaces + `Client` composite.
ADD `broker.Ticker` port for websocket abstraction (eliminates the
(c) leak). Make `GTTManager`, `MutualFundClient`, `NativeAlertCapable`
explicitly OPTIONAL via type assertion (already true for native
alerts; document the pattern). Mark optional sub-interfaces in
godoc. **Net new code: ~80 LOC for `broker.Ticker` interface +
DTO types (Tick, Mode, BinaryMode constants).**

**Test contract**: `PortContract` (113 LOC today) becomes the v1
baseline. Add 4 new conformance buckets:
- `auth_lifecycle` (login URL non-empty, ExchangeToken returns
  AuthResult shape)
- `optional_capability_advertisement` (verify
  `NativeAlertCapable` / `GTTManager` / `MutualFundClient` type
  assertion behavior matches broker's documented support)
- `error_classification` (transient vs permanent error wrapping
  per `broker/errors.go` `RateLimitError` pattern)
- `ticker_subscribe_unsubscribe` (when broker advertises Ticker,
  Subscribe → tick callback fires → Unsubscribe stops it)

Each bucket adds ~40-60 LOC. **Total contract: ~330 LOC.**

**Code organization**: **stays in `broker/` as separate
sub-packages, no per-adapter go.mod**. Per
`.research/100-pct-decomposition-strategy.md` empirical findings,
adapter modules would each need 3+ replace directives (root +
broker + kc/money) for marginal-zero CI isolation benefit. Single-
binary deployment + per-adapter sub-package compiles in <1s
incrementally. The lower-ceremony option preserves `go test
./broker/...` running every adapter conformance test in one shot.

---

## Q4 — Dispatchable next step

**Build `broker/ticker/` port + `broker/conformance/` test harness.
Don't add Upstox skeleton yet (no demand signal).**

Concrete first deliverable (~3-4 hours, single agent):

1. `broker/ticker/ticker.go` — new file, ~120 LOC. Defines
   `Ticker` interface (Subscribe, Unsubscribe, SetMode, OnTick,
   OnConnect, OnError, OnReconnect, Stop), `Tick` DTO, `Mode`
   const enum (`ModeLTP`, `ModeQuote`, `ModeFull`).
2. `broker/zerodha/ticker_adapter.go` — wraps `kiteticker.Ticker`
   to satisfy `broker.Ticker`. ~150 LOC; absorbs the
   kiteticker-specific code from `kc/ticker/service.go`.
3. `kc/ticker/service.go` — replace `*kiteticker.Ticker` with
   `broker.Ticker`. Drop the `Mode = kiteticker.Mode` alias;
   re-export `broker/ticker.Mode` instead. **~30 LOC of
   import-path changes; ZERO behavior change.**
4. `broker/conformance/conformance.go` — promote `PortContract`
   from a single test func to a package with 4 conformance
   buckets per Q3.
5. Verify: `go test ./broker/... ./kc/ticker/...` green; smoke
   test on production v189 unaffected (adapter is drop-in).

**Budget: 3-4 hours single-agent. Result: a 4th leak (the (c)
ticker leak) closed; framework rated "ready for second adapter
when demand arrives" rather than "rated ready and waiting for
ceremony".**

**Preconditions for this work** (per
`feedback_decoupling_denominator.md`, state explicit):
- **Agent-concurrency denominator**: a port-adapter framework
  let multiple agents work on broker adapters concurrently
  without conflict IS the goal. Today, 0 agents are working on
  non-Zerodha adapters because the framework gap (c) blocks
  them. The framework unblocks. Net concurrency: 0 → N where N
  = future adapter authors (currently uncertain).
- **User-MRR denominator**: zero direct lift. Multi-broker
  support is a future-revenue horizon, not pre-launch.
- **Tech-stack-portability denominator**: the framework makes
  the codebase BROKER-portable (cross-language portability is a
  separate question per `parallel-stack-shift-roadmap.md`).

**If preconditions don't hold today** (no second-broker user
demand visible at Show HN), defer to trigger:
- **Trigger A**: external developer files an issue requesting
  Upstox/Dhan/Angel One adapter. Probability per
  `.research/multi-product-and-repo-structure.md` §5.5: ~31%
  in 24 months.
- **Trigger B**: SEBI mandates multi-broker abstraction (no
  current signal).
- **Trigger C**: Zerodha changes API in a way that needs
  graceful-fallback to a second broker. Low probability;
  Zerodha's API has been stable since fork.

**Honest verdict**: option (C) IS empirically marginal-positive
(NOT marginal-zero like 5/5 grind), but the value is unlocked
ONLY when external second-broker demand materializes. The work
itself is small (3-4 hours), defensible (closes a real
SDK leak), and idempotent (drops in cleanly). Recommend
**deferring to post-Show-HN** unless launch-day feedback
explicitly requests second-broker support.

If user wants to ship now anyway: the deliverable is concrete
and the work is contained. NOT pre-launch ceremony — it's the
first port-adapter beachhead that future adapter authors will
build on.

---

## Sources

- `broker/broker.go` (635 LOC) — empirical port surface
- `broker/contract_test.go` (125 LOC) — `PortContract` reusable
- `broker/zerodha/client.go`, `factory.go`, `convert.go`,
  `retry.go`, `ratelimit.go` — adapter shape
- `kc/ticker/service.go` lines 10-145 — empirical (c) leak:
  `kiteticker.Mode` type alias + `*kiteticker.Ticker` direct use
- `mcp/alert_tools.go:179`, `mcp/watchlist_tools.go:407` — 2
  remaining `kiteconnect.QuoteLTP` callsites in upper layers
- `kc/alerts/briefing.go` lines 26-32 — parallel `BrokerProvider`
  interface using `kiteconnect.*` DTOs (refactor candidate)
- Commits `b7fedcc`, `5d74acf`, `9ce2248` — empirical cost-curve
  evidence informing "no per-adapter go.mod" recommendation
- `.research/100-pct-decomposition-strategy.md` (`28169b6`) —
  cost-curve framework
- `feedback_decoupling_denominator.md` — three-axis ROI

---

*2026-05-04. Read-only. Framework is 95% there; closing the (c)
ticker leak is the one beachhead worth shipping when demand arrives.*
