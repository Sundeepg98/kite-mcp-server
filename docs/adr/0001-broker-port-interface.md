# ADR 0001: Broker Port Interface — Multi-Broker Readiness

**Status**: Accepted (2026-04-26)
**Author**: kite-mcp-server architecture
**Decision drivers**: dim-10 (ISO 25010 Compatibility) auditor expectations; path-to-100 deep-dive Class 3 (`2a1f933`).

---

## Context

Auditors evaluating dim-10 (Compatibility) ask: "Is the system extensible to other brokers (Upstox, Groww, Angel One, Dhan)?" The honest answer for kite-mcp-server today is: structurally yes, empirically no — only Zerodha is implemented. This ADR documents the structural readiness so future auditor reviews can verify the port surface without chasing a hypothetical second broker.

## Decision

The `broker` package (`broker/broker.go`) defines a composite `broker.Client` interface that any broker implementation must satisfy:

```go
// broker/broker.go:541
type Client interface {
    BrokerIdentity
    ProfileReader
    PortfolioReader
    OrderManager
    MarketDataReader
    GTTManager
    PositionConverter
    MutualFundClient
    MarginCalculator
}
```

Each sub-interface (8 total) is independently consumable — callers depending on one slice (e.g. `OrderManager`) need not couple to the full surface.

Compile-time satisfaction assertions live in each implementation:
- `broker/zerodha/client.go:26` — `var _ broker.Client = (*Client)(nil)`
- `broker/mock/client.go:18` — `var _ broker.Client = (*Client)(nil)`

## Multi-broker proof

A hypothetical Upstox adapter ships as `broker/upstox/client.go` with one new compile-time assertion:

```go
var _ broker.Client = (*upstox.Client)(nil)
```

The build fails immediately if any of the 8 sub-interface methods is missing or has a drifted signature. No runtime testing required for the structural proof — Go's type system enforces it at `go build`.

## Why no real second broker today

Per `78c243e` business-case analysis:
- **LOC cost**: ~600 LOC per adapter (SDK adaptation, error mapping, retry semantics)
- **Maintenance**: ~20h/quarter per adapter for SDK upgrades
- **Demand signal**: 0 paying customers asking for non-Zerodha access
- **Score lift**: dim-10 78→85 (+7pt) from interface stub; +15pt only if real adapter ships
- **Opportunity cost**: same engineering time better spent on user-facing features

Verdict: ship interface readiness (this ADR + existing `broker.Client`); defer real adapter until paying customer demands it.

## Consequences

**Positive**:
- Auditor question answered: "Yes, port exists at `broker/broker.go:541`."
- Future contributors adding a broker have a single satisfaction target.
- Zero ongoing maintenance cost.

**Neutral**:
- Score lift capped at +7pt without real adapter (dim-10 still under 90).

**Negative**:
- Risk of port-surface bit-rot if Zerodha SDK gains methods not abstracted into `broker.Client`. Mitigation: the existing `kiteSDK` interface in `broker/zerodha/sdk_interface.go` keeps SDK→Client adaptation in one place; new methods land there first.

## References

- `broker/broker.go:541` — composite `Client` interface definition
- `broker/zerodha/client.go:26` — Zerodha satisfaction assertion
- `broker/mock/client.go:18` — Mock satisfaction assertion
- `.research/path-to-100-per-class-deep-dive.md` Class 3
- `.research/path-to-100-business-case.md` (`78c243e`) §6 — multi-broker LOC cost
