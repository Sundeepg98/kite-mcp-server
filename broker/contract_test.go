package broker_test

// Package broker_test (note: external _test package — kept separate from
// the broker package itself so this contract harness can import any
// concrete implementation freely without circular-import risk).
//
// Contract test pattern — extracts a reusable PortContract suite that
// any future broker implementation (Upstox, Dhan, Angel One, etc.) can
// run against itself by passing a factory func. The Zerodha test below
// is the canonical example. To wire a new broker:
//
//	func TestUpstoxClient_Contract(t *testing.T) {
//	    PortContract(t, func(t *testing.T) broker.Client {
//	        return upstox.NewMockedClient(t)  // your test factory
//	    })
//	}
//
// The contract enforces:
//  1. The returned value satisfies broker.Client (compile-time + runtime).
//  2. Each sub-interface (BrokerIdentity, ProfileReader, ...) is reachable
//     via the composite — proves no method-set holes.
//  3. BrokerName() returns a non-empty broker.Name (identity invariant).
//  4. Read methods (GetProfile, GetMargins, GetHoldings, GetOrders, ...)
//     are callable without panicking. They may return errors if the mock
//     isn't configured for that path; the test only asserts no nil-deref.
//
// What the contract does NOT enforce:
//  - Specific behaviour of each method (broker semantics differ — Zerodha
//    has GTT, Upstox has different order varieties, etc.). Per-broker
//    tests cover semantics; this contract covers shape.
//  - Mock-SDK setup. Each broker provides its own factory; failure to
//    configure mock methods that the contract calls produces test errors
//    that point at the missing mock, which is the correct affordance.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/broker"
	mockbroker "github.com/zerodha/kite-mcp-server/broker/mock"
)

// PortContract is a reusable contract-test suite. Any broker.Client
// implementation can run it via t.Run("Contract", func(t *testing.T) {
// PortContract(t, factory) }).
//
// factory must return a fresh, ready-to-use broker.Client per call —
// the contract may invoke factory multiple times to get isolated
// instances. Backing mock state is the factory's responsibility.
//
// nolint:thelper // factory returns a value, not invokes test-helper
func PortContract(t *testing.T, factory func(t *testing.T) broker.Client) {
	t.Run("satisfies_broker_Client", func(t *testing.T) {
		t.Parallel()
		c := factory(t)
		require.NotNil(t, c, "factory must return non-nil broker.Client")
		// Compile-time + runtime: every sub-interface reachable via the
		// composite. If the implementation drops a method, this loop
		// fails with a clear interface-conversion panic; we recover via
		// assert.NotPanics so the failure mode is a test failure rather
		// than a process abort.
		assert.NotPanics(t, func() {
			var _ broker.BrokerIdentity = c
			var _ broker.ProfileReader = c
			var _ broker.PortfolioReader = c
			var _ broker.OrderManager = c
			var _ broker.MarketDataReader = c
			var _ broker.GTTManager = c
			var _ broker.PositionConverter = c
			var _ broker.MutualFundClient = c
			var _ broker.MarginCalculator = c
		}, "all sub-interfaces must be reachable via the composite")
	})

	t.Run("BrokerName_non_empty", func(t *testing.T) {
		t.Parallel()
		c := factory(t)
		name := c.BrokerName()
		assert.NotEmpty(t, string(name),
			"BrokerName must return a non-empty identifier")
	})

	t.Run("read_methods_callable_no_panic", func(t *testing.T) {
		t.Parallel()
		c := factory(t)
		// Each call may return an error (mock not configured, network,
		// auth, etc.) — we only assert no panic. A well-configured
		// per-broker test in the broker's own package can layer on
		// behaviour assertions; this contract just shapes the surface.
		assert.NotPanics(t, func() { _, _ = c.GetProfile() })
		assert.NotPanics(t, func() { _, _ = c.GetMargins() })
		assert.NotPanics(t, func() { _, _ = c.GetHoldings() })
		assert.NotPanics(t, func() { _, _ = c.GetPositions() })
		assert.NotPanics(t, func() { _, _ = c.GetTrades() })
		assert.NotPanics(t, func() { _, _ = c.GetOrders() })
		assert.NotPanics(t, func() { _, _ = c.GetGTTs() })
		assert.NotPanics(t, func() { _, _ = c.GetMFOrders() })
		assert.NotPanics(t, func() { _, _ = c.GetMFSIPs() })
		assert.NotPanics(t, func() { _, _ = c.GetMFHoldings() })
	})

	t.Run("market_data_methods_callable_no_panic", func(t *testing.T) {
		t.Parallel()
		c := factory(t)
		// Pass an empty slice — concrete brokers may treat empty as a
		// no-op or return ErrNoInstruments; either is acceptable shape.
		assert.NotPanics(t, func() { _, _ = c.GetLTP() })
		assert.NotPanics(t, func() { _, _ = c.GetOHLC() })
		assert.NotPanics(t, func() { _, _ = c.GetQuotes() })
	})
}

// TestZerodhaMockClient_Contract is the canonical contract-test
// invocation: validates that broker/mock.Client (the in-process mock
// used by mcp/* test fixtures) satisfies the full broker.Client
// contract. When a new broker implementation lands, copy this pattern
// in its own package — the contract itself stays in this file as the
// single source of truth.
func TestZerodhaMockClient_Contract(t *testing.T) {
	PortContract(t, func(_ *testing.T) broker.Client {
		return mockbroker.New()
	})
}
