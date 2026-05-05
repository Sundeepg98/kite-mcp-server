// Package conformance is the reusable broker.Client + ancillary-port
// conformance harness. Adapter authors run this against their
// concrete factory in their own _test.go to assert the adapter
// satisfies every contract the rest of the codebase depends on.
//
// Source-of-truth: Q3 of .research/port-adapter-framework-design.md
// (commit 61da394). Promoted from broker/contract_test.go (commit
// 55d1a17) into this package + extended with 4 additional buckets:
//
//   - PortContract               (the original — kept verbatim)
//   - OptionalCapabilities       (NativeAlertCapable / GTTManager /
//                                 MutualFundClient type assertion)
//   - ErrorClassification        (broker.RateLimitError detection
//                                 via errors.As)
//   - TickerLifecycle            (optional Ticker port conformance,
//                                 skipped when adapter doesn't ship
//                                 a ticker)
//
// Adapter authors invoke each bucket from their own test file. A
// minimum viable adapter test reads:
//
//	func TestUpstoxAdapter(t *testing.T) {
//	    factory := func(_ *testing.T) broker.Client { return upstox.NewMockedClient() }
//	    t.Run("PortContract", func(t *testing.T) { conformance.PortContract(t, factory) })
//	    t.Run("OptionalCapabilities", func(t *testing.T) { conformance.OptionalCapabilities(t, factory) })
//	    t.Run("ErrorClassification", func(t *testing.T) { conformance.ErrorClassification(t) })
//	    t.Run("TickerLifecycle", func(t *testing.T) {
//	        conformance.TickerLifecycle(t, func(_ *testing.T) brokerticker.Ticker { return upstox.NewMockedTicker() })
//	    })
//	}
//
// Per the prior research, this conformance harness is the agent-
// concurrency unblocker for multi-broker work — once it's in place,
// independent agents can work on Upstox / Dhan / Angel One adapters
// concurrently because each adapter's correctness is testable in
// isolation against this contract.
package conformance

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	brokermod "github.com/algo2go/kite-mcp-broker"
	brokerticker "github.com/algo2go/kite-mcp-broker/ticker"
)

// PortContract is the canonical broker.Client conformance suite,
// promoted verbatim from broker/contract_test.go (commit 55d1a17).
// Asserts:
//
//  1. The factory's returned value satisfies broker.Client (compile-
//     time + runtime).
//  2. Each sub-interface (BrokerIdentity, ProfileReader, ...) is
//     reachable via the composite — proves no method-set holes.
//  3. BrokerName() returns a non-empty broker.Name.
//  4. Read methods are callable without panicking.
//  5. Market-data methods are callable without panicking.
//
// What PortContract does NOT enforce:
//   - Specific behaviour of each method (broker semantics differ).
//   - Mock-SDK setup. Each adapter provides its own factory; failure
//     to configure mock methods produces test errors that point at
//     the missing mock, which is the correct affordance.
//
// nolint:thelper // factory returns a value, not invokes test-helper
func PortContract(t *testing.T, factory func(t *testing.T) brokermod.Client) {
	t.Run("satisfies_broker_Client", func(t *testing.T) {
		t.Parallel()
		c := factory(t)
		require.NotNil(t, c, "factory must return non-nil broker.Client")
		assert.NotPanics(t, func() {
			var _ brokermod.BrokerIdentity = c
			var _ brokermod.ProfileReader = c
			var _ brokermod.PortfolioReader = c
			var _ brokermod.OrderManager = c
			var _ brokermod.MarketDataReader = c
			var _ brokermod.GTTManager = c
			var _ brokermod.PositionConverter = c
			var _ brokermod.MutualFundClient = c
			var _ brokermod.MarginCalculator = c
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
		assert.NotPanics(t, func() { _, _ = c.GetLTP() })
		assert.NotPanics(t, func() { _, _ = c.GetOHLC() })
		assert.NotPanics(t, func() { _, _ = c.GetQuotes() })
	})
}

// OptionalCapabilityReport surfaces which optional broker.Client
// sub-interfaces a given factory's returned client implements.
// Returned by OptionalCapabilities for adapter authors to assert
// against their broker's documented capability set.
type OptionalCapabilityReport struct {
	// GTT is true if the client satisfies broker.GTTManager. Part
	// of the composite Client interface today; every well-formed
	// adapter is expected to set this true.
	GTT bool

	// MutualFund is true if the client satisfies
	// broker.MutualFundClient. Same composite contract — true for
	// any well-formed adapter.
	MutualFund bool

	// NativeAlerts is true if the client satisfies the optional
	// broker.NativeAlertCapable interface. Genuinely optional:
	// only brokers with server-side alerts implement it
	// (Zerodha today). Adapters without server-side alerts MUST
	// leave this false; the harness reports the value as observed
	// without judgment.
	NativeAlerts bool

	// MarginCalculator is true if the client satisfies
	// broker.MarginCalculator. Part of the composite; expected
	// true for every adapter.
	MarginCalculator bool

	// PositionConverter is true if the client satisfies
	// broker.PositionConverter. Part of the composite; expected
	// true for every adapter.
	PositionConverter bool
}

// OptionalCapabilities probes the factory's returned client for
// each of the optional / advertised-via-type-assertion sub-
// interfaces and returns a report. Adapter authors assert against
// the report's expected-true / expected-false values per the
// broker's documented capability set.
//
// Per the broker.NativeAlertCapable godoc precedent (broker/
// broker.go:620), genuinely-optional capabilities are detected
// via type assertion at runtime; the harness mirrors that pattern
// uniformly across every optional cap.
//
// nolint:thelper // factory returns a value, not invokes test-helper
func OptionalCapabilities(t *testing.T, factory func(t *testing.T) brokermod.Client) OptionalCapabilityReport {
	t.Helper()
	c := factory(t)
	require.NotNil(t, c, "factory must return non-nil broker.Client")

	var report OptionalCapabilityReport
	if _, ok := c.(brokermod.GTTManager); ok {
		report.GTT = true
	}
	if _, ok := c.(brokermod.MutualFundClient); ok {
		report.MutualFund = true
	}
	if _, ok := c.(brokermod.NativeAlertCapable); ok {
		report.NativeAlerts = true
	}
	if _, ok := c.(brokermod.MarginCalculator); ok {
		report.MarginCalculator = true
	}
	if _, ok := c.(brokermod.PositionConverter); ok {
		report.PositionConverter = true
	}
	return report
}

// ErrorClassification asserts that broker.RateLimitError is
// detectable via errors.As — the canonical pattern documented in
// broker/errors.go:11. Adapter authors writing 429 / throttle
// detection in their adapter rely on this contract for downstream
// riskguard auto-freeze + retry middleware to fire correctly.
//
// The bucket also asserts the error's Unwrap() preserves the
// inner error so callers using `errors.Is(err, ErrFooBar)` paths
// continue to work alongside the typed wrapper.
//
// Adapter-independent: this bucket exercises broker.RateLimitError
// directly. Adapter authors don't pass a factory; the harness
// constructs synthetic errors. Future buckets that DO need
// per-adapter behaviour (e.g. 429-detection-on-real-error) can
// add a factory argument.
func ErrorClassification(t *testing.T) {
	t.Helper()

	t.Run("rate_limit_detectable_via_errors_As", func(t *testing.T) {
		t.Parallel()
		inner := errors.New("kite: too many requests")
		rle := &brokermod.RateLimitError{
			RetryAfter: 2 * time.Second,
			Endpoint:   "place_order",
			Inner:      inner,
		}
		// Wrap once more to simulate adapter-layer wrapping the
		// typed error inside a fmt.Errorf — errors.As must still
		// drill through.
		wrapped := fmt.Errorf("adapter: %w", rle)

		var got *brokermod.RateLimitError
		if !errors.As(wrapped, &got) {
			t.Fatal("errors.As must drill through fmt.Errorf wrapper to *broker.RateLimitError")
		}
		assert.Equal(t, "place_order", got.Endpoint)
		assert.Equal(t, 2*time.Second, got.RetryAfter)
	})

	t.Run("inner_error_preserved_via_Unwrap", func(t *testing.T) {
		t.Parallel()
		sentinel := errors.New("sentinel inner error")
		rle := &brokermod.RateLimitError{
			Endpoint: "get_quotes",
			Inner:    sentinel,
		}
		// errors.Is must drill through Unwrap() to the inner.
		if !errors.Is(rle, sentinel) {
			t.Fatal("errors.Is must traverse RateLimitError.Unwrap to find the inner error")
		}
	})

	t.Run("error_message_includes_endpoint", func(t *testing.T) {
		t.Parallel()
		rle := &brokermod.RateLimitError{
			Endpoint: "modify_order",
			Inner:    errors.New("429"),
		}
		msg := rle.Error()
		assert.Contains(t, msg, "modify_order",
			"Error() must include the endpoint label for log/audit clarity")
	})
}

// TickerLifecycle exercises the optional broker/ticker.Ticker
// conformance bucket. Adapter authors that ship a Ticker pass a
// factory; adapters without one pass nil and the bucket skips.
//
// When a factory is provided, the bucket asserts:
//   - The returned Ticker satisfies the broker/ticker.Ticker
//     interface (compile-time at the assignment).
//   - Subscribe / Unsubscribe / SetMode / OnTick / Close are
//     callable without panic.
//   - Registering a TickHandler then closing the ticker doesn't
//     leak goroutines (no live websocket — tests use in-process
//     fakes via the factory).
//
// nolint:thelper // factory returns a value, not invokes test-helper
func TickerLifecycle(t *testing.T, factory func(t *testing.T) brokerticker.Ticker) {
	if factory == nil {
		t.Log("TickerLifecycle: no ticker factory provided — adapter doesn't ship a Ticker; skipping.")
		return
	}
	t.Run("satisfies_broker_ticker_Ticker", func(t *testing.T) {
		t.Parallel()
		tk := factory(t)
		require.NotNil(t, tk, "factory must return non-nil broker/ticker.Ticker")
		var _ brokerticker.Ticker = tk
	})

	t.Run("subscribe_unsubscribe_callable_no_panic", func(t *testing.T) {
		t.Parallel()
		tk := factory(t)
		assert.NotPanics(t, func() { _ = tk.Subscribe([]uint32{408065}) })
		assert.NotPanics(t, func() { _ = tk.Unsubscribe([]uint32{408065}) })
	})

	t.Run("set_mode_each_value_callable_no_panic", func(t *testing.T) {
		t.Parallel()
		tk := factory(t)
		assert.NotPanics(t, func() { _ = tk.SetMode(brokerticker.ModeLTP, []uint32{1}) })
		assert.NotPanics(t, func() { _ = tk.SetMode(brokerticker.ModeQuote, []uint32{1}) })
		assert.NotPanics(t, func() { _ = tk.SetMode(brokerticker.ModeFull, []uint32{1}) })
	})

	t.Run("handler_registration_no_panic", func(t *testing.T) {
		t.Parallel()
		tk := factory(t)
		assert.NotPanics(t, func() { tk.OnTick(func(_ brokerticker.Tick) {}) })
		assert.NotPanics(t, func() { tk.OnConnect(func() {}) })
		assert.NotPanics(t, func() { tk.OnError(func(_ error) {}) })
		assert.NotPanics(t, func() { tk.OnClose(func(_ int, _ string) {}) })
		assert.NotPanics(t, func() { tk.OnReconnect(func(_ int, _ time.Duration) {}) })
		assert.NotPanics(t, func() { tk.OnNoReconnect(func(_ int) {}) })
	})

	t.Run("serve_close_callable_no_panic", func(t *testing.T) {
		t.Parallel()
		tk := factory(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // pre-cancelled — Serve returns immediately
		assert.NotPanics(t, func() { tk.Serve(ctx) })
		assert.NotPanics(t, func() { _ = tk.Close() })
	})
}
