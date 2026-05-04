package conformance_test

// Package conformance_test exercises the broker/conformance harness
// against the in-tree mock broker. The tests pin the harness's
// SHAPE — the 4 conformance bucket functions exist with the
// expected signatures and wire correctly to broker.PortContract +
// the new buckets. Adapter authors copy this pattern in their own
// _test.go files; the conformance package itself stays the single
// source of truth.

import (
	"testing"

	brokermod "github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/broker/conformance"
	mockbroker "github.com/zerodha/kite-mcp-server/broker/mock"
)

// TestPortContract_HarnessRunsAgainstMock verifies the canonical
// broker.Client contract suite (promoted from broker/contract_test.go,
// commit 55d1a17) executes against the in-tree mock without panic.
// Equivalent to TestZerodhaMockClient_Contract at the old location.
func TestPortContract_HarnessRunsAgainstMock(t *testing.T) {
	conformance.PortContract(t, func(_ *testing.T) brokermod.Client {
		return mockbroker.New()
	})
}

// TestOptionalCapabilities_AdvertisedConsistently exercises the
// NativeAlertCapable / GTTManager / MutualFundClient / Margin /
// PositionConverter type assertion gating. The in-tree mock broker
// advertises ALL of these because it simulates the full Zerodha
// surface (broker/mock/client.go:19 has var _ broker.NativeAlertCapable
// = (*Client)(nil)). The harness must report each capability's status
// without false positives or panics — true for all five here.
func TestOptionalCapabilities_AdvertisedConsistently(t *testing.T) {
	caps := conformance.OptionalCapabilities(t, func(_ *testing.T) brokermod.Client {
		return mockbroker.New()
	})
	// All five are part of either the composite Client interface or
	// the optional NativeAlertCapable that the mock implements.
	if !caps.GTT {
		t.Error("OptionalCapabilities.GTT must be true for any broker.Client (it's part of the composite)")
	}
	if !caps.MutualFund {
		t.Error("OptionalCapabilities.MutualFund must be true for any broker.Client")
	}
	if !caps.MarginCalculator {
		t.Error("OptionalCapabilities.MarginCalculator must be true for any broker.Client")
	}
	if !caps.PositionConverter {
		t.Error("OptionalCapabilities.PositionConverter must be true for any broker.Client")
	}
	if !caps.NativeAlerts {
		t.Error("OptionalCapabilities.NativeAlerts must be true for the in-tree mock (it satisfies NativeAlertCapable)")
	}
}

// TestErrorClassification_RateLimitWrapping verifies the error_
// classification harness function detects when a broker error
// satisfies broker.RateLimitError via errors.As.
func TestErrorClassification_RateLimitWrapping(t *testing.T) {
	// Construct a synthetic RateLimitError as a concrete adapter
	// would emit one; confirm the harness flags it correctly.
	conformance.ErrorClassification(t)
}

// TestTickerLifecycle_SubscribeUnsubscribeNoPanic exercises the
// optional ticker conformance bucket. The mock broker doesn't ship
// a Ticker today, so the harness must accept a nil-factory
// gracefully (skip the bucket rather than fail).
func TestTickerLifecycle_SubscribeUnsubscribeNoPanic(t *testing.T) {
	// Pass nil factory — harness should skip the test rather than
	// run it (NativeAlertCapable / GTTManager precedent: optional
	// capabilities don't fail when absent).
	conformance.TickerLifecycle(t, nil)
}
