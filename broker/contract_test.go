package broker_test

// Package broker_test (note: external _test package — kept separate
// from the broker package itself so this contract harness can import
// any concrete implementation freely without circular-import risk).
//
// Contract-test entry point — historical home of broker.PortContract
// (commit 55d1a17). The reusable harness has been promoted to
// broker/conformance/ (commit ef5d075 → next) with 4 additional
// buckets (OptionalCapabilities, ErrorClassification, TickerLifecycle,
// preserved PortContract). This file remains as the in-tree
// invocation of the canonical PortContract bucket against
// broker/mock.Client; new broker adapters wire all 4 conformance
// buckets in their own package.

import (
	"testing"

	brokermod "github.com/algo2go/kite-mcp-broker"
	"github.com/algo2go/kite-mcp-broker/conformance"
	mockbroker "github.com/algo2go/kite-mcp-broker/mock"
)

// TestZerodhaMockClient_Contract is the canonical contract-test
// invocation. Routes through broker/conformance.PortContract — the
// promoted harness — so any change to the contract suite lands in
// the conformance package's single source of truth.
//
// To wire a new broker:
//
//	import "github.com/algo2go/kite-mcp-broker/conformance"
//
//	func TestUpstoxClient_Contract(t *testing.T) {
//	    factory := func(_ *testing.T) broker.Client {
//	        return upstox.NewMockedClient(t)
//	    }
//	    t.Run("PortContract",          func(t *testing.T) { conformance.PortContract(t, factory) })
//	    t.Run("OptionalCapabilities",  func(t *testing.T) { conformance.OptionalCapabilities(t, factory) })
//	    t.Run("ErrorClassification",   func(t *testing.T) { conformance.ErrorClassification(t) })
//	    t.Run("TickerLifecycle",       func(t *testing.T) { conformance.TickerLifecycle(t, tickerFactory) })
//	}
func TestZerodhaMockClient_Contract(t *testing.T) {
	conformance.PortContract(t, func(_ *testing.T) brokermod.Client {
		return mockbroker.New()
	})
}
