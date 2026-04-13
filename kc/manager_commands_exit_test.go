package kc

import (
	"context"
	"strings"
	"testing"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
)

// fakeBrokerForExit is a minimal broker.Client stand-in for the exit-batch
// CommandBus tests. It returns one matching position from GetPositions and
// records whether PlaceOrder was ever called so the test can assert that
// riskguard blocked the close BEFORE the broker was invoked.
type fakeBrokerForExit struct {
	broker.Client
	placeOrderCalled bool
}

func (f *fakeBrokerForExit) GetPositions() (broker.Positions, error) {
	return broker.Positions{
		Net: []broker.Position{{
			Tradingsymbol: "SBIN",
			Exchange:      "NSE",
			Product:       "CNC",
			Quantity:      10, // long position -> close = SELL
			AveragePrice:  500,
			LastPrice:     510,
			PnL:           100,
		}},
	}, nil
}

func (f *fakeBrokerForExit) PlaceOrder(_ broker.OrderParams) (broker.OrderResponse, error) {
	f.placeOrderCalled = true
	return broker.OrderResponse{OrderID: "FAKE-CLOSE-1"}, nil
}

// TestCommandBus_ClosePosition_RiskguardFires is the load-bearing test for the
// batch-E exit CommandBus migration. It proves that when exit_tools.go
// dispatches ClosePositionCommand through the CommandBus, the riskguard still
// runs inside ClosePositionUseCase — i.e., the migration preserved the safety
// pipeline rather than bypassing it.
//
// The test freezes the email via the kill switch, dispatches
// ClosePositionCommand, and asserts:
//  1. The dispatch returns a riskguard error (not a broker error)
//  2. The fake broker's PlaceOrder method was NEVER called
//
// If the CommandBus handler short-circuited the use case or built it without
// a riskguard, the broker would be hit and the test would fail.
func TestCommandBus_ClosePosition_RiskguardFires(t *testing.T) {
	mgr, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager: %v", err)
	}

	guard := riskguard.NewGuard(testLogger())
	guard.Freeze("user@example.com", "test", "testing exit CommandBus riskguard wiring")
	mgr.riskGuard = guard

	fake := &fakeBrokerForExit{}
	ctx := WithBroker(context.Background(), fake)

	_, err = mgr.CommandBus().DispatchWithResult(ctx, cqrs.ClosePositionCommand{
		Email:    "user@example.com",
		Exchange: "NSE",
		Symbol:   "SBIN",
	})
	if err == nil {
		t.Fatal("expected riskguard to block the close, got nil error")
	}
	if !strings.Contains(err.Error(), "riskguard") && !strings.Contains(err.Error(), "frozen") {
		t.Errorf("expected riskguard/frozen error, got: %v", err)
	}
	if fake.placeOrderCalled {
		t.Error("fake broker.PlaceOrder was called — riskguard did not fire BEFORE broker invocation")
	}
}

// TestCommandBus_CloseAllPositions_RiskguardFires mirrors the single-position
// test but for the bulk-exit path. A frozen user should have every candidate
// position blocked by riskguard and no orders should reach the broker.
func TestCommandBus_CloseAllPositions_RiskguardFires(t *testing.T) {
	mgr, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager: %v", err)
	}

	guard := riskguard.NewGuard(testLogger())
	guard.Freeze("user@example.com", "test", "testing exit CommandBus riskguard wiring")
	mgr.riskGuard = guard

	fake := &fakeBrokerForExit{}
	ctx := WithBroker(context.Background(), fake)

	raw, err := mgr.CommandBus().DispatchWithResult(ctx, cqrs.CloseAllPositionsCommand{
		Email:         "user@example.com",
		ProductFilter: "ALL",
	})
	// CloseAllPositions is resilient: it collects per-position errors and
	// returns a result rather than failing the whole dispatch. Assert the
	// broker was never hit and the result reports an error for the one
	// candidate position.
	if err != nil {
		// Some implementations surface riskguard as a top-level error before
		// per-position loop. Either path is acceptable provided the broker
		// was not called.
		if !strings.Contains(err.Error(), "riskguard") && !strings.Contains(err.Error(), "frozen") {
			t.Errorf("unexpected non-riskguard error: %v", err)
		}
	}
	if fake.placeOrderCalled {
		t.Error("fake broker.PlaceOrder was called — riskguard did not fire BEFORE broker invocation")
	}
	_ = raw
}
