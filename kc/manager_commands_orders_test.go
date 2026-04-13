package kc

import (
	"context"
	"strings"
	"testing"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
)

// fakeBrokerForOrders is a minimal broker.Client stand-in for the order
// CommandBus tests. It records whether PlaceOrder was called so the test
// can assert that riskguard blocked it BEFORE the broker was ever invoked.
type fakeBrokerForOrders struct {
	broker.Client
	placeOrderCalled bool
}

func (f *fakeBrokerForOrders) PlaceOrder(_ broker.OrderParams) (broker.OrderResponse, error) {
	f.placeOrderCalled = true
	return broker.OrderResponse{OrderID: "FAKE-1"}, nil
}

// TestCommandBus_PlaceOrder_RiskguardFires is the load-bearing test for the
// batch-B CommandBus migration. It proves that when an MCP tool dispatches
// PlaceOrderCommand through the CommandBus, the riskguard still runs inside
// the PlaceOrderUseCase reached by the handler — i.e., the migration
// preserved the safety pipeline rather than bypassing it.
//
// The test freezes the email globally via the kill switch, dispatches
// PlaceOrderCommand, and asserts:
//  1. The dispatch returns a riskguard error (not a broker error)
//  2. The fake broker's PlaceOrder method was NEVER called
//
// If the CommandBus handler short-circuited the use case or constructed it
// without a riskguard, the broker would be hit and the test would fail.
func TestCommandBus_PlaceOrder_RiskguardFires(t *testing.T) {
	mgr, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager: %v", err)
	}

	// Attach a real Guard and freeze the user (kill switch path).
	guard := riskguard.NewGuard(testLogger())
	guard.Freeze("user@example.com", "test", "testing CommandBus riskguard wiring")
	mgr.riskGuard = guard

	// Attach a fake broker via ctx so resolverFromContext hands it to the
	// use case instead of falling back to SessionService.
	fake := &fakeBrokerForOrders{}
	ctx := WithBroker(context.Background(), fake)

	qty, _ := domain.NewQuantity(1)
	_, err = mgr.CommandBus().DispatchWithResult(ctx, cqrs.PlaceOrderCommand{
		Email:           "user@example.com",
		Instrument:      domain.NewInstrumentKey("NSE", "SBIN"),
		TransactionType: "BUY",
		Qty:             qty,
		Price:           domain.NewINR(500.0),
		OrderType:       "LIMIT",
		Product:         "CNC",
		Variety:         "regular",
	})
	if err == nil {
		t.Fatal("expected riskguard to block the order, got nil error")
	}
	if !strings.Contains(err.Error(), "riskguard") && !strings.Contains(err.Error(), "frozen") {
		t.Errorf("expected riskguard/frozen error, got: %v", err)
	}
	if fake.placeOrderCalled {
		t.Error("fake broker.PlaceOrder was called — riskguard did not fire BEFORE broker invocation")
	}
}

// TestCommandBus_SetTrailingStop_NilManager_ReturnsError mirrors the
// cancel-path nil-guard check for the SetTrailingStopCommand handler.
// Production builds without SQLite leave trailingStopMgr nil and the
// CommandBus handler must refuse to run instead of nil-panicking inside
// the use case.
func TestCommandBus_SetTrailingStop_NilManager_ReturnsError(t *testing.T) {
	mgr, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager: %v", err)
	}
	mgr.trailingStopMgr = nil

	_, err = mgr.CommandBus().DispatchWithResult(context.Background(), cqrs.SetTrailingStopCommand{
		Email:         "user@example.com",
		Exchange:      "NSE",
		Tradingsymbol: "SBIN",
	})
	if err == nil {
		t.Fatal("expected error from nil trailing stop manager, got nil")
	}
	if !strings.Contains(err.Error(), "trailing stop manager") {
		t.Errorf("expected trailing-stop-manager error, got: %v", err)
	}
}

// TestCommandBus_CancelTrailingStop_NilManager_ReturnsError asserts the
// CancelTrailingStopCommand handler refuses to run when the trailing-stop
// manager is not configured. This mirrors the pre-migration behavior (the
// MCP tool used to check handler.deps.TrailingStop.TrailingStopManager()
// before calling the use case) and proves the migration preserved the
// guard at the bus level.
func TestCommandBus_CancelTrailingStop_NilManager_ReturnsError(t *testing.T) {
	mgr, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager: %v", err)
	}
	// Force the nil-manager branch: newTestManager wires a real
	// TrailingStopManager, but production deployments without SQLite leave
	// it nil and we want to prove the CommandBus handler refuses to run in
	// that case instead of panicking.
	mgr.trailingStopMgr = nil

	_, err = mgr.CommandBus().DispatchWithResult(context.Background(), cqrs.CancelTrailingStopCommand{
		Email:          "user@example.com",
		TrailingStopID: "ts-1",
	})
	if err == nil {
		t.Fatal("expected error from nil trailing stop manager, got nil")
	}
	if !strings.Contains(err.Error(), "trailing stop manager") {
		t.Errorf("expected trailing-stop-manager error, got: %v", err)
	}
}
