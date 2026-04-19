package kc

import (
	"context"
	"strings"
	"testing"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
)

// TestCommandBus_AdminFreezeUser_FlipsRiskguard proves the batch-C admin
// handler wires AdminFreezeUserCommand through to the real riskguard and
// the user is actually frozen afterwards. The test dispatches the command,
// then queries the riskguard directly and asserts IsFrozen=true for the
// target email.
//
// This is the cleanest end-to-end proof that the CommandBus → handler →
// use case → riskguard chain is wired: a frozen state only exists if every
// link in the chain executed.
func TestCommandBus_AdminFreezeUser_FlipsRiskguard(t *testing.T) {
	t.Parallel()
	mgr, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager: %v", err)
	}
	// Attach a real Guard so the handler has something to flip.
	mgr.riskGuard = riskguard.NewGuard(testLogger())

	target := "target@example.com"
	if mgr.RiskGuard().IsFrozen(target) {
		t.Fatal("precondition: target should not be frozen before dispatch")
	}

	_, err = mgr.CommandBus().DispatchWithResult(context.Background(), cqrs.AdminFreezeUserCommand{
		AdminEmail:  "admin@example.com",
		TargetEmail: target,
		Reason:      "testing admin CommandBus wiring",
	})
	if err != nil {
		t.Fatalf("unexpected dispatch error: %v", err)
	}

	if !mgr.RiskGuard().IsFrozen(target) {
		t.Error("expected target to be frozen after AdminFreezeUserCommand dispatch")
	}

	// Round-trip: AdminUnfreezeUserCommand should lift the freeze.
	_, err = mgr.CommandBus().DispatchWithResult(context.Background(), cqrs.AdminUnfreezeUserCommand{
		AdminEmail:  "admin@example.com",
		TargetEmail: target,
	})
	if err != nil {
		t.Fatalf("unexpected unfreeze dispatch error: %v", err)
	}
	if mgr.RiskGuard().IsFrozen(target) {
		t.Error("expected target to be unfrozen after AdminUnfreezeUserCommand dispatch")
	}
}

// TestCommandBus_AdminFreezeGlobal_FlipsGlobalFreeze mirrors the per-user
// freeze test but for the global kill switch. Proves the global freeze
// dispatch path flows through the handler → use case → riskguard chain.
func TestCommandBus_AdminFreezeGlobal_FlipsGlobalFreeze(t *testing.T) {
	t.Parallel()
	mgr, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager: %v", err)
	}
	mgr.riskGuard = riskguard.NewGuard(testLogger())

	if mgr.RiskGuard().IsGloballyFrozen() {
		t.Fatal("precondition: global freeze should be off before dispatch")
	}

	_, err = mgr.CommandBus().DispatchWithResult(context.Background(), cqrs.AdminFreezeGlobalCommand{
		AdminEmail: "admin@example.com",
		Reason:     "maintenance",
	})
	if err != nil {
		t.Fatalf("unexpected dispatch error: %v", err)
	}
	if !mgr.RiskGuard().IsGloballyFrozen() {
		t.Error("expected global freeze after AdminFreezeGlobalCommand dispatch")
	}

	_, err = mgr.CommandBus().DispatchWithResult(context.Background(), cqrs.AdminUnfreezeGlobalCommand{
		AdminEmail: "admin@example.com",
	})
	if err != nil {
		t.Fatalf("unexpected unfreeze-global dispatch error: %v", err)
	}
	if mgr.RiskGuard().IsGloballyFrozen() {
		t.Error("expected global freeze lifted after AdminUnfreezeGlobalCommand dispatch")
	}
}

// TestCommandBus_StartTicker_NilService_ReturnsError asserts the batch-C
// ticker handler refuses to run when the ticker service is not configured.
// Production deployments that disable the WebSocket ticker leave
// tickerService nil and we want to prove the handler short-circuits
// instead of nil-panicking inside the use case.
func TestCommandBus_StartTicker_NilService_ReturnsError(t *testing.T) {
	t.Parallel()
	mgr, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager: %v", err)
	}
	// Force nil to exercise the handler's nil-guard branch; production
	// deployments without WebSocket ticker wiring hit this path.
	mgr.tickerService = nil

	_, err = mgr.CommandBus().DispatchWithResult(context.Background(), cqrs.StartTickerCommand{
		Email:       "user@example.com",
		APIKey:      "k",
		AccessToken: "t",
	})
	if err == nil {
		t.Fatal("expected ticker-service error, got nil")
	}
	if !strings.Contains(err.Error(), "ticker service") {
		t.Errorf("expected 'ticker service' error, got: %v", err)
	}
}

// TestCommandBus_AdminSuspendUser_ValidationError proves the dispatch
// surfaces the use case's 'cannot suspend yourself' guard. This isn't a
// riskguard or store assertion — it's a proof that the handler faithfully
// returns the use case's validation errors rather than swallowing them.
func TestCommandBus_AdminSuspendUser_ValidationError(t *testing.T) {
	t.Parallel()
	mgr, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager: %v", err)
	}
	mgr.riskGuard = riskguard.NewGuard(testLogger())

	_, err = mgr.CommandBus().DispatchWithResult(context.Background(), cqrs.AdminSuspendUserCommand{
		AdminEmail:  "same@example.com",
		TargetEmail: "same@example.com",
		Reason:      "trying to self-suspend",
	})
	if err == nil {
		t.Fatal("expected 'cannot suspend yourself' error, got nil")
	}
	if !strings.Contains(err.Error(), "cannot suspend yourself") {
		t.Errorf("expected self-suspend error, got: %v", err)
	}
}
