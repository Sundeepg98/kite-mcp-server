package riskguard

import (
	"fmt"
	"io"
	"log/slog"
	"testing"
)

// TestRegisterCustomCheck verifies that a plugin-registered Check:
//  1. Participates in the ordered chain at its declared Order().
//  2. Is able to reject an otherwise-valid order.
//  3. Fires strictly between built-in checks when its Order() sits between
//     two known built-in positions.
//
// The test also confirms the Order() contract: a custom check with
// Order=99999 must run AFTER all built-ins; one with Order=-1 must run
// BEFORE every built-in (so even the kill-switch can be preempted by a
// custom pre-guard if an operator deliberately chooses to).
func TestRegisterCustomCheck(t *testing.T) {
	t.Parallel()
	t.Run("custom check rejects otherwise-valid order", func(t *testing.T) {
		g := NewGuard(slog.New(slog.NewTextHandler(io.Discard, nil)))

		// Synthetic custom check: always reject.
		g.RegisterCheck(&stubCheck{
			name:  "stub.always_reject",
			order: 50,
			fn: func(req OrderCheckRequest) CheckResult {
				return CheckResult{
					Allowed: false,
					Reason:  "stub_reject",
					Message: "synthetic reject",
				}
			},
		})

		r := g.CheckOrder(OrderCheckRequest{
			Email:     "user@test.com",
			ToolName:  "place_order",
			Confirmed: true,
			Quantity:  1,
			Price:     100,
		})
		if r.Allowed {
			t.Fatalf("expected custom check to reject; got Allowed=true")
		}
		if r.Reason != "stub_reject" {
			t.Fatalf("expected custom reason stub_reject; got %q", r.Reason)
		}
	})

	t.Run("Order() ordering is respected", func(t *testing.T) {
		g := NewGuard(slog.New(slog.NewTextHandler(io.Discard, nil)))

		// Record the order in which checks fire.
		var seen []string
		g.RegisterCheck(&stubCheck{
			name:  "stub.z_last",
			order: 99999,
			fn: func(req OrderCheckRequest) CheckResult {
				seen = append(seen, "z_last")
				return CheckResult{Allowed: true}
			},
		})
		g.RegisterCheck(&stubCheck{
			name:  "stub.a_first",
			order: -1,
			fn: func(req OrderCheckRequest) CheckResult {
				seen = append(seen, "a_first")
				return CheckResult{Allowed: true}
			},
		})
		g.RegisterCheck(&stubCheck{
			name:  "stub.middle",
			order: 500,
			fn: func(req OrderCheckRequest) CheckResult {
				seen = append(seen, "middle")
				return CheckResult{Allowed: true}
			},
		})

		r := g.CheckOrder(OrderCheckRequest{
			Email:     "user@test.com",
			ToolName:  "place_order",
			Confirmed: true,
		})
		if !r.Allowed {
			t.Fatalf("expected allow; got %+v", r)
		}
		// a_first (Order=-1) runs before every built-in, middle (500)
		// between kill-switch (100) and quantity-limit (400) [depending
		// on built-in ordering], z_last (99999) after everything.
		// We assert the relative order rather than exact positions so
		// the test survives adding/removing built-in checks.
		if idx := indexOf(seen, "a_first"); idx != 0 {
			t.Errorf("a_first should have fired first; seen=%v", seen)
		}
		if idx := indexOf(seen, "z_last"); idx != len(seen)-1 {
			t.Errorf("z_last should have fired last; seen=%v", seen)
		}
		aIdx := indexOf(seen, "a_first")
		mIdx := indexOf(seen, "middle")
		zIdx := indexOf(seen, "z_last")
		if !(aIdx < mIdx && mIdx < zIdx) {
			t.Errorf("expected a_first < middle < z_last ordering; seen=%v", seen)
		}
	})

	t.Run("custom check between built-ins fires between them", func(t *testing.T) {
		g := NewGuard(slog.New(slog.NewTextHandler(io.Discard, nil)))

		// Built-ins occupy OrderKillSwitch=100 through OrderOffHours=1200.
		// Put a stub at 650 (between daily-value and anomaly) that rejects
		// based on a side channel, and confirm it fires only when the
		// earlier built-ins pass.
		var stubFired bool
		g.RegisterCheck(&stubCheck{
			name:  "stub.sentinel",
			order: 650,
			fn: func(req OrderCheckRequest) CheckResult {
				stubFired = true
				return CheckResult{Allowed: false, Reason: "stub_sentinel", Message: "stub fired"}
			},
		})

		// Order that passes all prior checks (small, confirmed, no dup).
		r := g.CheckOrder(OrderCheckRequest{
			Email:     "user@test.com",
			ToolName:  "place_order",
			Confirmed: true,
			Quantity:  1,
			Price:     10,
		})
		if !stubFired {
			t.Fatalf("expected stub sentinel to fire after prior built-ins passed")
		}
		if r.Allowed {
			t.Fatalf("expected stub to reject; got Allowed=true")
		}
	})

	t.Run("kill-switch still takes precedence over custom checks at order >100", func(t *testing.T) {
		g := NewGuard(slog.New(slog.NewTextHandler(io.Discard, nil)))
		g.Freeze("user@test.com", "admin", "test freeze")

		var stubFired bool
		g.RegisterCheck(&stubCheck{
			name:  "stub.after_killswitch",
			order: 150,
			fn: func(req OrderCheckRequest) CheckResult {
				stubFired = true
				return CheckResult{Allowed: true}
			},
		})

		r := g.CheckOrder(OrderCheckRequest{
			Email:     "user@test.com",
			ToolName:  "place_order",
			Confirmed: true,
		})
		if r.Allowed {
			t.Fatalf("expected kill-switch reject; got allowed")
		}
		if stubFired {
			t.Fatalf("stub at Order=150 should NOT have fired after kill-switch reject")
		}
	})
}

// TestBuiltinChecksRegisteredByDefault confirms NewGuard pre-registers
// all 12 built-in checks. This is a regression guard: removing a check
// from the registration list is a behaviour change that should surface
// as a failing test.
func TestBuiltinChecksRegisteredByDefault(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.New(slog.NewTextHandler(io.Discard, nil)))
	names := g.ListCheckNames()
	want := []string{
		"kill_switch",
		"confirmation_required",
		"order_value",
		"margin_check",  // T5: optional pre-trade margin (default off)
		"circuit_limit", // T2: exchange circuit-band pre-trade reject
		"quantity_limit",
		"daily_order_count",
		"per_second_rate",
		"rate_limit",
		"client_order_id_duplicate",
		"duplicate_order",
		"daily_value",
		"otr_band", // PR-C: SEBI OTR Apr 2026
		"anomaly_multiplier",
		"off_hours",
	}
	if len(names) != len(want) {
		t.Fatalf("expected %d built-in checks, got %d: %v", len(want), len(names), names)
	}
	for i, n := range want {
		if names[i] != n {
			t.Errorf("check[%d]: want %q, got %q (full list: %v)", i, n, names[i], names)
		}
	}
}

// --- test helpers ---

// stubCheck is a minimal Check implementation for tests.
type stubCheck struct {
	name  string
	order int
	fn    func(req OrderCheckRequest) CheckResult
}

func (s *stubCheck) Name() string  { return s.name }
func (s *stubCheck) Order() int    { return s.order }
func (s *stubCheck) RecordOnRejection() bool {
	// Stubs never trigger the auto-freeze circuit breaker — that keeps
	// test expectations deterministic.
	return false
}
func (s *stubCheck) Evaluate(req OrderCheckRequest) CheckResult {
	return s.fn(req)
}

// indexOf returns the index of s in ss, or -1 if not found.
func indexOf(ss []string, s string) int {
	for i, v := range ss {
		if v == s {
			return i
		}
	}
	return -1
}

// Assert stubCheck satisfies the Check interface at compile time.
var _ Check = (*stubCheck)(nil)

// Silence unused imports when the file is compiled standalone (fmt used
// for future test assertions).
var _ = fmt.Sprintf

// TestPanickingCheckFailsClosed confirms the safeEvaluate net: a
// buggy Check whose Evaluate panics does NOT crash CheckOrder and
// does NOT silently allow the order. The rejection uses reason
// "check_panic" so the ops page can filter for it.
//
// Fail-closed is deliberate — a rejected order can be retried; a
// silently-allowed bad order carries financial consequences. See
// safeEvaluate doc in guard.go.
func TestPanickingCheckFailsClosed(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.New(slog.NewTextHandler(io.Discard, nil)))

	g.RegisterCheck(&stubCheck{
		name:  "stub.panicker",
		order: 50,
		fn: func(req OrderCheckRequest) CheckResult {
			panic("plugin bug")
		},
	})

	r := g.CheckOrder(OrderCheckRequest{
		Email:     "user@test.com",
		ToolName:  "place_order",
		Confirmed: true,
		Quantity:  1,
		Price:     100,
	})

	if r.Allowed {
		t.Fatal("panicking check must fail closed (Allowed=false), not silently allow")
	}
	if r.Reason != "check_panic" {
		t.Errorf("expected Reason=check_panic; got %q", r.Reason)
	}
	if !contains(r.Message, "stub.panicker") {
		t.Errorf("expected message to name the panicking check; got %q", r.Message)
	}
	if !contains(r.Message, "plugin bug") {
		t.Errorf("expected message to include the panic value; got %q", r.Message)
	}
}

// TestPanickingCheckDoesNotBlockSubsequentCalls — a panic in one
// CheckOrder call must not leave the Guard in a bad state; the next
// call with the same panicking check still returns the panic
// rejection cleanly (no deadlock, no corrupted tracker).
func TestPanickingCheckDoesNotBlockSubsequentCalls(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.New(slog.NewTextHandler(io.Discard, nil)))

	g.RegisterCheck(&stubCheck{
		name:  "stub.panicker",
		order: 50,
		fn: func(req OrderCheckRequest) CheckResult {
			panic("once more")
		},
	})

	for i := 0; i < 3; i++ {
		r := g.CheckOrder(OrderCheckRequest{
			Email:     "user@test.com",
			ToolName:  "place_order",
			Confirmed: true,
		})
		if r.Allowed {
			t.Fatalf("call %d: panicking check must keep failing closed", i)
		}
		if r.Reason != "check_panic" {
			t.Fatalf("call %d: expected Reason=check_panic; got %q", i, r.Reason)
		}
	}
}

// contains is a test-local string-contains helper so we don't pull
// in the testify assert package for the two assertions above.
func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
