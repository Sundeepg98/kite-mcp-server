package domain

import (
	"testing"
	"time"
)

// TestAllEventTypes_Interface tests EventType() and OccurredAt() for every
// concrete domain event type, ensuring 100% method coverage.
func TestAllEventTypes_Interface(t *testing.T) {
	t.Parallel()
	now := time.Now()

	tests := []struct {
		name      string
		event     Event
		wantType  string
	}{
		{"OrderPlacedEvent", OrderPlacedEvent{Timestamp: now}, "order.placed"},
		{"OrderModifiedEvent", OrderModifiedEvent{Timestamp: now}, "order.modified"},
		{"OrderCancelledEvent", OrderCancelledEvent{Timestamp: now}, "order.cancelled"},
		{"OrderFilledEvent", OrderFilledEvent{Timestamp: now}, "order.filled"},
		{"OrderRejectedEvent", OrderRejectedEvent{Timestamp: now}, "order.rejected"},
		{"PositionOpenedEvent", PositionOpenedEvent{Timestamp: now}, "position.opened"},
		{"PositionClosedEvent", PositionClosedEvent{Timestamp: now}, "position.closed"},
		{"AlertCreatedEvent", AlertCreatedEvent{Timestamp: now}, "alert.created"},
		{"AlertTriggeredEvent", AlertTriggeredEvent{Timestamp: now}, "alert.triggered"},
		{"AlertDeletedEvent", AlertDeletedEvent{Timestamp: now}, "alert.deleted"},
		{"RiskLimitBreachedEvent", RiskLimitBreachedEvent{Timestamp: now}, "risk.limit_breached"},
		{"SessionCreatedEvent", SessionCreatedEvent{Timestamp: now}, "session.created"},
		{"UserFrozenEvent", UserFrozenEvent{Timestamp: now}, "user.frozen"},
		{"UserSuspendedEvent", UserSuspendedEvent{Timestamp: now}, "user.suspended"},
		{"GlobalFreezeEvent", GlobalFreezeEvent{Timestamp: now}, "global.freeze"},
		{"FamilyInvitedEvent", FamilyInvitedEvent{Timestamp: now}, "family.invited"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.event.EventType(); got != tc.wantType {
				t.Errorf("EventType() = %q, want %q", got, tc.wantType)
			}
			if got := tc.event.OccurredAt(); !got.Equal(now) {
				t.Errorf("OccurredAt() = %v, want %v", got, now)
			}
		})
	}
}

// TestOrderModifiedEvent tests the OrderModifiedEvent specifically (was 0% covered).
func TestOrderModifiedEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now()
	e := OrderModifiedEvent{
		Email:     "user@example.com",
		OrderID:   "ORD456",
		Timestamp: now,
	}

	if e.EventType() != "order.modified" {
		t.Errorf("EventType() = %q, want order.modified", e.EventType())
	}
	if !e.OccurredAt().Equal(now) {
		t.Error("OccurredAt() mismatch")
	}
	if e.Email != "user@example.com" {
		t.Errorf("Email = %q", e.Email)
	}
}

// TestOrderCancelledEvent tests the OrderCancelledEvent specifically (was 0% covered).
func TestOrderCancelledEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now()
	e := OrderCancelledEvent{
		Email:     "user@example.com",
		OrderID:   "ORD789",
		Timestamp: now,
	}

	if e.EventType() != "order.cancelled" {
		t.Errorf("EventType() = %q, want order.cancelled", e.EventType())
	}
	if !e.OccurredAt().Equal(now) {
		t.Error("OccurredAt() mismatch")
	}
}

// TestPositionClosedEvent tests the PositionClosedEvent specifically (was 0% covered).
func TestPositionClosedEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now()
	e := PositionClosedEvent{
		Email:           "user@example.com",
		OrderID:         "ORD-CLOSE",
		Instrument:      NewInstrumentKey("NSE", "RELIANCE"),
		Qty:             Quantity{value: 10},
		TransactionType: "SELL",
		Timestamp:       now,
	}

	if e.EventType() != "position.closed" {
		t.Errorf("EventType() = %q, want position.closed", e.EventType())
	}
	if !e.OccurredAt().Equal(now) {
		t.Error("OccurredAt() mismatch")
	}
}

// TestUserSuspendedEvent tests the UserSuspendedEvent specifically (was 0% covered).
func TestUserSuspendedEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now()
	e := UserSuspendedEvent{
		Email:     "suspended@example.com",
		By:        "admin@example.com",
		Reason:    "policy violation",
		Timestamp: now,
	}

	if e.EventType() != "user.suspended" {
		t.Errorf("EventType() = %q, want user.suspended", e.EventType())
	}
	if !e.OccurredAt().Equal(now) {
		t.Error("OccurredAt() mismatch")
	}
	if e.By != "admin@example.com" {
		t.Errorf("By = %q", e.By)
	}
}

// TestGlobalFreezeEvent tests the GlobalFreezeEvent specifically (was 0% covered).
func TestGlobalFreezeEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now()
	e := GlobalFreezeEvent{
		By:        "admin@example.com",
		Reason:    "market emergency",
		Timestamp: now,
	}

	if e.EventType() != "global.freeze" {
		t.Errorf("EventType() = %q, want global.freeze", e.EventType())
	}
	if !e.OccurredAt().Equal(now) {
		t.Error("OccurredAt() mismatch")
	}
}

// TestFamilyInvitedEvent tests the FamilyInvitedEvent specifically (was 0% covered).
func TestFamilyInvitedEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now()
	e := FamilyInvitedEvent{
		AdminEmail:   "admin@example.com",
		InvitedEmail: "family@example.com",
		Timestamp:    now,
	}

	if e.EventType() != "family.invited" {
		t.Errorf("EventType() = %q, want family.invited", e.EventType())
	}
	if !e.OccurredAt().Equal(now) {
		t.Error("OccurredAt() mismatch")
	}
	if e.InvitedEmail != "family@example.com" {
		t.Errorf("InvitedEmail = %q", e.InvitedEmail)
	}
}

// TestOrderFilledEvent_StatusField pins the T4 contract: OrderFilledEvent
// carries a Status field (COMPLETE / PARTIAL / AMO) so projections and
// the activity feed can distinguish a partial fill from a full fill
// without re-querying the broker.
//
// Pre-T4, OrderFilledEvent only fired on COMPLETE — but the broker may
// also surface PARTIAL fills (multi-tranche execution) and AMO orders
// (after-market, queued for next session). Carrying Status on the
// event preserves the broker's classification for downstream consumers.
func TestOrderFilledEvent_StatusField(t *testing.T) {
	t.Parallel()
	qty, _ := NewQuantity(10)
	price := NewINR(101.5)
	now := time.Now().UTC()

	complete := OrderFilledEvent{
		Email: "trader@example.com", OrderID: "ORD-1",
		FilledQty: qty, FilledPrice: price,
		Status:    "COMPLETE",
		Timestamp: now,
	}
	if complete.Status != "COMPLETE" {
		t.Errorf("Status = %q, want COMPLETE", complete.Status)
	}

	partial := OrderFilledEvent{Status: "PARTIAL", Timestamp: now}
	if partial.Status != "PARTIAL" {
		t.Errorf("Status = %q, want PARTIAL", partial.Status)
	}

	amo := OrderFilledEvent{Status: "AMO", Timestamp: now}
	if amo.Status != "AMO" {
		t.Errorf("Status = %q, want AMO", amo.Status)
	}

	// EventType still resolves to "order.filled" regardless of Status.
	if complete.EventType() != "order.filled" {
		t.Errorf("EventType drift: %q", complete.EventType())
	}
}

// TestOrderRejectedEvent_Fields pins OrderRejectedEvent's interface
// contract and the field surface the use cases populate. The event
// fires on broker round-trip failures (place/modify/cancel) so the
// audit stream surfaces post-riskguard rejections that would otherwise
// be silent — see place_order.go / modify_order.go / cancel_order.go
// emit sites for the dispatch contract.
func TestOrderRejectedEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	e := OrderRejectedEvent{
		Email:     "trader@example.com",
		OrderID:   "ORD-REJ-1",
		ToolName:  "modify_order",
		Reason:    "MARGIN_INSUFFICIENT",
		Timestamp: now,
	}

	if e.EventType() != "order.rejected" {
		t.Errorf("EventType() = %q, want order.rejected", e.EventType())
	}
	if !e.OccurredAt().Equal(now) {
		t.Error("OccurredAt() mismatch")
	}
	if e.Email != "trader@example.com" {
		t.Errorf("Email = %q", e.Email)
	}
	if e.OrderID != "ORD-REJ-1" {
		t.Errorf("OrderID = %q", e.OrderID)
	}
	if e.ToolName != "modify_order" {
		t.Errorf("ToolName = %q", e.ToolName)
	}
	if e.Reason != "MARGIN_INSUFFICIENT" {
		t.Errorf("Reason = %q", e.Reason)
	}
}

// TestOrderRejectedEvent_PlaceOrderEmptyOrderID pins the place_order
// rejection shape: no broker-assigned OrderID, so the event's OrderID
// stays empty. Aggregate-ID derivation falls back to the synthetic
// "rejected:<email>:<ts>" form (covered separately in
// TestOrderRejectedAggregateID).
func TestOrderRejectedEvent_PlaceOrderEmptyOrderID(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	e := OrderRejectedEvent{
		Email:     "trader@example.com",
		ToolName:  "place_order",
		Reason:    "RATE_LIMIT_EXCEEDED",
		Timestamp: now,
	}

	if e.OrderID != "" {
		t.Errorf("OrderID = %q, want empty for place_order rejection", e.OrderID)
	}
	if e.EventType() != "order.rejected" {
		t.Errorf("EventType() = %q", e.EventType())
	}
}

// TestOrderRejectedAggregateID covers the OrderID-vs-synthetic-key
// branching: modify/cancel rejections (OrderID set) join the existing
// order aggregate stream; place rejections (OrderID empty) get a per-
// rejection synthetic key built from email + timestamp; pathological
// "no email + no order ID" falls back to the unknown sentinel.
func TestOrderRejectedAggregateID(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 10, 30, 0, 0, time.UTC)

	tests := []struct {
		name     string
		orderID  string
		email    string
		want     string
	}{
		{
			name:    "OrderID present joins existing order stream",
			orderID: "ORD-123",
			email:   "trader@example.com",
			want:    "ORD-123",
		},
		{
			name:    "Empty OrderID with email uses synthetic key",
			orderID: "",
			email:   "trader@example.com",
			want:    "rejected:trader@example.com:" + now.Format(time.RFC3339Nano),
		},
		{
			name:    "Empty OrderID and email falls back to unknown",
			orderID: "",
			email:   "",
			want:    "rejected:unknown",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := OrderRejectedAggregateID(tc.orderID, tc.email, now)
			if got != tc.want {
				t.Errorf("OrderRejectedAggregateID(%q, %q, %v) = %q, want %q",
					tc.orderID, tc.email, now, got, tc.want)
			}
		})
	}
}

// TestDispatcherSubscribeUnknownEventType dispatches an event type with no handlers
// to cover the "no handlers found" path in Dispatch.
func TestDispatcherDispatchUnknownEventType(t *testing.T) {
	t.Parallel()
	d := NewEventDispatcher()
	// Subscribe to one type, dispatch another
	d.Subscribe("order.placed", func(e Event) {
		t.Error("should not be called for different event type")
	})
	// Dispatch a different type — no handlers, should not panic.
	d.Dispatch(UserSuspendedEvent{Timestamp: time.Now()})
}
