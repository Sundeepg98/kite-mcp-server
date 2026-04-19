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
