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
		{"PaperOrderRejectedEvent", PaperOrderRejectedEvent{Timestamp: now}, "paper.order_rejected"},
		{"MFOrderRejectedEvent", MFOrderRejectedEvent{Timestamp: now}, "mf.order_rejected"},
		{"MFOrderPlacedEvent", MFOrderPlacedEvent{Timestamp: now}, "mf.order_placed"},
		{"MFOrderCancelledEvent", MFOrderCancelledEvent{Timestamp: now}, "mf.order_cancelled"},
		{"MFSIPPlacedEvent", MFSIPPlacedEvent{Timestamp: now}, "mf.sip_placed"},
		{"MFSIPCancelledEvent", MFSIPCancelledEvent{Timestamp: now}, "mf.sip_cancelled"},
		{"GTTRejectedEvent", GTTRejectedEvent{Timestamp: now}, "gtt.rejected"},
		{"GTTPlacedEvent", GTTPlacedEvent{Timestamp: now}, "gtt.placed"},
		{"GTTModifiedEvent", GTTModifiedEvent{Timestamp: now}, "gtt.modified"},
		{"GTTDeletedEvent", GTTDeletedEvent{Timestamp: now}, "gtt.deleted"},
		{"TrailingStopTriggeredEvent", TrailingStopTriggeredEvent{Timestamp: now}, "trailing_stop.triggered"},
		{"TrailingStopSetEvent", TrailingStopSetEvent{Timestamp: now}, "trailing_stop.set"},
		{"TrailingStopCancelledEvent", TrailingStopCancelledEvent{Timestamp: now}, "trailing_stop.cancelled"},
		{"NativeAlertPlacedEvent", NativeAlertPlacedEvent{Timestamp: now}, "native_alert.placed"},
		{"NativeAlertModifiedEvent", NativeAlertModifiedEvent{Timestamp: now}, "native_alert.modified"},
		{"NativeAlertDeletedEvent", NativeAlertDeletedEvent{Timestamp: now}, "native_alert.deleted"},
		{"PaperTradingEnabledEvent", PaperTradingEnabledEvent{Timestamp: now}, "paper.enabled"},
		{"PaperTradingDisabledEvent", PaperTradingDisabledEvent{Timestamp: now}, "paper.disabled"},
		{"PaperTradingResetEvent", PaperTradingResetEvent{Timestamp: now}, "paper.reset"},
		{"PositionOpenedEvent", PositionOpenedEvent{Timestamp: now}, "position.opened"},
		{"PositionClosedEvent", PositionClosedEvent{Timestamp: now}, "position.closed"},
		{"PositionConvertedEvent", PositionConvertedEvent{Timestamp: now}, "position.converted"},
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

// TestPositionConvertedEvent_Fields pins the field surface of the typed
// position.converted event. Replaces the prior untyped appendAuxEvent
// payload (kc/usecases/convert_position.go pre-ES) so the audit stream
// uses a real domain.Event with stable field names rather than a
// map[string]any blob projector consumers had to type-assert.
func TestPositionConvertedEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	e := PositionConvertedEvent{
		Email:           "trader@example.com",
		Instrument:      NewInstrumentKey("NSE", "RELIANCE"),
		TransactionType: "BUY",
		Quantity:        10,
		OldProduct:      "MIS",
		NewProduct:      "CNC",
		PositionType:    "day",
		Timestamp:       now,
	}

	if e.EventType() != "position.converted" {
		t.Errorf("EventType() = %q, want position.converted", e.EventType())
	}
	if !e.OccurredAt().Equal(now) {
		t.Error("OccurredAt() mismatch")
	}
	if e.Email != "trader@example.com" {
		t.Errorf("Email = %q", e.Email)
	}
	if e.OldProduct != "MIS" {
		t.Errorf("OldProduct = %q", e.OldProduct)
	}
	if e.NewProduct != "CNC" {
		t.Errorf("NewProduct = %q", e.NewProduct)
	}
	if e.Quantity != 10 {
		t.Errorf("Quantity = %d", e.Quantity)
	}
}

// TestPositionConvertedAggregateID pins the natural aggregate key for
// position-conversion events: keyed by (email, exchange, symbol, OLD
// product) so a CNC->MIS->CNC sequence over time replays as a coherent
// stream under stable IDs. Using OldProduct (not NewProduct) matches
// the pre-ES appendAuxEvent payload's key derivation in
// kc/usecases/convert_position.go so the new typed events drop into
// the same aggregate slot existing un-typed conversions live under —
// no migration of in-flight aggregate IDs needed.
func TestPositionConvertedAggregateID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		email      string
		exchange   string
		symbol     string
		oldProduct string
		want       string
	}{
		{
			name:       "Standard CNC->MIS conversion key",
			email:      "trader@example.com",
			exchange:   "NSE",
			symbol:     "RELIANCE",
			oldProduct: "CNC",
			want:       "trader@example.com|NSE|RELIANCE|CNC",
		},
		{
			name:       "MIS->CNC keyed by old (MIS) so reverse sequence joins same stream slot",
			email:      "trader@example.com",
			exchange:   "NSE",
			symbol:     "RELIANCE",
			oldProduct: "MIS",
			want:       "trader@example.com|NSE|RELIANCE|MIS",
		},
		{
			name:       "Empty email falls back to unknown sentinel",
			email:      "",
			exchange:   "NSE",
			symbol:     "RELIANCE",
			oldProduct: "CNC",
			want:       "position-converted:unknown",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := PositionConvertedAggregateID(tc.email, tc.exchange, tc.symbol, tc.oldProduct)
			if got != tc.want {
				t.Errorf("PositionConvertedAggregateID(%q,%q,%q,%q) = %q, want %q",
					tc.email, tc.exchange, tc.symbol, tc.oldProduct, got, tc.want)
			}
		})
	}
}

// TestPaperOrderRejectedEvent_Fields pins the field surface of the
// paper-trading rejection event. Distinct event type from real
// OrderRejectedEvent so projector consumers (activity feeds, dashboards)
// can filter "real broker rejection" vs "virtual-account rejection"
// without parsing OrderID prefixes — paper IDs use "PAPER_<n>" but
// relying on prefix-sniffing for projection-side classification is
// fragile, so we surface the distinction at the event type itself.
func TestPaperOrderRejectedEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	e := PaperOrderRejectedEvent{
		Email:     "trader@example.com",
		OrderID:   "PAPER_42",
		Reason:    "insufficient cash: need 1000.00, have 500.00",
		Source:    "place_limit",
		Timestamp: now,
	}

	if e.EventType() != "paper.order_rejected" {
		t.Errorf("EventType() = %q, want paper.order_rejected", e.EventType())
	}
	if !e.OccurredAt().Equal(now) {
		t.Error("OccurredAt() mismatch")
	}
	if e.Email != "trader@example.com" {
		t.Errorf("Email = %q", e.Email)
	}
	if e.OrderID != "PAPER_42" {
		t.Errorf("OrderID = %q", e.OrderID)
	}
	if e.Source != "place_limit" {
		t.Errorf("Source = %q", e.Source)
	}
	if e.Reason == "" {
		t.Error("Reason should be populated")
	}
}

// TestPaperOrderAggregateID pins the natural aggregate key for paper
// trading order events: keyed by OrderID alone since paper IDs are
// already process-unique ("PAPER_<n>" with monotonic atomic counter)
// so no email-prefix is needed to disambiguate. Empty OrderID falls
// back to "paper:unknown" so a malformed dispatch doesn't collide
// with real rows.
func TestPaperOrderAggregateID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		orderID string
		want    string
	}{
		{"Standard paper ID joins by OrderID", "PAPER_42", "PAPER_42"},
		{"Empty OrderID falls back to unknown", "", "paper:unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := PaperOrderAggregateID(tc.orderID)
			if got != tc.want {
				t.Errorf("PaperOrderAggregateID(%q) = %q, want %q", tc.orderID, got, tc.want)
			}
		})
	}
}

// TestMFOrderRejectedEvent_Fields pins the field surface of the MF
// rejection event. Source distinguishes the four MF mutation paths
// ("place_order", "cancel_order", "place_sip", "cancel_sip") so a
// projector consumer can render rejection timelines per surface
// without parsing OrderID prefixes.
func TestMFOrderRejectedEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	e := MFOrderRejectedEvent{
		Email:     "trader@example.com",
		OrderID:   "MF-123",
		Source:    "place_order",
		Reason:    "MARKET_CLOSED",
		Timestamp: now,
	}

	if e.EventType() != "mf.order_rejected" {
		t.Errorf("EventType() = %q, want mf.order_rejected", e.EventType())
	}
	if !e.OccurredAt().Equal(now) {
		t.Error("OccurredAt() mismatch")
	}
	if e.Source != "place_order" {
		t.Errorf("Source = %q", e.Source)
	}
	if e.Reason == "" {
		t.Error("Reason should be populated")
	}
}

// TestMFOrderRejectedAggregateID covers the OrderID-vs-synthetic-key
// branching: when OrderID is non-empty (cancel paths, where the caller
// supplied an existing MF order/SIP ID), the rejection joins the MF
// aggregate stream. When OrderID is empty (place_order failure, no
// broker-assigned ID), it falls back to "mf-rejected:<email>:<ts>".
func TestMFOrderRejectedAggregateID(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 10, 30, 0, 0, time.UTC)
	tests := []struct {
		name    string
		orderID string
		email   string
		want    string
	}{
		{"OrderID present joins existing MF stream", "MF-123", "trader@example.com", "MF-123"},
		{"Empty OrderID with email falls back to synthetic", "", "trader@example.com",
			"mf-rejected:trader@example.com:" + now.Format(time.RFC3339Nano)},
		{"Empty everything falls back to unknown", "", "", "mf-rejected:unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MFOrderRejectedAggregateID(tc.orderID, tc.email, now)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestGTTRejectedEvent_Fields pins the field surface of the GTT
// rejection event. Source distinguishes the three GTT mutation paths
// ("place", "modify", "delete") so projector consumers can render
// rejection timelines per surface.
func TestGTTRejectedEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	e := GTTRejectedEvent{
		Email:     "trader@example.com",
		TriggerID: 42,
		Source:    "modify",
		Reason:    "GTT_NOT_FOUND",
		Timestamp: now,
	}

	if e.EventType() != "gtt.rejected" {
		t.Errorf("EventType() = %q, want gtt.rejected", e.EventType())
	}
	if !e.OccurredAt().Equal(now) {
		t.Error("OccurredAt() mismatch")
	}
	if e.TriggerID != 42 {
		t.Errorf("TriggerID = %d", e.TriggerID)
	}
	if e.Source != "modify" {
		t.Errorf("Source = %q", e.Source)
	}
}

// TestGTTRejectedAggregateID covers the TriggerID-vs-synthetic-key
// branching. TriggerID is a Kite-assigned int64; when present
// (modify/delete paths) the rejection joins the existing GTT aggregate
// stream stringified to "<id>". When TriggerID is 0 (place rejection,
// no broker ID issued), falls back to "gtt-rejected:<email>:<ts>".
func TestGTTRejectedAggregateID(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 10, 30, 0, 0, time.UTC)
	tests := []struct {
		name      string
		triggerID int
		email     string
		want      string
	}{
		{"TriggerID present joins GTT stream", 42, "trader@example.com", "42"},
		{"Zero TriggerID with email falls back to synthetic", 0, "trader@example.com",
			"gtt-rejected:trader@example.com:" + now.Format(time.RFC3339Nano)},
		{"Zero everything falls back to unknown", 0, "", "gtt-rejected:unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := GTTRejectedAggregateID(tc.triggerID, tc.email, now)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestTrailingStopTriggeredEvent_Fields pins the trailing-stop trigger
// event surface. Fires when evaluateOne actually modifies an SL order
// — captures the trailing transition (oldStop -> newStop) and the
// underlying SL OrderID so a forensic walk of the SL order ID sees
// the trailing-stop modification inline with place/modify/cancel
// transitions.
func TestTrailingStopTriggeredEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	e := TrailingStopTriggeredEvent{
		Email:          "trader@example.com",
		TrailingStopID: "TS1",
		OrderID:        "ORD-555",
		Instrument:     NewInstrumentKey("NSE", "RELIANCE"),
		Direction:      "long",
		OldStop:        100.0,
		NewStop:        110.0,
		HighWaterMark:  120.0,
		ModifyCount:    3,
		Timestamp:      now,
	}

	if e.EventType() != "trailing_stop.triggered" {
		t.Errorf("EventType() = %q, want trailing_stop.triggered", e.EventType())
	}
	if !e.OccurredAt().Equal(now) {
		t.Error("OccurredAt() mismatch")
	}
	if e.TrailingStopID != "TS1" {
		t.Errorf("TrailingStopID = %q", e.TrailingStopID)
	}
	if e.OldStop != 100.0 || e.NewStop != 110.0 {
		t.Errorf("OldStop=%v NewStop=%v", e.OldStop, e.NewStop)
	}
	if e.Direction != "long" {
		t.Errorf("Direction = %q", e.Direction)
	}
}

// TestTrailingStopAggregateID pins the natural aggregate key for
// trailing-stop trigger events: keyed by TrailingStopID alone since
// trailing IDs are uuid-derived and globally unique. Empty falls back
// to "trailing-stop:unknown".
func TestTrailingStopAggregateID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		trailingStopID string
		want           string
	}{
		{"Standard ID", "TS1", "TS1"},
		{"Empty falls back to unknown", "", "trailing-stop:unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := TrailingStopAggregateID(tc.trailingStopID)
			if got != tc.want {
				t.Errorf("TrailingStopAggregateID(%q) = %q, want %q",
					tc.trailingStopID, got, tc.want)
			}
		})
	}
}

// --- Success-path migration: typed events for surfaces previously
// using untyped appendAuxEvent (mf.*, gtt.*, trailing_stop.set/cancel) ---

// TestMFOrderPlacedEvent_Fields pins the typed-event surface for the
// MF order placement success path. Replaces the prior untyped
// appendAuxEvent("mf.order_placed", map[string]any{...}) emit so
// projector consumers receive a stable schema with named fields.
func TestMFOrderPlacedEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	e := MFOrderPlacedEvent{
		Email:           "trader@example.com",
		OrderID:         "MFO-1",
		Tradingsymbol:   "INF123",
		TransactionType: "BUY",
		Amount:          5000,
		Quantity:        0,
		Tag:             "monthly_topup",
		Timestamp:       now,
	}
	if e.EventType() != "mf.order_placed" {
		t.Errorf("EventType() = %q, want mf.order_placed", e.EventType())
	}
	if !e.OccurredAt().Equal(now) {
		t.Error("OccurredAt() mismatch")
	}
	if e.OrderID != "MFO-1" {
		t.Errorf("OrderID = %q", e.OrderID)
	}
}

// TestMFOrderCancelledEvent_Fields pins the cancelled-MF-order surface.
func TestMFOrderCancelledEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	e := MFOrderCancelledEvent{
		Email:     "trader@example.com",
		OrderID:   "MFO-2",
		Timestamp: now,
	}
	if e.EventType() != "mf.order_cancelled" {
		t.Errorf("EventType() = %q", e.EventType())
	}
	if !e.OccurredAt().Equal(now) {
		t.Error("OccurredAt() mismatch")
	}
}

// TestMFSIPPlacedEvent_Fields pins the SIP-placed surface. Frequency
// + Instalments + InitialAmount + InstalmentDay are all preserved
// verbatim from the Kite MFSIPParams so a forensic walk can reconstruct
// the SIP creation parameters without re-querying the broker.
func TestMFSIPPlacedEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	e := MFSIPPlacedEvent{
		Email:         "trader@example.com",
		SIPID:         "SIP-1",
		Tradingsymbol: "INF123",
		Amount:        5000,
		Frequency:     "monthly",
		Instalments:   12,
		InitialAmount: 0,
		InstalmentDay: 1,
		Tag:           "auto",
		Timestamp:     now,
	}
	if e.EventType() != "mf.sip_placed" {
		t.Errorf("EventType() = %q", e.EventType())
	}
	if e.SIPID != "SIP-1" {
		t.Errorf("SIPID = %q", e.SIPID)
	}
	if e.Frequency != "monthly" {
		t.Errorf("Frequency = %q", e.Frequency)
	}
}

// TestMFSIPCancelledEvent_Fields pins the SIP-cancelled surface.
func TestMFSIPCancelledEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	e := MFSIPCancelledEvent{
		Email:     "trader@example.com",
		SIPID:     "SIP-1",
		Timestamp: now,
	}
	if e.EventType() != "mf.sip_cancelled" {
		t.Errorf("EventType() = %q", e.EventType())
	}
}

// TestMFAggregateID pins the aggregate-key derivation for the MF
// success events. Format mirrors the existing appendAuxEvent
// aggregate IDs (OrderID for MFOrder, SIPID for MFSIP) so existing
// audit rows and the new typed events sort under the same key.
func TestMFAggregateID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, id, want string
	}{
		{"present joins existing stream", "MFO-1", "MFO-1"},
		{"empty falls back to unknown", "", "mf:unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := MFAggregateID(tc.id); got != tc.want {
				t.Errorf("MFAggregateID(%q) = %q, want %q", tc.id, got, tc.want)
			}
		})
	}
}

// TestGTTPlacedEvent_Fields pins the typed-event surface for GTT
// placement. Replaces the prior untyped appendAuxEvent("gtt.placed",
// ...) with a stable schema. Type field ("single" / "two-leg") matters
// because two-leg GTTs carry Upper/Lower trigger params that aren't
// meaningful on single-leg.
func TestGTTPlacedEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	e := GTTPlacedEvent{
		Email:           "trader@example.com",
		TriggerID:       42,
		Instrument:      NewInstrumentKey("NSE", "RELIANCE"),
		TransactionType: "BUY",
		Product:         "CNC",
		Type:            "single",
		TriggerValue:    2400,
		Quantity:        10.0,
		LimitPrice:      2390,
		Timestamp:       now,
	}
	if e.EventType() != "gtt.placed" {
		t.Errorf("EventType() = %q", e.EventType())
	}
	if e.TriggerID != 42 {
		t.Errorf("TriggerID = %d", e.TriggerID)
	}
	if e.Type != "single" {
		t.Errorf("Type = %q", e.Type)
	}
}

// TestGTTModifiedEvent_Fields pins the modified-GTT surface.
func TestGTTModifiedEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	e := GTTModifiedEvent{
		Email:           "trader@example.com",
		TriggerID:       42,
		Instrument:      NewInstrumentKey("NSE", "RELIANCE"),
		TransactionType: "BUY",
		Product:         "CNC",
		Type:            "single",
		TriggerValue:    2450,
		Quantity:        15.0,
		LimitPrice:      2440,
		Timestamp:       now,
	}
	if e.EventType() != "gtt.modified" {
		t.Errorf("EventType() = %q", e.EventType())
	}
}

// TestGTTDeletedEvent_Fields pins the deleted-GTT surface.
func TestGTTDeletedEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	e := GTTDeletedEvent{
		Email:     "trader@example.com",
		TriggerID: 42,
		Timestamp: now,
	}
	if e.EventType() != "gtt.deleted" {
		t.Errorf("EventType() = %q", e.EventType())
	}
}

// TestGTTAggregateID pins the aggregate-key derivation for GTT events.
// Format matches the existing appendAuxEvent aggregate IDs:
// fmt.Sprintf("%d", triggerID) so the rejection events from prior
// commits and the new typed success events sort under the same key.
func TestGTTAggregateID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		triggerID int
		want      string
	}{
		{"non-zero stringified", 42, "42"},
		{"zero falls back to unknown", 0, "gtt:unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := GTTAggregateID(tc.triggerID); got != tc.want {
				t.Errorf("GTTAggregateID(%d) = %q, want %q", tc.triggerID, got, tc.want)
			}
		})
	}
}

// TestTrailingStopSetEvent_Fields pins the typed-event surface for
// trailing-stop creation. ReferencePrice = HighWaterMark at activation
// time (the price the trailing window is anchored on); CurrentStop is
// the initial SL trigger.
func TestTrailingStopSetEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	e := TrailingStopSetEvent{
		Email:           "trader@example.com",
		TrailingStopID:  "TS1",
		Instrument:      NewInstrumentKey("NSE", "RELIANCE"),
		OrderID:         "SL-1",
		Variety:         "regular",
		Direction:       "long",
		TrailAmount:     20,
		TrailPct:        0,
		CurrentStop:     1480,
		ReferencePrice:  1500,
		Timestamp:       now,
	}
	if e.EventType() != "trailing_stop.set" {
		t.Errorf("EventType() = %q", e.EventType())
	}
	if e.TrailingStopID != "TS1" {
		t.Errorf("TrailingStopID = %q", e.TrailingStopID)
	}
	if e.Direction != "long" {
		t.Errorf("Direction = %q", e.Direction)
	}
}

// TestTrailingStopCancelledEvent_Fields pins the cancelled-trailing-stop
// surface. Pairs with TrailingStopSetEvent under the same aggregate ID
// (uuid-derived TrailingStopID) so a full set->triggers->cancel
// lifecycle replays as a coherent stream.
func TestTrailingStopCancelledEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	e := TrailingStopCancelledEvent{
		Email:          "trader@example.com",
		TrailingStopID: "TS1",
		Timestamp:      now,
	}
	if e.EventType() != "trailing_stop.cancelled" {
		t.Errorf("EventType() = %q", e.EventType())
	}
}

// --- Native alert + paper trading lifecycle: typed events ---

// TestNativeAlertPlacedEvent_Fields pins the typed event surface
// for native (Kite-side) alert creation. UUID may be empty here —
// the broker assigns it lazily and the use case doesn't always see
// it in the immediate response. Aggregate-ID falls back to email
// when UUID is empty (matching the existing appendAuxEvent shape).
func TestNativeAlertPlacedEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	e := NativeAlertPlacedEvent{
		Email:     "trader@example.com",
		UUID:      "", // commonly empty at place time
		Timestamp: now,
	}
	if e.EventType() != "native_alert.placed" {
		t.Errorf("EventType() = %q", e.EventType())
	}
	if !e.OccurredAt().Equal(now) {
		t.Error("OccurredAt() mismatch")
	}
	if e.Email != "trader@example.com" {
		t.Errorf("Email = %q", e.Email)
	}
}

// TestNativeAlertModifiedEvent_Fields pins the modified-alert surface.
// UUID is required for modify (broker needs the existing alert ID).
func TestNativeAlertModifiedEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	e := NativeAlertModifiedEvent{
		Email:     "trader@example.com",
		UUID:      "alert-uuid-1",
		Timestamp: now,
	}
	if e.EventType() != "native_alert.modified" {
		t.Errorf("EventType() = %q", e.EventType())
	}
	if e.UUID != "alert-uuid-1" {
		t.Errorf("UUID = %q", e.UUID)
	}
}

// TestNativeAlertDeletedEvent_Fields pins the deleted-alert surface.
// One event per UUID (matching the existing appendAuxEvent loop in
// DeleteNativeAlertUseCase).
func TestNativeAlertDeletedEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	e := NativeAlertDeletedEvent{
		Email:     "trader@example.com",
		UUID:      "alert-uuid-2",
		Timestamp: now,
	}
	if e.EventType() != "native_alert.deleted" {
		t.Errorf("EventType() = %q", e.EventType())
	}
}

// TestNativeAlertAggregateID pins the aggregate-key derivation:
// non-empty UUID joins the alert aggregate stream; empty UUID falls
// back to the email (matching the prior appendAuxEvent behaviour
// where PlaceNativeAlertUseCase keyed by email because the broker
// hadn't assigned a UUID yet).
func TestNativeAlertAggregateID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, uuid, email, want string
	}{
		{"UUID present joins alert stream", "alert-1", "u@t.com", "alert-1"},
		{"empty UUID falls back to email", "", "u@t.com", "u@t.com"},
		{"both empty falls back to unknown", "", "", "native-alert:unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := NativeAlertAggregateID(tc.uuid, tc.email); got != tc.want {
				t.Errorf("NativeAlertAggregateID(%q, %q) = %q, want %q",
					tc.uuid, tc.email, got, tc.want)
			}
		})
	}
}

// TestPaperTradingEnabledEvent_Fields pins the typed event surface
// for paper-trading lifecycle activation. InitialCash captures the
// virtual portfolio's starting capital so a forensic walk can
// reconstruct the seed condition without re-querying the engine.
func TestPaperTradingEnabledEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	e := PaperTradingEnabledEvent{
		Email:       "trader@example.com",
		InitialCash: 10000000,
		Timestamp:   now,
	}
	if e.EventType() != "paper.enabled" {
		t.Errorf("EventType() = %q", e.EventType())
	}
	if e.InitialCash != 10000000 {
		t.Errorf("InitialCash = %v", e.InitialCash)
	}
}

// TestPaperTradingDisabledEvent_Fields pins the disable surface.
func TestPaperTradingDisabledEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	e := PaperTradingDisabledEvent{
		Email:     "trader@example.com",
		Timestamp: now,
	}
	if e.EventType() != "paper.disabled" {
		t.Errorf("EventType() = %q", e.EventType())
	}
}

// TestPaperTradingResetEvent_Fields pins the reset surface — clears
// the virtual portfolio back to InitialCash and zero positions.
func TestPaperTradingResetEvent_Fields(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	e := PaperTradingResetEvent{
		Email:     "trader@example.com",
		Timestamp: now,
	}
	if e.EventType() != "paper.reset" {
		t.Errorf("EventType() = %q", e.EventType())
	}
}

// TestPaperTradingAggregateID pins the aggregate-key derivation:
// keyed by email (the user's paper-trading "account"). The full
// enable->reset->disable lifecycle replays under one stream.
func TestPaperTradingAggregateID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, email, want string
	}{
		{"present", "trader@example.com", "trader@example.com"},
		{"empty falls back to unknown", "", "paper-trading:unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := PaperTradingAggregateID(tc.email); got != tc.want {
				t.Errorf("PaperTradingAggregateID(%q) = %q, want %q",
					tc.email, got, tc.want)
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
