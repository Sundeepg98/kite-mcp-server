package eventsourcing

import (
	"testing"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// TestProjector_OrderFlow exercises the full place->modify->fill lifecycle on
// the projector by dispatching public domain events on the EventDispatcher.
func TestProjector_OrderFlow(t *testing.T) {
	dispatcher := domain.NewEventDispatcher()
	proj := NewProjector()
	proj.Subscribe(dispatcher)

	now := time.Now().UTC()
	qty, _ := domain.NewQuantity(10)
	price := domain.NewINR(100.5)

	dispatcher.Dispatch(domain.OrderPlacedEvent{
		Email:           "u@example.com",
		OrderID:         "ORD-1",
		Instrument:      domain.NewInstrumentKey("NSE", "INFY"),
		Qty:             qty,
		Price:           price,
		TransactionType: "BUY",
		Timestamp:       now,
	})

	agg, ok := proj.GetOrder("ORD-1")
	if !ok {
		t.Fatal("expected order ORD-1 to be projected after placed event")
	}
	if agg.Status != OrderStatusPlaced {
		t.Errorf("status = %s, want PLACED", agg.Status)
	}
	if agg.Email != "u@example.com" {
		t.Errorf("email = %q, want u@example.com", agg.Email)
	}
	if agg.Quantity.Int() != 10 {
		t.Errorf("quantity = %d, want 10", agg.Quantity.Int())
	}

	dispatcher.Dispatch(domain.OrderModifiedEvent{
		Email:     "u@example.com",
		OrderID:   "ORD-1",
		Timestamp: now.Add(time.Minute),
	})
	agg, _ = proj.GetOrder("ORD-1")
	if agg.Status != OrderStatusModified {
		t.Errorf("after modify: status = %s, want MODIFIED", agg.Status)
	}
	if agg.ModifyCount != 1 {
		t.Errorf("modify count = %d, want 1", agg.ModifyCount)
	}

	filledQty, _ := domain.NewQuantity(10)
	dispatcher.Dispatch(domain.OrderFilledEvent{
		Email:       "u@example.com",
		OrderID:     "ORD-1",
		FilledQty:   filledQty,
		FilledPrice: domain.NewINR(100.75),
		Timestamp:   now.Add(2 * time.Minute),
	})
	agg, _ = proj.GetOrder("ORD-1")
	if agg.Status != OrderStatusFilled {
		t.Errorf("after fill: status = %s, want FILLED", agg.Status)
	}
	if agg.FilledPrice.Amount != 100.75 {
		t.Errorf("filled price = %v, want 100.75", agg.FilledPrice.Amount)
	}

	if n := proj.OrderCount(); n != 1 {
		t.Errorf("order count = %d, want 1", n)
	}
}

// TestProjector_OrderCancel verifies OrderCancelledEvent flips status.
func TestProjector_OrderCancel(t *testing.T) {
	dispatcher := domain.NewEventDispatcher()
	proj := NewProjector()
	proj.Subscribe(dispatcher)

	now := time.Now().UTC()
	qty, _ := domain.NewQuantity(5)
	dispatcher.Dispatch(domain.OrderPlacedEvent{
		Email:           "u@example.com",
		OrderID:         "ORD-2",
		Instrument:      domain.NewInstrumentKey("NSE", "TCS"),
		Qty:             qty,
		Price:           domain.NewINR(3500),
		TransactionType: "SELL",
		Timestamp:       now,
	})
	dispatcher.Dispatch(domain.OrderCancelledEvent{
		Email:     "u@example.com",
		OrderID:   "ORD-2",
		Timestamp: now.Add(time.Minute),
	})

	agg, ok := proj.GetOrder("ORD-2")
	if !ok {
		t.Fatal("expected ORD-2 to exist")
	}
	if agg.Status != OrderStatusCancelled {
		t.Errorf("status = %s, want CANCELLED", agg.Status)
	}
	if agg.CancelledAt.IsZero() {
		t.Error("cancelled_at should be set")
	}
}

// TestProjector_AlertFlow exercises alert lifecycle events.
func TestProjector_AlertFlow(t *testing.T) {
	dispatcher := domain.NewEventDispatcher()
	proj := NewProjector()
	proj.Subscribe(dispatcher)

	now := time.Now().UTC()
	dispatcher.Dispatch(domain.AlertCreatedEvent{
		Email:       "u@example.com",
		AlertID:     "ALERT-1",
		Instrument:  domain.NewInstrumentKey("NSE", "RELIANCE"),
		TargetPrice: domain.NewINR(2500),
		Direction:   "above",
		Timestamp:   now,
	})

	alert, ok := proj.GetAlert("ALERT-1")
	if !ok {
		t.Fatal("expected ALERT-1 to exist")
	}
	if alert.Status != AlertStatusActive {
		t.Errorf("status = %s, want ACTIVE", alert.Status)
	}
	if alert.TargetPrice.Amount != 2500 {
		t.Errorf("target price = %v, want 2500", alert.TargetPrice.Amount)
	}

	actives := proj.ListActiveAlerts()
	if len(actives) != 1 {
		t.Errorf("active alerts = %d, want 1", len(actives))
	}

	dispatcher.Dispatch(domain.AlertTriggeredEvent{
		Email:        "u@example.com",
		AlertID:      "ALERT-1",
		Instrument:   domain.NewInstrumentKey("NSE", "RELIANCE"),
		TargetPrice:  domain.NewINR(2500),
		CurrentPrice: domain.NewINR(2502),
		Direction:    "above",
		Timestamp:    now.Add(time.Minute),
	})

	alert, _ = proj.GetAlert("ALERT-1")
	if alert.Status != AlertStatusTriggered {
		t.Errorf("after trigger: status = %s, want TRIGGERED", alert.Status)
	}
	if alert.TriggeredAt.IsZero() {
		t.Error("triggered_at should be set")
	}

	if len(proj.ListActiveAlerts()) != 0 {
		t.Error("active alerts should be empty after trigger")
	}
}

// TestProjector_PositionClose projects a PositionClosedEvent keyed by the
// natural (email, exchange, symbol, product) tuple — positions don't have
// a broker-assigned unique ID, so we use PositionAggregateID for the join.
func TestProjector_PositionClose(t *testing.T) {
	dispatcher := domain.NewEventDispatcher()
	proj := NewProjector()
	proj.Subscribe(dispatcher)

	now := time.Now().UTC()
	qty, _ := domain.NewQuantity(3)
	instrument := domain.NewInstrumentKey("NSE", "HDFC")
	dispatcher.Dispatch(domain.PositionClosedEvent{
		Email:           "u@example.com",
		OrderID:         "CLOSE-ORD-1",
		Instrument:      instrument,
		Product:         "CNC",
		Qty:             qty,
		TransactionType: "SELL",
		Timestamp:       now,
	})

	aggID := domain.PositionAggregateID("u@example.com", instrument, "CNC")
	pos, ok := proj.GetPosition(aggID)
	if !ok {
		t.Fatalf("expected %s to be projected", aggID)
	}
	if pos.Status != PositionStatusClosed {
		t.Errorf("status = %s, want CLOSED", pos.Status)
	}
	if pos.ClosedAt.IsZero() {
		t.Error("closed_at should be set")
	}
	if proj.PositionCount() != 1 {
		t.Errorf("position count = %d, want 1", proj.PositionCount())
	}
}

// TestProjector_PositionOpenClose_Lifecycle verifies the full OPEN -> CLOSED
// transition on a single position aggregate using the natural-key join.
// Both events for the same (email, exchange, symbol, product) tuple land
// on the same aggregate ID computed by domain.PositionAggregateID, so a
// single open→close cycle produces one aggregate with OPEN then CLOSED
// state.
func TestProjector_PositionOpenClose_Lifecycle(t *testing.T) {
	dispatcher := domain.NewEventDispatcher()
	proj := NewProjector()
	proj.Subscribe(dispatcher)

	now := time.Now().UTC()
	openQty, _ := domain.NewQuantity(7)
	instrument := domain.NewInstrumentKey("NSE", "INFY")
	const product = "MIS"
	aggID := domain.PositionAggregateID("u@example.com", instrument, product)

	dispatcher.Dispatch(domain.PositionOpenedEvent{
		Email:           "u@example.com",
		PositionID:      "POS-ORD-42",
		Instrument:      instrument,
		Product:         product,
		Qty:             openQty,
		AvgPrice:        domain.NewINR(1500.25),
		TransactionType: "BUY",
		Timestamp:       now,
	})

	pos, ok := proj.GetPosition(aggID)
	if !ok {
		t.Fatalf("expected %s to be projected after open event", aggID)
	}
	if pos.Status != PositionStatusOpen {
		t.Errorf("after open: status = %s, want OPEN", pos.Status)
	}
	if pos.Email != "u@example.com" {
		t.Errorf("email after open = %q, want u@example.com", pos.Email)
	}
	if pos.Instrument != instrument {
		t.Errorf("instrument after open = %+v, want %+v", pos.Instrument, instrument)
	}
	if pos.Product != product {
		t.Errorf("product after open = %q, want %q", pos.Product, product)
	}
	if pos.Quantity.Int() != 7 {
		t.Errorf("qty after open = %d, want 7", pos.Quantity.Int())
	}
	if pos.AvgPrice.Amount != 1500.25 {
		t.Errorf("avg price after open = %v, want 1500.25", pos.AvgPrice.Amount)
	}
	if pos.TransactionType != "BUY" {
		t.Errorf("txn type after open = %q, want BUY", pos.TransactionType)
	}
	if pos.OpenedAt.IsZero() {
		t.Error("opened_at should be set after open")
	}
	if !pos.ClosedAt.IsZero() {
		t.Error("closed_at should be zero before close event")
	}

	closeQty, _ := domain.NewQuantity(7)
	dispatcher.Dispatch(domain.PositionClosedEvent{
		Email:           "u@example.com",
		OrderID:         "CLOSE-ORD-99",
		Instrument:      instrument,
		Product:         product,
		Qty:             closeQty,
		TransactionType: "SELL",
		Timestamp:       now.Add(time.Hour),
	})

	pos, ok = proj.GetPosition(aggID)
	if !ok {
		t.Fatalf("expected %s to still exist after close event", aggID)
	}
	if pos.Status != PositionStatusClosed {
		t.Errorf("after close: status = %s, want CLOSED", pos.Status)
	}
	if pos.ClosedAt.IsZero() {
		t.Error("closed_at should be set after close")
	}
	if !pos.ClosedAt.After(pos.OpenedAt) {
		t.Errorf("closed_at %v should be after opened_at %v", pos.ClosedAt, pos.OpenedAt)
	}
	if pos.Quantity.Int() != 0 {
		t.Errorf("qty after close = %d, want 0 (zeroed by Apply on PositionClosedEvent)", pos.Quantity.Int())
	}
	// Metadata preserved from the open event — Apply on close should not wipe
	// instrument or email since they are used by downstream readers.
	if pos.Email != "u@example.com" {
		t.Errorf("email after close = %q, want u@example.com", pos.Email)
	}
	if pos.Instrument != instrument {
		t.Errorf("instrument after close = %+v, want %+v", pos.Instrument, instrument)
	}

	if proj.PositionCount() != 1 {
		t.Errorf("position count = %d, want 1 (same aggregate through lifecycle)", proj.PositionCount())
	}
}

// TestProjector_ListActiveOrders checks that PLACED and MODIFIED orders are
// returned while CANCELLED/FILLED are filtered out.
func TestProjector_ListActiveOrders(t *testing.T) {
	dispatcher := domain.NewEventDispatcher()
	proj := NewProjector()
	proj.Subscribe(dispatcher)

	now := time.Now().UTC()
	qty, _ := domain.NewQuantity(1)

	place := func(id string, offset time.Duration) {
		dispatcher.Dispatch(domain.OrderPlacedEvent{
			Email:           "u@example.com",
			OrderID:         id,
			Instrument:      domain.NewInstrumentKey("NSE", "X"),
			Qty:             qty,
			Price:           domain.NewINR(100),
			TransactionType: "BUY",
			Timestamp:       now.Add(offset),
		})
	}
	place("A", 0)
	place("B", time.Second)
	place("C", 2*time.Second)

	dispatcher.Dispatch(domain.OrderCancelledEvent{Email: "u@example.com", OrderID: "A", Timestamp: now.Add(3 * time.Second)})
	filled, _ := domain.NewQuantity(1)
	dispatcher.Dispatch(domain.OrderFilledEvent{Email: "u@example.com", OrderID: "B", FilledQty: filled, FilledPrice: domain.NewINR(101), Timestamp: now.Add(4 * time.Second)})

	active := proj.ListActiveOrders()
	if len(active) != 1 {
		t.Fatalf("active orders = %d, want 1 (only C should remain)", len(active))
	}
	if active[0].AggregateID() != "C" {
		t.Errorf("active[0] = %s, want C", active[0].AggregateID())
	}
}

// TestProjector_SubscribeNilDispatcher is a no-op and must not panic.
func TestProjector_SubscribeNilDispatcher(t *testing.T) {
	proj := NewProjector()
	proj.Subscribe(nil)
	if proj.OrderCount() != 0 {
		t.Error("expected empty projector after nil subscribe")
	}
}

// TestProjector_MissingIDIgnored verifies events with empty IDs are silently
// dropped rather than crashing the projector.
func TestProjector_MissingIDIgnored(t *testing.T) {
	dispatcher := domain.NewEventDispatcher()
	proj := NewProjector()
	proj.Subscribe(dispatcher)

	qty, _ := domain.NewQuantity(1)
	dispatcher.Dispatch(domain.OrderPlacedEvent{
		Email:      "u@example.com",
		OrderID:    "",
		Instrument: domain.NewInstrumentKey("NSE", "X"),
		Qty:        qty,
		Price:      domain.NewINR(100),
		Timestamp:  time.Now(),
	})
	if proj.OrderCount() != 0 {
		t.Error("event with empty ID should be ignored")
	}
}
