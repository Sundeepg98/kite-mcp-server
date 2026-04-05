package domain

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- Money tests ---

func TestNewINR(t *testing.T) {
	m := NewINR(1234.56)
	if m.Amount != 1234.56 {
		t.Errorf("Amount = %f, want 1234.56", m.Amount)
	}
	if m.Currency != "INR" {
		t.Errorf("Currency = %s, want INR", m.Currency)
	}
}

func TestMoneyAdd(t *testing.T) {
	a := NewINR(100.50)
	b := NewINR(200.25)
	sum := a.Add(b)
	if sum.Amount != 300.75 {
		t.Errorf("Add: got %f, want 300.75", sum.Amount)
	}
	if sum.Currency != "INR" {
		t.Errorf("Currency = %s, want INR", sum.Currency)
	}
}

func TestMoneyAddMismatchPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic when adding different currencies")
		}
	}()
	a := NewINR(100)
	b := Money{Amount: 50, Currency: "USD"}
	_ = a.Add(b)
}

func TestMoneySub(t *testing.T) {
	a := NewINR(500)
	b := NewINR(123.45)
	diff := a.Sub(b)
	want := 376.55
	if diff.Amount < want-0.001 || diff.Amount > want+0.001 {
		t.Errorf("Sub: got %f, want %f", diff.Amount, want)
	}
}

func TestMoneyMultiply(t *testing.T) {
	m := NewINR(100).Multiply(2.5)
	if m.Amount != 250 {
		t.Errorf("Multiply: got %f, want 250", m.Amount)
	}
}

func TestMoneyIsZero(t *testing.T) {
	if !NewINR(0).IsZero() {
		t.Error("expected IsZero for 0")
	}
	if NewINR(1).IsZero() {
		t.Error("expected !IsZero for 1")
	}
}

func TestMoneyIsNegative(t *testing.T) {
	if !NewINR(-10).IsNegative() {
		t.Error("expected IsNegative for -10")
	}
	if NewINR(10).IsNegative() {
		t.Error("expected !IsNegative for 10")
	}
}

func TestMoneyStringINR(t *testing.T) {
	tests := []struct {
		amount float64
		want   string
	}{
		{0, "₹0.00"},
		{5, "₹5.00"},
		{999, "₹999.00"},
		{1234.56, "₹1,234.56"},
		{12345.00, "₹12,345.00"},
		{123456.78, "₹1,23,456.78"},
		{1234567.89, "₹12,34,567.89"},
		{10000000, "₹1,00,00,000.00"},
		{-1234.56, "₹-1,234.56"},
	}
	for _, tt := range tests {
		got := NewINR(tt.amount).String()
		if got != tt.want {
			t.Errorf("NewINR(%v).String() = %q, want %q", tt.amount, got, tt.want)
		}
	}
}

func TestMoneyStringOtherCurrency(t *testing.T) {
	m := Money{Amount: 99.99, Currency: "USD"}
	got := m.String()
	if got != "USD 99.99" {
		t.Errorf("String() = %q, want %q", got, "USD 99.99")
	}
}

// --- Quantity tests ---

func TestNewQuantityValid(t *testing.T) {
	q, err := NewQuantity(10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.Int() != 10 {
		t.Errorf("Int() = %d, want 10", q.Int())
	}
}

func TestNewQuantityZeroRejected(t *testing.T) {
	_, err := NewQuantity(0)
	if err == nil {
		t.Error("expected error for quantity 0")
	}
}

func TestNewQuantityNegativeRejected(t *testing.T) {
	_, err := NewQuantity(-5)
	if err == nil {
		t.Error("expected error for negative quantity")
	}
}

func TestQuantityString(t *testing.T) {
	q, _ := NewQuantity(42)
	if q.String() != "42" {
		t.Errorf("String() = %q, want %q", q.String(), "42")
	}
}

// --- InstrumentKey tests ---

func TestNewInstrumentKey(t *testing.T) {
	k := NewInstrumentKey("nse", "reliance")
	if k.Exchange != "NSE" {
		t.Errorf("Exchange = %q, want NSE", k.Exchange)
	}
	if k.Tradingsymbol != "RELIANCE" {
		t.Errorf("Tradingsymbol = %q, want RELIANCE", k.Tradingsymbol)
	}
}

func TestInstrumentKeyString(t *testing.T) {
	k := NewInstrumentKey("NSE", "INFY")
	if k.String() != "NSE:INFY" {
		t.Errorf("String() = %q, want NSE:INFY", k.String())
	}
}

func TestInstrumentKeyIsZero(t *testing.T) {
	var zero InstrumentKey
	if !zero.IsZero() {
		t.Error("expected IsZero for empty key")
	}
	if NewInstrumentKey("NSE", "RELIANCE").IsZero() {
		t.Error("expected !IsZero for valid key")
	}
}

func TestParseInstrumentKey(t *testing.T) {
	k, err := ParseInstrumentKey("NSE:RELIANCE")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if k.Exchange != "NSE" || k.Tradingsymbol != "RELIANCE" {
		t.Errorf("got %v, want NSE:RELIANCE", k)
	}
}

func TestParseInstrumentKeyLowercase(t *testing.T) {
	k, err := ParseInstrumentKey("bse:infy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if k.Exchange != "BSE" || k.Tradingsymbol != "INFY" {
		t.Errorf("got %v, want BSE:INFY", k)
	}
}

func TestParseInstrumentKeyInvalid(t *testing.T) {
	cases := []string{"", "NSE", "NSE:", ":RELIANCE", "RELIANCE"}
	for _, s := range cases {
		_, err := ParseInstrumentKey(s)
		if err == nil {
			t.Errorf("expected error for %q", s)
		}
	}
}

// --- Event interface tests ---

func TestOrderPlacedEventInterface(t *testing.T) {
	now := time.Now()
	e := OrderPlacedEvent{
		Email:           "test@example.com",
		OrderID:         "ORD123",
		Instrument:      NewInstrumentKey("NSE", "RELIANCE"),
		Qty:             Quantity{value: 10},
		Price:           NewINR(2500),
		TransactionType: "BUY",
		Timestamp:       now,
	}
	var ev Event = e // compile-time check
	if ev.EventType() != "order.placed" {
		t.Errorf("EventType() = %q, want order.placed", ev.EventType())
	}
	if ev.OccurredAt() != now {
		t.Errorf("OccurredAt() mismatch")
	}
}

func TestAlertTriggeredEventInterface(t *testing.T) {
	e := AlertTriggeredEvent{Timestamp: time.Now()}
	var ev Event = e
	if ev.EventType() != "alert.triggered" {
		t.Errorf("EventType() = %q", ev.EventType())
	}
}

func TestRiskLimitBreachedEventInterface(t *testing.T) {
	e := RiskLimitBreachedEvent{Timestamp: time.Now()}
	var ev Event = e
	if ev.EventType() != "risk.limit_breached" {
		t.Errorf("EventType() = %q", ev.EventType())
	}
}

func TestSessionCreatedEventInterface(t *testing.T) {
	e := SessionCreatedEvent{Timestamp: time.Now()}
	var ev Event = e
	if ev.EventType() != "session.created" {
		t.Errorf("EventType() = %q", ev.EventType())
	}
}

func TestUserFrozenEventInterface(t *testing.T) {
	e := UserFrozenEvent{Timestamp: time.Now()}
	var ev Event = e
	if ev.EventType() != "user.frozen" {
		t.Errorf("EventType() = %q", ev.EventType())
	}
}

// --- EventDispatcher tests ---

func TestDispatcherSubscribeAndDispatch(t *testing.T) {
	d := NewEventDispatcher()

	var received []string
	d.Subscribe("order.placed", func(e Event) {
		received = append(received, e.EventType())
	})
	d.Subscribe("order.placed", func(e Event) {
		received = append(received, "handler2:"+e.EventType())
	})

	d.Dispatch(OrderPlacedEvent{Timestamp: time.Now()})

	if len(received) != 2 {
		t.Fatalf("expected 2 handlers called, got %d", len(received))
	}
	if received[0] != "order.placed" {
		t.Errorf("handler 1 got %q", received[0])
	}
	if received[1] != "handler2:order.placed" {
		t.Errorf("handler 2 got %q", received[1])
	}
}

func TestDispatcherNoHandlers(t *testing.T) {
	d := NewEventDispatcher()
	// Should not panic with no handlers registered.
	d.Dispatch(OrderPlacedEvent{Timestamp: time.Now()})
}

func TestDispatcherDifferentEventTypes(t *testing.T) {
	d := NewEventDispatcher()

	var orderCount, alertCount int
	d.Subscribe("order.placed", func(e Event) { orderCount++ })
	d.Subscribe("alert.triggered", func(e Event) { alertCount++ })

	d.Dispatch(OrderPlacedEvent{Timestamp: time.Now()})
	d.Dispatch(OrderPlacedEvent{Timestamp: time.Now()})
	d.Dispatch(AlertTriggeredEvent{Timestamp: time.Now()})

	if orderCount != 2 {
		t.Errorf("orderCount = %d, want 2", orderCount)
	}
	if alertCount != 1 {
		t.Errorf("alertCount = %d, want 1", alertCount)
	}
}

func TestDispatcherConcurrentSafety(t *testing.T) {
	d := NewEventDispatcher()

	var count atomic.Int64
	d.Subscribe("order.placed", func(e Event) {
		count.Add(1)
	})

	const goroutines = 50
	const eventsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < eventsPerGoroutine; j++ {
				d.Dispatch(OrderPlacedEvent{Timestamp: time.Now()})
			}
		}()
	}
	wg.Wait()

	got := count.Load()
	want := int64(goroutines * eventsPerGoroutine)
	if got != want {
		t.Errorf("concurrent dispatch count = %d, want %d", got, want)
	}
}

func TestDispatcherConcurrentSubscribeAndDispatch(t *testing.T) {
	d := NewEventDispatcher()

	var count atomic.Int64

	var wg sync.WaitGroup
	// Concurrent subscribes.
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func() {
			defer wg.Done()
			d.Subscribe("order.placed", func(e Event) {
				count.Add(1)
			})
		}()
	}
	wg.Wait()

	// Concurrent dispatches after all subscriptions.
	wg.Add(20)
	for i := 0; i < 20; i++ {
		go func() {
			defer wg.Done()
			d.Dispatch(OrderPlacedEvent{Timestamp: time.Now()})
		}()
	}
	wg.Wait()

	// Each dispatch should call all 10 handlers.
	got := count.Load()
	want := int64(10 * 20)
	if got != want {
		t.Errorf("concurrent subscribe+dispatch count = %d, want %d", got, want)
	}
}
