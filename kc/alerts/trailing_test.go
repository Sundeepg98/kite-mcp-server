package alerts

import (
	"log/slog"
	"testing"
	"time"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/gokiteconnect/v4/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// mockModifier is a test double for KiteOrderModifier.
type mockModifier struct {
	calls     []modifyCall
	returnErr error
}

type modifyCall struct {
	variety  string
	orderID  string
	trigger  float64
}

func (m *mockModifier) ModifyOrder(variety, orderID string, params kiteconnect.OrderParams) (kiteconnect.OrderResponse, error) {
	m.calls = append(m.calls, modifyCall{
		variety:  variety,
		orderID:  orderID,
		trigger:  params.TriggerPrice,
	})
	return kiteconnect.OrderResponse{OrderID: orderID}, m.returnErr
}

func newTestManager(t *testing.T) (*TrailingStopManager, *mockModifier) {
	t.Helper()
	logger := slog.Default()
	m := NewTrailingStopManager(logger)

	mock := &mockModifier{}
	m.SetModifier(func(email string) (KiteOrderModifier, error) {
		return mock, nil
	})

	return m, mock
}

func TestTrailingStopAdd(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager(t)

	ts := &TrailingStop{
		Email:           "test@example.com",
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		InstrumentToken: 408065,
		OrderID:         "220101000000001",
		TrailAmount:     20,
		Direction:       "long",
		HighWaterMark:   1500,
		CurrentStop:     1480,
	}

	id, err := m.Add(ts)
	require.NoError(t, err)
	assert.NotEmpty(t, id)
	assert.True(t, ts.Active)

	stops := m.List("test@example.com")
	assert.Len(t, stops, 1)
	assert.Equal(t, id, stops[0].ID)
	assert.Equal(t, "regular", stops[0].Variety)
}

func TestTrailingStopAddValidation(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager(t)

	// Missing order_id
	_, err := m.Add(&TrailingStop{
		Email: "test@example.com", Direction: "long", TrailAmount: 10, CurrentStop: 100, HighWaterMark: 110,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "order_id")

	// Invalid direction
	_, err = m.Add(&TrailingStop{
		Email: "test@example.com", OrderID: "123", Direction: "sideways", TrailAmount: 10, CurrentStop: 100, HighWaterMark: 110,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "direction")

	// No trail
	_, err = m.Add(&TrailingStop{
		Email: "test@example.com", OrderID: "123", Direction: "long", CurrentStop: 100, HighWaterMark: 110,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "trail_amount or trail_pct")

	// Zero current stop
	_, err = m.Add(&TrailingStop{
		Email: "test@example.com", OrderID: "123", Direction: "long", TrailAmount: 10, HighWaterMark: 110,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "current_stop")
}

func TestTrailingStopCancel(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager(t)

	ts := &TrailingStop{
		Email: "test@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "123", TrailAmount: 20,
		Direction: "long", HighWaterMark: 1500, CurrentStop: 1480,
	}
	id, err := m.Add(ts)
	require.NoError(t, err)

	// Cancel
	err = m.Cancel("test@example.com", id)
	require.NoError(t, err)

	// Cancel again should fail
	err = m.Cancel("test@example.com", id)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already inactive")

	// Wrong user
	err = m.Cancel("other@example.com", id)
	assert.Error(t, err)
}

func TestTrailingStopEvaluateLong(t *testing.T) {
	t.Parallel()
	m, mock := newTestManager(t)

	ts := &TrailingStop{
		Email: "test@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "SL001", TrailAmount: 20,
		Direction: "long", HighWaterMark: 1500, CurrentStop: 1480,
	}
	_, err := m.Add(ts)
	require.NoError(t, err)

	// Price rises above HWM -> stop should move up
	tick := models.Tick{InstrumentToken: 408065, LastPrice: 1540}
	m.Evaluate("test@example.com", tick)

	// Expected new stop: 1540 - 20 = 1520 (which is > 1480)
	require.Len(t, mock.calls, 1)
	assert.Equal(t, "SL001", mock.calls[0].orderID)
	assert.InDelta(t, 1520, mock.calls[0].trigger, 0.01)

	// Verify state updated
	stops := m.List("test@example.com")
	require.Len(t, stops, 1)
	assert.InDelta(t, 1540, stops[0].HighWaterMark, 0.01)
	assert.InDelta(t, 1520, stops[0].CurrentStop, 0.01)
	assert.Equal(t, 1, stops[0].ModifyCount)
}

func TestTrailingStopEvaluateLongPct(t *testing.T) {
	t.Parallel()
	m, mock := newTestManager(t)

	ts := &TrailingStop{
		Email: "test@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "SL002", TrailPct: 2.0,
		Direction: "long", HighWaterMark: 1000, CurrentStop: 980,
	}
	_, err := m.Add(ts)
	require.NoError(t, err)

	// Price rises to 1100 -> new stop = 1100 * 0.98 = 1078 (> 980)
	tick := models.Tick{InstrumentToken: 408065, LastPrice: 1100}
	m.Evaluate("test@example.com", tick)

	require.Len(t, mock.calls, 1)
	assert.InDelta(t, 1078, mock.calls[0].trigger, 0.01)
}

func TestTrailingStopEvaluateNoMoveDown(t *testing.T) {
	t.Parallel()
	m, mock := newTestManager(t)

	ts := &TrailingStop{
		Email: "test@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "SL003", TrailAmount: 20,
		Direction: "long", HighWaterMark: 1500, CurrentStop: 1480,
	}
	_, err := m.Add(ts)
	require.NoError(t, err)

	// Price drops -> no modification (stop never moves down for long)
	tick := models.Tick{InstrumentToken: 408065, LastPrice: 1400}
	m.Evaluate("test@example.com", tick)

	assert.Len(t, mock.calls, 0)
}

func TestTrailingStopRateLimit(t *testing.T) {
	t.Parallel()
	m, mock := newTestManager(t)

	ts := &TrailingStop{
		Email: "test@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "SL004", TrailAmount: 10,
		Direction: "long", HighWaterMark: 100, CurrentStop: 90,
	}
	_, err := m.Add(ts)
	require.NoError(t, err)

	// First tick: price rises -> modify
	tick := models.Tick{InstrumentToken: 408065, LastPrice: 120}
	m.Evaluate("test@example.com", tick)
	require.Len(t, mock.calls, 1)

	// Second tick immediately after: should be rate limited (within 30s)
	tick.LastPrice = 130
	m.Evaluate("test@example.com", tick)
	assert.Len(t, mock.calls, 1) // still 1, rate limited
}

func TestTrailingStopEvaluateShort(t *testing.T) {
	t.Parallel()
	m, mock := newTestManager(t)

	ts := &TrailingStop{
		Email: "test@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "SL005", TrailAmount: 15,
		Direction: "short", HighWaterMark: 1000, CurrentStop: 1015,
	}
	_, err := m.Add(ts)
	require.NoError(t, err)

	// Price drops below HWM -> stop should move down
	tick := models.Tick{InstrumentToken: 408065, LastPrice: 950}
	m.Evaluate("test@example.com", tick)

	// Expected new stop: 950 + 15 = 965 (which is < 1015)
	require.Len(t, mock.calls, 1)
	assert.InDelta(t, 965, mock.calls[0].trigger, 0.01)
}

func TestTrailingStopDBPersistence(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	logger := slog.Default()
	m := NewTrailingStopManager(logger)
	m.SetDB(db)

	ts := &TrailingStop{
		Email: "test@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "DB001", TrailAmount: 20,
		Direction: "long", HighWaterMark: 1500, CurrentStop: 1480,
	}
	id, err := m.Add(ts)
	require.NoError(t, err)

	// Load from DB into a new manager
	m2 := NewTrailingStopManager(logger)
	m2.SetDB(db)
	err = m2.LoadFromDB()
	require.NoError(t, err)

	stops := m2.List("test@example.com")
	require.Len(t, stops, 1)
	assert.Equal(t, id, stops[0].ID)
	assert.Equal(t, "DB001", stops[0].OrderID)
	assert.True(t, stops[0].Active)

	// Cancel and verify persistence
	err = m.Cancel("test@example.com", id)
	require.NoError(t, err)

	m3 := NewTrailingStopManager(logger)
	m3.SetDB(db)
	err = m3.LoadFromDB()
	require.NoError(t, err)

	// LoadFromDB only loads active stops
	stops = m3.List("test@example.com")
	assert.Len(t, stops, 0)
}

// --- ES: TrailingStopTriggeredEvent dispatch ---

// TestTrailingStopEvaluate_DispatchesTriggeredEvent verifies that on a
// successful trailing-stop trigger (HWM rises, SL order modified
// successfully via Kite API), the manager dispatches a typed
// domain.TrailingStopTriggeredEvent capturing the full transition
// (oldStop -> newStop, HWM, ModifyCount) and the underlying SL OrderID.
func TestTrailingStopEvaluate_DispatchesTriggeredEvent(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager(t)

	dispatcher := domain.NewEventDispatcher()
	var captured []domain.TrailingStopTriggeredEvent
	dispatcher.Subscribe("trailing_stop.triggered", func(e domain.Event) {
		captured = append(captured, e.(domain.TrailingStopTriggeredEvent))
	})
	m.SetEventDispatcher(dispatcher)

	ts := &TrailingStop{
		Email: "trader@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "SL-TS1", TrailAmount: 20,
		Direction: "long", HighWaterMark: 1500, CurrentStop: 1480,
	}
	id, err := m.Add(ts)
	require.NoError(t, err)

	// Tick raises HWM from 1500 -> 1540, stop 1480 -> 1520.
	tick := models.Tick{InstrumentToken: 408065, LastPrice: 1540}
	m.Evaluate("trader@example.com", tick)

	require.Len(t, captured, 1, "TrailingStopTriggeredEvent must fire on successful trail")
	got := captured[0]
	assert.Equal(t, "trader@example.com", got.Email)
	assert.Equal(t, id, got.TrailingStopID)
	assert.Equal(t, "SL-TS1", got.OrderID)
	assert.Equal(t, "NSE", got.Instrument.Exchange)
	assert.Equal(t, "INFY", got.Instrument.Tradingsymbol)
	assert.Equal(t, "long", got.Direction)
	assert.InDelta(t, 1480, got.OldStop, 0.01)
	assert.InDelta(t, 1520, got.NewStop, 0.01)
	assert.InDelta(t, 1540, got.HighWaterMark, 0.01)
	assert.Equal(t, 1, got.ModifyCount)
	assert.False(t, got.Timestamp.IsZero())
}

// TestTrailingStopEvaluate_NoTriggerNoEvent verifies the silent path:
// when a tick doesn't move the trailing stop (price drops on a long,
// or price within HWM band), no event fires. The audit stream must
// reflect actual state transitions, not no-op evaluations.
func TestTrailingStopEvaluate_NoTriggerNoEvent(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager(t)

	dispatcher := domain.NewEventDispatcher()
	var captured []domain.TrailingStopTriggeredEvent
	dispatcher.Subscribe("trailing_stop.triggered", func(e domain.Event) {
		captured = append(captured, e.(domain.TrailingStopTriggeredEvent))
	})
	m.SetEventDispatcher(dispatcher)

	ts := &TrailingStop{
		Email: "trader@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "SL-TS2", TrailAmount: 20,
		Direction: "long", HighWaterMark: 1500, CurrentStop: 1480,
	}
	_, err := m.Add(ts)
	require.NoError(t, err)

	// Tick price drops — long direction, no trigger.
	m.Evaluate("trader@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 1400})

	assert.Len(t, captured, 0, "no event should fire when stop doesn't move")
}

// TestTrailingStopEvaluate_BrokerErrorNoEvent verifies that if the
// underlying ModifyOrder Kite call fails, no TrailingStopTriggeredEvent
// fires — the trailing stop's logical state was reverted (or the
// modification was a logical no-op since broker rejected). Future
// follow-up: a TrailingStopRejectedEvent could close that loop.
func TestTrailingStopEvaluate_BrokerErrorNoEvent(t *testing.T) {
	t.Parallel()
	logger := slog.Default()
	m := NewTrailingStopManager(logger)

	mock := &mockModifier{returnErr: assertError("kite_api_fail")}
	m.SetModifier(func(email string) (KiteOrderModifier, error) { return mock, nil })

	dispatcher := domain.NewEventDispatcher()
	var captured []domain.TrailingStopTriggeredEvent
	dispatcher.Subscribe("trailing_stop.triggered", func(e domain.Event) {
		captured = append(captured, e.(domain.TrailingStopTriggeredEvent))
	})
	m.SetEventDispatcher(dispatcher)

	ts := &TrailingStop{
		Email: "trader@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "SL-TS3", TrailAmount: 20,
		Direction: "long", HighWaterMark: 1500, CurrentStop: 1480,
	}
	_, err := m.Add(ts)
	require.NoError(t, err)

	m.Evaluate("trader@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 1540})

	assert.Len(t, captured, 0, "no event should fire when broker rejects modify")
}

// TestTrailingStopEvaluate_NilDispatcherSafe verifies the nil-dispatcher
// path: a successful trigger without a wired dispatcher must not panic
// on a nil Dispatch call.
func TestTrailingStopEvaluate_NilDispatcherSafe(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager(t)
	// Deliberately no SetEventDispatcher.

	ts := &TrailingStop{
		Email: "trader@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "SL-TS4", TrailAmount: 20,
		Direction: "long", HighWaterMark: 1500, CurrentStop: 1480,
	}
	_, err := m.Add(ts)
	require.NoError(t, err)

	// Should not panic.
	m.Evaluate("trader@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 1540})
}

// assertError is a tiny error sentinel for the test mock — keeps the
// test file self-contained without pulling in errors just for one line.
type assertError string

func (a assertError) Error() string { return string(a) }

func TestTrailingStopMaxPerUser(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager(t)

	// Add 20 trailing stops (the maximum)
	for i := 0; i < 20; i++ {
		ts := &TrailingStop{
			Email: "test@example.com", Exchange: "NSE",
			Tradingsymbol:   "INFY",
			InstrumentToken: 408065,
			OrderID:         "ORD" + time.Now().Format("150405") + string(rune('A'+i)),
			TrailAmount:     10,
			Direction:       "long",
			HighWaterMark:   1000,
			CurrentStop:     990,
		}
		_, err := m.Add(ts)
		require.NoError(t, err)
	}

	// 21st should fail
	_, err := m.Add(&TrailingStop{
		Email: "test@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "TOOMANY", TrailAmount: 10,
		Direction: "long", HighWaterMark: 1000, CurrentStop: 990,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "maximum")
}
