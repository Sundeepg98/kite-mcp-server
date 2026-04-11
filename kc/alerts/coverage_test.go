package alerts

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/gokiteconnect/v4/models"
)

// ===========================================================================
// Evaluator — evaluate triggers for all 4 directions
// ===========================================================================

func TestEvaluator_Above(t *testing.T) {
	t.Parallel()
	var notified []*Alert
	s := NewStore(func(a *Alert, price float64) {
		notified = append(notified, a)
	})

	s.Add("user@example.com", "INFY", "NSE", 408065, 1600.0, DirectionAbove)
	eval := NewEvaluator(s, defaultTestLogger())

	// Price below target: no trigger
	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 1500})
	assert.Empty(t, notified)

	// Price at target: trigger
	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 1600})
	assert.Len(t, notified, 1)
}

func TestEvaluator_Below(t *testing.T) {
	t.Parallel()
	var notified []*Alert
	s := NewStore(func(a *Alert, price float64) {
		notified = append(notified, a)
	})

	s.Add("user@example.com", "INFY", "NSE", 408065, 1400.0, DirectionBelow)
	eval := NewEvaluator(s, defaultTestLogger())

	// Price above target: no trigger
	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 1500})
	assert.Empty(t, notified)

	// Price at target: trigger
	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 1400})
	assert.Len(t, notified, 1)
}

func TestEvaluator_DropPct(t *testing.T) {
	t.Parallel()
	var notified []*Alert
	s := NewStore(func(a *Alert, price float64) {
		notified = append(notified, a)
	})

	// Alert: trigger when price drops 5% from reference 1000
	s.AddWithReferencePrice("user@example.com", "INFY", "NSE", 408065, 5.0, DirectionDropPct, 1000.0)
	eval := NewEvaluator(s, defaultTestLogger())

	// 3% drop: no trigger
	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 970})
	assert.Empty(t, notified)

	// 5% drop (price 950): trigger
	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 950})
	assert.Len(t, notified, 1)
}

func TestEvaluator_RisePct(t *testing.T) {
	t.Parallel()
	var notified []*Alert
	s := NewStore(func(a *Alert, price float64) {
		notified = append(notified, a)
	})

	// Alert: trigger when price rises 10% from reference 1000
	s.AddWithReferencePrice("user@example.com", "INFY", "NSE", 408065, 10.0, DirectionRisePct, 1000.0)
	eval := NewEvaluator(s, defaultTestLogger())

	// 5% rise: no trigger
	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 1050})
	assert.Empty(t, notified)

	// 10% rise (price 1100): trigger
	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 1100})
	assert.Len(t, notified, 1)
}

func TestEvaluator_DropPct_ZeroReference(t *testing.T) {
	t.Parallel()
	var notified []*Alert
	s := NewStore(func(a *Alert, price float64) {
		notified = append(notified, a)
	})

	// Reference price 0 -> should never trigger
	s.AddWithReferencePrice("user@example.com", "INFY", "NSE", 408065, 5.0, DirectionDropPct, 0)
	eval := NewEvaluator(s, defaultTestLogger())

	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 0})
	assert.Empty(t, notified)
}

func TestEvaluator_NoAlerts(t *testing.T) {
	t.Parallel()
	s := NewStore(nil)
	eval := NewEvaluator(s, defaultTestLogger())

	// Should not panic
	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 999999, LastPrice: 100})
}

func TestShouldTrigger_InvalidDirection_Coverage(t *testing.T) {
	t.Parallel()
	a := &Alert{Direction: Direction("unknown"), TargetPrice: 100}
	assert.False(t, shouldTrigger(a, 100))
}

// ===========================================================================
// TrailingStop — CancelByEmail
// ===========================================================================

func TestTrailingStopCancelByEmail(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager(t)

	// Add 2 trailing stops for user1
	for i := 0; i < 2; i++ {
		ts := &TrailingStop{
			Email: "user1@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
			InstrumentToken: 408065, OrderID: "ORD" + string(rune('A'+i)),
			TrailAmount: 20, Direction: "long", HighWaterMark: 1500, CurrentStop: 1480,
		}
		_, err := m.Add(ts)
		require.NoError(t, err)
	}

	// Add 1 for user2
	ts := &TrailingStop{
		Email: "user2@example.com", Exchange: "NSE", Tradingsymbol: "TCS",
		InstrumentToken: 408066, OrderID: "ORDX",
		TrailAmount: 10, Direction: "long", HighWaterMark: 4000, CurrentStop: 3990,
	}
	_, err := m.Add(ts)
	require.NoError(t, err)

	// Cancel all for user1
	m.CancelByEmail("user1@example.com")

	// user1 should have 2 inactive stops
	stops1 := m.List("user1@example.com")
	assert.Len(t, stops1, 2)
	for _, s := range stops1 {
		assert.False(t, s.Active)
	}

	// user2 should be unaffected
	stops2 := m.List("user2@example.com")
	assert.Len(t, stops2, 1)
	assert.True(t, stops2[0].Active)
}

func TestTrailingStopCancelByEmail_NoStops(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager(t)
	// Should not panic
	m.CancelByEmail("nobody@example.com")
}

// ===========================================================================
// TrailingStop — Evaluate short direction with percentage trail
// ===========================================================================

func TestTrailingStopEvaluateShortPct(t *testing.T) {
	t.Parallel()
	m, mock := newTestManager(t)

	ts := &TrailingStop{
		Email: "test@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "SL006", TrailPct: 2.0,
		Direction: "short", HighWaterMark: 1000, CurrentStop: 1020,
	}
	_, err := m.Add(ts)
	require.NoError(t, err)

	// Price drops to 900 -> new stop = 900 * 1.02 = 918 (< 1020)
	tick := models.Tick{InstrumentToken: 408065, LastPrice: 900}
	m.Evaluate("test@example.com", tick)

	require.Len(t, mock.calls, 1)
	assert.InDelta(t, 918, mock.calls[0].trigger, 0.01)
}

// ===========================================================================
// TrailingStop — Evaluate with no modifier
// ===========================================================================

func TestTrailingStopEvaluateNoModifier(t *testing.T) {
	t.Parallel()
	logger := slog.Default()
	m := NewTrailingStopManager(logger)
	// No modifier set

	ts := &TrailingStop{
		Email: "test@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "SL007", TrailAmount: 20,
		Direction: "long", HighWaterMark: 1500, CurrentStop: 1480,
	}
	_, err := m.Add(ts)
	require.NoError(t, err)

	// Price rises -> should attempt modify but no modifier set (logged warning)
	tick := models.Tick{InstrumentToken: 408065, LastPrice: 1540}
	m.Evaluate("test@example.com", tick)

	// No panic, state should still update
	stops := m.List("test@example.com")
	require.Len(t, stops, 1)
	assert.InDelta(t, 1540, stops[0].HighWaterMark, 0.01)
}

// ===========================================================================
// TrailingStop — Evaluate with onModify callback
// ===========================================================================

func TestTrailingStopEvaluateWithOnModify(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager(t)

	var callbackCalled bool
	var callbackOldStop, callbackNewStop float64
	m.SetOnModify(func(ts *TrailingStop, oldStop, newStop float64) {
		callbackCalled = true
		callbackOldStop = oldStop
		callbackNewStop = newStop
	})

	ts := &TrailingStop{
		Email: "test@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "SL008", TrailAmount: 20,
		Direction: "long", HighWaterMark: 1500, CurrentStop: 1480,
	}
	_, err := m.Add(ts)
	require.NoError(t, err)

	tick := models.Tick{InstrumentToken: 408065, LastPrice: 1540}
	m.Evaluate("test@example.com", tick)

	assert.True(t, callbackCalled)
	assert.InDelta(t, 1480, callbackOldStop, 0.01)
	assert.InDelta(t, 1520, callbackNewStop, 0.01)
}

// ===========================================================================
// TrailingStop — Evaluate with modifier error
// ===========================================================================

func TestTrailingStopEvaluateModifierError(t *testing.T) {
	t.Parallel()
	logger := slog.Default()
	m := NewTrailingStopManager(logger)

	mock := &mockModifier{returnErr: assert.AnError}
	m.SetModifier(func(email string) (KiteOrderModifier, error) {
		return mock, nil
	})

	ts := &TrailingStop{
		Email: "test@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "SL009", TrailAmount: 20,
		Direction: "long", HighWaterMark: 1500, CurrentStop: 1480,
	}
	_, err := m.Add(ts)
	require.NoError(t, err)

	// Should not panic even when modifier returns error
	tick := models.Tick{InstrumentToken: 408065, LastPrice: 1540}
	m.Evaluate("test@example.com", tick)
}

// ===========================================================================
// TrailingStop — Evaluate with getModifier returning error
// ===========================================================================

func TestTrailingStopEvaluateGetModifierError(t *testing.T) {
	t.Parallel()
	logger := slog.Default()
	m := NewTrailingStopManager(logger)

	m.SetModifier(func(email string) (KiteOrderModifier, error) {
		return nil, assert.AnError
	})

	ts := &TrailingStop{
		Email: "test@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "SL010", TrailAmount: 20,
		Direction: "long", HighWaterMark: 1500, CurrentStop: 1480,
	}
	_, err := m.Add(ts)
	require.NoError(t, err)

	// Should not panic
	tick := models.Tick{InstrumentToken: 408065, LastPrice: 1540}
	m.Evaluate("test@example.com", tick)
}

// ===========================================================================
// TrailingStop — Evaluate for wrong email (no match)
// ===========================================================================

func TestTrailingStopEvaluateWrongEmail(t *testing.T) {
	t.Parallel()
	m, mock := newTestManager(t)

	ts := &TrailingStop{
		Email: "user1@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "SL011", TrailAmount: 20,
		Direction: "long", HighWaterMark: 1500, CurrentStop: 1480,
	}
	_, err := m.Add(ts)
	require.NoError(t, err)

	// Evaluate with different email: should not modify
	tick := models.Tick{InstrumentToken: 408065, LastPrice: 1540}
	m.Evaluate("user2@example.com", tick)
	assert.Empty(t, mock.calls)
}

// ===========================================================================
// TrailingStop — Evaluate with no matching token
// ===========================================================================

func TestTrailingStopEvaluateNoMatchingToken(t *testing.T) {
	t.Parallel()
	m, mock := newTestManager(t)

	ts := &TrailingStop{
		Email: "test@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "SL012", TrailAmount: 20,
		Direction: "long", HighWaterMark: 1500, CurrentStop: 1480,
	}
	_, err := m.Add(ts)
	require.NoError(t, err)

	// Evaluate with different token
	tick := models.Tick{InstrumentToken: 999999, LastPrice: 9999}
	m.Evaluate("test@example.com", tick)
	assert.Empty(t, mock.calls)
}

// ===========================================================================
// TrailingStop — Long direction: HWM update without stop move
// ===========================================================================

func TestTrailingStopEvaluateLong_HWMUpdateNoStopMove(t *testing.T) {
	t.Parallel()
	m, mock := newTestManager(t)

	// Set up with a very large trail so that new stop won't exceed current stop
	ts := &TrailingStop{
		Email: "test@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "SL013", TrailAmount: 100,
		Direction: "long", HighWaterMark: 1500, CurrentStop: 1480,
	}
	_, err := m.Add(ts)
	require.NoError(t, err)

	// Price rises to 1510 -> new stop = 1510 - 100 = 1410 which is < 1480 (current stop)
	// So HWM should update but stop should NOT move
	tick := models.Tick{InstrumentToken: 408065, LastPrice: 1510}
	m.Evaluate("test@example.com", tick)

	// No API call
	assert.Empty(t, mock.calls)

	// But HWM should be updated
	stops := m.List("test@example.com")
	assert.InDelta(t, 1510, stops[0].HighWaterMark, 0.01)
	// Stop should remain unchanged
	assert.InDelta(t, 1480, stops[0].CurrentStop, 0.01)
}

// ===========================================================================
// Store — AddWithReferencePrice
// ===========================================================================

func TestStore_AddWithReferencePrice_Coverage(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	id, err := s.AddWithReferencePrice("user@example.com", "RELIANCE", "NSE", 738561, 5.0, DirectionDropPct, 2500.0)
	require.NoError(t, err)
	assert.NotEmpty(t, id)

	alerts := s.List("user@example.com")
	require.Len(t, alerts, 1)
	assert.Equal(t, DirectionDropPct, alerts[0].Direction)
	assert.Equal(t, 2500.0, alerts[0].ReferencePrice)
	assert.Equal(t, 5.0, alerts[0].TargetPrice)
}

// ===========================================================================
// TelegramNotifier — Store/Logger accessors
// ===========================================================================

func TestTelegramNotifier_Accessors(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	logger := defaultTestLogger()

	// Non-nil notifier with nil bot — test Store() and Logger() accessors
	tn := &TelegramNotifier{store: s, logger: logger}
	assert.Equal(t, s, tn.Store())
	assert.Equal(t, logger, tn.Logger())
}

// ===========================================================================
// PnL Journal
// ===========================================================================

func TestPnLJournal_EmptyRange(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	svc := NewPnLSnapshotService(db, nil, nil, defaultTestLogger())
	require.NotNil(t, svc)

	result, err := svc.GetJournal("user@example.com", "2026-01-01", "2026-01-31")
	require.NoError(t, err)
	assert.Equal(t, 0, result.TotalDays)
	assert.Empty(t, result.Entries)
}

func TestPnLJournal_WithEntries(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	svc := NewPnLSnapshotService(db, nil, nil, defaultTestLogger())
	require.NotNil(t, svc)

	// Insert sample data
	entries := []*DailyPnLEntry{
		{Date: "2026-01-01", Email: "user@example.com", HoldingsPnL: 1000, PositionsPnL: 500, NetPnL: 1500, HoldingsCount: 5, TradesCount: 3},
		{Date: "2026-01-02", Email: "user@example.com", HoldingsPnL: -800, PositionsPnL: 200, NetPnL: -600, HoldingsCount: 5, TradesCount: 2},
		{Date: "2026-01-03", Email: "user@example.com", HoldingsPnL: 2000, PositionsPnL: -100, NetPnL: 1900, HoldingsCount: 5, TradesCount: 4},
	}
	for _, e := range entries {
		require.NoError(t, db.SaveDailyPnL(e))
	}

	result, err := svc.GetJournal("user@example.com", "2026-01-01", "2026-01-03")
	require.NoError(t, err)
	assert.Equal(t, 3, result.TotalDays)
	assert.Equal(t, 2, result.WinDays)
	assert.Equal(t, 1, result.LossDays)
	assert.InDelta(t, 2800, result.CumulativePnL, 0.01) // 1500 - 600 + 1900
	assert.NotNil(t, result.BestDay)
	assert.Equal(t, "2026-01-03", result.BestDay.Date)
	assert.NotNil(t, result.WorstDay)
	assert.Equal(t, "2026-01-02", result.WorstDay.Date)
	assert.InDelta(t, 2800.0/3.0, result.AvgDailyPnL, 0.01)
}

// ===========================================================================
// IsPercentageDirection
// ===========================================================================

func TestIsPercentageDirection_Coverage(t *testing.T) {
	t.Parallel()
	assert.True(t, IsPercentageDirection(DirectionDropPct))
	assert.True(t, IsPercentageDirection(DirectionRisePct))
	assert.False(t, IsPercentageDirection(DirectionAbove))
	assert.False(t, IsPercentageDirection(DirectionBelow))
}

// ===========================================================================
// Store — DB persistence tests
// ===========================================================================

func TestStore_DBPersistence_AddAndLoad(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	s := NewStore(nil)
	s.SetDB(db)
	s.SetLogger(defaultTestLogger())

	// Add alert
	id, err := s.Add("user@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)
	require.NoError(t, err)
	assert.NotEmpty(t, id)

	// Load into a new store
	s2 := NewStore(nil)
	s2.SetDB(db)
	s2.SetLogger(defaultTestLogger())
	err = s2.LoadFromDB()
	require.NoError(t, err)

	alerts := s2.List("user@example.com")
	require.Len(t, alerts, 1)
	assert.Equal(t, id, alerts[0].ID)
	assert.Equal(t, "RELIANCE", alerts[0].Tradingsymbol)
	assert.Equal(t, 2500.0, alerts[0].TargetPrice)
}

func TestStore_DBPersistence_Delete(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	s := NewStore(nil)
	s.SetDB(db)
	s.SetLogger(defaultTestLogger())

	id, err := s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionBelow)
	require.NoError(t, err)

	err = s.Delete("user@example.com", id)
	require.NoError(t, err)

	// Load into a new store — should be empty
	s2 := NewStore(nil)
	s2.SetDB(db)
	s2.SetLogger(defaultTestLogger())
	err = s2.LoadFromDB()
	require.NoError(t, err)
	assert.Empty(t, s2.List("user@example.com"))
}

func TestStore_DBPersistence_MarkTriggered(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	s := NewStore(nil)
	s.SetDB(db)
	s.SetLogger(defaultTestLogger())

	id, err := s.Add("user@example.com", "TCS", "NSE", 2953217, 4000.0, DirectionAbove)
	require.NoError(t, err)

	ok := s.MarkTriggered(id, 4100.0)
	assert.True(t, ok)

	// Load into a new store
	s2 := NewStore(nil)
	s2.SetDB(db)
	s2.SetLogger(defaultTestLogger())
	err = s2.LoadFromDB()
	require.NoError(t, err)

	alerts := s2.List("user@example.com")
	require.Len(t, alerts, 1)
	assert.True(t, alerts[0].Triggered)
	assert.Equal(t, 4100.0, alerts[0].TriggeredPrice)
}

func TestStore_DBPersistence_TelegramChatID(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	s := NewStore(nil)
	s.SetDB(db)
	s.SetLogger(defaultTestLogger())

	s.SetTelegramChatID("user@example.com", 123456789)

	// Load into a new store
	s2 := NewStore(nil)
	s2.SetDB(db)
	s2.SetLogger(defaultTestLogger())
	err := s2.LoadFromDB()
	require.NoError(t, err)

	chatID, ok := s2.GetTelegramChatID("user@example.com")
	assert.True(t, ok)
	assert.Equal(t, int64(123456789), chatID)
}

func TestStore_DBPersistence_DeleteByEmail(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	s := NewStore(nil)
	s.SetDB(db)
	s.SetLogger(defaultTestLogger())

	s.Add("user@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)
	s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionBelow)
	s.SetTelegramChatID("user@example.com", 123456789)

	s.DeleteByEmail("user@example.com")

	// Load into a new store
	s2 := NewStore(nil)
	s2.SetDB(db)
	s2.SetLogger(defaultTestLogger())
	err := s2.LoadFromDB()
	require.NoError(t, err)

	assert.Empty(t, s2.List("user@example.com"))
	_, ok := s2.GetTelegramChatID("user@example.com")
	assert.False(t, ok)
}

func TestStore_DBPersistence_MarkNotificationSent(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	s := NewStore(nil)
	s.SetDB(db)
	s.SetLogger(defaultTestLogger())

	id, err := s.Add("user@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)
	require.NoError(t, err)

	now := time.Now().Truncate(time.Second)
	s.MarkNotificationSent(id, now)

	// Load into new store
	s2 := NewStore(nil)
	s2.SetDB(db)
	s2.SetLogger(defaultTestLogger())
	err = s2.LoadFromDB()
	require.NoError(t, err)

	alerts := s2.List("user@example.com")
	require.Len(t, alerts, 1)
	assert.Equal(t, now.Unix(), alerts[0].NotificationSentAt.Unix())
}

func TestStore_DBPersistence_AddWithReferencePrice(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	s := NewStore(nil)
	s.SetDB(db)
	s.SetLogger(defaultTestLogger())

	id, err := s.AddWithReferencePrice("user@example.com", "INFY", "NSE", 408065, 5.0, DirectionDropPct, 1800.0)
	require.NoError(t, err)

	// Load
	s2 := NewStore(nil)
	s2.SetDB(db)
	s2.SetLogger(defaultTestLogger())
	err = s2.LoadFromDB()
	require.NoError(t, err)

	alerts := s2.List("user@example.com")
	require.Len(t, alerts, 1)
	assert.Equal(t, id, alerts[0].ID)
	assert.Equal(t, DirectionDropPct, alerts[0].Direction)
	assert.Equal(t, 1800.0, alerts[0].ReferencePrice)
}

// ===========================================================================
// TrailingStop — Evaluate trailing stop with DB persistence
// ===========================================================================

func TestTrailingStopEvaluateWithDB(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	logger := defaultTestLogger()
	m := NewTrailingStopManager(logger)
	m.SetDB(db)

	mock := &mockModifier{}
	m.SetModifier(func(email string) (KiteOrderModifier, error) {
		return mock, nil
	})

	ts := &TrailingStop{
		Email: "test@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "SLDB01", TrailAmount: 20,
		Direction: "long", HighWaterMark: 1500, CurrentStop: 1480,
	}
	id, err := m.Add(ts)
	require.NoError(t, err)

	// Price rises -> modify + persist
	tick := models.Tick{InstrumentToken: 408065, LastPrice: 1540}
	m.Evaluate("test@example.com", tick)

	// Load from DB and verify state
	m2 := NewTrailingStopManager(logger)
	m2.SetDB(db)
	err = m2.LoadFromDB()
	require.NoError(t, err)

	stops := m2.List("test@example.com")
	require.Len(t, stops, 1)
	assert.Equal(t, id, stops[0].ID)
	assert.InDelta(t, 1540, stops[0].HighWaterMark, 0.01)
	assert.InDelta(t, 1520, stops[0].CurrentStop, 0.01)
	assert.Equal(t, 1, stops[0].ModifyCount)
}

// ===========================================================================
// DB — Registry CRUD
// ===========================================================================

func TestDB_RegistryCRUD_Extended(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	now := time.Now().Truncate(time.Second)
	lastUsed := now.Add(-1 * time.Hour)

	entry := &RegistryDBEntry{
		ID:           "reg-001",
		APIKey:       "test-api-key",
		APISecret:    "test-api-secret",
		AssignedTo:   "user@example.com",
		Label:        "Test App",
		Status:       "active",
		RegisteredBy: "admin@example.com",
		Source:       "manual",
		LastUsedAt:   &lastUsed,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	// Save
	err := db.SaveRegistryEntry(entry)
	require.NoError(t, err)

	// Load
	entries, err := db.LoadRegistryEntries()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "reg-001", entries["reg-001"].ID)
	assert.Equal(t, "test-api-key", entries["reg-001"].APIKey)
	assert.Equal(t, "user@example.com", entries["reg-001"].AssignedTo)
	assert.NotNil(t, entries["reg-001"].LastUsedAt)

	// Save without LastUsedAt
	entry2 := &RegistryDBEntry{
		ID:           "reg-002",
		APIKey:       "key2",
		APISecret:    "secret2",
		AssignedTo:   "user2@example.com",
		Label:        "App 2",
		Status:       "active",
		RegisteredBy: "admin@example.com",
		Source:       "api",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	err = db.SaveRegistryEntry(entry2)
	require.NoError(t, err)

	entries, err = db.LoadRegistryEntries()
	require.NoError(t, err)
	assert.Len(t, entries, 2)

	// Delete
	err = db.DeleteRegistryEntry("reg-001")
	require.NoError(t, err)

	entries, err = db.LoadRegistryEntries()
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}

// ===========================================================================
// DB — Config get/set
// ===========================================================================

func TestDB_Config(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	// Get nonexistent — returns error (sql.ErrNoRows)
	val, err := db.GetConfig("nonexistent")
	assert.Error(t, err)
	assert.Empty(t, val)

	// Set
	err = db.SetConfig("test_key", "test_value")
	require.NoError(t, err)

	// Get
	val, err = db.GetConfig("test_key")
	require.NoError(t, err)
	assert.Equal(t, "test_value", val)

	// Overwrite
	err = db.SetConfig("test_key", "new_value")
	require.NoError(t, err)

	val, err = db.GetConfig("test_key")
	require.NoError(t, err)
	assert.Equal(t, "new_value", val)
}

// ===========================================================================
// DB — Session CRUD
// ===========================================================================

func TestDB_SessionCRUD(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	now := time.Now().Truncate(time.Second)
	expires := now.Add(24 * time.Hour)

	// Save
	err := db.SaveSession("sess-001", "user@example.com", now, expires, false)
	require.NoError(t, err)

	// Load
	sessions, err := db.LoadSessions()
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, "user@example.com", sessions[0].Email)

	// Delete
	err = db.DeleteSession("sess-001")
	require.NoError(t, err)

	sessions, err = db.LoadSessions()
	require.NoError(t, err)
	assert.Empty(t, sessions)
}

// ===========================================================================
// DB — Token CRUD
// ===========================================================================

func TestDB_TokenCRUD(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	now := time.Now().Truncate(time.Second)

	// Save
	err := db.SaveToken("user@example.com", "token_abc", "UID01", "Alice", now)
	require.NoError(t, err)

	// Load
	tokens, err := db.LoadTokens()
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.Equal(t, "token_abc", tokens[0].AccessToken)

	// Delete
	err = db.DeleteToken("user@example.com")
	require.NoError(t, err)

	tokens, err = db.LoadTokens()
	require.NoError(t, err)
	assert.Empty(t, tokens)
}

// ===========================================================================
// DB — Client CRUD
// ===========================================================================

func TestDB_ClientCRUD(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	now := time.Now().Truncate(time.Second)

	// Save
	err := db.SaveClient("client-001", "secret-001", `["https://example.com/cb"]`, "Test App", now, true)
	require.NoError(t, err)

	// Load
	clients, err := db.LoadClients()
	require.NoError(t, err)
	require.Len(t, clients, 1)
	assert.Equal(t, "client-001", clients[0].ClientID)
	assert.Equal(t, "Test App", clients[0].ClientName)
	assert.True(t, clients[0].IsKiteAPIKey)

	// Delete
	err = db.DeleteClient("client-001")
	require.NoError(t, err)

	clients, err = db.LoadClients()
	require.NoError(t, err)
	assert.Empty(t, clients)
}

// ===========================================================================
// DB — Credential CRUD
// ===========================================================================

func TestDB_CredentialCRUD(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	now := time.Now().Truncate(time.Second)

	// Save
	err := db.SaveCredential("user@example.com", "key_abc", "secret_xyz", "key_abc", now)
	require.NoError(t, err)

	// Load
	creds, err := db.LoadCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "key_abc", creds[0].APIKey)

	// Delete
	err = db.DeleteCredential("user@example.com")
	require.NoError(t, err)

	creds, err = db.LoadCredentials()
	require.NoError(t, err)
	assert.Empty(t, creds)
}

// ===========================================================================
// TrailingStop — CancelByEmail with DB
// ===========================================================================

func TestTrailingStopCancelByEmailWithDB(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	logger := slog.Default()
	m := NewTrailingStopManager(logger)
	m.SetDB(db)

	ts := &TrailingStop{
		Email: "user@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "CDB01",
		TrailAmount: 20, Direction: "long", HighWaterMark: 1500, CurrentStop: 1480,
	}
	_, err := m.Add(ts)
	require.NoError(t, err)

	m.CancelByEmail("user@example.com")

	// Verify stops are deactivated
	stops := m.List("user@example.com")
	assert.Len(t, stops, 1)
	assert.False(t, stops[0].Active)

	// Load from DB into a new manager — should find no active stops
	m2 := NewTrailingStopManager(logger)
	m2.SetDB(db)
	err = m2.LoadFromDB()
	require.NoError(t, err)
	assert.Empty(t, m2.List("user@example.com"))
}
