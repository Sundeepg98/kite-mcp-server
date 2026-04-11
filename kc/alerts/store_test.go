package alerts


import (
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/gokiteconnect/v4/models"
)


// newTestStore creates a Store with no notify callback (suitable for most tests).
func newTestStore() *Store {
	return NewStore(nil)
}

func TestStore_AddAndList(t *testing.T) {
	s := newTestStore()

	id, err := s.Add("user@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)
	require.NoError(t, err)
	assert.NotEmpty(t, id)

	alerts := s.List("user@example.com")
	require.Len(t, alerts, 1)

	a := alerts[0]
	assert.Equal(t, id, a.ID)
	assert.Equal(t, "user@example.com", a.Email)
	assert.Equal(t, "RELIANCE", a.Tradingsymbol)
	assert.Equal(t, "NSE", a.Exchange)
	assert.Equal(t, uint32(738561), a.InstrumentToken)
	assert.Equal(t, 2500.0, a.TargetPrice)
	assert.Equal(t, DirectionAbove, a.Direction)
	assert.False(t, a.Triggered)
	assert.WithinDuration(t, time.Now(), a.CreatedAt, 2*time.Second)

	// Verify deep copy: mutating the returned alert must not affect the store.
	a.TargetPrice = 9999.0
	a.Tradingsymbol = "MUTATED"
	storeAlerts := s.List("user@example.com")
	assert.Equal(t, 2500.0, storeAlerts[0].TargetPrice)
	assert.Equal(t, "RELIANCE", storeAlerts[0].Tradingsymbol)
}

func TestStore_AddMaxAlerts(t *testing.T) {
	s := newTestStore()

	for i := 0; i < MaxAlertsPerUser; i++ {
		_, err := s.Add("user@example.com", fmt.Sprintf("SYM%d", i), "NSE", uint32(i+1), float64(i), DirectionAbove)
		require.NoError(t, err)
	}

	// The next add should fail.
	_, err := s.Add("user@example.com", "OVERFLOW", "NSE", 999, 100.0, DirectionAbove)
	require.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("%d", MaxAlertsPerUser))

	// Verify the count hasn't changed.
	assert.Len(t, s.List("user@example.com"), MaxAlertsPerUser)

	// A different user should still be able to add.
	_, err = s.Add("other@example.com", "INFY", "NSE", 1000, 50.0, DirectionBelow)
	require.NoError(t, err)
}

func TestStore_Delete(t *testing.T) {
	s := newTestStore()

	id, err := s.Add("user@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)
	require.NoError(t, err)

	// Delete existing alert succeeds.
	err = s.Delete("user@example.com", id)
	require.NoError(t, err)
	assert.Empty(t, s.List("user@example.com"))

	// Delete non-existent alert (user exists but alert ID doesn't) returns error.
	// First re-add so the user key still has entries, then try a bogus ID.
	id2, err := s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionBelow)
	require.NoError(t, err)
	err = s.Delete("user@example.com", "nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	// The valid alert should still be there.
	assert.Len(t, s.List("user@example.com"), 1)

	// Clean up.
	err = s.Delete("user@example.com", id2)
	require.NoError(t, err)

	// Delete from user with no alerts at all (key never existed).
	err = s.Delete("nobody@example.com", "abc")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no alerts found")
}

func TestStore_DeleteWrongUser(t *testing.T) {
	s := newTestStore()

	idA, err := s.Add("userA@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)
	require.NoError(t, err)

	_, err = s.Add("userB@example.com", "INFY", "NSE", 408065, 1500.0, DirectionBelow)
	require.NoError(t, err)

	// User B cannot delete User A's alert.
	err = s.Delete("userB@example.com", idA)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// User A's alert still exists.
	assert.Len(t, s.List("userA@example.com"), 1)
}

func TestStore_GetByToken(t *testing.T) {
	s := newTestStore()

	// Add alerts for different instruments and users.
	s.Add("user1@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)
	s.Add("user1@example.com", "INFY", "NSE", 408065, 1500.0, DirectionBelow)
	s.Add("user2@example.com", "RELIANCE", "NSE", 738561, 2600.0, DirectionBelow)

	// GetByToken should return all active alerts matching token, across users.
	matches := s.GetByToken(738561)
	assert.Len(t, matches, 2)

	// Non-matching token returns empty.
	assert.Empty(t, s.GetByToken(999999))

	// After marking one triggered, GetByToken should exclude it.
	s.MarkTriggered(matches[0].ID, 2550.0)
	matches = s.GetByToken(738561)
	assert.Len(t, matches, 1)
}

func TestStore_MarkTriggered(t *testing.T) {
	s := newTestStore()

	id, err := s.Add("user@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)
	require.NoError(t, err)

	// First mark returns true.
	ok := s.MarkTriggered(id, 2550.0)
	assert.True(t, ok)

	// Second mark returns false (idempotent).
	ok = s.MarkTriggered(id, 2560.0)
	assert.False(t, ok)

	// Non-existent alert returns false.
	ok = s.MarkTriggered("nonexistent", 100.0)
	assert.False(t, ok)
}

func TestStore_MarkTriggered_SetsTimestamp(t *testing.T) {
	s := newTestStore()

	id, err := s.Add("user@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)
	require.NoError(t, err)

	before := time.Now()
	ok := s.MarkTriggered(id, 2550.50)
	after := time.Now()
	assert.True(t, ok)

	alerts := s.List("user@example.com")
	require.Len(t, alerts, 1)

	a := alerts[0]
	assert.True(t, a.Triggered)
	assert.Equal(t, 2550.50, a.TriggeredPrice)
	assert.False(t, a.TriggeredAt.IsZero())
	assert.True(t, !a.TriggeredAt.Before(before) && !a.TriggeredAt.After(after),
		"TriggeredAt should be between before and after timestamps")
}

func TestStore_ListAll(t *testing.T) {
	s := newTestStore()

	s.Add("user1@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)
	s.Add("user1@example.com", "INFY", "NSE", 408065, 1500.0, DirectionBelow)
	s.Add("user2@example.com", "TCS", "NSE", 2953217, 3500.0, DirectionAbove)

	all := s.ListAll()
	assert.Len(t, all, 2) // 2 users
	assert.Len(t, all["user1@example.com"], 2)
	assert.Len(t, all["user2@example.com"], 1)
}

func TestStore_ListAll_DeepCopy(t *testing.T) {
	s := newTestStore()

	s.Add("user@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)

	all := s.ListAll()
	require.Len(t, all["user@example.com"], 1)

	// Mutate the returned copy.
	all["user@example.com"][0].TargetPrice = 9999.0
	all["user@example.com"][0].Tradingsymbol = "MUTATED"

	// Append an extra alert to the returned slice.
	all["user@example.com"] = append(all["user@example.com"], &Alert{ID: "fake"})

	// Store should be unaffected.
	fresh := s.ListAll()
	require.Len(t, fresh["user@example.com"], 1)
	assert.Equal(t, 2500.0, fresh["user@example.com"][0].TargetPrice)
	assert.Equal(t, "RELIANCE", fresh["user@example.com"][0].Tradingsymbol)
}

func TestStore_SetAndGetTelegramChatID(t *testing.T) {
	s := newTestStore()

	// Initially not found.
	_, ok := s.GetTelegramChatID("user@example.com")
	assert.False(t, ok)

	// Set and get.
	s.SetTelegramChatID("user@example.com", 123456789)
	chatID, ok := s.GetTelegramChatID("user@example.com")
	assert.True(t, ok)
	assert.Equal(t, int64(123456789), chatID)

	// Overwrite.
	s.SetTelegramChatID("user@example.com", 987654321)
	chatID, ok = s.GetTelegramChatID("user@example.com")
	assert.True(t, ok)
	assert.Equal(t, int64(987654321), chatID)

	// Different user is still not found.
	_, ok = s.GetTelegramChatID("other@example.com")
	assert.False(t, ok)

	// ListAllTelegram returns all mappings.
	s.SetTelegramChatID("other@example.com", 111222333)
	allTg := s.ListAllTelegram()
	assert.Len(t, allTg, 2)
	assert.Equal(t, int64(987654321), allTg["user@example.com"])
	assert.Equal(t, int64(111222333), allTg["other@example.com"])
}

func TestStore_ActiveCount(t *testing.T) {
	s := newTestStore()

	s.Add("user@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)
	id2, _ := s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionBelow)
	s.Add("user@example.com", "TCS", "NSE", 2953217, 3500.0, DirectionAbove)

	assert.Equal(t, 3, s.ActiveCount("user@example.com"))

	s.MarkTriggered(id2, 1400.0)
	assert.Equal(t, 2, s.ActiveCount("user@example.com"))

	// Unknown user returns 0.
	assert.Equal(t, 0, s.ActiveCount("nobody@example.com"))
}

func TestStore_ConcurrentAccess(t *testing.T) {
	s := newTestStore()
	const goroutines = 20
	const opsPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(gID int) {
			defer wg.Done()
			email := fmt.Sprintf("user%d@example.com", gID%5) // 5 distinct users

			for i := 0; i < opsPerGoroutine; i++ {
				switch i % 6 {
				case 0, 1:
					// Add
					s.Add(email, fmt.Sprintf("SYM%d_%d", gID, i), "NSE", uint32(gID*1000+i), float64(i)*10, DirectionAbove)
				case 2:
					// List
					s.List(email)
				case 3:
					// GetByToken
					s.GetByToken(uint32(gID*1000 + i))
				case 4:
					// ListAll
					s.ListAll()
				case 5:
					// MarkTriggered (may or may not find the alert)
					alerts := s.List(email)
					if len(alerts) > 0 {
						s.MarkTriggered(alerts[0].ID, 999.0)
					}
				}
			}

			// Also exercise Telegram operations concurrently.
			s.SetTelegramChatID(email, int64(gID*100))
			s.GetTelegramChatID(email)
			s.ListAllTelegram()
			s.ActiveCount(email)
		}(g)
	}

	wg.Wait()
	// No assertion needed — the test passes if no race detector violations occur.
}

// ---------------------------------------------------------------------------
// shouldTrigger / Evaluator tests
// ---------------------------------------------------------------------------

func TestShouldTrigger_Above(t *testing.T) {
	alert := &Alert{TargetPrice: 100.0, Direction: DirectionAbove}

	// Price above target triggers.
	assert.True(t, shouldTrigger(alert, 100.01))
	assert.True(t, shouldTrigger(alert, 200.0))

	// Price below target does not trigger.
	assert.False(t, shouldTrigger(alert, 99.99))
}

func TestShouldTrigger_Below(t *testing.T) {
	alert := &Alert{TargetPrice: 100.0, Direction: DirectionBelow}

	// Price below target triggers.
	assert.True(t, shouldTrigger(alert, 99.99))
	assert.True(t, shouldTrigger(alert, 50.0))

	// Price above target does not trigger.
	assert.False(t, shouldTrigger(alert, 100.01))
}

func TestShouldTrigger_NoTrigger(t *testing.T) {
	above := &Alert{TargetPrice: 100.0, Direction: DirectionAbove}
	below := &Alert{TargetPrice: 80.0, Direction: DirectionBelow}

	// Price between the two thresholds triggers neither.
	assert.False(t, shouldTrigger(above, 90.0))
	assert.False(t, shouldTrigger(below, 90.0))
}

func TestShouldTrigger_ExactPrice(t *testing.T) {
	above := &Alert{TargetPrice: 100.0, Direction: DirectionAbove}
	below := &Alert{TargetPrice: 100.0, Direction: DirectionBelow}

	// Exact price should trigger both "above" (>=) and "below" (<=).
	assert.True(t, shouldTrigger(above, 100.0))
	assert.True(t, shouldTrigger(below, 100.0))
}

func TestShouldTrigger_InvalidDirection(t *testing.T) {
	alert := &Alert{TargetPrice: 100.0, Direction: Direction("sideways")}
	assert.False(t, shouldTrigger(alert, 100.0))
}

func TestShouldTrigger_AlreadyTriggered(t *testing.T) {
	// shouldTrigger itself does not check the Triggered flag — that's the Evaluator's
	// responsibility via GetByToken (which filters out triggered alerts) and MarkTriggered
	// (which returns false if already triggered). Verify the full flow:
	s := newTestStore()

	id, _ := s.Add("user@example.com", "RELIANCE", "NSE", 738561, 100.0, DirectionAbove)

	// First trigger works.
	assert.True(t, s.MarkTriggered(id, 105.0))

	// Triggered alert no longer appears in GetByToken.
	assert.Empty(t, s.GetByToken(738561))

	// MarkTriggered again returns false.
	assert.False(t, s.MarkTriggered(id, 110.0))
}

func TestEvaluator_Evaluate(t *testing.T) {
	var notified []*Alert
	var notifiedPrices []float64
	var mu sync.Mutex

	s := NewStore(func(alert *Alert, currentPrice float64) {
		mu.Lock()
		defer mu.Unlock()
		notified = append(notified, alert)
		notifiedPrices = append(notifiedPrices, currentPrice)
	})

	s.Add("user@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)
	s.Add("user@example.com", "INFY", "NSE", 408065, 1400.0, DirectionBelow)

	eval := NewEvaluator(s, defaultTestLogger())

	// Tick that triggers the RELIANCE "above" alert.
	eval.Evaluate("user@example.com", models.Tick{
		InstrumentToken: 738561,
		LastPrice:       2550.0,
	})

	mu.Lock()
	assert.Len(t, notified, 1)
	assert.Equal(t, "RELIANCE", notified[0].Tradingsymbol)
	assert.Equal(t, 2550.0, notifiedPrices[0])
	mu.Unlock()

	// Same tick again should not re-notify (already triggered).
	eval.Evaluate("user@example.com", models.Tick{
		InstrumentToken: 738561,
		LastPrice:       2600.0,
	})

	mu.Lock()
	assert.Len(t, notified, 1) // still 1
	mu.Unlock()

	// Tick that does NOT trigger INFY (price is above target for a "below" alert).
	eval.Evaluate("user@example.com", models.Tick{
		InstrumentToken: 408065,
		LastPrice:       1500.0,
	})

	mu.Lock()
	assert.Len(t, notified, 1) // still 1
	mu.Unlock()

	// Tick that triggers the INFY "below" alert.
	eval.Evaluate("user@example.com", models.Tick{
		InstrumentToken: 408065,
		LastPrice:       1390.0,
	})

	mu.Lock()
	assert.Len(t, notified, 2)
	assert.Equal(t, "INFY", notified[1].Tradingsymbol)
	assert.Equal(t, 1390.0, notifiedPrices[1])
	mu.Unlock()
}

func TestEvaluator_NoAlertsForToken(t *testing.T) {
	called := false
	s := NewStore(func(alert *Alert, currentPrice float64) {
		called = true
	})

	eval := NewEvaluator(s, defaultTestLogger())

	// Tick for an instrument with no alerts — callback should never fire.
	eval.Evaluate("user@example.com", models.Tick{
		InstrumentToken: 999999,
		LastPrice:       100.0,
	})

	assert.False(t, called)
}

// ---------------------------------------------------------------------------
// Percentage alert tests (drop_pct, rise_pct)
// ---------------------------------------------------------------------------

func TestShouldTrigger_DropPct(t *testing.T) {
	alert := &Alert{
		TargetPrice:    5.0, // 5% drop threshold
		Direction:      DirectionDropPct,
		ReferencePrice: 1000.0,
	}

	// Price dropped 5% (1000 -> 950) — should trigger
	assert.True(t, shouldTrigger(alert, 950.0))

	// Price dropped more than 5% — should trigger
	assert.True(t, shouldTrigger(alert, 900.0))

	// Price dropped exactly 5% — should trigger (>=)
	assert.True(t, shouldTrigger(alert, 950.0))

	// Price dropped less than 5% — should NOT trigger
	assert.False(t, shouldTrigger(alert, 960.0))

	// Price went UP — should NOT trigger
	assert.False(t, shouldTrigger(alert, 1050.0))
}

func TestShouldTrigger_RisePct(t *testing.T) {
	alert := &Alert{
		TargetPrice:    10.0, // 10% rise threshold
		Direction:      DirectionRisePct,
		ReferencePrice: 500.0,
	}

	// Price rose 10% (500 -> 550) — should trigger
	assert.True(t, shouldTrigger(alert, 550.0))

	// Price rose more than 10% — should trigger
	assert.True(t, shouldTrigger(alert, 600.0))

	// Price rose exactly 10% — should trigger (>=)
	assert.True(t, shouldTrigger(alert, 550.0))

	// Price rose less than 10% — should NOT trigger
	assert.False(t, shouldTrigger(alert, 540.0))

	// Price went DOWN — should NOT trigger
	assert.False(t, shouldTrigger(alert, 450.0))
}

func TestShouldTrigger_DropPct_ZeroReferencePrice(t *testing.T) {
	alert := &Alert{
		TargetPrice:    5.0,
		Direction:      DirectionDropPct,
		ReferencePrice: 0, // invalid — should not trigger
	}
	assert.False(t, shouldTrigger(alert, 950.0))
}

func TestShouldTrigger_RisePct_ZeroReferencePrice(t *testing.T) {
	alert := &Alert{
		TargetPrice:    5.0,
		Direction:      DirectionRisePct,
		ReferencePrice: 0, // invalid — should not trigger
	}
	assert.False(t, shouldTrigger(alert, 550.0))
}

func TestShouldTrigger_DropPct_NegativeReferencePrice(t *testing.T) {
	alert := &Alert{
		TargetPrice:    5.0,
		Direction:      DirectionDropPct,
		ReferencePrice: -100.0, // invalid — should not trigger
	}
	assert.False(t, shouldTrigger(alert, 50.0))
}

func TestShouldTrigger_RisePct_NegativeReferencePrice(t *testing.T) {
	alert := &Alert{
		TargetPrice:    5.0,
		Direction:      DirectionRisePct,
		ReferencePrice: -100.0, // invalid — should not trigger
	}
	assert.False(t, shouldTrigger(alert, 50.0))
}

func TestShouldTrigger_DropPct_ExactThreshold(t *testing.T) {
	// 5% of 200 = 10, so price at 190 is exactly 5% drop
	alert := &Alert{
		TargetPrice:    5.0,
		Direction:      DirectionDropPct,
		ReferencePrice: 200.0,
	}
	assert.True(t, shouldTrigger(alert, 190.0))
}

func TestShouldTrigger_RisePct_ExactThreshold(t *testing.T) {
	// 10% of 200 = 20, so price at 220 is exactly 10% rise
	alert := &Alert{
		TargetPrice:    10.0,
		Direction:      DirectionRisePct,
		ReferencePrice: 200.0,
	}
	assert.True(t, shouldTrigger(alert, 220.0))
}

func TestShouldTrigger_DropPct_SmallPercentage(t *testing.T) {
	// 0.5% of 100 = 0.5, so price at 99.5 is exactly 0.5% drop
	alert := &Alert{
		TargetPrice:    0.5,
		Direction:      DirectionDropPct,
		ReferencePrice: 100.0,
	}
	assert.True(t, shouldTrigger(alert, 99.5))
	assert.False(t, shouldTrigger(alert, 99.6))
}

func TestStore_AddWithReferencePrice(t *testing.T) {
	s := newTestStore()

	id, err := s.AddWithReferencePrice("user@example.com", "RELIANCE", "NSE", 738561, 5.0, DirectionDropPct, 2500.0)
	require.NoError(t, err)
	assert.NotEmpty(t, id)

	alertList := s.List("user@example.com")
	require.Len(t, alertList, 1)

	a := alertList[0]
	assert.Equal(t, id, a.ID)
	assert.Equal(t, 5.0, a.TargetPrice)
	assert.Equal(t, DirectionDropPct, a.Direction)
	assert.Equal(t, 2500.0, a.ReferencePrice)
}

func TestIsPercentageDirection(t *testing.T) {
	assert.True(t, IsPercentageDirection(DirectionDropPct))
	assert.True(t, IsPercentageDirection(DirectionRisePct))
	assert.False(t, IsPercentageDirection(DirectionAbove))
	assert.False(t, IsPercentageDirection(DirectionBelow))
}

func TestValidDirections(t *testing.T) {
	assert.True(t, ValidDirections[DirectionAbove])
	assert.True(t, ValidDirections[DirectionBelow])
	assert.True(t, ValidDirections[DirectionDropPct])
	assert.True(t, ValidDirections[DirectionRisePct])
	assert.False(t, ValidDirections[Direction("invalid")])
}

func TestEvaluator_Evaluate_DropPct(t *testing.T) {
	var notified []*Alert
	var notifiedPrices []float64
	var mu sync.Mutex

	s := NewStore(func(alert *Alert, currentPrice float64) {
		mu.Lock()
		defer mu.Unlock()
		notified = append(notified, alert)
		notifiedPrices = append(notifiedPrices, currentPrice)
	})

	// Alert: trigger when RELIANCE drops 5% from 2500 (i.e., price <= 2375)
	s.AddWithReferencePrice("user@example.com", "RELIANCE", "NSE", 738561, 5.0, DirectionDropPct, 2500.0)

	eval := NewEvaluator(s, defaultTestLogger())

	// Tick at 2400 (4% drop) — should NOT trigger
	eval.Evaluate("user@example.com", models.Tick{
		InstrumentToken: 738561,
		LastPrice:       2400.0,
	})

	mu.Lock()
	assert.Len(t, notified, 0)
	mu.Unlock()

	// Tick at 2375 (exactly 5% drop) — should trigger
	eval.Evaluate("user@example.com", models.Tick{
		InstrumentToken: 738561,
		LastPrice:       2375.0,
	})

	mu.Lock()
	assert.Len(t, notified, 1)
	assert.Equal(t, "RELIANCE", notified[0].Tradingsymbol)
	assert.Equal(t, 2375.0, notifiedPrices[0])
	mu.Unlock()
}

func TestEvaluator_Evaluate_RisePct(t *testing.T) {
	var notified []*Alert
	var notifiedPrices []float64
	var mu sync.Mutex

	s := NewStore(func(alert *Alert, currentPrice float64) {
		mu.Lock()
		defer mu.Unlock()
		notified = append(notified, alert)
		notifiedPrices = append(notifiedPrices, currentPrice)
	})

	// Alert: trigger when INFY rises 10% from 1500 (i.e., price >= 1650)
	s.AddWithReferencePrice("user@example.com", "INFY", "NSE", 408065, 10.0, DirectionRisePct, 1500.0)

	eval := NewEvaluator(s, defaultTestLogger())

	// Tick at 1600 (6.67% rise) — should NOT trigger
	eval.Evaluate("user@example.com", models.Tick{
		InstrumentToken: 408065,
		LastPrice:       1600.0,
	})

	mu.Lock()
	assert.Len(t, notified, 0)
	mu.Unlock()

	// Tick at 1650 (exactly 10% rise) — should trigger
	eval.Evaluate("user@example.com", models.Tick{
		InstrumentToken: 408065,
		LastPrice:       1650.0,
	})

	mu.Lock()
	assert.Len(t, notified, 1)
	assert.Equal(t, "INFY", notified[0].Tradingsymbol)
	assert.Equal(t, 1650.0, notifiedPrices[0])
	mu.Unlock()
}

// defaultTestLogger returns a no-op slog.Logger for tests.
func defaultTestLogger() *slog.Logger {
	return slog.Default()
}

// ---------------------------------------------------------------------------
// Store.SetDB / Store.SetLogger / Store.LoadFromDB
// ---------------------------------------------------------------------------

func TestStore_SetDB(t *testing.T) {
	s := newTestStore()
	// SetDB should not panic with nil.
	s.SetDB(nil)
}

func TestStore_SetLogger(t *testing.T) {
	s := newTestStore()
	// SetLogger should not panic.
	s.SetLogger(slog.Default())
}

func TestStore_LoadFromDB_NilDB(t *testing.T) {
	s := newTestStore()
	// LoadFromDB with nil DB should be a no-op.
	err := s.LoadFromDB()
	require.NoError(t, err)
}

func TestStore_LoadFromDB_WithDB(t *testing.T) {
	db := openTestDB(t)
	s := NewStore(nil)
	s.SetDB(db)

	// Save an alert directly to DB.
	alert := &Alert{
		ID:              "load-db-1",
		Email:           "dbuser@example.com",
		Tradingsymbol:   "TCS",
		Exchange:        "NSE",
		InstrumentToken: 2953217,
		TargetPrice:     3500.0,
		Direction:       DirectionAbove,
		CreatedAt:       time.Now().Truncate(time.Second),
	}
	require.NoError(t, db.SaveAlert(alert))

	// Save a Telegram chat ID directly to DB.
	require.NoError(t, db.SaveTelegramChatID("dbuser@example.com", 555666777))

	// Create a new store and load from DB.
	s2 := NewStore(nil)
	s2.SetDB(db)
	require.NoError(t, s2.LoadFromDB())

	// Verify alert loaded.
	alerts := s2.List("dbuser@example.com")
	require.Len(t, alerts, 1)
	assert.Equal(t, "load-db-1", alerts[0].ID)
	assert.Equal(t, "TCS", alerts[0].Tradingsymbol)

	// Verify Telegram chat ID loaded.
	chatID, ok := s2.GetTelegramChatID("dbuser@example.com")
	assert.True(t, ok)
	assert.Equal(t, int64(555666777), chatID)
}

func TestStore_ListByEmail_Empty(t *testing.T) {
	s := newTestStore()
	// List for a non-existent email should return empty (not nil).
	alerts := s.List("nonexistent@example.com")
	assert.Empty(t, alerts)
}

// ---------------------------------------------------------------------------
// DB operations: DeleteAlert, DeleteAlertsByEmail, LoadTelegramChatIDs,
// SaveTelegramChatID, UpdateTriggered, UpdateAlertNotification, DeleteTelegramChatID
// ---------------------------------------------------------------------------

func TestDB_DeleteAlert(t *testing.T) {
	db := openTestDB(t)

	alert := &Alert{
		ID:              "del-01",
		Email:           "user@example.com",
		Tradingsymbol:   "RELIANCE",
		Exchange:        "NSE",
		InstrumentToken: 738561,
		TargetPrice:     2500.0,
		Direction:       DirectionAbove,
		CreatedAt:       time.Now().Truncate(time.Second),
	}
	require.NoError(t, db.SaveAlert(alert))

	// Delete the alert.
	require.NoError(t, db.DeleteAlert("user@example.com", "del-01"))

	// Verify it's gone.
	alertMap, err := db.LoadAlerts()
	require.NoError(t, err)
	assert.Empty(t, alertMap["user@example.com"])
}

func TestDB_DeleteAlertsByEmail(t *testing.T) {
	db := openTestDB(t)

	for i := 0; i < 3; i++ {
		alert := &Alert{
			ID:              fmt.Sprintf("batch-%d", i),
			Email:           "user@example.com",
			Tradingsymbol:   fmt.Sprintf("SYM%d", i),
			Exchange:        "NSE",
			InstrumentToken: uint32(1000 + i),
			TargetPrice:     float64(100 + i),
			Direction:       DirectionAbove,
			CreatedAt:       time.Now().Truncate(time.Second),
		}
		require.NoError(t, db.SaveAlert(alert))
	}

	// Delete all alerts for user.
	require.NoError(t, db.DeleteAlertsByEmail("user@example.com"))

	// Verify all gone.
	alertMap, err := db.LoadAlerts()
	require.NoError(t, err)
	assert.Empty(t, alertMap["user@example.com"])
}

func TestDB_TelegramChatIDs(t *testing.T) {
	db := openTestDB(t)

	// Save chat IDs.
	require.NoError(t, db.SaveTelegramChatID("a@example.com", 111))
	require.NoError(t, db.SaveTelegramChatID("b@example.com", 222))

	// Load all.
	chatIDs, err := db.LoadTelegramChatIDs()
	require.NoError(t, err)
	assert.Equal(t, int64(111), chatIDs["a@example.com"])
	assert.Equal(t, int64(222), chatIDs["b@example.com"])

	// Overwrite.
	require.NoError(t, db.SaveTelegramChatID("a@example.com", 333))
	chatIDs, err = db.LoadTelegramChatIDs()
	require.NoError(t, err)
	assert.Equal(t, int64(333), chatIDs["a@example.com"])

	// Delete.
	require.NoError(t, db.DeleteTelegramChatID("a@example.com"))
	chatIDs, err = db.LoadTelegramChatIDs()
	require.NoError(t, err)
	_, exists := chatIDs["a@example.com"]
	assert.False(t, exists)
	assert.Equal(t, int64(222), chatIDs["b@example.com"])
}

func TestDB_UpdateTriggered(t *testing.T) {
	db := openTestDB(t)

	alert := &Alert{
		ID:              "trig-01",
		Email:           "user@example.com",
		Tradingsymbol:   "INFY",
		Exchange:        "NSE",
		InstrumentToken: 408065,
		TargetPrice:     1500.0,
		Direction:       DirectionBelow,
		CreatedAt:       time.Now().Truncate(time.Second),
	}
	require.NoError(t, db.SaveAlert(alert))

	// Trigger the alert.
	trigTime := time.Now().Truncate(time.Second)
	require.NoError(t, db.UpdateTriggered("trig-01", 1490.5, trigTime))

	// Verify in DB.
	alertMap, err := db.LoadAlerts()
	require.NoError(t, err)
	require.Len(t, alertMap["user@example.com"], 1)
	loaded := alertMap["user@example.com"][0]
	assert.True(t, loaded.Triggered)
	assert.InDelta(t, 1490.5, loaded.TriggeredPrice, 0.01)
}

func TestDB_UpdateAlertNotification(t *testing.T) {
	db := openTestDB(t)

	alert := &Alert{
		ID:              "notif-01",
		Email:           "user@example.com",
		Tradingsymbol:   "TCS",
		Exchange:        "NSE",
		InstrumentToken: 2953217,
		TargetPrice:     3500.0,
		Direction:       DirectionAbove,
		CreatedAt:       time.Now().Truncate(time.Second),
	}
	require.NoError(t, db.SaveAlert(alert))

	// Update notification sent time.
	sentAt := time.Now().Truncate(time.Second)
	require.NoError(t, db.UpdateAlertNotification("notif-01", sentAt))

	// Verify in DB (LoadAlerts doesn't load notification_sent_at, but the update should not error).
	alertMap, err := db.LoadAlerts()
	require.NoError(t, err)
	assert.Len(t, alertMap["user@example.com"], 1)
}

func TestDB_DeleteClient(t *testing.T) {
	db := openTestDB(t)

	now := time.Now().Truncate(time.Second)
	require.NoError(t, db.SaveClient("client-del-1", "secret", `["http://localhost"]`, "App", now, false))

	// Verify it exists.
	clients, err := db.LoadClients()
	require.NoError(t, err)
	assert.Len(t, clients, 1)

	// Delete it.
	require.NoError(t, db.DeleteClient("client-del-1"))

	// Verify gone.
	clients, err = db.LoadClients()
	require.NoError(t, err)
	assert.Empty(t, clients)
}

// ---------------------------------------------------------------------------
// Store.Add with DB persistence
// ---------------------------------------------------------------------------

func TestStore_AddWithDB(t *testing.T) {
	db := openTestDB(t)
	s := NewStore(nil)
	s.SetDB(db)

	id, err := s.Add("user@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)
	require.NoError(t, err)
	assert.NotEmpty(t, id)

	// Verify persisted in DB.
	alertMap, err := db.LoadAlerts()
	require.NoError(t, err)
	require.Len(t, alertMap["user@example.com"], 1)
	assert.Equal(t, "RELIANCE", alertMap["user@example.com"][0].Tradingsymbol)
}

func TestStore_DeleteWithDB(t *testing.T) {
	db := openTestDB(t)
	s := NewStore(nil)
	s.SetDB(db)

	id, err := s.Add("user@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)
	require.NoError(t, err)

	// Delete via store.
	require.NoError(t, s.Delete("user@example.com", id))

	// Verify removed from DB.
	alertMap, err := db.LoadAlerts()
	require.NoError(t, err)
	assert.Empty(t, alertMap["user@example.com"])
}

func TestStore_DeleteByEmailWithDB(t *testing.T) {
	db := openTestDB(t)
	s := NewStore(nil)
	s.SetDB(db)

	s.Add("user@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)
	s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionBelow)
	s.SetTelegramChatID("user@example.com", 123456)

	// Delete all by email.
	s.DeleteByEmail("user@example.com")

	// Verify removed from DB.
	alertMap, err := db.LoadAlerts()
	require.NoError(t, err)
	assert.Empty(t, alertMap["user@example.com"])

	chatIDs, err := db.LoadTelegramChatIDs()
	require.NoError(t, err)
	_, exists := chatIDs["user@example.com"]
	assert.False(t, exists)
}

func TestStore_SetTelegramChatIDWithDB(t *testing.T) {
	db := openTestDB(t)
	s := NewStore(nil)
	s.SetDB(db)

	s.SetTelegramChatID("user@example.com", 999888777)

	// Verify persisted.
	chatIDs, err := db.LoadTelegramChatIDs()
	require.NoError(t, err)
	assert.Equal(t, int64(999888777), chatIDs["user@example.com"])
}

func TestStore_MarkTriggeredWithDB(t *testing.T) {
	db := openTestDB(t)
	s := NewStore(nil)
	s.SetDB(db)

	id, err := s.Add("user@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)
	require.NoError(t, err)

	ok := s.MarkTriggered(id, 2550.0)
	assert.True(t, ok)

	// Verify in DB.
	alertMap, err := db.LoadAlerts()
	require.NoError(t, err)
	require.Len(t, alertMap["user@example.com"], 1)
	assert.True(t, alertMap["user@example.com"][0].Triggered)
	assert.InDelta(t, 2550.0, alertMap["user@example.com"][0].TriggeredPrice, 0.01)
}

func TestStore_MarkNotificationSentWithDB(t *testing.T) {
	db := openTestDB(t)
	s := NewStore(nil)
	s.SetDB(db)

	id, _ := s.Add("user@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)

	sentAt := time.Now().Truncate(time.Second)
	s.MarkNotificationSent(id, sentAt)

	// Should not panic — just verify it didn't error silently.
	alerts := s.List("user@example.com")
	require.Len(t, alerts, 1)
	assert.WithinDuration(t, sentAt, alerts[0].NotificationSentAt, 2*time.Second)
}

// ---------------------------------------------------------------------------
// PnLSnapshotService.GetJournal
// ---------------------------------------------------------------------------

func TestPnLSnapshotService_GetJournal(t *testing.T) {
	db := openTestDB(t)

	svc := NewPnLSnapshotService(db, nil, nil, defaultTestLogger())
	require.NotNil(t, svc)

	// Insert P&L data.
	entries := []*DailyPnLEntry{
		{Date: "2026-04-01", Email: "user@example.com", HoldingsPnL: 1000, PositionsPnL: 200, NetPnL: 1200, HoldingsCount: 10, TradesCount: 3},
		{Date: "2026-04-02", Email: "user@example.com", HoldingsPnL: -500, PositionsPnL: 100, NetPnL: -400, HoldingsCount: 10, TradesCount: 2},
		{Date: "2026-04-03", Email: "user@example.com", HoldingsPnL: 300, PositionsPnL: 0, NetPnL: 300, HoldingsCount: 10, TradesCount: 1},
		{Date: "2026-04-04", Email: "user@example.com", HoldingsPnL: 700, PositionsPnL: 50, NetPnL: 750, HoldingsCount: 10, TradesCount: 4},
	}
	for _, e := range entries {
		require.NoError(t, db.SaveDailyPnL(e))
	}

	result, err := svc.GetJournal("user@example.com", "2026-04-01", "2026-04-04")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, 4, result.TotalDays)
	assert.InDelta(t, 1850.0, result.CumulativePnL, 0.01)
	assert.Equal(t, 3, result.WinDays)
	assert.Equal(t, 1, result.LossDays)
	assert.InDelta(t, 1850.0/4, result.AvgDailyPnL, 0.01)

	require.NotNil(t, result.BestDay)
	assert.Equal(t, "2026-04-01", result.BestDay.Date)

	require.NotNil(t, result.WorstDay)
	assert.Equal(t, "2026-04-02", result.WorstDay.Date)
}

func TestPnLSnapshotService_GetJournal_Empty(t *testing.T) {
	db := openTestDB(t)

	svc := NewPnLSnapshotService(db, nil, nil, defaultTestLogger())
	require.NotNil(t, svc)

	result, err := svc.GetJournal("nobody@example.com", "2026-01-01", "2026-12-31")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 0, result.TotalDays)
	assert.Empty(t, result.Entries)
	assert.Nil(t, result.BestDay)
	assert.Nil(t, result.WorstDay)
}

// ---------------------------------------------------------------------------
// TrailingStopManager.CancelByEmail / SetOnModify
// ---------------------------------------------------------------------------

func TestTrailingStopManager_CancelByEmail(t *testing.T) {
	m, _ := newTestManager(t)

	// Add stops for two users.
	ts1 := &TrailingStop{
		Email: "userA@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "O1", TrailAmount: 20,
		Direction: "long", HighWaterMark: 1500, CurrentStop: 1480,
	}
	ts2 := &TrailingStop{
		Email: "userA@example.com", Exchange: "NSE", Tradingsymbol: "TCS",
		InstrumentToken: 2953217, OrderID: "O2", TrailAmount: 15,
		Direction: "long", HighWaterMark: 3500, CurrentStop: 3485,
	}
	ts3 := &TrailingStop{
		Email: "userB@example.com", Exchange: "NSE", Tradingsymbol: "RELIANCE",
		InstrumentToken: 738561, OrderID: "O3", TrailAmount: 25,
		Direction: "long", HighWaterMark: 2500, CurrentStop: 2475,
	}

	_, err := m.Add(ts1)
	require.NoError(t, err)
	_, err = m.Add(ts2)
	require.NoError(t, err)
	_, err = m.Add(ts3)
	require.NoError(t, err)

	// Cancel all for userA.
	m.CancelByEmail("userA@example.com")

	// userA's stops should be inactive.
	stopsA := m.List("userA@example.com")
	for _, s := range stopsA {
		assert.False(t, s.Active, "userA's stop %s should be inactive", s.ID)
	}

	// userB's stop should still be active.
	stopsB := m.List("userB@example.com")
	require.Len(t, stopsB, 1)
	assert.True(t, stopsB[0].Active)
}

func TestTrailingStopManager_CancelByEmail_NoneExist(t *testing.T) {
	m, _ := newTestManager(t)
	// Should not panic when no stops exist for the user.
	m.CancelByEmail("nobody@example.com")
}

func TestTrailingStopManager_SetOnModify(t *testing.T) {
	m, _ := newTestManager(t)

	var called bool
	m.SetOnModify(func(ts *TrailingStop, oldStop, newStop float64) {
		called = true
	})

	ts := &TrailingStop{
		Email: "test@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "SL-ONMOD", TrailAmount: 20,
		Direction: "long", HighWaterMark: 1500, CurrentStop: 1480,
	}
	_, err := m.Add(ts)
	require.NoError(t, err)

	// Trigger a modify.
	tick := models.Tick{InstrumentToken: 408065, LastPrice: 1550}
	m.Evaluate("test@example.com", tick)

	assert.True(t, called, "onModify callback should have been invoked")
}

// ---------------------------------------------------------------------------
// DB ExecDDL, ExecInsert, QueryRow (used by billing package)
// ---------------------------------------------------------------------------

func TestDB_ExecDDL(t *testing.T) {
	db := openTestDB(t)

	// Create a custom table.
	err := db.ExecDDL(`CREATE TABLE IF NOT EXISTS test_table (id TEXT PRIMARY KEY)`)
	require.NoError(t, err)

	// Insert via ExecInsert.
	err = db.ExecInsert(`INSERT INTO test_table (id) VALUES (?)`, "row1")
	require.NoError(t, err)

	// Query via QueryRow.
	var id string
	row := db.QueryRow(`SELECT id FROM test_table WHERE id = ?`, "row1")
	require.NoError(t, row.Scan(&id))
	assert.Equal(t, "row1", id)
}

// ---------------------------------------------------------------------------
// DB registry operations
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TelegramNotifier.Store / Logger (non-nil receiver)
// ---------------------------------------------------------------------------

func TestTelegramNotifier_StoreAndLogger(t *testing.T) {
	s := newTestStore()
	logger := defaultTestLogger()
	// Construct a TelegramNotifier directly (no bot, but non-nil receiver).
	tn := &TelegramNotifier{
		store:  s,
		logger: logger,
	}
	assert.Equal(t, s, tn.Store())
	assert.Equal(t, logger, tn.Logger())
}

// ---------------------------------------------------------------------------
// BriefingService.recentlyTriggeredAlerts
// ---------------------------------------------------------------------------

func TestBriefingService_RecentlyTriggeredAlerts(t *testing.T) {
	s := newTestStore()

	// Add and trigger an alert.
	id, err := s.Add("user@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)
	require.NoError(t, err)
	s.MarkTriggered(id, 2550.0)

	// Add a non-triggered alert.
	s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionBelow)

	// Create a BriefingService with a nil notifier (won't send, but we can test the method).
	// Since the method is on BriefingService, we need a non-nil service.
	logger := defaultTestLogger()
	// Can't use NewBriefingService (requires non-nil notifier), so construct directly.
	bs := &BriefingService{
		alertStore: s,
		logger:     logger,
	}

	// Cutoff before now — the triggered alert should be included.
	cutoff := time.Now().Add(-1 * time.Minute)
	triggered := bs.recentlyTriggeredAlerts("user@example.com", cutoff)
	assert.Len(t, triggered, 1)
	assert.Equal(t, "RELIANCE", triggered[0].Tradingsymbol)

	// Cutoff after now — nothing should match.
	futureCutoff := time.Now().Add(1 * time.Hour)
	triggered = bs.recentlyTriggeredAlerts("user@example.com", futureCutoff)
	assert.Empty(t, triggered)

	// Non-existent user.
	triggered = bs.recentlyTriggeredAlerts("nobody@example.com", cutoff)
	assert.Empty(t, triggered)
}

// ---------------------------------------------------------------------------
// Store.LoadFromDB round-trip (alerts + telegram)
// ---------------------------------------------------------------------------

func TestStore_LoadFromDB_FullRoundTrip(t *testing.T) {
	db := openTestDB(t)

	// Populate store and persist.
	s := NewStore(nil)
	s.SetDB(db)

	id1, _ := s.Add("a@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)
	s.AddWithReferencePrice("a@example.com", "INFY", "NSE", 408065, 5.0, DirectionDropPct, 1500.0)
	s.MarkTriggered(id1, 2550.0)
	s.SetTelegramChatID("a@example.com", 111222)
	s.Add("b@example.com", "TCS", "NSE", 2953217, 3500.0, DirectionBelow)

	// Create new store and load from DB.
	s2 := NewStore(nil)
	s2.SetDB(db)
	require.NoError(t, s2.LoadFromDB())

	// Verify user a.
	alertsA := s2.List("a@example.com")
	assert.Len(t, alertsA, 2)
	chatID, ok := s2.GetTelegramChatID("a@example.com")
	assert.True(t, ok)
	assert.Equal(t, int64(111222), chatID)

	// Verify user b.
	alertsB := s2.List("b@example.com")
	assert.Len(t, alertsB, 1)
}

func TestDB_RegistryCRUD(t *testing.T) {
	db := openTestDB(t)

	now := time.Now().Truncate(time.Second)
	entry := &RegistryDBEntry{
		ID:           "reg-001",
		APIKey:       "apikey1",
		APISecret:    "apisecret1",
		AssignedTo:   "user@example.com",
		Label:        "Test App",
		Status:       "active",
		RegisteredBy: "admin@example.com",
		Source:       "manual",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	require.NoError(t, db.SaveRegistryEntry(entry))

	// Load entries.
	entries, err := db.LoadRegistryEntries()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "admin@example.com", entries["reg-001"].RegisteredBy)
	assert.Equal(t, "apikey1", entries["reg-001"].APIKey)
	assert.Equal(t, "apisecret1", entries["reg-001"].APISecret)

	// Delete entry.
	require.NoError(t, db.DeleteRegistryEntry("reg-001"))

	entries, err = db.LoadRegistryEntries()
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestStore_DeleteByEmail_NoAlerts(t *testing.T) {
	s := newTestStore()

	// DeleteByEmail on non-existent user should not panic.
	s.DeleteByEmail("nobody@example.com")

	// Also exercise with telegram mapping only.
	s.SetTelegramChatID("tgonly@example.com", 111222)
	s.DeleteByEmail("tgonly@example.com")

	_, ok := s.GetTelegramChatID("tgonly@example.com")
	assert.False(t, ok)
}

func TestStore_DeleteByEmail_WithAlertsAndTelegram(t *testing.T) {
	s := newTestStore()

	s.Add("user@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)
	s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionBelow)
	s.SetTelegramChatID("user@example.com", 555666)

	// Verify data exists.
	assert.Len(t, s.List("user@example.com"), 2)
	_, ok := s.GetTelegramChatID("user@example.com")
	assert.True(t, ok)

	s.DeleteByEmail("user@example.com")

	// All data should be gone.
	assert.Empty(t, s.List("user@example.com"))
	_, ok = s.GetTelegramChatID("user@example.com")
	assert.False(t, ok)
}

func TestEvaluator_PercentageDropAlert(t *testing.T) {
	var notified []*Alert
	s := NewStore(func(alert *Alert, currentPrice float64) {
		notified = append(notified, alert)
	})

	// Create a 5% drop alert with reference price 1000.
	s.AddWithReferencePrice("user@example.com", "RELIANCE", "NSE", 738561, 5.0, DirectionDropPct, 1000.0)

	eval := NewEvaluator(s, defaultTestLogger())

	// Price at 960 → only 4% drop → should NOT trigger.
	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 738561, LastPrice: 960.0})
	assert.Len(t, notified, 0)

	// Price at 950 → exactly 5% drop → should trigger.
	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 738561, LastPrice: 950.0})
	assert.Len(t, notified, 1)
	assert.Equal(t, DirectionDropPct, notified[0].Direction)
}

func TestEvaluator_PercentageRiseAlert(t *testing.T) {
	var notified []*Alert
	s := NewStore(func(alert *Alert, currentPrice float64) {
		notified = append(notified, alert)
	})

	// Create a 10% rise alert with reference price 500.
	s.AddWithReferencePrice("user@example.com", "INFY", "NSE", 408065, 10.0, DirectionRisePct, 500.0)

	eval := NewEvaluator(s, defaultTestLogger())

	// Price at 540 → only 8% rise → should NOT trigger.
	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 540.0})
	assert.Len(t, notified, 0)

	// Price at 550 → exactly 10% rise → should trigger.
	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 550.0})
	assert.Len(t, notified, 1)
	assert.Equal(t, DirectionRisePct, notified[0].Direction)
}



// ===========================================================================
// Merged from coverage_test.go
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
