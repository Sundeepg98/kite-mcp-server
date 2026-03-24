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

// defaultTestLogger returns a no-op slog.Logger for tests.
func defaultTestLogger() *slog.Logger {
	return slog.Default()
}

