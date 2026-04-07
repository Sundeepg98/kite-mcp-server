package alerts

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// ===========================================================================
// Pure helper tests (no external dependencies)
// ===========================================================================

func TestFormatRupee(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   float64
		want string
	}{
		{0, "+\u20B90"},
		{5000, "+\u20B95000"},
		{-3000, "-\u20B93000"},
		{0.5, "+\u20B90"},  // rounds to 0 (%.0f)
		{-0.5, "-\u20B90"}, // rounds to 0
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, formatRupee(tc.in), "formatRupee(%f)", tc.in)
	}
}

func TestPreviousTradingDayClose_Weekday(t *testing.T) {
	t.Parallel()
	// Tuesday 10 AM IST -> previous trading day close = Monday 3:30 PM IST
	now := time.Date(2026, 4, 7, 10, 0, 0, 0, kolkataLoc) // Tuesday
	close := previousTradingDayClose(now)
	assert.Equal(t, time.Monday, close.Weekday())
	assert.Equal(t, 15, close.Hour())
	assert.Equal(t, 30, close.Minute())
}

func TestPreviousTradingDayClose_Monday(t *testing.T) {
	t.Parallel()
	// Monday 10 AM -> previous trading day = Friday
	now := time.Date(2026, 4, 6, 10, 0, 0, 0, kolkataLoc) // Monday
	close := previousTradingDayClose(now)
	assert.Equal(t, time.Friday, close.Weekday())
	assert.Equal(t, 15, close.Hour())
	assert.Equal(t, 30, close.Minute())
}

func TestPreviousTradingDayClose_Sunday(t *testing.T) {
	t.Parallel()
	// Sunday -> previous trading day = Friday
	now := time.Date(2026, 4, 5, 12, 0, 0, 0, kolkataLoc) // Sunday
	close := previousTradingDayClose(now)
	assert.Equal(t, time.Friday, close.Weekday())
}

func TestPreviousTradingDayClose_Saturday(t *testing.T) {
	t.Parallel()
	// Saturday -> previous trading day = Friday
	now := time.Date(2026, 4, 4, 12, 0, 0, 0, kolkataLoc) // Saturday
	close := previousTradingDayClose(now)
	assert.Equal(t, time.Friday, close.Weekday())
}

func TestFilterPositiveChanges(t *testing.T) {
	t.Parallel()
	changes := []stockChange{
		{Symbol: "A", Percent: 5.0},
		{Symbol: "B", Percent: 3.0},
		{Symbol: "C", Percent: 1.0},
		{Symbol: "D", Percent: -2.0},
	}
	result := filterPositiveChanges(changes, 2)
	assert.Len(t, result, 2)
	assert.Equal(t, "A", result[0].Symbol)
	assert.Equal(t, "B", result[1].Symbol)
}

func TestFilterPositiveChanges_LessThanN(t *testing.T) {
	t.Parallel()
	changes := []stockChange{
		{Symbol: "A", Percent: 5.0},
	}
	result := filterPositiveChanges(changes, 3)
	assert.Len(t, result, 1)
}

func TestFilterPositiveChanges_NonePositive(t *testing.T) {
	t.Parallel()
	changes := []stockChange{
		{Symbol: "A", Percent: -1.0},
		{Symbol: "B", Percent: -3.0},
	}
	result := filterPositiveChanges(changes, 3)
	assert.Empty(t, result)
}

func TestFilterNegativeChanges(t *testing.T) {
	t.Parallel()
	// Input must be sorted descending (as in production code).
	changes := []stockChange{
		{Symbol: "A", Percent: 5.0},
		{Symbol: "B", Percent: 1.0},
		{Symbol: "C", Percent: -2.0},
		{Symbol: "D", Percent: -5.0},
	}
	result := filterNegativeChanges(changes, 2)
	assert.Len(t, result, 2)
	// Reversed: worst first
	assert.Equal(t, "D", result[0].Symbol)
	assert.Equal(t, "C", result[1].Symbol)
}

func TestFilterNegativeChanges_LessThanN(t *testing.T) {
	t.Parallel()
	changes := []stockChange{
		{Symbol: "A", Percent: 5.0},
		{Symbol: "B", Percent: -1.0},
	}
	result := filterNegativeChanges(changes, 5)
	assert.Len(t, result, 1)
}

func TestFilterNegativeChanges_NoneNegative(t *testing.T) {
	t.Parallel()
	changes := []stockChange{
		{Symbol: "A", Percent: 5.0},
		{Symbol: "B", Percent: 1.0},
	}
	result := filterNegativeChanges(changes, 3)
	assert.Empty(t, result)
}

func TestAbs(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 5, abs(5))
	assert.Equal(t, 5, abs(-5))
	assert.Equal(t, 0, abs(0))
}

// ===========================================================================
// EscapeTelegramMarkdown
// ===========================================================================

func TestEscapeTelegramMarkdown(t *testing.T) {
	t.Parallel()
	input := "Hello_world *bold* (test) [link] {curly} ~strike~ `code`"
	escaped := escapeTelegramMarkdown(input)

	// Each special char should be escaped
	assert.Contains(t, escaped, "\\_")
	assert.Contains(t, escaped, "\\*")
	assert.Contains(t, escaped, "\\(")
	assert.Contains(t, escaped, "\\)")
	assert.Contains(t, escaped, "\\[")
	assert.Contains(t, escaped, "\\]")
	assert.Contains(t, escaped, "\\{")
	assert.Contains(t, escaped, "\\}")
	assert.Contains(t, escaped, "\\~")
	assert.Contains(t, escaped, "\\`")
}

func TestEscapeMarkdown_Exported(t *testing.T) {
	t.Parallel()
	// EscapeMarkdown is the exported alias
	assert.Equal(t, escapeTelegramMarkdown("test.value"), EscapeMarkdown("test.value"))
}

// ===========================================================================
// NewBriefingService
// ===========================================================================

func TestNewBriefingService_NilNotifier(t *testing.T) {
	t.Parallel()
	bs := NewBriefingService(nil, nil, nil, nil, nil)
	assert.Nil(t, bs)
}

func TestNewBriefingService_NilSafe(t *testing.T) {
	t.Parallel()
	// Calling SendMorningBriefings on nil BriefingService should not panic.
	var bs *BriefingService
	bs.SendMorningBriefings()
	bs.SendDailySummaries()
	bs.SendMISWarnings()
}

// ===========================================================================
// NewTelegramNotifier
// ===========================================================================

func TestNewTelegramNotifier_EmptyToken(t *testing.T) {
	t.Parallel()
	notifier, err := NewTelegramNotifier("", nil, defaultTestLogger())
	assert.Nil(t, notifier)
	assert.NoError(t, err)
}

func TestTelegramNotifier_NilSafeMethods(t *testing.T) {
	t.Parallel()
	// Nil notifier should not panic on these methods.
	var tn *TelegramNotifier
	assert.Nil(t, tn.Bot())

	// Notify with nil should not panic.
	tn.Notify(&Alert{Email: "test@example.com", Direction: DirectionAbove}, 100.0)
}

func TestTelegramNotifier_SendMessage_NilSafe(t *testing.T) {
	t.Parallel()
	var tn *TelegramNotifier
	err := tn.SendMessage(12345, "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")

	err = tn.SendHTMLMessage(12345, "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

// ===========================================================================
// Store.DeleteByEmail
// ===========================================================================

func TestStore_DeleteByEmail(t *testing.T) {
	t.Parallel()
	s := newTestStore()

	s.Add("user@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)
	s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionBelow)
	s.SetTelegramChatID("user@example.com", 123456789)

	// Verify data exists
	assert.Len(t, s.List("user@example.com"), 2)
	_, ok := s.GetTelegramChatID("user@example.com")
	assert.True(t, ok)

	// Delete all data for user
	s.DeleteByEmail("user@example.com")

	// Verify data is gone
	assert.Empty(t, s.List("user@example.com"))
	_, ok = s.GetTelegramChatID("user@example.com")
	assert.False(t, ok)
}

func TestStore_DeleteByEmail_NonExistent(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	// Should not panic
	s.DeleteByEmail("nobody@example.com")
}

// ===========================================================================
// Store.GetEmailByChatID
// ===========================================================================

func TestStore_GetEmailByChatID(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	s.SetTelegramChatID("user@example.com", 123456789)

	email, ok := s.GetEmailByChatID(123456789)
	assert.True(t, ok)
	assert.Equal(t, "user@example.com", email)

	// Not found
	_, ok = s.GetEmailByChatID(999999)
	assert.False(t, ok)
}

// ===========================================================================
// Store.MarkNotificationSent
// ===========================================================================

func TestStore_MarkNotificationSent(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	id, _ := s.Add("user@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)

	now := time.Now()
	s.MarkNotificationSent(id, now)

	alerts := s.List("user@example.com")
	assert.Len(t, alerts, 1)
	assert.Equal(t, now.Unix(), alerts[0].NotificationSentAt.Unix())
}

func TestStore_MarkNotificationSent_NonExistent(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	// Should not panic
	s.MarkNotificationSent("nonexistent", time.Now())
}

// ===========================================================================
// PnL Snapshot service
// ===========================================================================

func TestNewPnLSnapshotService_NilDB(t *testing.T) {
	t.Parallel()
	svc := NewPnLSnapshotService(nil, nil, nil, defaultTestLogger())
	assert.Nil(t, svc)
}

// ===========================================================================
// NewEvaluator
// ===========================================================================

func TestNewEvaluator(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	e := NewEvaluator(s, defaultTestLogger())
	assert.NotNil(t, e)
}
