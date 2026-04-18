package audit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCleanupOldRecords_DeletesOldKeepsNew verifies that CleanupOldRecords
// removes entries older than the cutoff and preserves newer ones.
func TestCleanupOldRecords_DeletesOldKeepsNew(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	now := time.Now().UTC().Truncate(time.Microsecond)
	// Old entry: 100 days ago (older than 90-day retention)
	// New entry: today (within 90-day retention)
	oldEntry := makeEntry("cleanup-old-001", "keep@test.com", "get_ltp", "market_data", false, now.Add(-100*24*time.Hour))
	newEntry := makeEntry("cleanup-new-001", "keep@test.com", "get_ltp", "market_data", false, now)

	require.NoError(t, s.Record(oldEntry))
	require.NoError(t, s.Record(newEntry))

	// Sanity: both present.
	_, total, err := s.List("keep@test.com", ListOptions{})
	require.NoError(t, err)
	require.Equal(t, 2, total, "expected 2 rows before cleanup")

	// Run cleanup at 90-day retention — should delete the 100-day-old row only.
	deleted, err := s.CleanupOldRecords(90)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted, "CleanupOldRecords should delete 1 old row")

	// Confirm only the newer row survives.
	results, total, err := s.List("keep@test.com", ListOptions{})
	require.NoError(t, err)
	assert.Equal(t, 1, total, "expected 1 row after cleanup")
	require.Len(t, results, 1)
	assert.Equal(t, "cleanup-new-001", results[0].CallID)
}

// TestCleanupOldRecords_Disabled verifies that passing days <= 0 is a no-op
// (no rows deleted, no error). This is how operators disable retention via
// AUDIT_RETENTION_DAYS=0.
func TestCleanupOldRecords_Disabled(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	now := time.Now().UTC().Truncate(time.Microsecond)
	// Insert an entry that WOULD be deleted under any positive retention.
	old := makeEntry("disabled-001", "disabled@test.com", "get_ltp", "market_data", false, now.Add(-10000*24*time.Hour))
	require.NoError(t, s.Record(old))

	// days = 0 → disabled → no-op, no error.
	deleted, err := s.CleanupOldRecords(0)
	require.NoError(t, err)
	assert.Equal(t, int64(0), deleted, "days=0 should be a no-op")

	// days = -1 → disabled → no-op, no error.
	deleted, err = s.CleanupOldRecords(-1)
	require.NoError(t, err)
	assert.Equal(t, int64(0), deleted, "days=-1 should be a no-op")

	// Row should still be present.
	_, total, err := s.List("disabled@test.com", ListOptions{})
	require.NoError(t, err)
	assert.Equal(t, 1, total, "row should survive when cleanup is disabled")
}

// TestCleanupOldRecords_ReturnsDeletedCount verifies the returned count
// matches the number of rows actually removed.
func TestCleanupOldRecords_ReturnsDeletedCount(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	now := time.Now().UTC().Truncate(time.Microsecond)
	// Insert 3 old rows and 2 new rows.
	for i, callID := range []string{"old-a", "old-b", "old-c"} {
		e := makeEntry(callID, "count@test.com", "get_ltp", "market_data", false, now.Add(-time.Duration(100+i)*24*time.Hour))
		require.NoError(t, s.Record(e))
	}
	for _, callID := range []string{"new-a", "new-b"} {
		e := makeEntry(callID, "count@test.com", "get_ltp", "market_data", false, now)
		require.NoError(t, s.Record(e))
	}

	// 90-day retention deletes the 3 old rows, keeps the 2 new rows.
	deleted, err := s.CleanupOldRecords(90)
	require.NoError(t, err)
	assert.Equal(t, int64(3), deleted, "expected 3 rows deleted")

	// Running cleanup again on the same data returns 0 (idempotent).
	deleted, err = s.CleanupOldRecords(90)
	require.NoError(t, err)
	assert.Equal(t, int64(0), deleted, "second cleanup should delete 0 rows")
}

// TestRetentionDaysFromEnv verifies AUDIT_RETENTION_DAYS env var parsing.
// 0, negative, or invalid values are treated as "use default"; positive
// integers override the default.
func TestRetentionDaysFromEnv(t *testing.T) {
	tests := []struct {
		name    string
		envVal  string // "" means env var unset
		defVal  int
		want    int
	}{
		{"unset uses default", "", 90, 90},
		{"explicit 30 overrides", "30", 90, 30},
		{"explicit 1825 overrides", "1825", 90, 1825},
		{"explicit 0 disables (returns 0)", "0", 90, 0},
		{"negative treated as disable", "-5", 90, 0},
		{"garbage falls back to default", "not-a-number", 90, 90},
		{"empty string falls back to default", "", 90, 90},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if tc.envVal == "" {
				t.Setenv("AUDIT_RETENTION_DAYS", "")
			} else {
				t.Setenv("AUDIT_RETENTION_DAYS", tc.envVal)
			}
			got := retentionDaysFromEnv(tc.defVal)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestStartRetentionWorker_Disabled verifies that StartRetentionWorker with
// days <= 0 does not start a goroutine — StopRetentionWorker becomes a no-op.
func TestStartRetentionWorker_Disabled(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	// Start with retention disabled.
	s.StartRetentionWorker(0)

	// Stop should not hang — the worker was never launched.
	done := make(chan struct{})
	go func() {
		s.StopRetentionWorker()
		close(done)
	}()
	select {
	case <-done:
		// Good — Stop returned immediately.
	case <-time.After(2 * time.Second):
		t.Fatal("StopRetentionWorker hung when worker was never started")
	}
}

// TestStartRetentionWorker_StartsAndStops verifies that enabling the worker
// spawns a goroutine that can be stopped cleanly.
func TestStartRetentionWorker_StartsAndStops(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	s.StartRetentionWorker(90)

	// The goroutine has a 24h ticker — we won't wait that long. Instead we
	// verify that Stop drains the goroutine quickly.
	done := make(chan struct{})
	go func() {
		s.StopRetentionWorker()
		close(done)
	}()
	select {
	case <-done:
		// Good — worker exited promptly on Stop.
	case <-time.After(2 * time.Second):
		t.Fatal("StopRetentionWorker did not return within 2s")
	}
}
