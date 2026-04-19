package isttz

import (
	"testing"
	"time"
)

func TestLocation(t *testing.T) {
	t.Parallel()
	if Location == nil {
		t.Fatal("Location should not be nil")
	}
	if Location.String() != "Asia/Kolkata" {
		t.Errorf("Location = %q, want %q", Location.String(), "Asia/Kolkata")
	}
}

func TestLocationOffset(t *testing.T) {
	t.Parallel()
	// IST is UTC+5:30 = 19800 seconds.
	// Use a fixed time to get the zone offset (IST doesn't have DST so any time works).
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, Location)
	_, offset := now.Zone()
	if offset != 19800 {
		t.Errorf("offset = %d, want 19800 (UTC+5:30)", offset)
	}
}
