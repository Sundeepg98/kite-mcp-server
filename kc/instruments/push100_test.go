package instruments

// push100_test.go — tests targeting remaining uncovered lines in kc/instruments.

import (
	"context"
	"testing"
	"time"
)

// ===========================================================================
// manager.go:648-650 — getNextScheduledUpdate "tomorrow" branch
//
// When the scheduled update time has already passed today, the function
// adds 24 hours to schedule for tomorrow. We trigger this by setting
// UpdateHour/UpdateMinute to a time guaranteed to be in the past.
// ===========================================================================

func TestGetNextScheduledUpdate_Tomorrow(t *testing.T) {
	t.Parallel()

	// Set update time to midnight (00:00 IST) which is always in the past
	// unless the test runs exactly at midnight.
	config := DefaultUpdateConfig()
	config.EnableScheduler = false
	config.UpdateHour = 0
	config.UpdateMinute = 0

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := &Manager{
		isinToInstruments: make(map[string][]*Instrument),
		idToInst:          make(map[string]*Instrument),
		idToToken:         make(map[string]uint32),
		tokenToInstrument: make(map[uint32]*Instrument),
		segmentIDs:        make(map[string]uint32),
		lastUpdated:       time.Now(),
		instrumentsURL:    "http://localhost:1/never",
		config:            config,
		logger:            testLogger(),
		schedulerCtx:      ctx,
		schedulerCancel:   cancel,
		schedulerDone:     make(chan struct{}),
	}
	close(m.schedulerDone)
	defer m.Shutdown()

	stats := m.GetUpdateStats()
	now := time.Now().In(kolkataLoc)

	// The scheduled time should be tomorrow (since 00:00 IST already passed today).
	// Unless it's exactly midnight, the next update should be tomorrow.
	if now.Hour() > 0 || now.Minute() > 0 {
		if stats.ScheduledNextUpdate.Day() == now.Day() && stats.ScheduledNextUpdate.Month() == now.Month() {
			t.Error("Expected scheduled update to be tomorrow, but it's today")
		}
		// The scheduled time should be in the future.
		if stats.ScheduledNextUpdate.Before(now) {
			t.Error("Scheduled next update should be in the future")
		}
	}
}

// ===========================================================================
// manager.go:592-599 — startScheduler ticker.C branch
//
// COVERAGE: manager.go:592-599 — The scheduler goroutine's ticker.C branch
// executes when the 5-minute ticker fires and shouldUpdate() returns true.
// Testing this requires either:
//   1. Waiting 5 minutes for the ticker to fire (unacceptable in tests), or
//   2. Injecting a mock ticker (not supported by the current API).
//
// The code inside the branch (ForceUpdateInstruments) is tested directly
// by TestForceUpdateInstruments and TestStartScheduler_TickerBranch in
// manager_final_test.go. The goroutine plumbing is the only untested part.
//
// COVERAGE: unreachable in unit tests — requires 5-minute ticker wait.
// ===========================================================================
