package instruments

// ceil_test.go — coverage ceiling documentation for kc/instruments.
// Current: 98.3%. Ceiling: 98.3%.
//
// ===========================================================================
// manager.go
// ===========================================================================
//
// Lines 592-600: The entire `case <-ticker.C:` block in startScheduler.
//   The scheduler goroutine ticks every 5 minutes and calls shouldUpdate()
//   then ForceUpdateInstruments(). Testing this branch would require:
//   (a) Waiting 5 real minutes in a test (unacceptable).
//   (b) Injecting a fake ticker (no time injection available in this design).
//   The actual update logic (ForceUpdateInstruments, shouldUpdate) is tested
//   directly. The only untested code is the ticker delivery + conditional
//   execution path.
//
//   Specific uncovered lines within the block:
//   - Line 593: `if m.shouldUpdate()` — ticker delivery
//   - Line 594: `m.logger.Info("Starting scheduled instrument update")` — log
//   - Line 595: `if err := m.ForceUpdateInstruments(); err != nil` — update call
//   - Line 596: `m.logger.Error(...)` — error path
//   - Line 597-598: `} else { m.logger.Info(...)` — success path
//
//   All 5 lines are unreachable in tests (behind 5-minute ticker).
//
// ===========================================================================
// Summary
// ===========================================================================
//
// All uncovered lines (5 statements) are inside the ticker-driven branch of
// the background scheduler goroutine. The business logic (shouldUpdate,
// ForceUpdateInstruments) is fully tested.
//
// Ceiling: 98.3% (~5 unreachable statements out of ~290 total).
