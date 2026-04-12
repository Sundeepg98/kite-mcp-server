package metrics

// ceil_test.go — coverage ceiling documentation for app/metrics.
// Current: 99.3%. Ceiling: 99.3%.
//
// ===========================================================================
// metrics.go
// ===========================================================================
//
// Line 194: `case <-time.After(delay): _ = m.CleanupOldData()`
//   in startCleanupRoutine — the goroutine waits until the next Saturday at
//   3 AM UTC to fire. Testing this branch would require:
//   (a) Waiting days in a test (unacceptable).
//   (b) Injecting a fake clock (no time injection available in this design).
//   The actual cleanup logic (CleanupOldData) and the scheduling calculation
//   (getNextCleanupTime) are both tested directly. The only untested code is
//   the timer delivery path in the goroutine.
//   Unreachable in tests.
//
// ===========================================================================
// Summary
// ===========================================================================
//
// The sole uncovered line is the timer-driven branch in the background
// cleanup goroutine. Both CleanupOldData and getNextCleanupTime are fully tested.
//
// Ceiling: 99.3% (1 unreachable timer branch out of ~150 statements).
