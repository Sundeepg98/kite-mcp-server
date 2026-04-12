package telegram

// ceil_test.go — coverage ceiling documentation for kc/telegram.
// Current: 99.8%. Ceiling: 99.8%.
//
// ===========================================================================
// bot.go
// ===========================================================================
//
// Lines 125-126: `case <-ticker.C: h.cleanupStaleEntries()`
//   in runCleanup — the goroutine's ticker fires every 2 minutes. Testing
//   this branch would require either:
//   (a) Waiting 2 real minutes in a test (unacceptable).
//   (b) Injecting a fake ticker (no time injection available in this design).
//   The actual cleanup logic (cleanupStaleEntries) is tested directly in
//   existing tests. The only untested code is the ticker delivery path.
//   Unreachable in tests.
//
// ===========================================================================
// Summary
// ===========================================================================
//
// The sole uncovered line is the ticker-driven branch in the background
// cleanup goroutine. The cleanup logic itself is fully tested.
//
// Ceiling: 99.8% (1 unreachable ticker branch out of ~500 statements).
