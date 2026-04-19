//go:build race

package ticker

// raceEnabled is true when the binary is built with `-race`. See
// race_flag_off_test.go for the full rationale — this twin exists only
// so tests can pick up the right value regardless of build flags.
const raceEnabled = true
