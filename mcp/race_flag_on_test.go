//go:build race

package mcp

// raceEnabled is true when the binary is built with `-race`. See
// race_flag_off_test.go for rationale.
const raceEnabled = true
