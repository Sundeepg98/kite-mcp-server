package testutil

import (
	"io"
	"log/slog"

	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// DiscardLogger returns a slog.Logger that discards all output. It is the
// canonical no-op logger used by every package's test suite, so tests can
// converge on a single fixture instead of re-building their own.
func DiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// NoopLogger returns the kc/logger.Logger port wired to a no-op
// implementation — the test-time companion to DiscardLogger for code
// that has been migrated to depend on the Logger port instead of the
// concrete *slog.Logger. Both fixtures coexist during the gradual
// migration: pick whichever matches the constructor signature you're
// testing.
func NoopLogger() logport.Logger {
	return logport.NewNoop()
}

// CaptureLogger returns a fresh kc/logger.CaptureLogger so a test can
// assert "logger received X" without piping through io.Discard +
// regex matching. The returned value is both the *CaptureLogger
// (with a Records() method) and a Logger — the test can pass it into
// the system under test and read back observed records afterwards.
func CaptureLogger() *logport.CaptureLogger {
	return logport.NewCapture()
}
