package testutil

import (
	"io"
	"log/slog"
)

// DiscardLogger returns a slog.Logger that discards all output. It is the
// canonical no-op logger used by every package's test suite, so tests can
// converge on a single fixture instead of re-building their own.
func DiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
