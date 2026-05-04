package ops

import (
	"log/slog"

	"github.com/zerodha/kite-mcp-server/kc/ops/shared"
)

// Backward-compatibility type aliases for the LogBuffer / TeeHandler
// observability primitives relocated to kc/ops/shared in Anchor 3
// PR 3.1. Existing kc/ops/ callers + external consumers continue to
// reference kc/ops.LogBuffer etc. via the alias chain unchanged.
//
// NewLogBuffer and NewTeeHandler are constructor passthroughs (Go
// does not allow function aliases, so these are thin function
// wrappers — zero-cost at the call site, identical pointer return).
type (
	LogEntry   = shared.LogEntry
	LogBuffer  = shared.LogBuffer
	TeeHandler = shared.TeeHandler
)

// NewLogBuffer is a passthrough to shared.NewLogBuffer for backward
// compatibility with the pre-PR-3.1 kc/ops.NewLogBuffer call site.
// New code should call shared.NewLogBuffer directly.
func NewLogBuffer(capacity int) *LogBuffer {
	return shared.NewLogBuffer(capacity)
}

// NewTeeHandler is a passthrough to shared.NewTeeHandler for backward
// compatibility. New code should call shared.NewTeeHandler directly.
func NewTeeHandler(inner slog.Handler, buf *LogBuffer) *TeeHandler {
	return shared.NewTeeHandler(inner, buf)
}
