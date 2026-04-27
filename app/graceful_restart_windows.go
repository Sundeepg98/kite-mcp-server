//go:build windows

package app

import (
	"context"
	"log/slog"
	"net"
	"sync/atomic"

	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// StartGracefulRestartListener is a Windows-only stub that logs a
// one-line "not supported" message and returns. Graceful-restart
// on unix relies on:
//
//   - signal.Notify(ch, syscall.SIGUSR2) — SIGUSR2 doesn't exist on Windows.
//   - exec.Cmd ExtraFiles — inherited file descriptors work
//     differently on Windows (HANDLE inheritance via lpReserved2).
//   - syscall.Socketpair — not implemented on Windows in Go.
//
// All three would need per-platform reimplementation (roughly:
// use a named pipe + WM_USER-class Windows message or a registered
// console-control event). Doable, but the Windows host is a
// developer machine — the production target is Linux (Fly.io bom
// region), where SIGUSR2 restart is the canonical path. Operators
// who want graceful restart on Windows should run under WSL2.
//
// The stub exists so the Windows build compiles cleanly and
// main.go can call StartGracefulRestartListener unconditionally
// regardless of target OS.
//
// Wave D Phase 3 Package 7b: signature retained for back-compat;
// internally wraps via logport.NewSlog. The unix variant has the
// matching shape — see graceful_restart_unix.go for rationale.
// Pre-migration semantic preserved: when logger is nil, the
// "not wired" message is suppressed (no slog.Default() fallback —
// matches the prior `if logger != nil { logger.Info(...) }` guard).
func StartGracefulRestartListener(
	ctx context.Context,
	_ GracefulRestartConfig,
	_ *atomic.Int32,
	logger *slog.Logger,
	_ func(),
) {
	if logger != nil {
		logport.NewSlog(logger).Info(ctx, "graceful restart: SIGUSR2 handler not wired on Windows (use WSL2 for hot-restart; production target is Linux)")
	}
}

// OpenGracefulChildConn returns nil on Windows. The equivalent of
// ExtraFiles FD inheritance would need to come through a named-pipe
// path rather than a low integer fd; future Windows work can
// implement that when the developer workflow needs it.
func OpenGracefulChildConn() net.Conn {
	return nil
}
