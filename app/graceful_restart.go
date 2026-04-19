// Graceful restart (nginx -s reload style) for kite-mcp-server.
//
// On SIGUSR2, the running process (the "parent") fork-execs a fresh
// copy of os.Args[0] with an inherited socketpair FD. The child
// starts up, binds its listener(s), and once its /healthz probe
// returns 200 it writes "ready!" over the socketpair. The parent
// reads that message, stops accepting new connections, waits for
// in-flight HTTP handlers to drain (up to DrainDeadline), and
// exits cleanly. The child now owns all new traffic.
//
// The protocol here is deliberately portable-to-unit-test: the
// socketpair is replaced by a net.Pipe in tests (stream semantics
// identical). See graceful_restart_test.go.
//
// Signal + FD-passing primitives are unix-only — Windows Go
// ignores SIGUSR2 and `exec.Command` cannot pass listening socket
// FDs. The Windows build of this package ships a stub that logs
// "graceful restart not supported" and returns nil — see
// graceful_restart_windows.go.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"time"
)

// readyMessage is the canonical payload the child writes to the
// handshake socket once it is serving traffic. Parent reads
// exactly len(readyMessage) bytes and compares.
const readyMessage = "ready!"

// probeMessage is what the parent writes to the handshake socket
// BEFORE waiting for the child to signal ready. Gives the child a
// deterministic "your parent is listening" signal so it can't
// accidentally write to a closed fd.
const probeMessage = "ready?"

// ErrUnexpectedResponse is returned by askReady when the child
// writes bytes that aren't the expected readyMessage. Treated as
// fatal — a child that can't respect the protocol isn't trustable
// to take over traffic.
var ErrUnexpectedResponse = errors.New("unexpected response from child during graceful handshake")

// GracefulRestartConfig tunes the protocol timeouts.
//
// DrainDeadline is how long the parent waits for in-flight HTTP
// handlers to finish after the child signals ready. 30 seconds is
// the nginx default. If a request is still running after the
// deadline, the parent logs the count and exits anyway — losing a
// long-running request is worse than stalling the deploy forever.
//
// ChildReadyTimeout is how long the parent waits for the child to
// write "ready!" after fork-exec. 10 seconds is generous — a
// normal boot is <2s on Fly.io bom region. If the child doesn't
// signal ready, the parent does NOT drain; it logs the failure
// and continues serving (the old process is the only safe fallback
// when the new binary is broken).
type GracefulRestartConfig struct {
	DrainDeadline     time.Duration
	ChildReadyTimeout time.Duration
}

// WithDefaults fills in sensible defaults for zero-valued fields.
// Called once at Start time — operators who want overrides set
// them in the App config struct; nothing reads env vars here
// because graceful restart is a dev / deploy-time feature, not a
// per-request knob.
func (c GracefulRestartConfig) WithDefaults() GracefulRestartConfig {
	if c.DrainDeadline == 0 {
		c.DrainDeadline = 30 * time.Second
	}
	if c.ChildReadyTimeout == 0 {
		c.ChildReadyTimeout = 10 * time.Second
	}
	return c
}

// isGracefulChild reports whether THIS process was fork-execed by a
// parent doing graceful restart. Child-side main() checks this
// flag before signalling ready: if false, this is a fresh boot
// (no handshake fd inherited); if true, this binary must complete
// its ready-probe and signal upstream.
//
// Environment-variable contract: KITE_GRACEFUL_CHILD=1 enables.
// Only exact "1" — not "true", not "yes" — matches the exec.Cmd
// spawn convention where parents set a boolean env var to the
// literal string "1".
func isGracefulChild() bool {
	return os.Getenv("KITE_GRACEFUL_CHILD") == "1"
}

// askReady writes probeMessage to the handshake socket and waits
// for the child to write readyMessage back. Timeout applies to
// BOTH write and read — a child that accepts the probe but never
// responds must be treated as stuck.
//
// Returns nil on successful handshake, a wrapped deadline error on
// timeout, or ErrUnexpectedResponse if the child's payload doesn't
// match. The socket is NOT closed by this function — caller owns
// lifecycle (the child may also receive subsequent control
// messages in future protocol versions; closing here would break
// that extension).
func askReady(conn net.Conn, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set handshake deadline: %w", err)
	}
	if _, err := conn.Write([]byte(probeMessage)); err != nil {
		return fmt.Errorf("send probe: %w", err)
	}
	got, err := readExactN(conn, len(readyMessage))
	if err != nil {
		return fmt.Errorf("await ready: %w", err)
	}
	if string(got) != readyMessage {
		return fmt.Errorf("%w: got %q, want %q", ErrUnexpectedResponse, got, readyMessage)
	}
	return nil
}

// respondReady is the child-side counterpart: read the probe,
// write readyMessage back. Symmetric timeout to askReady.
// Idempotent against the probe arriving before the child has
// fully booted — the handshake socket is drained then replied to.
func respondReady(conn net.Conn, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set handshake deadline: %w", err)
	}
	// Drain whatever the parent sent. We don't strictly need to
	// parse probeMessage — any byte sequence that terminates a
	// read counts — but reading the exact-length probe lets future
	// protocol revisions introspect the bytes.
	if _, err := readExactN(conn, len(probeMessage)); err != nil {
		return fmt.Errorf("read probe: %w", err)
	}
	if _, err := conn.Write([]byte(readyMessage)); err != nil {
		return fmt.Errorf("send ready: %w", err)
	}
	return nil
}

// signalReady is a convenience for the child main() to fire the
// ready signal AFTER its /healthz returns 200. Unlike respondReady
// it doesn't require a prior probe — some deployments (systemd
// Type=notify style) flip the ready socket without a handshake.
// Idempotent: repeated calls on an already-closed socket return
// nil rather than panicking. Writes don't wait for the parent to
// have set a read deadline — if the pipe buffer is full and the
// parent is slow, the write blocks briefly.
func signalReady(conn net.Conn) error {
	if conn == nil {
		return nil
	}
	_, err := conn.Write([]byte(readyMessage))
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("signal ready: %w", err)
	}
	return nil
}

// SignalReady is the exported alias so the child-side main() (which
// lives in a separate `package main` outside this package) can
// invoke the ready-signal path after its /healthz reports green.
// Thin wrapper over signalReady — the underscore-prefix naming is
// just a style for the internal implementation.
func SignalReady(conn net.Conn) error {
	return signalReady(conn)
}

// readExactN reads exactly n bytes from r into a fresh buffer.
// Wraps io.ReadFull so short reads bubble ErrUnexpectedEOF — the
// protocol treats truncated child response as a fatal error.
func readExactN(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// waitForDrain polls the active-request counter until it hits zero
// or the deadline elapses. pollInterval controls how often the
// counter is checked (10ms is a good default for a 30s deadline —
// low overhead, good granularity). Returns nil when active hits 0,
// or an error naming the still-active count when the deadline
// fires.
func waitForDrain(active *atomic.Int32, deadline time.Duration, pollInterval time.Duration) error {
	if active.Load() == 0 {
		return nil
	}
	timeout := time.NewTimer(deadline)
	defer timeout.Stop()
	tick := time.NewTicker(pollInterval)
	defer tick.Stop()
	for {
		select {
		case <-timeout.C:
			n := active.Load()
			if n == 0 {
				return nil
			}
			return fmt.Errorf("drain deadline exceeded with %d in-flight requests", n)
		case <-tick.C:
			if active.Load() == 0 {
				return nil
			}
		}
	}
}

// GracefulRestartHandler is the function invoked by the SIGUSR2
// handler goroutine. Implementations fork-exec the child, perform
// the ready-handshake, and initiate drain. The production
// implementation lives in graceful_restart_unix.go (unix-only);
// graceful_restart_windows.go provides a logging stub.
//
// Contract: on success the handler must NOT return until the
// child is serving AND the drain has been initiated. Returning
// without either step is a programming error — the parent
// process continues listening, the child process may or may not
// have come up, and traffic routing is undefined.
type GracefulRestartHandler func(ctx context.Context) error

// handleGracefulRestartSignal invokes handler inside a panic-
// recovered scope so a buggy handler cannot kill the SIGUSR2
// listener goroutine. nil handler is a no-op (Windows stub path
// or tests that don't wire a real handler).
func handleGracefulRestartSignal(ctx context.Context, logger *slog.Logger, handler GracefulRestartHandler) {
	if handler == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			if logger != nil {
				logger.Error("graceful restart handler panicked", "panic", r)
			}
		}
	}()
	if err := handler(ctx); err != nil {
		if logger != nil {
			logger.Error("graceful restart failed", "error", err)
		}
	}
}
