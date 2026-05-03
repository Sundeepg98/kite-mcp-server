//go:build !windows

package app

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// StartGracefulRestartListener wires a SIGUSR2 handler that
// fork-execs a fresh copy of this binary, performs the
// parent-child ready handshake, and initiates drain on success.
//
// Wire-up (from the app's startup path):
//
//     app.StartGracefulRestartListener(ctx,
//         app.GracefulRestartConfig{}.WithDefaults(),
//         app.activeRequests,  // *atomic.Int32 tracking in-flight handlers
//         app.logger,
//         func() { app.shutdownCh <- struct{}{} }, // trigger drain
//     )
//
// Returns immediately; the listener runs in a background goroutine
// that exits when ctx is cancelled (i.e. when the process is
// shutting down for any other reason).
//
// Unix-only: this file is behind `//go:build !windows`. The
// Windows build of this package provides a logging-stub variant
// that returns nil without starting a listener.
//
// Wave D Phase 3 Package 7b (Logger sweep): the public *slog.Logger
// parameter is preserved as a back-compat shim so main.go and tests
// compile unchanged. Internally the listener and fork-exec handler
// route through logport.Logger via logport.NewSlog at the entry seam.
// When app.go's app.logger field migrates (Package 7c) the call site
// can flip to a port-typed accessor and this shim drops in Package 8.
func StartGracefulRestartListener(
	ctx context.Context,
	cfg GracefulRestartConfig,
	active *atomic.Int32,
	logger *slog.Logger,
	triggerDrain func(),
) {
	startGracefulRestartListenerWithPort(ctx, cfg, active, logport.NewSlog(logger), triggerDrain)
}

// startGracefulRestartListenerWithPort is the canonical Wave D Phase 3
// implementation. Unexported because the public StartGracefulRestartListener
// is the one main.go calls; this internal variant is the migration
// landing zone (Package 7c may export it once app.logger is port-typed).
func startGracefulRestartListenerWithPort(
	ctx context.Context,
	cfg GracefulRestartConfig,
	active *atomic.Int32,
	logger logport.Logger,
	triggerDrain func(),
) {
	cfg = cfg.WithDefaults()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGUSR2)

	go func() {
		defer signal.Stop(sigCh)
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigCh:
				handler := buildForkExecHandlerWithPort(cfg, active, logger, triggerDrain)
				handleGracefulRestartSignalWithPort(ctx, logger, handler)
				// After a successful graceful restart the parent
				// process exits via triggerDrain's normal path.
				// If we get here, the restart FAILED and we want
				// to remain serving — loop back to wait for
				// another SIGUSR2.
			}
		}
	}()
}

// buildForkExecHandlerWithPort is the canonical Wave D Phase 3
// implementation. The handler closure receives the cancellation ctx
// from the SIGUSR2 listener, threading it through every log call so
// the restart event chain has consistent trace correlation.
func buildForkExecHandlerWithPort(
	cfg GracefulRestartConfig,
	active *atomic.Int32,
	logger logport.Logger,
	triggerDrain func(),
) GracefulRestartHandler {
	return func(ctx context.Context) error {
		if logger != nil {
			logger.Info(ctx, "graceful restart: SIGUSR2 received, forking child")
		}

		parentConn, childFile, err := makeSocketpair()
		if err != nil {
			return fmt.Errorf("socketpair: %w", err)
		}
		defer parentConn.Close()
		defer childFile.Close()

		// Fork-exec the same binary with inherited FD + env flag.
		executable, err := os.Executable()
		if err != nil {
			return fmt.Errorf("locate executable: %w", err)
		}
		// #nosec G702 G204 -- self-fork-exec of os.Executable() with the same os.Args we were launched with; not user input.
		cmd := exec.Command(executable, os.Args[1:]...)
		cmd.Env = append(os.Environ(), "KITE_GRACEFUL_CHILD=1")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.ExtraFiles = []*os.File{childFile}

		if err := cmd.Start(); err != nil {
			return fmt.Errorf("fork child: %w", err)
		}
		if logger != nil {
			logger.Info(ctx, "graceful restart: child launched", "pid", cmd.Process.Pid)
		}

		// Wait for the child to write readyMessage.
		if err := askReady(parentConn, cfg.ChildReadyTimeout); err != nil {
			if logger != nil {
				logger.Error(ctx, "graceful restart: child failed to signal ready; parent stays up",
					err, "child_pid", cmd.Process.Pid)
			}
			// Don't kill the child — it might be a slow-boot that
			// just missed the deadline. The operator will notice
			// the failed restart via logs and can retry.
			return fmt.Errorf("child not ready: %w", err)
		}
		if logger != nil {
			logger.Info(ctx, "graceful restart: child ready, starting parent drain",
				"child_pid", cmd.Process.Pid,
				"drain_deadline", cfg.DrainDeadline)
		}

		// Child is live. Stop accepting new traffic — triggerDrain
		// closes the shutdown channel, which the existing
		// setupGracefulShutdown goroutine handles (stops scheduler,
		// calls srv.Shutdown which drains in-flight handlers, etc.).
		if triggerDrain != nil {
			triggerDrain()
		}

		// Optional: also wait here so we can log the final status.
		// The http.Server.Shutdown path inside setupGracefulShutdown
		// handles its own 10-second deadline; we layer a
		// DrainDeadline on top so the restart logs a clean "drain
		// complete" message matching the nginx ecosystem.
		if active != nil {
			if err := waitForDrain(active, cfg.DrainDeadline, 50*time.Millisecond); err != nil {
				if logger != nil {
					logger.Warn(ctx, "graceful restart: drain deadline exceeded", "error", err)
				}
			} else if logger != nil {
				logger.Info(ctx, "graceful restart: drain complete, parent exiting")
			}
		}
		return nil
	}
}

// makeSocketpair creates a unix domain socketpair, wraps the
// parent end as a net.Conn (for convenient Read/Write/Deadline
// usage), and returns the child end as *os.File (what exec.Cmd
// needs for ExtraFiles inheritance).
//
// The child side is NOT wrapped as net.Conn because exec.Cmd
// ExtraFiles requires *os.File, and wrapping and re-unwrapping
// loses the file descriptor number the child needs to dup.
func makeSocketpair() (parentConn net.Conn, childFile *os.File, err error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("syscall.Socketpair: %w", err)
	}
	// Parent side.
	parentFile := os.NewFile(uintptr(fds[0]), "graceful-restart-parent")
	parent, err := net.FileConn(parentFile)
	// net.FileConn dups the fd; close the original file handle.
	// We no longer need parentFile after net.FileConn succeeds.
	_ = parentFile.Close()
	if err != nil {
		_ = syscall.Close(fds[1]) //nolint:errcheck // best-effort cleanup on error path
		return nil, nil, fmt.Errorf("net.FileConn: %w", err)
	}
	// Child side — returned as *os.File for ExtraFiles inheritance.
	child := os.NewFile(uintptr(fds[1]), "graceful-restart-child")
	return parent, child, nil
}

// OpenGracefulChildConn is called from the CHILD-side main() when
// isGracefulChild() reports true. It re-wraps the inherited FD
// (exec.Cmd ExtraFiles[0] shows up as fd 3 in the child) as a
// net.Conn the child can use to signalReady once /healthz is
// green.
//
// Returns nil if this process was not spawned as a graceful child,
// or if the inherited fd cannot be opened (something went wrong
// with ExtraFiles — rare).
func OpenGracefulChildConn() net.Conn {
	if !isGracefulChild() {
		return nil
	}
	// exec.Cmd ExtraFiles[0] is inherited as fd 3 (stdin=0,
	// stdout=1, stderr=2, then ExtraFiles in order). Python's
	// os.fdopen, Node's fs.createReadStream, and Rust std all
	// follow the same convention.
	const inheritedFd = 3
	f := os.NewFile(inheritedFd, "graceful-restart-child-socket")
	if f == nil {
		return nil
	}
	conn, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		return nil
	}
	return conn
}
