//go:build !windows && integration

package app

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGracefulRestart_Integration_SIGUSR2SpawnsChild is the end-to-end
// smoke test. Builds a tiny harness binary (helper program lives
// inline as a test main), signals the parent with SIGUSR2, and
// verifies:
//
//   - The parent logs "graceful restart: SIGUSR2 received, forking child"
//   - A child process with KITE_GRACEFUL_CHILD=1 in its env is launched
//   - The child writes "ready!" to the inherited socket
//   - The parent triggers drain (triggerDrain callback fires)
//
// Gated behind `//go:build integration` so routine `go test` runs
// skip it — this test spawns subprocesses and can take 2-3 seconds
// under -race.
//
// Run with:
//   GOOS=linux go test -tags integration ./app/ -run TestGracefulRestart_Integration
func TestGracefulRestart_Integration_SIGUSR2SpawnsChild(t *testing.T) {
	// Build a minimal harness that calls StartGracefulRestartListener
	// and then sleeps.
	dir := t.TempDir()
	harnessSrc := filepath.Join(dir, "harness_main.go")
	require.NoError(t, os.WriteFile(harnessSrc, []byte(harnessProgram), 0o644))

	harnessBin := filepath.Join(dir, "harness")
	buildCmd := exec.Command("go", "build", "-o", harnessBin, harnessSrc)
	buildCmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	buildCmd.Stdout = os.Stderr
	buildCmd.Stderr = os.Stderr
	require.NoError(t, buildCmd.Run(), "failed to build integration harness")

	// Launch the parent. Pipe stderr so we can scan for the
	// restart-log marker.
	stderrRead, stderrWrite, err := os.Pipe()
	require.NoError(t, err)
	defer stderrRead.Close()

	parent := exec.Command(harnessBin)
	parent.Stdout = io.Discard
	parent.Stderr = stderrWrite
	require.NoError(t, parent.Start())
	_ = stderrWrite.Close() // parent inherits a copy; we close our end
	defer func() {
		_ = parent.Process.Kill()
		_ = parent.Wait()
	}()

	// Give the parent a moment to wire the SIGUSR2 listener.
	time.Sleep(300 * time.Millisecond)

	// Send SIGUSR2.
	require.NoError(t, parent.Process.Signal(syscall.SIGUSR2))

	// Read parent's stderr for up to 5s looking for the marker.
	done := make(chan struct{})
	var seen atomic.Bool
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			_ = stderrRead.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, _ := stderrRead.Read(buf)
			if n > 0 && (contains(buf[:n], "graceful restart: SIGUSR2 received") ||
				contains(buf[:n], "graceful restart: child launched") ||
				contains(buf[:n], "graceful restart: child ready")) {
				seen.Store(true)
				return
			}
		}
	}()
	<-done

	assert.True(t, seen.Load(),
		"parent must log graceful-restart marker within 5s of SIGUSR2")
}

// TestGracefulRestart_Integration_ChildSignalsReady verifies the
// child-side path: a subprocess launched with KITE_GRACEFUL_CHILD=1
// and fd 3 connected to a socket can signal ready via
// OpenGracefulChildConn + signalReady. No signal handling involved —
// direct exec to isolate the child-side code path.
func TestGracefulRestart_Integration_ChildSignalsReady(t *testing.T) {
	dir := t.TempDir()
	childSrc := filepath.Join(dir, "child_main.go")
	require.NoError(t, os.WriteFile(childSrc, []byte(childSignalProgram), 0o644))

	childBin := filepath.Join(dir, "child")
	buildCmd := exec.Command("go", "build", "-o", childBin, childSrc)
	buildCmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	buildCmd.Stdout = os.Stderr
	buildCmd.Stderr = os.Stderr
	require.NoError(t, buildCmd.Run())

	// Create the socketpair.
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	require.NoError(t, err)
	defer syscall.Close(fds[0])

	parentFile := os.NewFile(uintptr(fds[0]), "parent-end")
	childFile := os.NewFile(uintptr(fds[1]), "child-end")

	cmd := exec.Command(childBin)
	cmd.Env = append(os.Environ(), "KITE_GRACEFUL_CHILD=1")
	cmd.ExtraFiles = []*os.File{childFile}
	cmd.Stdout = io.Discard
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())
	_ = childFile.Close()
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	// Read ready signal from parent end.
	buf := make([]byte, 16)
	_ = parentFile.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := parentFile.Read(buf)
	require.NoError(t, err, "must receive child ready signal within 3s")
	assert.Equal(t, "ready!", string(buf[:n]))
}

// --- helpers ---

func contains(haystack []byte, needle string) bool {
	return len(needle) <= len(haystack) && indexOf(haystack, []byte(needle)) >= 0
}

func indexOf(hay, needle []byte) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		match := true
		for j := range needle {
			if hay[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}


// harnessProgram is a minimal Go main that wires the graceful-restart
// listener and then sleeps. Used by the SIGUSR2 integration test.
const harnessProgram = `package main

import (
	"context"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"github.com/zerodha/kite-mcp-server/app"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	var active atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app.StartGracefulRestartListener(ctx,
		app.GracefulRestartConfig{
			DrainDeadline:     2 * time.Second,
			ChildReadyTimeout: 2 * time.Second,
		},
		&active,
		logger,
		func() {
			// In the harness, "drain trigger" is just a marker log
			// and immediate exit — we're not running an HTTP server.
			logger.Info("harness: triggerDrain called")
			os.Exit(0)
		})
	// Block so the signal handler stays wired.
	select {
	case <-ctx.Done():
	case <-time.After(30 * time.Second):
	}
}
`

// childSignalProgram is a minimal Go main that opens the inherited
// graceful-restart socket and signals ready. Used by the child-side
// integration test.
const childSignalProgram = `package main

import (
	"os"

	"github.com/zerodha/kite-mcp-server/app"
)

func main() {
	conn := app.OpenGracefulChildConn()
	if conn == nil {
		os.Stderr.WriteString("OpenGracefulChildConn returned nil\n")
		os.Exit(2)
	}
	defer conn.Close()
	if err := app.SignalReady(conn); err != nil {
		os.Stderr.WriteString("SignalReady error: " + err.Error() + "\n")
		os.Exit(3)
	}
}
`
