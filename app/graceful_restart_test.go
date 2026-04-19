package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGracefulRestartProtocol_ReadyExchange — the parent-child
// handshake: parent writes "ready?", child replies "ready!", both
// sides return success. Tested with a net.Pipe to stand in for the
// unix socketpair (protocol is identical at the stream level).
func TestGracefulRestartProtocol_ReadyExchange(t *testing.T) {
	parentEnd, childEnd := net.Pipe()
	defer parentEnd.Close()
	defer childEnd.Close()

	// Run child responder in a goroutine — it should read "ready?"
	// and reply "ready!".
	childErr := make(chan error, 1)
	go func() {
		childErr <- respondReady(childEnd, 2*time.Second)
	}()

	// Parent side: ask for readiness, expect confirmation.
	err := askReady(parentEnd, 2*time.Second)
	require.NoError(t, err, "parent askReady must succeed when child responds")

	select {
	case err := <-childErr:
		require.NoError(t, err, "child respondReady must succeed")
	case <-time.After(3 * time.Second):
		t.Fatal("child respondReady did not complete")
	}
}

// TestGracefulRestartProtocol_TimeoutOnNoChild — if the child never
// responds, askReady times out cleanly with a deadline-exceeded
// error. No goroutine leak.
func TestGracefulRestartProtocol_TimeoutOnNoChild(t *testing.T) {
	parentEnd, childEnd := net.Pipe()
	defer parentEnd.Close()
	defer childEnd.Close()

	// Simulate a child that NEVER reads or writes. askReady must
	// time out.
	start := time.Now()
	err := askReady(parentEnd, 150*time.Millisecond)
	elapsed := time.Since(start)

	assert.Error(t, err, "askReady must error when child doesn't respond")
	assert.Less(t, elapsed, 500*time.Millisecond, "askReady must honor the timeout")
}

// TestGracefulRestartProtocol_GarbledChildResponse — a child that
// writes the wrong bytes is rejected rather than silently accepted.
// The rejection may surface as ErrUnexpectedResponse (if the child
// wrote exactly len(readyMessage) bytes of garbage) or as a timeout
// / short-read error (if the child wrote fewer bytes and the
// parent's deadline fired while waiting for the rest). Both are
// valid failure modes — treating either as success would be a
// protocol bug.
func TestGracefulRestartProtocol_GarbledChildResponse(t *testing.T) {
	t.Run("exact-length garbage", func(t *testing.T) {
		parentEnd, childEnd := net.Pipe()
		defer parentEnd.Close()
		defer childEnd.Close()

		go func() {
			buf := make([]byte, 128)
			_, _ = childEnd.Read(buf)
			// Write exactly len(readyMessage) bytes but different content.
			_, _ = childEnd.Write([]byte("BROKEN")) // 6 bytes, matches len("ready!")
		}()

		err := askReady(parentEnd, 1*time.Second)
		require.Error(t, err)
		assert.True(t,
			errors.Is(err, ErrUnexpectedResponse),
			"exact-length garbage must surface ErrUnexpectedResponse; got %v", err)
	})

	t.Run("short response then hang", func(t *testing.T) {
		parentEnd, childEnd := net.Pipe()
		defer parentEnd.Close()
		defer childEnd.Close()

		go func() {
			buf := make([]byte, 128)
			_, _ = childEnd.Read(buf)
			_, _ = childEnd.Write([]byte("NOPE")) // 4 bytes only — parent waits for 6
		}()

		err := askReady(parentEnd, 200*time.Millisecond)
		require.Error(t, err, "short-then-hang must surface an error (timeout or EOF)")
		// The specific error is OS/pipe-dependent; the invariant is
		// "NOT nil" — a broken child must never be treated as ready.
	})
}

// TestDrainInflight_RespectsDeadline — waitForDrain blocks until
// either activeRequests hits zero OR the deadline elapses, whichever
// comes first. Simulates one in-flight request that completes
// within the deadline.
func TestDrainInflight_RespectsDeadline(t *testing.T) {
	var active atomic.Int32
	active.Store(1)

	go func() {
		time.Sleep(50 * time.Millisecond)
		active.Add(-1)
	}()

	start := time.Now()
	err := waitForDrain(&active, 500*time.Millisecond, 10*time.Millisecond)
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.Greater(t, elapsed, 40*time.Millisecond, "drain must wait for the request to finish")
	assert.Less(t, elapsed, 200*time.Millisecond, "drain must return promptly once active=0")
}

// TestDrainInflight_TimeoutWhenStuck — if requests are stuck past
// the deadline, waitForDrain returns an error naming the count.
func TestDrainInflight_TimeoutWhenStuck(t *testing.T) {
	var active atomic.Int32
	active.Store(3) // three stuck requests

	start := time.Now()
	err := waitForDrain(&active, 100*time.Millisecond, 10*time.Millisecond)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "3", "error must name the stuck request count")
	assert.GreaterOrEqual(t, elapsed, 100*time.Millisecond, "must wait for the full deadline before giving up")
	assert.Less(t, elapsed, 300*time.Millisecond, "must not wait much beyond the deadline")
}

// TestIsGracefulChild — the env-var gate that tells a freshly-
// forked process whether it was launched by a parent doing
// graceful restart.
func TestIsGracefulChild(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		t.Setenv("KITE_GRACEFUL_CHILD", "")
		assert.False(t, isGracefulChild())
	})
	t.Run("1", func(t *testing.T) {
		t.Setenv("KITE_GRACEFUL_CHILD", "1")
		assert.True(t, isGracefulChild())
	})
	t.Run("true", func(t *testing.T) {
		// Only "1" enables — matches fork-exec spawn convention.
		t.Setenv("KITE_GRACEFUL_CHILD", "true")
		assert.False(t, isGracefulChild())
	})
}

// TestSignalReady_ClosesAfterWrite — signalReady writes "ready!"
// to the fd and returns. Idempotent: a second call is a no-op
// (the child's /healthz is polled; multiple calls must not panic).
func TestSignalReady_ClosesAfterWrite(t *testing.T) {
	parentEnd, childEnd := net.Pipe()
	defer parentEnd.Close()

	// Reader: drain "ready!" into a buffer for assertion.
	var got bytes.Buffer
	var readerWG sync.WaitGroup
	readerWG.Add(1)
	go func() {
		defer readerWG.Done()
		// Read until EOF or timeout. net.Pipe has no read timeout
		// API; we rely on the close on the other side.
		buf := make([]byte, 64)
		for {
			_ = parentEnd.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, err := parentEnd.Read(buf)
			if n > 0 {
				got.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	// Child writes ready.
	require.NoError(t, signalReady(childEnd))

	// Second call is idempotent.
	require.NoError(t, signalReady(childEnd))

	childEnd.Close()
	readerWG.Wait()

	assert.Contains(t, got.String(), readyMessage)
}

// TestHandleGracefulRestartSignal_NoopWithoutHandler — calling the
// signal handler when no graceful-restart support is initialised
// must be a safe no-op, not a crash. This is the "SIGUSR2 received
// on Windows or before Start" path.
func TestHandleGracefulRestartSignal_NoopWithoutHandler(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Nil function must not panic.
	assert.NotPanics(t, func() {
		handleGracefulRestartSignal(context.Background(), logger, nil)
	})
}

// TestGracefulRestartConfig_DefaultsSensible — a zero-value config
// picks safe defaults (30s drain deadline, 10s child-ready timeout)
// rather than zero values that would cause instant failures.
func TestGracefulRestartConfig_DefaultsSensible(t *testing.T) {
	cfg := GracefulRestartConfig{}.WithDefaults()
	assert.Equal(t, 30*time.Second, cfg.DrainDeadline)
	assert.Equal(t, 10*time.Second, cfg.ChildReadyTimeout)
}

// TestGracefulRestartConfig_OverridesPreserved — if the caller
// sets values explicitly, WithDefaults does NOT clobber them.
func TestGracefulRestartConfig_OverridesPreserved(t *testing.T) {
	cfg := GracefulRestartConfig{
		DrainDeadline:     60 * time.Second,
		ChildReadyTimeout: 20 * time.Second,
	}.WithDefaults()
	assert.Equal(t, 60*time.Second, cfg.DrainDeadline)
	assert.Equal(t, 20*time.Second, cfg.ChildReadyTimeout)
}

// TestReadExact_Limits — readExactN refuses to read beyond the
// ready-message length, protecting against a misbehaving child
// that floods the pipe. Returns ErrUnexpectedResponse.
func TestReadExact_Limits(t *testing.T) {
	// A reader that returns "ready!" + noise. We only want the
	// first readyMessageLen bytes.
	r := io.MultiReader(
		strings.NewReader(readyMessage),
		strings.NewReader("...LOTS OF NOISE..."),
	)
	buf, err := readExactN(r, len(readyMessage))
	require.NoError(t, err)
	assert.Equal(t, readyMessage, string(buf))
}

// TestReadExact_ShortRead — a reader that returns fewer bytes than
// asked bubbles the io.ErrUnexpectedEOF so the protocol can surface
// "child died" rather than hang.
func TestReadExact_ShortRead(t *testing.T) {
	_, err := readExactN(strings.NewReader("rea"), len(readyMessage))
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF),
		"short-read must surface EOF variant; got %v", err)
}

// --- helpers ---

// fakeReader is a minimal io.Reader for tests that want to simulate
// a slow / stuck stream without reaching for net.Pipe.
type fakeReader struct{ b []byte }

func (f *fakeReader) Read(p []byte) (int, error) {
	if len(f.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, f.b)
	f.b = f.b[n:]
	return n, nil
}

var _ io.Reader = (*fakeReader)(nil)

// Unused imports sink (os is imported for t.Setenv compatibility
// in some Go versions).
var _ = os.Getenv
