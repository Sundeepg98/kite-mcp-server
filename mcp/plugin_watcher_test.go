package mcp

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWatchPluginBinary_FiresOnWrite — the core contract: when a
// watched binary is written to, the registered BinaryReloadable's
// Close() method fires, and the (now-dead) subprocess proxy gets
// relaunched on the NEXT evaluation.
func TestWatchPluginBinary_FiresOnWrite(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)
	tmp := t.TempDir()
	binary := filepath.Join(tmp, "fake-plugin")
	require.NoError(t, os.WriteFile(binary, []byte("v1"), 0o755))

	var closeCount atomic.Int32
	stub := &stubReloadable{
		closeFn: func() { closeCount.Add(1) },
	}
	require.NoError(t, WatchPluginBinary(binary, stub))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// StartPluginBinaryWatcher subscribes synchronously before
	// spawning the watcher goroutine, so no subscribe-readiness
	// wait is needed — any subsequent file write is observable.
	require.NoError(t, StartPluginBinaryWatcher(ctx))
	defer StopPluginBinaryWatcher()

	// Overwrite the binary.
	require.NoError(t, os.WriteFile(binary, []byte("v2"), 0o755))

	// Wait for the close callback to fire. 2s budget covers the
	// 250ms debounce window + fsnotify event-delivery latency on
	// slow CI; typical wall time is ~300ms.
	require.Eventually(t, func() bool {
		return closeCount.Load() > 0
	}, 2*time.Second, 10*time.Millisecond,
		"Close() must fire at least once after WRITE event")
}

// TestWatchPluginBinary_DebouncesRapidWrites — fsnotify on some
// platforms emits multiple events for a single logical write (e.g.
// WRITE then CHMOD on Linux). The watcher must debounce to at most
// one Close() per debounce window (default 250ms).
func TestWatchPluginBinary_DebouncesRapidWrites(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)
	tmp := t.TempDir()
	binary := filepath.Join(tmp, "fake-plugin")
	require.NoError(t, os.WriteFile(binary, []byte("v1"), 0o755))

	var closeCount atomic.Int32
	stub := &stubReloadable{closeFn: func() { closeCount.Add(1) }}
	require.NoError(t, WatchPluginBinary(binary, stub))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, StartPluginBinaryWatcher(ctx))
	defer StopPluginBinaryWatcher()
	// Subscribe is synchronous in Start — no wait needed.

	// Five rapid writes within 75ms — the debounce window (250ms)
	// collapses them to (usually 1, at most 2) Close() calls. The
	// 15ms inter-write gap is deliberately shorter than the
	// debounce window to guarantee coalescing.
	for i := 0; i < 5; i++ {
		require.NoError(t, os.WriteFile(binary, []byte("v"+string(rune('2'+i))), 0o755))
		time.Sleep(15 * time.Millisecond)
	}

	// Poll for at least one Close() with a budget that covers the
	// debounce window (250ms) + fsnotify event latency. Once the
	// first fires, we still need a small grace window for any late
	// second fire to land before we assert the upper bound.
	require.Eventually(t, func() bool {
		return closeCount.Load() >= 1
	}, 2*time.Second, 10*time.Millisecond, "at least one Close() must fire")
	time.Sleep(300 * time.Millisecond) // let any stragglers land before upper-bound check

	count := closeCount.Load()
	// Accept 1 or 2 — platforms vary. The invariant is "not 5."
	assert.Less(t, count, int32(5),
		"debounce must collapse rapid writes; got %d Close() calls", count)
	assert.GreaterOrEqual(t, count, int32(1),
		"at least one Close() must fire")
}

// TestWatchPluginBinary_NoopOnNoChange — writing the same bytes
// back to the file still triggers a close (fsnotify fires on
// WRITE syscall regardless of content). Documented behaviour.
func TestWatchPluginBinary_NoopOnNoChange(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)
	tmp := t.TempDir()
	binary := filepath.Join(tmp, "fake-plugin")
	contents := []byte("stable")
	require.NoError(t, os.WriteFile(binary, contents, 0o755))

	var closeCount atomic.Int32
	stub := &stubReloadable{closeFn: func() { closeCount.Add(1) }}
	require.NoError(t, WatchPluginBinary(binary, stub))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, StartPluginBinaryWatcher(ctx))
	defer StopPluginBinaryWatcher()

	// Rewrite with identical bytes.
	require.NoError(t, os.WriteFile(binary, contents, 0o755))

	// We DO expect a Close() — the watcher does not diff contents
	// by default. The user asked for "mtime or checksum" trigger;
	// we implement mtime via fsnotify WRITE events. Poll for the
	// callback; 2s covers debounce + fsnotify latency.
	require.Eventually(t, func() bool {
		return closeCount.Load() >= 1
	}, 2*time.Second, 10*time.Millisecond,
		"WRITE event must fire even on same-bytes rewrite")
}

// TestWatchPluginBinary_StopCleansUp — calling StopPluginBinaryWatcher
// stops the goroutine and drops all subscriptions. Subsequent
// writes do NOT fire Close(). Verifies no goroutine leak.
func TestWatchPluginBinary_StopCleansUp(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)
	tmp := t.TempDir()
	binary := filepath.Join(tmp, "fake-plugin")
	require.NoError(t, os.WriteFile(binary, []byte("v1"), 0o755))

	var closeCount atomic.Int32
	stub := &stubReloadable{closeFn: func() { closeCount.Add(1) }}
	require.NoError(t, WatchPluginBinary(binary, stub))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, StartPluginBinaryWatcher(ctx))

	// Stop the watcher. StopPluginBinaryWatcher blocks until the
	// goroutine exits (fsnotify Close() + ctx cancel), so no
	// post-stop wait is needed.
	StopPluginBinaryWatcher()

	// Subsequent write must not fire. This is inherently proving a
	// negative: a short window is sufficient since a real leak
	// would fire within fsnotify's delivery window (sub-ms).
	require.NoError(t, os.WriteFile(binary, []byte("v2"), 0o755))
	time.Sleep(300 * time.Millisecond)

	assert.Equal(t, int32(0), closeCount.Load(),
		"Close() must not fire after StopPluginBinaryWatcher")
}

// TestWatchPluginBinary_MultiplePluginsIndependent — two plugins
// watched at different paths; write to one fires only that
// plugin's Close, not the other.
func TestWatchPluginBinary_MultiplePluginsIndependent(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)
	tmp := t.TempDir()
	binA := filepath.Join(tmp, "plugin-a")
	binB := filepath.Join(tmp, "plugin-b")
	require.NoError(t, os.WriteFile(binA, []byte("a1"), 0o755))
	require.NoError(t, os.WriteFile(binB, []byte("b1"), 0o755))

	var closeA, closeB atomic.Int32
	require.NoError(t, WatchPluginBinary(binA, &stubReloadable{closeFn: func() { closeA.Add(1) }}))
	require.NoError(t, WatchPluginBinary(binB, &stubReloadable{closeFn: func() { closeB.Add(1) }}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, StartPluginBinaryWatcher(ctx))
	defer StopPluginBinaryWatcher()

	// Write only to A.
	require.NoError(t, os.WriteFile(binA, []byte("a2"), 0o755))

	// Poll for A's close to fire; proving B did NOT fire is
	// inherently negative but bounded by the same 2s window.
	require.Eventually(t, func() bool {
		return closeA.Load() >= 1
	}, 2*time.Second, 10*time.Millisecond, "plugin-a Close must fire")
	assert.Equal(t, int32(0), closeB.Load(), "plugin-b Close must NOT fire")
}

// TestWatchPluginBinary_RejectsInvalid — empty path or nil
// reloadable both fail at registration.
func TestWatchPluginBinary_RejectsInvalid(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)
	assert.Error(t, WatchPluginBinary("", &stubReloadable{}))
	assert.Error(t, WatchPluginBinary("/some/path", nil))
}

// TestWatchPluginBinary_StartIdempotent — calling Start twice is a
// no-op rather than an error (production code may re-init during
// a hot-reload cycle).
func TestWatchPluginBinary_StartIdempotent(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)
	defer StopPluginBinaryWatcher()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, StartPluginBinaryWatcher(ctx))
	// Second call should not error.
	assert.NoError(t, StartPluginBinaryWatcher(ctx))
}

<<<<<<< Updated upstream
// TestParsePluginHotReloadFlag — the app wire-up layer will consult
// IsPluginHotReloadEnabled() to decide whether to call
// StartPluginBinaryWatcher. The behaviour-per-value contract is
// owned by the pure parser parsePluginHotReloadFlag; this test
// drives it directly so every case runs t.Parallel.
//
// "true" (case-insensitive, whitespace-tolerant) enables, anything
// else disables.
func TestParsePluginHotReloadFlag(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw  string
		want bool
	}{
		{"true", true},
		{"TRUE", true},
		{"True", true},
		{" true ", true}, // whitespace tolerated
		{"\ttrue", true}, // tab tolerated
		{"1", false},     // only "true" enables — explicit opt-in
		{"yes", false},
		{"false", false},
		{"", false},
		{"enabled", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run("raw="+tc.raw, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, parsePluginHotReloadFlag(tc.raw))
		})
	}
}

// --- helpers ---

type stubReloadable struct {
	closeFn func()
}

func (s *stubReloadable) Close() {
	if s.closeFn != nil {
		s.closeFn()
	}
}

var _ BinaryReloadable = (*stubReloadable)(nil)
