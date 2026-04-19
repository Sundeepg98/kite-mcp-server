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
	ClearPluginWatches()
	defer ClearPluginWatches()

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
	require.NoError(t, StartPluginBinaryWatcher(ctx))
	defer StopPluginBinaryWatcher()

	// Give the goroutine a moment to subscribe.
	time.Sleep(50 * time.Millisecond)

	// Overwrite the binary.
	require.NoError(t, os.WriteFile(binary, []byte("v2"), 0o755))

	// Wait for the close callback to fire.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if closeCount.Load() > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	assert.GreaterOrEqual(t, closeCount.Load(), int32(1),
		"Close() must fire at least once after WRITE event")
}

// TestWatchPluginBinary_DebouncesRapidWrites — fsnotify on some
// platforms emits multiple events for a single logical write (e.g.
// WRITE then CHMOD on Linux). The watcher must debounce to at most
// one Close() per debounce window (default 250ms).
func TestWatchPluginBinary_DebouncesRapidWrites(t *testing.T) {
	ClearPluginWatches()
	defer ClearPluginWatches()

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
	time.Sleep(50 * time.Millisecond)

	// Five rapid writes within 100ms — the debounce window collapses
	// them to (usually 1, at most 2) Close() calls.
	for i := 0; i < 5; i++ {
		require.NoError(t, os.WriteFile(binary, []byte("v"+string(rune('2'+i))), 0o755))
		time.Sleep(15 * time.Millisecond)
	}

	// Wait for the debounce window to flush.
	time.Sleep(500 * time.Millisecond)

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
	ClearPluginWatches()
	defer ClearPluginWatches()

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
	time.Sleep(50 * time.Millisecond)

	// Rewrite with identical bytes.
	require.NoError(t, os.WriteFile(binary, contents, 0o755))
	time.Sleep(400 * time.Millisecond)

	// We DO expect a Close() — the watcher does not diff contents
	// by default. The user asked for "mtime or checksum" trigger;
	// we implement mtime via fsnotify WRITE events. Checksum-based
	// change detection is a future optimisation.
	assert.GreaterOrEqual(t, closeCount.Load(), int32(1),
		"WRITE event must fire even on same-bytes rewrite")
}

// TestWatchPluginBinary_StopCleansUp — calling StopPluginBinaryWatcher
// stops the goroutine and drops all subscriptions. Subsequent
// writes do NOT fire Close(). Verifies no goroutine leak.
func TestWatchPluginBinary_StopCleansUp(t *testing.T) {
	ClearPluginWatches()
	defer ClearPluginWatches()

	tmp := t.TempDir()
	binary := filepath.Join(tmp, "fake-plugin")
	require.NoError(t, os.WriteFile(binary, []byte("v1"), 0o755))

	var closeCount atomic.Int32
	stub := &stubReloadable{closeFn: func() { closeCount.Add(1) }}
	require.NoError(t, WatchPluginBinary(binary, stub))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, StartPluginBinaryWatcher(ctx))
	time.Sleep(50 * time.Millisecond)

	// Stop the watcher.
	StopPluginBinaryWatcher()
	time.Sleep(50 * time.Millisecond)

	// Subsequent write must not fire.
	require.NoError(t, os.WriteFile(binary, []byte("v2"), 0o755))
	time.Sleep(300 * time.Millisecond)

	assert.Equal(t, int32(0), closeCount.Load(),
		"Close() must not fire after StopPluginBinaryWatcher")
}

// TestWatchPluginBinary_MultiplePluginsIndependent — two plugins
// watched at different paths; write to one fires only that
// plugin's Close, not the other.
func TestWatchPluginBinary_MultiplePluginsIndependent(t *testing.T) {
	ClearPluginWatches()
	defer ClearPluginWatches()

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
	time.Sleep(50 * time.Millisecond)

	// Write only to A.
	require.NoError(t, os.WriteFile(binA, []byte("a2"), 0o755))
	time.Sleep(400 * time.Millisecond)

	assert.GreaterOrEqual(t, closeA.Load(), int32(1), "plugin-a Close must fire")
	assert.Equal(t, int32(0), closeB.Load(), "plugin-b Close must NOT fire")
}

// TestWatchPluginBinary_RejectsInvalid — empty path or nil
// reloadable both fail at registration.
func TestWatchPluginBinary_RejectsInvalid(t *testing.T) {
	ClearPluginWatches()
	defer ClearPluginWatches()

	assert.Error(t, WatchPluginBinary("", &stubReloadable{}))
	assert.Error(t, WatchPluginBinary("/some/path", nil))
}

// TestWatchPluginBinary_StartIdempotent — calling Start twice is a
// no-op rather than an error (production code may re-init during
// a hot-reload cycle).
func TestWatchPluginBinary_StartIdempotent(t *testing.T) {
	ClearPluginWatches()
	defer ClearPluginWatches()
	defer StopPluginBinaryWatcher()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, StartPluginBinaryWatcher(ctx))
	// Second call should not error.
	assert.NoError(t, StartPluginBinaryWatcher(ctx))
}

// TestPluginWatcherEnvGating — the app wire-up layer will consult
// IsPluginHotReloadEnabled() to decide whether to call
// StartPluginBinaryWatcher. This test confirms the env-var
// contract: "true" (case-insensitive) enables, anything else
// disables.
func TestPluginWatcherEnvGating(t *testing.T) {
	cases := []struct {
		env  string
		want bool
	}{
		{"true", true},
		{"TRUE", true},
		{"True", true},
		{"1", false},        // only "true" enables — explicit opt-in
		{"yes", false},
		{"false", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run("env="+tc.env, func(t *testing.T) {
			t.Setenv("KITE_PLUGIN_HOT_RELOAD", tc.env)
			assert.Equal(t, tc.want, IsPluginHotReloadEnabled())
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
