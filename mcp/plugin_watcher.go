package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

// BinaryReloadable is the narrow interface the binary watcher
// needs from a subprocess-plugin handle. Defined here (not in
// riskguard) so the watcher stays cycle-free — any plugin kind
// that manages a subprocess can implement Close() and opt in.
//
// Contract: Close() tears down the current subprocess handle. The
// NEXT plugin invocation is responsible for relaunching (this
// mirrors the fail-closed-then-relaunch contract that
// SubprocessCheck already implements). Close() MUST be safe to
// call repeatedly — the watcher may fire multiple events for a
// single logical write on some platforms.
type BinaryReloadable interface {
	Close()
}

// pluginBinaryWatchRegistry holds (path -> reloadable) pairs. The
// watcher goroutine consults this map on every fsnotify event to
// decide which plugin's Close() to invoke. Mutex-protected so
// concurrent WatchPluginBinary calls during startup don't race
// against the goroutine's map read.
var pluginBinaryWatchRegistry = struct {
	mu      sync.RWMutex
	entries map[string]BinaryReloadable
}{
	entries: make(map[string]BinaryReloadable),
}

// watcherState holds the singleton watcher goroutine state.
// A single fsnotify.Watcher serves every registered binary; this
// is standard fsnotify idiom and bounds OS-level handle usage at
// one regardless of plugin count.
var watcherState = struct {
	mu      sync.Mutex
	watcher *fsnotify.Watcher
	cancel  context.CancelFunc
	done    chan struct{} // closed by the goroutine on exit; nil before Start.
	started bool
}{}

// pluginWatcherLogger holds the slog.Logger the watcher goroutine logs
// fsnotify errors to. atomic.Pointer (not a plain *slog.Logger field)
// lets ops swap loggers at runtime without coordinating with a mutex
// the watcher goroutine doesn't otherwise hold. nil → fall back to
// slog.Default() so the error path can never nil-deref.
var pluginWatcherLogger atomic.Pointer[slog.Logger]

// SetPluginWatcherLogger wires the logger that runPluginBinaryWatcher
// uses for fsnotify error reporting (Plugin#4). Pre-fix, errors were
// silently swallowed; this exposes them to ops dashboards. Pass nil to
// clear (fall back to slog.Default()).
func SetPluginWatcherLogger(logger *slog.Logger) {
	pluginWatcherLogger.Store(logger)
}

// watcherLogger returns the current logger, falling back to
// slog.Default() when none is set. Never returns nil.
func watcherLogger() *slog.Logger {
	if l := pluginWatcherLogger.Load(); l != nil {
		return l
	}
	return slog.Default()
}

// WatchPluginBinary registers a (path, reloadable) pair for the
// watcher to monitor. Path must be non-empty and reloadable
// non-nil. The file at path does NOT need to exist yet — the
// watcher tolerates missing files and will pick them up when
// they're created (common during dev-loop first boot).
//
// Safe to call before OR after StartPluginBinaryWatcher. If the
// watcher is already running, the path is subscribed immediately;
// otherwise it's queued for subscription at Start time.
func WatchPluginBinary(path string, r BinaryReloadable) error {
	if path == "" {
		return fmt.Errorf("mcp: WatchPluginBinary requires non-empty path")
	}
	if r == nil {
		return fmt.Errorf("mcp: WatchPluginBinary requires non-nil reloadable")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("mcp: WatchPluginBinary: resolve path %q: %w", path, err)
	}
	pluginBinaryWatchRegistry.mu.Lock()
	pluginBinaryWatchRegistry.entries[abs] = r
	pluginBinaryWatchRegistry.mu.Unlock()

	// Subscribe immediately if the watcher is already running. fsnotify
	// tolerates non-existent paths on most platforms; where it doesn't,
	// we log and move on — the watcher goroutine will re-try on
	// successive writes via the parent-directory event stream.
	watcherState.mu.Lock()
	defer watcherState.mu.Unlock()
	if watcherState.watcher != nil {
		_ = subscribeToPath(watcherState.watcher, abs)
	}
	return nil
}

// subscribeToPath adds the file at abs to the watcher. Some
// platforms (notably Windows) require watching the PARENT
// directory for file-write events to fire reliably, so we watch
// the parent AND the file itself; the event handler filters on
// the absolute file path.
func subscribeToPath(w *fsnotify.Watcher, abs string) error {
	// Watch the parent directory (gives us rename/create signals
	// for atomic-swap dev flows like `go build -o tmp && mv tmp
	// plugin`). Best-effort — ignore errors here since a missing
	// parent is not a hard failure; the direct Add below still
	// works for create-in-place flows.
	parent := filepath.Dir(abs)
	_ = w.Add(parent)
	// Watch the file itself. fsnotify returns an error when the
	// file doesn't exist yet — that's OK, the parent-dir watch
	// will catch creation events.
	if err := w.Add(abs); err != nil {
		// Not a blocking failure; parent watch still works.
		return err
	}
	return nil
}

// ClearPluginWatches drops every registered watch entry. Test-only.
// Does NOT stop the watcher goroutine — call StopPluginBinaryWatcher
// for that.
func ClearPluginWatches() {
	pluginBinaryWatchRegistry.mu.Lock()
	defer pluginBinaryWatchRegistry.mu.Unlock()
	pluginBinaryWatchRegistry.entries = make(map[string]BinaryReloadable)
}

// StartPluginBinaryWatcher spins up the fsnotify watcher goroutine.
// Safe to call multiple times — only the first call starts the
// goroutine; subsequent calls are no-ops. The watcher stops when
// the supplied context is canceled OR StopPluginBinaryWatcher is
// called, whichever comes first.
//
// Returns an error only if fsnotify.NewWatcher itself fails (very
// rare — essentially "out of inotify watches" on Linux or similar
// OS-level resource exhaustion).
func StartPluginBinaryWatcher(ctx context.Context) error {
	watcherState.mu.Lock()
	defer watcherState.mu.Unlock()
	if watcherState.started {
		return nil // Idempotent.
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("mcp: fsnotify.NewWatcher: %w", err)
	}

	// Subscribe every path registered so far.
	pluginBinaryWatchRegistry.mu.RLock()
	for path := range pluginBinaryWatchRegistry.entries {
		_ = subscribeToPath(w, path)
	}
	pluginBinaryWatchRegistry.mu.RUnlock()

	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	watcherState.watcher = w
	watcherState.cancel = cancel
	watcherState.done = done
	watcherState.started = true

	go func() {
		defer close(done)
		runPluginBinaryWatcher(ctx, w)
	}()
	return nil
}

// StopPluginBinaryWatcher cancels the watcher context and closes
// the fsnotify watcher. Safe to call multiple times; no-op if
// never started. Blocks until the goroutine has exited (short —
// the goroutine returns on ctx.Done() or watcher channel close,
// then signals via the done channel; Plugin#9 deterministic join).
func StopPluginBinaryWatcher() {
	watcherState.mu.Lock()
	if !watcherState.started {
		watcherState.mu.Unlock()
		return
	}
	if watcherState.cancel != nil {
		watcherState.cancel()
	}
	if watcherState.watcher != nil {
		_ = watcherState.watcher.Close()
		watcherState.watcher = nil
	}
	done := watcherState.done
	watcherState.started = false
	watcherState.cancel = nil
	watcherState.done = nil
	watcherState.mu.Unlock()
	// Wait OUTSIDE the lock so the goroutine — which acquires no
	// watcherState.mu but may briefly contend on registry locks —
	// can drain its select and exit without deadlock risk.
	if done != nil {
		<-done
	}
}

// runPluginBinaryWatcher is the watcher goroutine entry point. It
// selects on the fsnotify event channel, debounces bursts of
// events per-path, and calls Close() on the registered
// reloadable. Exits on ctx.Done() or watcher error channel close.
func runPluginBinaryWatcher(ctx context.Context, w *fsnotify.Watcher) {
	// Per-path debounce timers. fsnotify may fire multiple events
	// for one logical write (WRITE + CHMOD on Linux, CREATE+WRITE
	// on atomic swap). Collapse them to at most one Close() per
	// debounce window.
	const debounceWindow = 250 * time.Millisecond
	timers := make(map[string]*time.Timer)
	var timersMu sync.Mutex

	scheduleReload := func(path string) {
		timersMu.Lock()
		defer timersMu.Unlock()
		if t, ok := timers[path]; ok {
			t.Stop()
		}
		timers[path] = time.AfterFunc(debounceWindow, func() {
			pluginBinaryWatchRegistry.mu.RLock()
			r, ok := pluginBinaryWatchRegistry.entries[path]
			pluginBinaryWatchRegistry.mu.RUnlock()
			if ok && r != nil {
				SafeInvoke("plugin_watcher:"+path, func() error {
					r.Close()
					return nil
				})
			}
			timersMu.Lock()
			delete(timers, path)
			timersMu.Unlock()
		})
	}

	for {
		select {
		case <-ctx.Done():
			timersMu.Lock()
			for _, t := range timers {
				t.Stop()
			}
			timersMu.Unlock()
			return
		case ev, ok := <-w.Events:
			if !ok {
				return
			}
			// Interested in WRITE, CREATE, and RENAME-target events.
			// Most dev-loop rebuilds surface as WRITE (go build -o
			// overwrites in place) or CREATE+WRITE (atomic mv).
			if ev.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}
			// Match the event path (may be an absolute path or
			// relative to the watched directory) against the
			// registered abs paths.
			abs, err := filepath.Abs(ev.Name)
			if err != nil {
				continue
			}
			pluginBinaryWatchRegistry.mu.RLock()
			_, registered := pluginBinaryWatchRegistry.entries[abs]
			pluginBinaryWatchRegistry.mu.RUnlock()
			if !registered {
				continue
			}
			scheduleReload(abs)
		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			// fsnotify errors during normal operation are rare and
			// usually transient (e.g. a watched directory was
			// temporarily unmountable, inotify watch evicted under
			// memory pressure). Plugin#4: log via the configured
			// logger so ops see them — silently swallowing was the
			// pre-fix behaviour and obscured production diagnostics.
			watcherLogger().Warn("plugin watcher: fsnotify error",
				"error", err.Error(),
			)
		}
	}
}

// IsPluginHotReloadEnabled reports whether the KITE_PLUGIN_HOT_RELOAD
// env var is set to "true" (case-insensitive). Explicit opt-in —
// any other value (including "1", "yes", "enabled") disables. The
// app wire-up layer calls this to decide whether to start the
// watcher.
//
// Rationale for explicit opt-in: hot-reload spawns a filesystem
// watcher goroutine + an fsnotify OS handle. In production, those
// resources are wasted (plugin binaries don't change in-flight).
// Defaulting off prevents accidental consumption.
//
// Production wrapper around parsePluginHotReloadFlag — the latter is
// a pure function tests drive directly with literals (no t.Setenv,
// parallel-safe).
func IsPluginHotReloadEnabled() bool {
	return parsePluginHotReloadFlag(os.Getenv("KITE_PLUGIN_HOT_RELOAD"))
}

// parsePluginHotReloadFlag is the pure parser. Returns true iff the
// raw value, after trim+lowercase, equals "true". Every other input
// (including "1", "yes", "enabled", whitespace garbage) returns false.
func parsePluginHotReloadFlag(raw string) bool {
	return strings.ToLower(strings.TrimSpace(raw)) == "true"
}

// PluginWatcherCount returns the number of paths currently watched.
// Exposed for the admin / manifest surface.
func PluginWatcherCount() int {
	pluginBinaryWatchRegistry.mu.RLock()
	defer pluginBinaryWatchRegistry.mu.RUnlock()
	return len(pluginBinaryWatchRegistry.entries)
}
