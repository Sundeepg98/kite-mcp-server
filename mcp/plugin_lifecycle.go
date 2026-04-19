// Package mcp plugin lifecycle: unified Init/Shutdown/Reload + panic
// isolation primitives shared by every plugin-extension registry.
//
// Purpose (solo-developer productivity):
//
//   - **Init/Shutdown/Reload** — every registry participating in the
//     plugin-lifecycle protocol can be driven from one call site at
//     app wire-up and shutdown time. The Reload path supports the
//     edit-plugin-code, hit-SIGHUP dev loop without tearing the whole
//     server down.
//
//   - **Panic isolation** — SafeInvoke / SafeCall wrap every
//     plugin-code invocation. A panicking plugin registers as
//     HealthStateFailed, surfaces in PluginHealth() + the manifest,
//     and cannot crash the host or sibling plugins.
//
//   - **Health surface** — ReportPluginHealth + PluginHealth() give
//     the admin panel a single snapshot of "is anything red right
//     now?" without each plugin owning its own reporting path.
package mcp

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// PluginLifecycle is the contract every plugin registry participates
// in to receive coordinated Init/Shutdown/Reload calls. Implementations
// are typically thin wrappers owned by a registry (e.g.
// pluginMiddlewareRegistry) that perform no-op Init and no-op
// Shutdown today, but can grow work without breaking callers.
//
// Reload intentionally isn't part of the interface — ReloadPluginRegistries
// composes Shutdown + Init so every participant gets a consistent
// Reload for free.
type PluginLifecycle interface {
	// Init is called once at app startup, after all plugin
	// registrations have landed. Errors surface to the caller but
	// do not abort the init chain — see InitPluginRegistries.
	Init(ctx context.Context) error

	// Shutdown is called during graceful shutdown. It runs in
	// reverse registration order so stateful teardown mirrors
	// setup.
	Shutdown(ctx context.Context) error
}

// HealthState represents the coarse-grained plugin status the
// admin surface cares about. Three values keep it scannable: if
// the op page has any red row, something needs attention.
type HealthState string

const (
	// HealthStateOK is the default for a healthy, running plugin.
	HealthStateOK HealthState = "ok"
	// HealthStateDegraded is a warning: the plugin is functional
	// but slower / partial / missing optional data.
	HealthStateDegraded HealthState = "degraded"
	// HealthStateFailed is red: the plugin panicked or its Init
	// returned an error, and subsequent calls may also fail.
	HealthStateFailed HealthState = "failed"
	// HealthStateUnknown is used when a plugin has not reported
	// health yet (typically right after registration, before the
	// first Init or call).
	HealthStateUnknown HealthState = "unknown"
)

// HealthStatus is what a plugin reports about itself. Message is
// free-form prose for the admin ("baseline cache hit rate 38% —
// low"). LastChecked is auto-stamped by ReportPluginHealth if the
// caller leaves it zero.
type HealthStatus struct {
	State       HealthState `json:"state"`
	Message     string      `json:"message,omitempty"`
	LastChecked time.Time   `json:"last_checked"`
}

// --- Lifecycle registry ---

var lifecycleRegistry = struct {
	mu      sync.RWMutex
	entries []lifecycleEntry
}{}

type lifecycleEntry struct {
	name      string
	lifecycle PluginLifecycle
}

// RegisterPluginLifecycle adds a participant to the coordinated
// Init/Shutdown/Reload chain. Registration is append-only; the
// order matters because Shutdown reverses it. Nil lifecycle is
// silently dropped (defensive — a feature-flagged-off plugin
// shouldn't crash startup).
func RegisterPluginLifecycle(name string, l PluginLifecycle) {
	if l == nil || name == "" {
		return
	}
	lifecycleRegistry.mu.Lock()
	defer lifecycleRegistry.mu.Unlock()
	lifecycleRegistry.entries = append(lifecycleRegistry.entries, lifecycleEntry{
		name:      name,
		lifecycle: l,
	})
}

// ClearPluginLifecycles drops every registered lifecycle. Test-only.
func ClearPluginLifecycles() {
	lifecycleRegistry.mu.Lock()
	defer lifecycleRegistry.mu.Unlock()
	lifecycleRegistry.entries = nil
}

// PluginLifecycleCount returns the number of registered lifecycle
// participants. Exposed for the admin surface and tests.
func PluginLifecycleCount() int {
	lifecycleRegistry.mu.RLock()
	defer lifecycleRegistry.mu.RUnlock()
	return len(lifecycleRegistry.entries)
}

// InitPluginRegistries fires Init on every registered lifecycle in
// registration order. A panic in one plugin's Init is recovered,
// reported to PluginHealth as Failed, and does NOT abort the chain
// — other plugins still get their chance to initialise. The returned
// error is a multi-error aggregate (nil if every Init succeeded).
func InitPluginRegistries(ctx context.Context) error {
	lifecycleRegistry.mu.RLock()
	entries := append([]lifecycleEntry(nil), lifecycleRegistry.entries...)
	lifecycleRegistry.mu.RUnlock()

	var errs []string
	for _, e := range entries {
		e := e
		if err := SafeInvoke(e.name+":init", func() error {
			return e.lifecycle.Init(ctx)
		}); err != nil {
			ReportPluginHealth(e.name, HealthStatus{
				State:   HealthStateFailed,
				Message: "init failed: " + err.Error(),
			})
			errs = append(errs, e.name+": "+err.Error())
			continue
		}
		ReportPluginHealth(e.name, HealthStatus{State: HealthStateOK})
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("plugin init errors (%d): %v", len(errs), errs)
}

// ShutdownPluginRegistries fires Shutdown on every registered
// lifecycle in REVERSE order of registration so stateful teardown
// mirrors setup. Panics are recovered; the chain always runs to
// completion so one misbehaving plugin cannot prevent others from
// releasing resources.
func ShutdownPluginRegistries(ctx context.Context) error {
	lifecycleRegistry.mu.RLock()
	entries := append([]lifecycleEntry(nil), lifecycleRegistry.entries...)
	lifecycleRegistry.mu.RUnlock()

	var errs []string
	// Reverse iteration.
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if err := SafeInvoke(e.name+":shutdown", func() error {
			return e.lifecycle.Shutdown(ctx)
		}); err != nil {
			errs = append(errs, e.name+": "+err.Error())
			continue
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("plugin shutdown errors (%d): %v", len(errs), errs)
}

// ReloadPluginRegistries runs Shutdown then Init on every registered
// lifecycle. Used by the edit-plugin-code, hit-SIGHUP dev loop —
// gives the solo developer a clean re-init without restarting the
// whole server.
func ReloadPluginRegistries(ctx context.Context) error {
	if err := ShutdownPluginRegistries(ctx); err != nil {
		return fmt.Errorf("reload: shutdown phase: %w", err)
	}
	return InitPluginRegistries(ctx)
}

// --- Health registry ---

var healthRegistry = struct {
	mu      sync.RWMutex
	entries map[string]HealthStatus
}{
	entries: make(map[string]HealthStatus),
}

// ReportPluginHealth records a plugin's health status. Replaces any
// prior entry for the same name (last-wins). Auto-stamps
// LastChecked if caller leaves it zero.
func ReportPluginHealth(name string, status HealthStatus) {
	if name == "" {
		return
	}
	if status.LastChecked.IsZero() {
		status.LastChecked = time.Now()
	}
	healthRegistry.mu.Lock()
	defer healthRegistry.mu.Unlock()
	healthRegistry.entries[name] = status
}

// PluginHealth returns a snapshot of every reported health status.
// Keys are plugin names, values are the most recent HealthStatus.
// Safe for concurrent use; the returned map is a fresh copy.
func PluginHealth() map[string]HealthStatus {
	healthRegistry.mu.RLock()
	defer healthRegistry.mu.RUnlock()
	out := make(map[string]HealthStatus, len(healthRegistry.entries))
	for k, v := range healthRegistry.entries {
		out[k] = v
	}
	return out
}

// ClearPluginHealth drops every reported health status. Test-only.
func ClearPluginHealth() {
	healthRegistry.mu.Lock()
	defer healthRegistry.mu.Unlock()
	healthRegistry.entries = make(map[string]HealthStatus)
}

// ListPluginHealthSorted returns plugin names in sorted order for
// deterministic admin-surface display. Convenience helper.
func ListPluginHealthSorted() []string {
	healthRegistry.mu.RLock()
	defer healthRegistry.mu.RUnlock()
	names := make([]string, 0, len(healthRegistry.entries))
	for k := range healthRegistry.entries {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// --- Safe-invoke primitives ---

// SafeInvoke runs fn with panic recovery. A panic is converted to
// a non-nil error that includes the plugin name and the panic value.
// Used by every plugin-code invocation site across the plugin
// registries so no single plugin bug can crash the host.
func SafeInvoke(pluginName string, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("plugin %q panicked: %v", pluginName, r)
		}
	}()
	return fn()
}

// SafeCall is the two-value variant of SafeInvoke: used when a plugin
// function returns (T, error). On panic, the zero value of T and a
// non-nil error are returned.
func SafeCall[T any](pluginName string, fn func() (T, error)) (result T, err error) {
	defer func() {
		if r := recover(); r != nil {
			var zero T
			result = zero
			err = fmt.Errorf("plugin %q panicked: %v", pluginName, r)
		}
	}()
	return fn()
}
