package mcp

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// Registry holds all plugin-state that used to live in package-level
// global vars across mcp/plugin_*.go. One process-wide instance
// (DefaultRegistry) services the production code path, and tests can
// construct fresh isolated instances via NewRegistry() to run in
// parallel without contending on shared state.
//
// Why a struct and not 9 separate global maps:
//
//   - Tests that mutate any of the plugin registries (widgets,
//     middleware, hooks, SBOM, etc.) could not run t.Parallel() —
//     two parallel tests would race on the same map under -race.
//     The test-arch agent had to revert t.Parallel() from 10 plugin
//     test files to land the broader parallelization push.
//   - Packaging state into a Registry struct lets every free-standing
//     Register*/Clear*/Count* function continue to exist as a
//     package-level function (backward-compat for production callers
//     in app/wire.go, examples/, kc/audit/plugin_event_types.go,
//     kc/telegram/plugin_commands.go) while tests that want
//     isolation call NewRegistry() and operate on that instance.
//
// Each sub-registry (tools, hooks, around, mutable-around, middleware,
// widgets, events, lifecycle, health, info, sbom) keeps its own
// RWMutex inside Registry — locks are NOT promoted to a single
// Registry-wide lock because (a) lock contention matters for the
// registration hot path during startup, and (b) deadlock analysis
// stays local to each sub-registry when the lock is a field of its
// own struct.
type Registry struct {
	// Tool-registry side — built-in Tool plugins supplied by
	// callers of RegisterPlugin. Merged with the built-in tool set
	// at server startup via GetAllTools.
	toolMu      sync.Mutex
	toolPlugins []Tool

	// Before / after hooks. Fired sequentially around every tool
	// call; see HookMiddleware.
	hooksMu          sync.RWMutex
	beforeHooks      []ToolHook
	afterHooks       []ToolHook
	aroundHooks      []aroundHookEntry
	aroundSeqCounter uint64

	// Mutable around-hooks. Separate mutex so OnToolExecutionMutable
	// and OnToolExecution don't contend on the same lock for
	// independent registrations.
	mutableAroundHookMu sync.RWMutex
	mutableAroundHooks  []mutableAroundHookEntry

	// Plugin-contributed middleware (server.ToolHandlerMiddleware).
	middlewareMu      sync.RWMutex
	middlewareEntries map[string]PluginMiddlewareEntry

	// Plugin-contributed ui:// resources.
	widgetMu      sync.RWMutex
	widgets       map[string]PluginWidget
	widgetOrdered []string // preserves registration order

	// Plugin-contributed domain-event subscriptions.
	eventMu            sync.RWMutex
	eventSubscriptions []pluginEventSubscription
	// installedAt is set the first time InstallPluginEventSubscriptions
	// runs, indicating the dispatcher window has closed for "fire-and-
	// forget" subscriptions. Plugin#5: post-Install registrations are
	// still recorded (so a future re-Install picks them up) but a
	// warning surfaces in the log so hot-reload code can be flagged.
	installedAt atomic.Pointer[domain.EventDispatcher]

	// Lifecycle hooks (Init/Shutdown/Reload).
	lifecycleMu      sync.RWMutex
	lifecycleEntries []lifecycleEntry

	// Plugin health status.
	healthMu      sync.RWMutex
	healthEntries map[string]HealthStatus

	// Plugin manifest (PluginInfo).
	infoMu    sync.RWMutex
	infoItems map[string]PluginInfo

	// SBOM entries (PluginSBOMEntry).
	sbomMu      sync.RWMutex
	sbomEntries map[string]PluginSBOMEntry

	// Signature verification trust state. See plugin_sbom_signature.go
	// for policy. Zero-value is legacy "no trust anchor" mode — SBOM
	// signatures are stored opaquely without verification.
	signer trustedSignerRegistry
}

// NewRegistry constructs a fresh, empty Registry. Intended primarily
// for tests that want plugin-state isolation across parallel runs;
// production code uses the process-wide DefaultRegistry.
func NewRegistry() *Registry {
	return &Registry{
		middlewareEntries: make(map[string]PluginMiddlewareEntry),
		widgets:           make(map[string]PluginWidget),
		healthEntries:     make(map[string]HealthStatus),
		infoItems:         make(map[string]PluginInfo),
		sbomEntries:       make(map[string]PluginSBOMEntry),
	}
}

// DefaultRegistry is the package-level singleton every free-standing
// Register*/Clear*/Count* function delegates to. Production callers
// never see this symbol — they call the free functions.
var DefaultRegistry = NewRegistry()

// Reset wipes every sub-registry so DefaultRegistry (or any other
// Registry) can be reused between tests. Safe for concurrent callers
// but typically invoked single-threaded in t.Cleanup.
func (r *Registry) Reset() {
	r.toolMu.Lock()
	r.toolPlugins = nil
	r.toolMu.Unlock()

	r.hooksMu.Lock()
	r.beforeHooks = nil
	r.afterHooks = nil
	r.aroundHooks = nil
	r.aroundSeqCounter = 0
	r.hooksMu.Unlock()

	r.mutableAroundHookMu.Lock()
	r.mutableAroundHooks = nil
	r.mutableAroundHookMu.Unlock()

	r.middlewareMu.Lock()
	r.middlewareEntries = make(map[string]PluginMiddlewareEntry)
	r.middlewareMu.Unlock()

	r.widgetMu.Lock()
	r.widgets = make(map[string]PluginWidget)
	r.widgetOrdered = nil
	r.widgetMu.Unlock()

	r.eventMu.Lock()
	r.eventSubscriptions = nil
	r.eventMu.Unlock()

	r.lifecycleMu.Lock()
	r.lifecycleEntries = nil
	r.lifecycleMu.Unlock()

	r.healthMu.Lock()
	r.healthEntries = make(map[string]HealthStatus)
	r.healthMu.Unlock()

	r.infoMu.Lock()
	r.infoItems = make(map[string]PluginInfo)
	r.infoMu.Unlock()

	r.sbomMu.Lock()
	r.sbomEntries = make(map[string]PluginSBOMEntry)
	r.sbomMu.Unlock()

	r.signer.mu.Lock()
	r.signer.key = nil
	r.signer.devMode = false
	r.signer.logger = nil
	r.signer.mu.Unlock()
}

// --- Tool-registry methods ---

// RegisterPlugin adds a Tool to this Registry. Thread-safe.
func (r *Registry) RegisterPlugin(tool Tool) {
	r.toolMu.Lock()
	defer r.toolMu.Unlock()
	r.toolPlugins = append(r.toolPlugins, tool)
}

// RegisterPlugins adds multiple Tools.
func (r *Registry) RegisterPlugins(tools ...Tool) {
	r.toolMu.Lock()
	defer r.toolMu.Unlock()
	r.toolPlugins = append(r.toolPlugins, tools...)
}

// PluginCount returns the number of registered Tool plugins.
func (r *Registry) PluginCount() int {
	r.toolMu.Lock()
	defer r.toolMu.Unlock()
	return len(r.toolPlugins)
}

// Tools returns a snapshot of registered Tool plugins.
func (r *Registry) Tools() []Tool {
	r.toolMu.Lock()
	defer r.toolMu.Unlock()
	out := make([]Tool, len(r.toolPlugins))
	copy(out, r.toolPlugins)
	return out
}

// --- Hook methods ---

// OnBeforeToolExecution registers a before-hook.
func (r *Registry) OnBeforeToolExecution(hook ToolHook) {
	r.hooksMu.Lock()
	defer r.hooksMu.Unlock()
	r.beforeHooks = append(r.beforeHooks, hook)
}

// OnAfterToolExecution registers an after-hook.
func (r *Registry) OnAfterToolExecution(hook ToolHook) {
	r.hooksMu.Lock()
	defer r.hooksMu.Unlock()
	r.afterHooks = append(r.afterHooks, hook)
}

// OnToolExecution registers an immutable around-hook.
func (r *Registry) OnToolExecution(hook ToolAroundHook) {
	if hook == nil {
		return
	}
	r.hooksMu.Lock()
	defer r.hooksMu.Unlock()
	r.aroundSeqCounter++
	r.aroundHooks = append(r.aroundHooks, aroundHookEntry{hook: hook, seq: r.aroundSeqCounter})
}

// OnToolExecutionMutable registers a mutable around-hook.
func (r *Registry) OnToolExecutionMutable(hook ToolMutableAroundHook) {
	if hook == nil {
		return
	}
	// Use the same sequence counter so immutable and mutable hooks
	// compose in true registration order.
	r.hooksMu.Lock()
	r.aroundSeqCounter++
	seq := r.aroundSeqCounter
	r.hooksMu.Unlock()
	r.mutableAroundHookMu.Lock()
	defer r.mutableAroundHookMu.Unlock()
	r.mutableAroundHooks = append(r.mutableAroundHooks, mutableAroundHookEntry{hook: hook, seq: seq})
}

// BeforeHookCount returns registered before-hook count.
func (r *Registry) BeforeHookCount() int {
	r.hooksMu.RLock()
	defer r.hooksMu.RUnlock()
	return len(r.beforeHooks)
}

// AfterHookCount returns registered after-hook count.
func (r *Registry) AfterHookCount() int {
	r.hooksMu.RLock()
	defer r.hooksMu.RUnlock()
	return len(r.afterHooks)
}

// AroundHookCount returns registered immutable around-hook count.
func (r *Registry) AroundHookCount() int {
	r.hooksMu.RLock()
	defer r.hooksMu.RUnlock()
	return len(r.aroundHooks)
}

// MutableAroundHookCount returns registered mutable around-hook count.
func (r *Registry) MutableAroundHookCount() int {
	r.mutableAroundHookMu.RLock()
	defer r.mutableAroundHookMu.RUnlock()
	return len(r.mutableAroundHooks)
}

// RunBeforeHooks executes all before-hooks sequentially with panic
// recovery. First non-nil error short-circuits.
func (r *Registry) RunBeforeHooks(ctx context.Context, toolName string, args map[string]any) error {
	r.hooksMu.RLock()
	hooks := append([]ToolHook(nil), r.beforeHooks...)
	r.hooksMu.RUnlock()
	for _, hook := range hooks {
		if err := safeRunBeforeHook(hook, ctx, toolName, args); err != nil {
			return err
		}
	}
	return nil
}

// RunAfterHooks fires all after-hooks (observe-only; errors swallowed).
func (r *Registry) RunAfterHooks(ctx context.Context, toolName string, args map[string]any) {
	r.hooksMu.RLock()
	hooks := append([]ToolHook(nil), r.afterHooks...)
	r.hooksMu.RUnlock()
	for _, hook := range hooks {
		safeRunAfterHook(hook, ctx, toolName, args)
	}
}

// mergedAroundChain returns the combined around-hook chain sorted by
// registration sequence. Used by HookMiddleware.
func (r *Registry) mergedAroundChain() []mergedAroundEntry {
	r.hooksMu.RLock()
	immutable := make([]aroundHookEntry, len(r.aroundHooks))
	copy(immutable, r.aroundHooks)
	r.hooksMu.RUnlock()

	r.mutableAroundHookMu.RLock()
	mutable := make([]mutableAroundHookEntry, len(r.mutableAroundHooks))
	copy(mutable, r.mutableAroundHooks)
	r.mutableAroundHookMu.RUnlock()

	out := make([]mergedAroundEntry, 0, len(immutable)+len(mutable))
	for _, e := range immutable {
		out = append(out, mergedAroundEntry{seq: e.seq, immutable: e.hook})
	}
	for _, e := range mutable {
		out = append(out, mergedAroundEntry{seq: e.seq, mutable: e.hook})
	}
	// Stable ascending sort by seq.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1].seq > out[j].seq; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// --- Middleware methods ---

// RegisterMiddleware installs a plugin middleware at a specific Order.
func (r *Registry) RegisterMiddleware(name string, mw server.ToolHandlerMiddleware, order int) error {
	if name == "" {
		return fmt.Errorf("mcp: middleware name is empty")
	}
	if mw == nil {
		return fmt.Errorf("mcp: middleware %q is nil", name)
	}
	r.middlewareMu.Lock()
	defer r.middlewareMu.Unlock()
	r.middlewareEntries[name] = PluginMiddlewareEntry{
		Name:       name,
		Order:      order,
		Middleware: mw,
	}
	return nil
}

// ListMiddleware returns registered entries in Order ascending.
func (r *Registry) ListMiddleware() []PluginMiddlewareEntry {
	r.middlewareMu.RLock()
	defer r.middlewareMu.RUnlock()
	out := make([]PluginMiddlewareEntry, 0, len(r.middlewareEntries))
	for _, e := range r.middlewareEntries {
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Order != out[j].Order {
			return out[i].Order < out[j].Order
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// MiddlewareCount returns the number of registered plugin middleware.
func (r *Registry) MiddlewareCount() int {
	r.middlewareMu.RLock()
	defer r.middlewareMu.RUnlock()
	return len(r.middlewareEntries)
}

// --- Widget methods ---

// RegisterWidget installs a plugin-supplied MCP App widget.
func (r *Registry) RegisterWidget(uri, name string, handler WidgetHandler) error {
	if err := validateWidgetURI(uri); err != nil {
		return err
	}
	if name == "" {
		return fmt.Errorf("mcp: widget name is empty for URI %q", uri)
	}
	if handler == nil {
		return fmt.Errorf("mcp: widget handler is nil for URI %q", uri)
	}
	if builtInWidgetURIs()[uri] {
		return fmt.Errorf("mcp: %q is a built-in widget URI — plugins cannot override it", uri)
	}
	r.widgetMu.Lock()
	defer r.widgetMu.Unlock()
	if _, existed := r.widgets[uri]; !existed {
		r.widgetOrdered = append(r.widgetOrdered, uri)
	}
	r.widgets[uri] = PluginWidget{URI: uri, Name: name, Handler: handler}
	return nil
}

// ListWidgets returns a snapshot in registration order.
func (r *Registry) ListWidgets() []PluginWidget {
	r.widgetMu.RLock()
	defer r.widgetMu.RUnlock()
	out := make([]PluginWidget, 0, len(r.widgetOrdered))
	for _, uri := range r.widgetOrdered {
		if w, ok := r.widgets[uri]; ok {
			out = append(out, w)
		}
	}
	return out
}

// WidgetCount returns the number of registered widgets.
func (r *Registry) WidgetCount() int {
	r.widgetMu.RLock()
	defer r.widgetMu.RUnlock()
	return len(r.widgets)
}

// --- Event-subscription methods ---

// SubscribePluginEvent registers a plugin handler for a domain event.
//
// Plugin#5: post-Install subscriptions are still recorded (so a future
// re-Install pass picks them up) but a warning surfaces — silent drops
// are a footgun for hot-reload-loaded plugins. The function still
// returns nil on validation success regardless of install state.
func (r *Registry) SubscribePluginEvent(eventType string, handler func(domain.Event)) error {
	if eventType == "" {
		return fmt.Errorf("mcp: plugin event subscription has empty event type")
	}
	if handler == nil {
		return fmt.Errorf("mcp: plugin event subscription for %q has nil handler", eventType)
	}
	r.eventMu.Lock()
	r.eventSubscriptions = append(r.eventSubscriptions, pluginEventSubscription{
		eventType: eventType,
		handler:   handler,
	})
	r.eventMu.Unlock()
	if d := r.installedAt.Load(); d != nil {
		// Already installed — caller (likely a hot-reloaded plugin) is
		// past the dispatcher's wiring window. Subscribe directly so
		// the handler still fires for THIS dispatcher; the recorded
		// entry above means a future Install also picks it up.
		watcherLogger().Warn(
			"plugin event subscription registered post-Install; subscribing directly",
			"event_type", eventType,
		)
		d.Subscribe(eventType, safeEventHandler(eventType, handler))
	}
	return nil
}

// InstallPluginEventSubscriptions wires registered plugin handlers onto a
// dispatcher. Each handler is wrapped with SafeInvoke (Plugin#14) so a
// buggy plugin's panic doesn't crash the dispatcher goroutine — Dispatch
// is called synchronously on the request path.
//
// Marks the registry as installed-at-this-dispatcher so future
// SubscribePluginEvent calls subscribe directly (and warn).
func (r *Registry) InstallPluginEventSubscriptions(d *domain.EventDispatcher) {
	if d == nil {
		return
	}
	r.eventMu.RLock()
	subs := append([]pluginEventSubscription(nil), r.eventSubscriptions...)
	r.eventMu.RUnlock()
	for _, s := range subs {
		d.Subscribe(s.eventType, safeEventHandler(s.eventType, s.handler))
	}
	r.installedAt.Store(d)
}

// safeEventHandler wraps a plugin handler in SafeInvoke. A handler
// panic during dispatch is converted to a logged error rather than
// propagated up the synchronous Dispatch chain — Plugin#14.
func safeEventHandler(eventType string, h func(domain.Event)) func(domain.Event) {
	return func(e domain.Event) {
		_ = SafeInvoke("plugin_event:"+eventType, func() error {
			h(e)
			return nil
		})
	}
}

// ListEventSubscriptions returns a snapshot keyed by event type.
func (r *Registry) ListEventSubscriptions() map[string]int {
	r.eventMu.RLock()
	defer r.eventMu.RUnlock()
	counts := make(map[string]int)
	for _, s := range r.eventSubscriptions {
		counts[s.eventType]++
	}
	return counts
}

// EventSubscriptionCount returns the total subscription count.
func (r *Registry) EventSubscriptionCount() int {
	r.eventMu.RLock()
	defer r.eventMu.RUnlock()
	return len(r.eventSubscriptions)
}

// --- Lifecycle methods ---

// RegisterPluginLifecycle adds a lifecycle participant.
func (r *Registry) RegisterPluginLifecycle(name string, l PluginLifecycle) {
	if l == nil || name == "" {
		return
	}
	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()
	r.lifecycleEntries = append(r.lifecycleEntries, lifecycleEntry{
		name:      name,
		lifecycle: l,
	})
}

// LifecycleCount returns registered lifecycle participants.
func (r *Registry) LifecycleCount() int {
	r.lifecycleMu.RLock()
	defer r.lifecycleMu.RUnlock()
	return len(r.lifecycleEntries)
}

// InitAll fires Init on every registered lifecycle.
func (r *Registry) InitAll(ctx context.Context) error {
	r.lifecycleMu.RLock()
	entries := append([]lifecycleEntry(nil), r.lifecycleEntries...)
	r.lifecycleMu.RUnlock()

	var errs []string
	for _, e := range entries {
		e := e
		if err := SafeInvoke(e.name+":init", func() error { return e.lifecycle.Init(ctx) }); err != nil {
			r.ReportPluginHealth(e.name, HealthStatus{
				State:   HealthStateFailed,
				Message: "init failed: " + err.Error(),
			})
			errs = append(errs, e.name+": "+err.Error())
			continue
		}
		r.ReportPluginHealth(e.name, HealthStatus{State: HealthStateOK})
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("plugin init errors (%d): %v", len(errs), errs)
}

// ShutdownAll fires Shutdown in reverse registration order.
func (r *Registry) ShutdownAll(ctx context.Context) error {
	r.lifecycleMu.RLock()
	entries := append([]lifecycleEntry(nil), r.lifecycleEntries...)
	r.lifecycleMu.RUnlock()

	var errs []string
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if err := SafeInvoke(e.name+":shutdown", func() error { return e.lifecycle.Shutdown(ctx) }); err != nil {
			errs = append(errs, e.name+": "+err.Error())
			continue
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("plugin shutdown errors (%d): %v", len(errs), errs)
}

// ReloadAll runs ShutdownAll followed by InitAll.
func (r *Registry) ReloadAll(ctx context.Context) error {
	if err := r.ShutdownAll(ctx); err != nil {
		return fmt.Errorf("reload: shutdown phase: %w", err)
	}
	return r.InitAll(ctx)
}

// --- Health methods ---

// ReportPluginHealth records a plugin's health status.
func (r *Registry) ReportPluginHealth(name string, status HealthStatus) {
	if name == "" {
		return
	}
	if status.LastChecked.IsZero() {
		status.LastChecked = time.Now()
	}
	r.healthMu.Lock()
	defer r.healthMu.Unlock()
	r.healthEntries[name] = status
}

// PluginHealth returns a snapshot of health entries.
func (r *Registry) PluginHealth() map[string]HealthStatus {
	r.healthMu.RLock()
	defer r.healthMu.RUnlock()
	out := make(map[string]HealthStatus, len(r.healthEntries))
	for k, v := range r.healthEntries {
		out[k] = v
	}
	return out
}

// --- Plugin-info methods ---

// RegisterPluginInfo stores a plugin manifest entry.
func (r *Registry) RegisterPluginInfo(info PluginInfo) error {
	if info.Name == "" {
		return fmt.Errorf("mcp: plugin info requires Name")
	}
	if info.Version == "" {
		return fmt.Errorf("mcp: plugin info requires Version")
	}
	r.infoMu.Lock()
	defer r.infoMu.Unlock()
	r.infoItems[info.Name] = info
	return nil
}

// ListPlugins returns manifests sorted by Name.
func (r *Registry) ListPlugins() []PluginInfo {
	r.infoMu.RLock()
	defer r.infoMu.RUnlock()
	out := make([]PluginInfo, 0, len(r.infoItems))
	for _, p := range r.infoItems {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// InfoCount returns the number of plugin manifests.
func (r *Registry) InfoCount() int {
	r.infoMu.RLock()
	defer r.infoMu.RUnlock()
	return len(r.infoItems)
}

// --- SBOM methods ---

// RegisterSBOM stores an SBOM entry. Phase G: when a trusted signer
// key is configured on the registry, the entry's signature is verified
// against the checksum here — mismatched or (in prod) missing
// signatures short-circuit registration. When no trusted signer is
// configured, behavior is unchanged from pre-Phase-G: opaque storage
// only. See plugin_sbom_signature.go verifyEntrySignature for the
// full policy table.
func (r *Registry) RegisterSBOM(entry PluginSBOMEntry) error {
	if entry.Name == "" {
		return fmt.Errorf("mcp: SBOM entry requires Name")
	}
	if entry.Checksum == "" {
		return fmt.Errorf("mcp: SBOM entry for %q requires Checksum", entry.Name)
	}
	if err := r.verifyEntrySignature(entry); err != nil {
		return err
	}
	if entry.Recorded.IsZero() {
		entry.Recorded = time.Now()
	}
	r.sbomMu.Lock()
	defer r.sbomMu.Unlock()
	r.sbomEntries[entry.Name] = entry
	return nil
}

// ListSBOM returns a snapshot of SBOM entries.
func (r *Registry) ListSBOM() map[string]PluginSBOMEntry {
	r.sbomMu.RLock()
	defer r.sbomMu.RUnlock()
	out := make(map[string]PluginSBOMEntry, len(r.sbomEntries))
	for k, v := range r.sbomEntries {
		out[k] = v
	}
	return out
}

// SBOMCount returns the number of SBOM entries.
func (r *Registry) SBOMCount() int {
	r.sbomMu.RLock()
	defer r.sbomMu.RUnlock()
	return len(r.sbomEntries)
}

// --- Misc helper that keeps the gomcp import used ---
var _ gomcp.Tool // silence unused-import if other exported helpers move elsewhere
