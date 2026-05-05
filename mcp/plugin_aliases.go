package mcp

import (
	"context"
	"log/slog"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/zerodha/kite-mcp-server/kc/domain"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
	"github.com/zerodha/kite-mcp-server/mcp/common"
	"github.com/zerodha/kite-mcp-server/mcp/plugin"

	// Side-effect imports — sub-packages whose init() functions
	// register their tools via plugin.RegisterInternalTool. Without
	// these blank imports, the per-domain sub-package init()s never
	// run when only the mcp/ root is loaded (e.g., tests in package
	// mcp), and tools=111 wire-protocol invariant breaks.
	//
	// Anchor 1 PR 1.4: introduced when mcp/admin extraction made
	// admin tools' init() registration unreachable from mcp/ root.
	// Each future per-domain PR (1.6 portfolio, etc.) adds its
	// sibling import here.
	_ "github.com/zerodha/kite-mcp-server/mcp/admin"
	_ "github.com/zerodha/kite-mcp-server/mcp/alerts"
	_ "github.com/zerodha/kite-mcp-server/mcp/analytics"
	_ "github.com/zerodha/kite-mcp-server/mcp/paper"
	_ "github.com/zerodha/kite-mcp-server/mcp/portfolio"
	_ "github.com/zerodha/kite-mcp-server/mcp/trade"
)

// plugin_aliases.go — Anchor 1 PR 1.3 (per .research/anchor-1-and-3-
// pr-design.md commit 04e069a). Backward-compatibility shims for the
// types, functions, and constants that moved into mcp/plugin.
//
// After this PR, mcp/plugin is the canonical home for:
//   - the App-scoped *Registry struct + DefaultRegistry singleton
//   - plugin lifecycle (RegisterPluginLifecycle, Init/Shutdown/Reload)
//   - plugin manifest (RegisterPluginInfo, ListPlugins, GetPluginManifest)
//   - plugin events (SubscribePluginEvent, InstallPluginEventSubscriptions)
//   - plugin SBOM (RegisterPluginSBOM, ListPluginSBOM, ChecksumBytes/File)
//   - plugin watcher (WatchPluginBinary, StartPluginBinaryWatcher)
//   - plugin middleware (RegisterMiddleware, ListPluginMiddleware,
//     PluginMiddlewareChain)
//   - plugin widgets (RegisterWidget, ListPluginWidgets,
//     PluginWidgetCount, WidgetHandler, PluginWidget)
//   - the typed-decorator HookMiddleware infrastructure
//     (mergedAroundEntry, safeInvokeAroundHook, ToolAroundHook,
//     ToolHandlerNext, ToolHook, OnBeforeToolExecution,
//     OnAfterToolExecution, OnToolExecution, RunBeforeHooks,
//     RunAfterHooks, ClearHooks, HookMiddleware, HookMiddlewareFor)
//   - the FullPluginOpts / RegisterFullPlugin one-shot installer
//   - the MutableCallToolRequest mutable-around-hook surface
//   - the kc/decorators bridge (composeAroundChain, mcpToolHandler,
//     mcpToolDecorator, aroundEntryToDecorator)
//
// EMPIRICAL SCOPE NARROWING vs AUDIT
//
// The audit listed 13 plugin files. Empirical analysis found 5 of
// them (the per-widget files: plugin_widget_ip_whitelist.go,
// plugin_widget_margin_gauge.go, plugin_widget_pnl_sparkline.go,
// plugin_widget_returns_matrix.go, plugin_widget_sector_donut.go)
// directly access symbols in mcp/ext_apps.go (extAppManagerPort
// interface, appResources slice) and mcp/sector_tool.go
// (stockSectors map, normalizeSymbol, formatPct helpers). Plus
// plugin_widgets_pack.go (the registration shim that wires them up)
// has the same coupling.
//
// Moving those 7 files to mcp/plugin would require either:
//   (a) Capitalising 5+ private symbols in ext_apps.go + sector_tool.go,
//       making them part of the public API permanently
//   (b) Moving ext_apps.go + sector_tool.go themselves, which contradicts
//       the audit's mcp/misc clustering for those files
//
// Both are larger refactors than the per-widget files justify. PR 1.3
// keeps the 7 widget-data files in mcp/ root; they will move in a
// future PR alongside ext_apps.go cleanup (or stay as mcp/misc per
// audit). plugin_widgets.go itself (the WidgetHandler type +
// RegisterWidget API) DID move to mcp/plugin because the Registry
// struct in plugin_registry.go has a `widgets map[string]PluginWidget`
// field — keeping plugin_widgets.go in mcp/ would force PluginWidget
// to be a cross-package type, with the same Tool↔Registry-style cycle
// PR 1.1 had to break.
//
// To preserve plugin_widgets.go's URI-collision check (which previously
// referenced appResources directly), the function was parameterised:
// plugin.SetBuiltInWidgetURIs([]string) is now called from this
// aliases file's init() with the URI list extracted from appResources.

// ---------------------------------------------------------------------
// Type aliases — exported symbols from mcp/plugin re-exposed under mcp.X
// ---------------------------------------------------------------------

type (
	// Plugin registry types
	Registry              = plugin.Registry
	ToolHook              = plugin.ToolHook
	ToolAroundHook        = plugin.ToolAroundHook
	ToolHandlerNext       = plugin.ToolHandlerNext

	// Plugin lifecycle
	PluginLifecycle = plugin.PluginLifecycle
	HealthState     = plugin.HealthState
	HealthStatus    = plugin.HealthStatus

	// Plugin manifest
	PluginInfo     = plugin.PluginInfo
	PluginManifest = plugin.PluginManifest

	// Plugin middleware
	PluginMiddlewareEntry = plugin.PluginMiddlewareEntry

	// Plugin SBOM
	PluginSBOMEntry = plugin.PluginSBOMEntry

	// Plugin watcher
	BinaryReloadable = plugin.BinaryReloadable

	// Plugin widgets
	WidgetHandler = plugin.WidgetHandler
	PluginWidget  = plugin.PluginWidget

	// Plugin full-plugin one-shot installer
	FullPluginMiddleware = plugin.FullPluginMiddleware
	FullPluginWidget     = plugin.FullPluginWidget
	FullPluginOpts       = plugin.FullPluginOpts

	// Mutable around-hook surface
	MutableCallToolRequest = plugin.MutableCallToolRequest
)

// ---------------------------------------------------------------------
// Var passthrough — DefaultRegistry singleton
// ---------------------------------------------------------------------

// DefaultRegistry is the package-level *Registry retained for legacy
// init()-time RegisterPlugin / RegisterMiddleware / RegisterWidget
// callers. New code should use the App-scoped *Registry returned by
// app.Registry() (B77 isolation).
var DefaultRegistry = plugin.DefaultRegistry

// HealthState constants — re-exported from mcp/plugin.
const (
	HealthStateOK       = plugin.HealthStateOK
	HealthStateDegraded = plugin.HealthStateDegraded
	HealthStateFailed   = plugin.HealthStateFailed
	HealthStateUnknown  = plugin.HealthStateUnknown
)

// ---------------------------------------------------------------------
// Function passthroughs — Registry construction
// ---------------------------------------------------------------------

// NewRegistry constructs a fresh App-scoped *Registry.
func NewRegistry() *Registry { return plugin.NewRegistry() }

// ---------------------------------------------------------------------
// Function passthroughs — DefaultRegistry tool-plugin API
// ---------------------------------------------------------------------

// RegisterPlugin adds a Tool to DefaultRegistry. Pre-startup-only.
func RegisterPlugin(tool Tool) { plugin.RegisterPlugin(tool) }

// RegisterPlugins adds multiple tools to DefaultRegistry.
func RegisterPlugins(tools ...Tool) { plugin.RegisterPlugins(tools...) }

// PluginCount returns the number of plugins on DefaultRegistry.
func PluginCount() int { return plugin.PluginCount() }

// ClearPlugins removes all plugins on DefaultRegistry (test helper).
func ClearPlugins() { plugin.ClearPlugins() }

// ---------------------------------------------------------------------
// Function passthroughs — DefaultRegistry hook API
// ---------------------------------------------------------------------

// OnBeforeToolExecution registers a before-hook on DefaultRegistry.
func OnBeforeToolExecution(hook ToolHook) { plugin.OnBeforeToolExecution(hook) }

// OnAfterToolExecution registers an after-hook on DefaultRegistry.
func OnAfterToolExecution(hook ToolHook) { plugin.OnAfterToolExecution(hook) }

// OnToolExecution registers an around-hook on DefaultRegistry.
func OnToolExecution(hook ToolAroundHook) { plugin.OnToolExecution(hook) }

// RunBeforeHooks invokes all before-hooks on DefaultRegistry.
func RunBeforeHooks(ctx context.Context, toolName string, args map[string]any) error {
	return plugin.RunBeforeHooks(ctx, toolName, args)
}

// RunAfterHooks invokes all after-hooks on DefaultRegistry.
func RunAfterHooks(ctx context.Context, toolName string, args map[string]any) {
	plugin.RunAfterHooks(ctx, toolName, args)
}

// ClearHooks removes all hooks on DefaultRegistry (test helper).
func ClearHooks() { plugin.ClearHooks() }

// HookMiddleware returns the around-hook middleware bound to
// DefaultRegistry.
func HookMiddleware() server.ToolHandlerMiddleware { return plugin.HookMiddleware() }

// HookMiddlewareFor returns the around-hook middleware bound to the
// supplied *Registry. Used by app/wire.go for App-scoped isolation.
func HookMiddlewareFor(reg *Registry) server.ToolHandlerMiddleware {
	return plugin.HookMiddlewareFor(reg)
}

// ---------------------------------------------------------------------
// Function passthroughs — Plugin lifecycle
// ---------------------------------------------------------------------

func RegisterPluginLifecycle(name string, l PluginLifecycle) {
	plugin.RegisterPluginLifecycle(name, l)
}
func ClearPluginLifecycles() { plugin.ClearPluginLifecycles() }
func PluginLifecycleCount() int {
	return plugin.PluginLifecycleCount()
}
func InitPluginRegistries(ctx context.Context) error {
	return plugin.InitPluginRegistries(ctx)
}
func ShutdownPluginRegistries(ctx context.Context) error {
	return plugin.ShutdownPluginRegistries(ctx)
}
func ReloadPluginRegistries(ctx context.Context) error {
	return plugin.ReloadPluginRegistries(ctx)
}
func ReportPluginHealth(name string, status HealthStatus) {
	plugin.ReportPluginHealth(name, status)
}
func PluginHealth() map[string]HealthStatus {
	return plugin.PluginHealth()
}
func ClearPluginHealth() { plugin.ClearPluginHealth() }
func ListPluginHealthSorted() []string {
	return plugin.ListPluginHealthSorted()
}
func SafeInvoke(pluginName string, fn func() error) error {
	return plugin.SafeInvoke(pluginName, fn)
}

// SafeCall is the typed companion of SafeInvoke. Generic functions
// cannot be aliased in Go, so this is a thin generic forwarder.
func SafeCall[T any](pluginName string, fn func() (T, error)) (T, error) {
	return plugin.SafeCall(pluginName, fn)
}

// ---------------------------------------------------------------------
// Function passthroughs — Plugin events
// ---------------------------------------------------------------------

func SubscribePluginEvent(eventType string, handler func(domain.Event)) error {
	return plugin.SubscribePluginEvent(eventType, handler)
}
func InstallPluginEventSubscriptions(d *domain.EventDispatcher) {
	plugin.InstallPluginEventSubscriptions(d)
}
func ListPluginEventSubscriptions() map[string]int {
	return plugin.ListPluginEventSubscriptions()
}
func PluginEventSubscriptionCount() int {
	return plugin.PluginEventSubscriptionCount()
}
func ClearPluginEventSubscriptions() {
	plugin.ClearPluginEventSubscriptions()
}

// ---------------------------------------------------------------------
// Function passthroughs — Plugin manifest
// ---------------------------------------------------------------------

func RegisterPluginInfo(info PluginInfo) error {
	return plugin.RegisterPluginInfo(info)
}
func ListPlugins() []PluginInfo {
	return plugin.ListPlugins()
}
func PluginInfoCount() int {
	return plugin.PluginInfoCount()
}
func ClearPluginInfo() {
	plugin.ClearPluginInfo()
}
func GetPluginManifest() PluginManifest {
	return plugin.GetPluginManifest()
}

// ---------------------------------------------------------------------
// Function passthroughs — Plugin middleware
// ---------------------------------------------------------------------

func RegisterMiddleware(name string, mw server.ToolHandlerMiddleware, order int) error {
	return plugin.RegisterMiddleware(name, mw, order)
}
func ListPluginMiddleware() []PluginMiddlewareEntry {
	return plugin.ListPluginMiddleware()
}
func PluginMiddlewareCount() int {
	return plugin.PluginMiddlewareCount()
}
func ClearPluginMiddleware() {
	plugin.ClearPluginMiddleware()
}
func PluginMiddlewareChain() server.ToolHandlerMiddleware {
	return plugin.PluginMiddlewareChain()
}

// ---------------------------------------------------------------------
// Function passthroughs — Plugin SBOM
// ---------------------------------------------------------------------

func RegisterPluginSBOM(entry PluginSBOMEntry) error {
	return plugin.RegisterPluginSBOM(entry)
}
func ListPluginSBOM() map[string]PluginSBOMEntry {
	return plugin.ListPluginSBOM()
}
func ListPluginSBOMSorted() []string {
	return plugin.ListPluginSBOMSorted()
}
func PluginSBOMCount() int {
	return plugin.PluginSBOMCount()
}
func ClearPluginSBOM() {
	plugin.ClearPluginSBOM()
}
func ChecksumBytes(data []byte) string {
	return plugin.ChecksumBytes(data)
}
func ChecksumFile(path string) (string, error) {
	return plugin.ChecksumFile(path)
}

// ---------------------------------------------------------------------
// Function passthroughs — Plugin watcher
// ---------------------------------------------------------------------

func SetPluginWatcherEventDispatcher(d *domain.EventDispatcher) {
	plugin.SetPluginWatcherEventDispatcher(d)
}
func SetPluginWatcherLogger(logger *slog.Logger) {
	plugin.SetPluginWatcherLogger(logger)
}
func SetPluginWatcherLoggerPort(logger logport.Logger) {
	plugin.SetPluginWatcherLoggerPort(logger)
}
func WatchPluginBinary(path string, r BinaryReloadable) error {
	return plugin.WatchPluginBinary(path, r)
}
func ClearPluginWatches() {
	plugin.ClearPluginWatches()
}
func StartPluginBinaryWatcher(ctx context.Context) error {
	return plugin.StartPluginBinaryWatcher(ctx)
}
func StopPluginBinaryWatcher() {
	plugin.StopPluginBinaryWatcher()
}
func IsPluginHotReloadEnabled() bool {
	return plugin.IsPluginHotReloadEnabled()
}
func PluginWatcherCount() int {
	return plugin.PluginWatcherCount()
}

// ---------------------------------------------------------------------
// Function passthroughs — Plugin widgets
// ---------------------------------------------------------------------

func RegisterWidget(uri, name string, handler WidgetHandler) error {
	return plugin.RegisterWidget(uri, name, handler)
}
func ListPluginWidgets() []PluginWidget {
	return plugin.ListPluginWidgets()
}
func ClearPluginWidgets() {
	plugin.ClearPluginWidgets()
}
func PluginWidgetCount() int {
	return plugin.PluginWidgetCount()
}

// ---------------------------------------------------------------------
// Function passthroughs — FullPlugin one-shot installer
// ---------------------------------------------------------------------

func RegisterFullPlugin(opts FullPluginOpts) error {
	return plugin.RegisterFullPlugin(opts)
}

// ---------------------------------------------------------------------
// Function passthroughs — MutableCallToolRequest
// ---------------------------------------------------------------------

func NewMutableCallToolRequest(req gomcp.CallToolRequest) *MutableCallToolRequest {
	return plugin.NewMutableCallToolRequest(req)
}

// ---------------------------------------------------------------------
// Var passthrough — common.Tool re-export
// ---------------------------------------------------------------------

// _ keeps the common import alive for readability of the rest of the
// file. Tool itself was already aliased in mcp/aliases.go (PR 1.1).
var _ common.Tool

// RegisterInternalTool is the legacy free-function passthrough for
// the 60+ in-tree `func init() { mcp.RegisterInternalTool(...) }`
// callers. Anchor 1 PR 1.4: the canonical implementation moved to
// mcp/plugin alongside the rest of the plugin-registry infrastructure.
// New code in per-domain sub-packages (mcp/admin, mcp/trade, etc.)
// calls plugin.RegisterInternalTool directly to avoid a cycle through
// mcp/ root.
func RegisterInternalTool(t Tool) {
	plugin.RegisterInternalTool(t)
}

// ServerStartTime returns the package-level server start time used
// by status tools (admin_server_status, server_metrics, server_version,
// ext_apps status). Anchor 1 PR 1.4: exposed so mcp/admin's
// admin_server_status tool can compute uptime without needing
// access to the package-private serverStartTime variable.
func ServerStartTime() time.Time {
	return common.ServerStartTime
}

// init wires the appResources URI list into mcp/plugin so plugin_widgets'
// URI-collision check has the same domain-name set as before extraction.
// Called once at process startup; idempotent.
func init() {
	uris := make([]string, 0, len(appResources))
	for _, r := range appResources {
		uris = append(uris, r.URI)
	}
	plugin.SetBuiltInWidgetURIs(uris)
}
