package mcp

// manifest helpers are pure delegates onto DefaultRegistry; all
// direct state has moved to the Registry struct in plugin_registry.go.

// PluginInfo is the manifest a plugin supplies at registration time.
// It describes the plugin for the admin surface (plugins-list endpoint,
// /admin dashboard "installed plugins" panel) and for log lines that
// want to attribute a hook, widget, or middleware registration to a
// named plugin.
//
// The manifest is INFORMATIONAL. It does not affect which hooks,
// widgets, middleware, routes, or commands the plugin has registered —
// those remain on their own per-category registries. The manifest
// exists so operators can answer "what plugins are loaded?" without
// grepping source or reading log lines.
type PluginInfo struct {
	// Name is the stable identifier for the plugin. Required.
	Name string
	// Version is the plugin's version string (semver recommended but
	// not enforced). Required.
	Version string
	// Description is a one-line human-readable summary.
	Description string
	// Author is a contact string (email, GitHub handle, etc.).
	Author string
	// Homepage is an optional URL for plugin docs.
	Homepage string
	// Extensions lists the categories of extension this plugin
	// contributes ("tool", "hook", "middleware", "widget",
	// "telegram_command", "route", "event_subscription",
	// "scheduler_task", "riskguard_check", "audit_event_type").
	// Informational only — the actual registrations are tracked on
	// the per-category registries.
	Extensions []string
}

// RegisterPluginInfo installs a plugin manifest on DefaultRegistry.
// Duplicate names replace (last-wins) to support plugin reload cycles.
//
// Returns an error when Name or Version is empty. Other fields are
// optional — plugins that care only about being visible in the
// admin listing can supply just Name + Version.
func RegisterPluginInfo(info PluginInfo) error {
	return DefaultRegistry.RegisterPluginInfo(info)
}

// ListPlugins returns a snapshot of registered plugin manifests on
// DefaultRegistry, sorted by Name.
func ListPlugins() []PluginInfo {
	return DefaultRegistry.ListPlugins()
}

// PluginInfoCount returns the number of registered plugin manifests
// on DefaultRegistry.
func PluginInfoCount() int {
	return DefaultRegistry.InfoCount()
}

// ClearPluginInfo drops every registered plugin manifest on
// DefaultRegistry. Test-only.
func ClearPluginInfo() {
	DefaultRegistry.infoMu.Lock()
	defer DefaultRegistry.infoMu.Unlock()
	DefaultRegistry.infoItems = make(map[string]PluginInfo)
}

// PluginManifest aggregates every plugin-registered extension into a
// single snapshot. Used by admin endpoints that want to answer
// "what does this deployment have?" in one call.
//
// Counts are live snapshots at the time of the call — subsequent
// registrations won't be reflected.
type PluginManifest struct {
	Plugins                []PluginInfo
	ToolPluginCount        int
	BeforeHookCount        int
	AfterHookCount         int
	AroundHookCount        int
	MiddlewareCount        int
	WidgetCount            int
	EventSubscriptionCount int
	// Health surfaces per-plugin ok/degraded/failed state, populated
	// by ReportPluginHealth (see plugin_lifecycle.go). Gives the
	// admin surface a single "is anything red?" snapshot.
	Health                 map[string]HealthStatus
	// LifecycleCount is the number of registries participating in
	// the Init/Shutdown/Reload coordination.
	LifecycleCount         int
	// SBOM is the Software Bill of Materials — per-plugin checksum,
	// optional version, optional signature. Populated by
	// RegisterPluginSBOM (see plugin_sbom.go). Answers "what code
	// is serving this plugin right now?" — the forensic question
	// after a drift / tampering incident.
	SBOM                   map[string]PluginSBOMEntry
}

// GetPluginManifest returns a snapshot of every plugin-contributed
// extension. The snapshot is captured atomically per-registry but NOT
// across registries — a registration racing with GetPluginManifest
// may appear in some counts but not others. This is acceptable for
// an admin-surface endpoint; high-fidelity coordination would require
// a global lock that would serialise every plugin registration.
func GetPluginManifest() PluginManifest {
	return PluginManifest{
		Plugins:                ListPlugins(),
		ToolPluginCount:        PluginCount(),
		BeforeHookCount:        beforeHookCount(),
		AfterHookCount:         afterHookCount(),
		AroundHookCount:        aroundHookCount(),
		MiddlewareCount:        PluginMiddlewareCount(),
		WidgetCount:            PluginWidgetCount(),
		EventSubscriptionCount: PluginEventSubscriptionCount(),
		Health:                 PluginHealth(),
		LifecycleCount:         PluginLifecycleCount(),
		SBOM:                   ListPluginSBOM(),
	}
}

// beforeHookCount, afterHookCount, aroundHookCount expose the hook
// slice lengths on DefaultRegistry. Kept as small helpers so manifest
// code doesn't reach directly into Registry's fields.
func beforeHookCount() int { return DefaultRegistry.BeforeHookCount() }
func afterHookCount() int  { return DefaultRegistry.AfterHookCount() }
func aroundHookCount() int { return DefaultRegistry.AroundHookCount() }
