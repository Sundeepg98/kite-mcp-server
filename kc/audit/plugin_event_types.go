package audit

import (
	"fmt"
	"sync"
)

// EventTypeSchema describes a plugin-registered audit event category.
// Plugins that emit audit events beyond the built-in ToolCall pipeline
// (e.g., webhook deliveries, external API calls, compliance snapshots)
// register a schema so the admin plugins-list surface can show what
// categories of audit data the server is producing.
//
// This is an inventory/documentation surface — it does NOT validate
// the payload. Plugins remain responsible for populating their audit
// rows through whatever storage path they own. The registry exists so
// auditors can enumerate "what audit event types does this deployment
// produce?" at a glance, and the admin endpoint can report plugin-
// contributed categories alongside built-ins.
type EventTypeSchema struct {
	// Description is a one-line human-readable summary. Required.
	Description string
	// Category groups related event types. Required. Plugins must
	// use their own namespace (e.g., "plugin", "integration",
	// "compliance") — the built-in categories (order, alert, session,
	// admin, billing) are reserved.
	Category string
	// Fields is the list of expected columns/keys on each event
	// of this type. Informational only — the registry doesn't
	// enforce shape on the audit rows.
	Fields []string
}

// reservedEventCategories matches the set of categories used by the
// built-in ToolCall audit pipeline. Plugins that try to shadow these
// are rejected — keeps the audit surface auditable.
var reservedEventCategories = map[string]bool{
	"order":   true,
	"alert":   true,
	"session": true,
	"admin":   true,
	"billing": true,
}

var pluginEventTypeRegistry = struct {
	mu    sync.RWMutex
	types map[string]EventTypeSchema
}{
	types: make(map[string]EventTypeSchema),
}

// RegisterEventType installs a plugin-contributed audit event type.
// Returns an error when:
//   - name is empty (the admin surface keys on name);
//   - schema.Description is empty;
//   - schema.Category is empty;
//   - schema.Category collides with a reserved built-in category.
//
// Duplicate names replace the prior schema (last-wins; matches
// RegisterWidget/RegisterMiddleware conventions).
func RegisterEventType(name string, schema EventTypeSchema) error {
	if name == "" {
		return fmt.Errorf("audit: event type name is empty")
	}
	if schema.Description == "" {
		return fmt.Errorf("audit: event type %q has empty Description", name)
	}
	if schema.Category == "" {
		return fmt.Errorf("audit: event type %q has empty Category", name)
	}
	if reservedEventCategories[schema.Category] {
		return fmt.Errorf("audit: event type %q category %q is reserved for built-in audit pipeline", name, schema.Category)
	}
	pluginEventTypeRegistry.mu.Lock()
	defer pluginEventTypeRegistry.mu.Unlock()
	pluginEventTypeRegistry.types[name] = schema
	return nil
}

// ListEventTypes returns a snapshot of all plugin-registered event
// types keyed by name. Safe for concurrent use; the returned map is
// a fresh allocation.
func ListEventTypes() map[string]EventTypeSchema {
	pluginEventTypeRegistry.mu.RLock()
	defer pluginEventTypeRegistry.mu.RUnlock()
	out := make(map[string]EventTypeSchema, len(pluginEventTypeRegistry.types))
	for k, v := range pluginEventTypeRegistry.types {
		out[k] = v
	}
	return out
}

// PluginEventTypeCount returns the number of registered plugin event
// types. Used by the admin plugins-list surface.
func PluginEventTypeCount() int {
	pluginEventTypeRegistry.mu.RLock()
	defer pluginEventTypeRegistry.mu.RUnlock()
	return len(pluginEventTypeRegistry.types)
}

// ClearPluginEventTypes removes every plugin-registered event type.
// Test-only.
func ClearPluginEventTypes() {
	pluginEventTypeRegistry.mu.Lock()
	defer pluginEventTypeRegistry.mu.Unlock()
	pluginEventTypeRegistry.types = make(map[string]EventTypeSchema)
}
