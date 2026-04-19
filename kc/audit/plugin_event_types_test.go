package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegisterEventType_Basic — happy path: register a new plugin
// event type and confirm it appears in ListEventTypes.
func TestRegisterEventType_Basic(t *testing.T) {
	ClearPluginEventTypes()
	defer ClearPluginEventTypes()

	err := RegisterEventType("plugin.webhook.sent", EventTypeSchema{
		Description: "Outgoing webhook delivery",
		Category:    "integration",
		Fields:      []string{"webhook_url", "status_code"},
	})
	require.NoError(t, err)

	types := ListEventTypes()
	require.Contains(t, types, "plugin.webhook.sent")
	assert.Equal(t, "integration", types["plugin.webhook.sent"].Category)
	assert.Equal(t, []string{"webhook_url", "status_code"}, types["plugin.webhook.sent"].Fields)
}

// TestRegisterEventType_RejectsEmpty — empty name, empty description,
// and empty category all fail at registration.
func TestRegisterEventType_RejectsEmpty(t *testing.T) {
	ClearPluginEventTypes()
	defer ClearPluginEventTypes()

	assert.Error(t, RegisterEventType("", EventTypeSchema{Description: "x", Category: "y"}))
	assert.Error(t, RegisterEventType("plugin.x", EventTypeSchema{Description: "", Category: "y"}))
	assert.Error(t, RegisterEventType("plugin.x", EventTypeSchema{Description: "x", Category: ""}))
}

// TestRegisterEventType_ReservedCategories — built-in categories
// cannot be shadowed. This keeps the audit category namespace clean
// for SEBI compliance reporting.
func TestRegisterEventType_ReservedCategories(t *testing.T) {
	ClearPluginEventTypes()
	defer ClearPluginEventTypes()

	// built-in categories used by the ToolCall pipeline
	for _, reserved := range []string{"order", "alert", "session", "admin", "billing"} {
		err := RegisterEventType("plugin.try."+reserved, EventTypeSchema{
			Description: "attempt",
			Category:    reserved,
		})
		assert.Error(t, err, "category %q should be reserved", reserved)
	}
}

// TestRegisterEventType_DuplicateReplaces — last-wins matches the
// pattern used across RegisterWidget / RegisterMiddleware.
func TestRegisterEventType_DuplicateReplaces(t *testing.T) {
	ClearPluginEventTypes()
	defer ClearPluginEventTypes()

	require.NoError(t, RegisterEventType("plugin.x", EventTypeSchema{
		Description: "first", Category: "plugin",
	}))
	require.NoError(t, RegisterEventType("plugin.x", EventTypeSchema{
		Description: "second", Category: "plugin",
	}))

	types := ListEventTypes()
	assert.Len(t, types, 1)
	assert.Equal(t, "second", types["plugin.x"].Description)
}

// TestEventTypeCount tracks registry size — used by the admin plugin
// listing endpoint.
func TestEventTypeCount(t *testing.T) {
	ClearPluginEventTypes()
	defer ClearPluginEventTypes()

	assert.Equal(t, 0, PluginEventTypeCount())
	_ = RegisterEventType("plugin.a", EventTypeSchema{Description: "d", Category: "plugin"})
	_ = RegisterEventType("plugin.b", EventTypeSchema{Description: "d", Category: "plugin"})
	assert.Equal(t, 2, PluginEventTypeCount())
}
