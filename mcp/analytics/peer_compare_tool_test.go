package analytics

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Anchor 1 PR 1.7: integration tests for peer_compare that exercise
// callToolWithManager moved to mcp/peer_compare_tool_integration_test.go.
// The pure tool-definition test below stays here because it references
// the analytics-internal type PeerCompareTool.

// TestPeerCompareTool_ToolDefinition verifies the tool registration metadata
// (name, description, read-only annotation) so the tool is surfaced correctly
// to MCP clients.
func TestPeerCompareTool_ToolDefinition(t *testing.T) {
	t.Parallel()
	tool := (&PeerCompareTool{}).Tool()
	assert.Equal(t, "peer_compare", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.NotNil(t, tool.Annotations)
	assert.NotNil(t, tool.Annotations.ReadOnlyHint, "peer_compare must be marked read-only")
	assert.True(t, *tool.Annotations.ReadOnlyHint, "peer_compare must be marked read-only")
}
