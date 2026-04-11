package example

import (
	"context"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

func TestServerTimeTool_ToolDefinition(t *testing.T) {
	tool := &ServerTimeTool{}
	def := tool.Tool()

	if def.Name != "server_time" {
		t.Errorf("Name = %q, want %q", def.Name, "server_time")
	}
	if def.Description != "Returns current server time and timezone. Example plugin tool." {
		t.Errorf("Description = %q", def.Description)
	}
}

func TestServerTimeTool_Handler(t *testing.T) {
	tool := &ServerTimeTool{}
	handler := tool.Handler(nil) // manager not needed for this tool

	result, err := handler(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("Handler error: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if len(result.Content) == 0 {
		t.Fatal("result should have content")
	}
	// Verify it's a text result.
	content := result.Content[0]
	textContent, ok := content.(mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", content)
	}
	if textContent.Text == "" {
		t.Error("text should not be empty")
	}
}

func TestServerTimeTool_Annotations(t *testing.T) {
	tool := &ServerTimeTool{}
	def := tool.Tool()

	if def.Annotations.Title != "Server Time (Plugin)" {
		t.Errorf("Title = %q, want %q", def.Annotations.Title, "Server Time (Plugin)")
	}
	if def.Annotations.ReadOnlyHint == nil || !*def.Annotations.ReadOnlyHint {
		t.Error("ReadOnlyHint should be true")
	}
	if def.Annotations.IdempotentHint == nil || !*def.Annotations.IdempotentHint {
		t.Error("IdempotentHint should be true")
	}
	if def.Annotations.OpenWorldHint == nil || *def.Annotations.OpenWorldHint {
		t.Error("OpenWorldHint should be false")
	}
}
