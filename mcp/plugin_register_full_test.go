package mcp

import (
	"context"
	"testing"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
)

// fakeFullTool is a minimal Tool used to populate FullPluginOpts.Tools.
type fakeFullTool struct{ name string }

func (f *fakeFullTool) Tool() gomcp.Tool { return gomcp.NewTool(f.name) }
func (f *fakeFullTool) Handler(_ *kc.Manager) server.ToolHandlerFunc {
	return func(_ context.Context, _ gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("ok"), nil
	}
}

// TestRegisterFullPlugin_HappyPath proves the convenience helper applies
// every section of FullPluginOpts in one call. Plugin#22 closes the
// 4-5-call boilerplate that every plugin author writes today.
func TestRegisterFullPlugin_HappyPath(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)

	beforeTools := PluginCount()
	beforeMW := DefaultRegistry.MiddlewareCount()
	beforeWidgets := PluginWidgetCount()
	beforeInfo := DefaultRegistry.InfoCount()

	mw := func(next server.ToolHandlerFunc) server.ToolHandlerFunc { return next }
	widgetH := func(_ context.Context, _ gomcp.ReadResourceRequest) ([]gomcp.ResourceContents, error) {
		return nil, nil
	}

	err := RegisterFullPlugin(FullPluginOpts{
		Info: PluginInfo{Name: "p22-fixture", Version: "0.0.1"},
		Tools: []Tool{&fakeFullTool{name: "p22_t"}},
		Middleware: []FullPluginMiddleware{{Name: "p22_mw", Order: 9999, Middleware: mw}},
		Widgets: []FullPluginWidget{{URI: "ui://p22/fixture", Name: "P22 Fixture", Handler: widgetH}},
		SBOM: &PluginSBOMEntry{Name: "p22-fixture", Version: "0.0.1", Checksum: "sha256:" + "00000000000000000000000000000000000000000000000000000000000000ff", Recorded: time.Now()},
	})
	if err != nil {
		t.Fatalf("RegisterFullPlugin: %v", err)
	}
	if got := PluginCount() - beforeTools; got != 1 {
		t.Errorf("tools delta = %d, want 1", got)
	}
	if got := DefaultRegistry.MiddlewareCount() - beforeMW; got != 1 {
		t.Errorf("middleware delta = %d, want 1", got)
	}
	if got := PluginWidgetCount() - beforeWidgets; got != 1 {
		t.Errorf("widget delta = %d, want 1", got)
	}
	if got := DefaultRegistry.InfoCount() - beforeInfo; got != 1 {
		t.Errorf("info delta = %d, want 1", got)
	}
}

// TestRegisterFullPlugin_FirstErrorWins — a bad widget URI surfaces the
// underlying RegisterWidget error without partial-applying anything in
// the same opts struct. Caller's expected contract: atomic-ish failure.
func TestRegisterFullPlugin_FirstErrorWins(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)

	err := RegisterFullPlugin(FullPluginOpts{
		Info: PluginInfo{Name: "p22-bad", Version: "0.0.1"},
		Widgets: []FullPluginWidget{{URI: "http://not-ui-scheme/x", Name: "bad", Handler: func(_ context.Context, _ gomcp.ReadResourceRequest) ([]gomcp.ResourceContents, error) {
			return nil, nil
		}}},
	})
	if err == nil {
		t.Fatal("RegisterFullPlugin should reject non-ui:// widget URI")
	}
	if err.Error() == "" {
		t.Errorf("error must be informative; got %v", err)
	}
}
