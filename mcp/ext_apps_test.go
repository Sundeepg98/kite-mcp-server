package mcp

import (
	"encoding/json"
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/templates"
)

func TestWithAppUI(t *testing.T) {
	t.Run("sets _meta.ui.resourceUri", func(t *testing.T) {
		tool := gomcp.NewTool("test_tool", gomcp.WithDescription("test"))
		result := withAppUI(tool, "ui://kite-mcp/portfolio")

		require.NotNil(t, result.Meta)
		require.NotNil(t, result.Meta.AdditionalFields)

		ui, ok := result.Meta.AdditionalFields["ui"].(map[string]any)
		require.True(t, ok, "expected ui to be map[string]any")
		assert.Equal(t, "ui://kite-mcp/portfolio", ui["resourceUri"])
	})

	t.Run("empty URI returns tool unchanged", func(t *testing.T) {
		tool := gomcp.NewTool("test_tool", gomcp.WithDescription("test"))
		result := withAppUI(tool, "")

		assert.Nil(t, result.Meta)
	})

	t.Run("serializes correctly in JSON", func(t *testing.T) {
		tool := gomcp.NewTool("test_tool", gomcp.WithDescription("test"))
		tool = withAppUI(tool, "ui://kite-mcp/orders")

		data, err := json.Marshal(tool)
		require.NoError(t, err)

		var parsed map[string]any
		require.NoError(t, json.Unmarshal(data, &parsed))

		meta, ok := parsed["_meta"].(map[string]any)
		require.True(t, ok, "expected _meta in serialized JSON")

		ui, ok := meta["ui"].(map[string]any)
		require.True(t, ok, "expected ui in _meta")
		assert.Equal(t, "ui://kite-mcp/orders", ui["resourceUri"])
	})
}

func TestResourceURIForTool(t *testing.T) {
	t.Run("portfolio tools return portfolio URI", func(t *testing.T) {
		portfolioTools := []string{
			"get_holdings", "get_positions", "get_margins", "get_profile",
			"portfolio_summary", "portfolio_concentration", "position_analysis",
			"trading_context", "pre_trade_check", "get_pnl_journal", "get_mf_holdings",
		}
		for _, name := range portfolioTools {
			uri := resourceURIForTool(name)
			assert.Equal(t, "ui://kite-mcp/portfolio", uri, "tool %s", name)
		}
	})

	t.Run("order tools return orders URI", func(t *testing.T) {
		orderTools := []string{
			"get_orders", "get_order_history", "place_order", "cancel_order",
			"get_gtts", "place_gtt_order",
		}
		for _, name := range orderTools {
			uri := resourceURIForTool(name)
			assert.Equal(t, "ui://kite-mcp/orders", uri, "tool %s", name)
		}
	})

	t.Run("alert tools return alerts URI", func(t *testing.T) {
		alertTools := []string{
			"list_alerts", "set_alert", "delete_alert",
			"set_trailing_stop", "list_trailing_stops", "cancel_trailing_stop",
		}
		for _, name := range alertTools {
			uri := resourceURIForTool(name)
			assert.Equal(t, "ui://kite-mcp/alerts", uri, "tool %s", name)
		}
	})

	t.Run("activity tools return activity URI", func(t *testing.T) {
		uri := resourceURIForTool("get_option_chain")
		assert.Equal(t, "ui://kite-mcp/activity", uri)
	})

	t.Run("unmapped tools return empty string", func(t *testing.T) {
		unmapped := []string{"login", "open_dashboard", "get_ltp", "search_instruments"}
		for _, name := range unmapped {
			uri := resourceURIForTool(name)
			assert.Empty(t, uri, "tool %s should have no resource URI", name)
		}
	})
}

func TestPagePathToResourceURI(t *testing.T) {
	t.Run("all toolDashboardPage paths have a resource URI", func(t *testing.T) {
		for toolName, pagePath := range toolDashboardPage {
			uri, ok := pagePathToResourceURI[pagePath]
			assert.True(t, ok,
				"pagePath %q (from tool %s) has no entry in pagePathToResourceURI", pagePath, toolName)
			assert.NotEmpty(t, uri)
		}
	})

	t.Run("all resource URIs start with ui://", func(t *testing.T) {
		for path, uri := range pagePathToResourceURI {
			assert.True(t, len(uri) > 5 && uri[:5] == "ui://",
				"resource URI for %s should start with ui://, got %s", path, uri)
		}
	})
}

func TestAppResources(t *testing.T) {
	t.Run("all app resources have valid template files", func(t *testing.T) {
		for _, res := range appResources {
			data, err := readEmbeddedTemplate(res.TemplateFile)
			assert.NoError(t, err, "template %s should be readable", res.TemplateFile)
			assert.True(t, len(data) > 0, "template %s should not be empty", res.TemplateFile)
		}
	})

	t.Run("all resource URIs are unique", func(t *testing.T) {
		seen := make(map[string]bool)
		for _, res := range appResources {
			assert.False(t, seen[res.URI], "duplicate resource URI: %s", res.URI)
			seen[res.URI] = true
		}
	})

	t.Run("all resource URIs match pagePathToResourceURI values", func(t *testing.T) {
		uriSet := make(map[string]bool)
		for _, uri := range pagePathToResourceURI {
			uriSet[uri] = true
		}
		for _, res := range appResources {
			assert.True(t, uriSet[res.URI],
				"appResource URI %s not found in pagePathToResourceURI", res.URI)
		}
	})
}

func TestInjectBaseURL(t *testing.T) {
	t.Run("injects after <head>", func(t *testing.T) {
		html := `<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body></body></html>`
		result := injectBaseURL(html, "https://example.com")
		assert.Contains(t, result, `<base href="https://example.com/">`)
		// <base> should appear between <head> and <meta
		headIdx := len(`<!DOCTYPE html><html><head>`)
		baseIdx := findIndex(result, `<base href=`)
		assert.Greater(t, baseIdx, headIdx-1)
	})

	t.Run("adds trailing slash", func(t *testing.T) {
		html := `<head></head>`
		result := injectBaseURL(html, "https://example.com")
		assert.Contains(t, result, `href="https://example.com/"`)
	})

	t.Run("preserves existing trailing slash", func(t *testing.T) {
		html := `<head></head>`
		result := injectBaseURL(html, "https://example.com/")
		assert.Contains(t, result, `href="https://example.com/"`)
		// Should not double-slash
		assert.NotContains(t, result, `href="https://example.com//"`)
	})

	t.Run("empty baseURL returns HTML unchanged", func(t *testing.T) {
		html := `<head><title>Test</title></head>`
		result := injectBaseURL(html, "")
		assert.Equal(t, html, result)
	})

	t.Run("no <head> tag falls back to prepend", func(t *testing.T) {
		html := `<div>hello</div>`
		result := injectBaseURL(html, "https://example.com")
		assert.True(t, len(result) > len(html))
		assert.Contains(t, result, `<base href="https://example.com/">`)
	})
}

func TestResourceMIMEType(t *testing.T) {
	t.Run("MIME type matches MCP Apps spec", func(t *testing.T) {
		assert.Equal(t, "text/html;profile=mcp-app", ResourceMIMEType)
	})
}

// readEmbeddedTemplate is a test helper to read from the embedded FS.
func readEmbeddedTemplate(name string) ([]byte, error) {
	return templates.FS.ReadFile(name)
}

// findIndex returns the position of substr in s, or -1.
func findIndex(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
