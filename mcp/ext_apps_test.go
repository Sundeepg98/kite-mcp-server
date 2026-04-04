package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/templates"
)

func TestWithAppUI(t *testing.T) {
	t.Run("sets flat _meta ui/resourceUri key", func(t *testing.T) {
		tool := gomcp.NewTool("test_tool", gomcp.WithDescription("test"))
		result := withAppUI(tool, "ui://kite-mcp/portfolio")

		require.NotNil(t, result.Meta)
		require.NotNil(t, result.Meta.AdditionalFields)

		uri, ok := result.Meta.AdditionalFields["ui/resourceUri"].(string)
		require.True(t, ok, "expected ui/resourceUri to be string")
		assert.Equal(t, "ui://kite-mcp/portfolio", uri)
	})

	t.Run("empty URI returns tool unchanged", func(t *testing.T) {
		tool := gomcp.NewTool("test_tool", gomcp.WithDescription("test"))
		result := withAppUI(tool, "")

		assert.Nil(t, result.Meta)
	})

	t.Run("serializes as flat key in JSON", func(t *testing.T) {
		tool := gomcp.NewTool("test_tool", gomcp.WithDescription("test"))
		tool = withAppUI(tool, "ui://kite-mcp/orders")

		data, err := json.Marshal(tool)
		require.NoError(t, err)

		var parsed map[string]any
		require.NoError(t, json.Unmarshal(data, &parsed))

		meta, ok := parsed["_meta"].(map[string]any)
		require.True(t, ok, "expected _meta in serialized JSON")

		// Flat key format: _meta["ui/resourceUri"]
		uri, ok := meta["ui/resourceUri"].(string)
		require.True(t, ok, "expected flat ui/resourceUri key in _meta")
		assert.Equal(t, "ui://kite-mcp/orders", uri)
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
		// /admin/ops is admin-only and intentionally has no MCP App widget
		skipPaths := map[string]bool{"/admin/ops": true}
		for toolName, pagePath := range toolDashboardPage {
			if skipPaths[pagePath] {
				continue
			}
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
			data, err := templates.FS.ReadFile(res.TemplateFile)
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

	t.Run("all widget templates contain data placeholder", func(t *testing.T) {
		for _, res := range appResources {
			data, _ := templates.FS.ReadFile(res.TemplateFile)
			assert.True(t, strings.Contains(string(data), dataPlaceholder),
				"template %s should contain data placeholder %s", res.TemplateFile, dataPlaceholder)
		}
	})
}

func TestInjectData(t *testing.T) {
	t.Run("replaces placeholder with JSON data", func(t *testing.T) {
		html := `<script>window.__DATA__ = "__INJECTED_DATA__";</script>`
		data := map[string]any{"holdings": []string{"RELIANCE"}}
		result := injectData(html, data)
		assert.Contains(t, result, `"holdings":["RELIANCE"]`)
		assert.NotContains(t, result, dataPlaceholder)
	})

	t.Run("nil data injects null", func(t *testing.T) {
		html := `<script>window.__DATA__ = "__INJECTED_DATA__";</script>`
		result := injectData(html, nil)
		assert.Contains(t, result, `window.__DATA__ = null;`)
	})

	t.Run("Go json.Marshal escapes script tags in values", func(t *testing.T) {
		html := `<script>window.__DATA__ = "__INJECTED_DATA__";</script>`
		data := map[string]string{"name": "test</script><script>alert(1)//"}
		result := injectData(html, data)
		// Go's json.Marshal escapes < and > to \u003c and \u003e, preventing XSS.
		assert.Contains(t, result, `\u003c/script\u003e`)
		// The literal </script> should NOT appear in the output.
		// Count occurrences: only the closing tag of the actual script element.
		assert.Equal(t, 1, strings.Count(result, "</script>"), "only the real closing tag")
	})

	t.Run("Go json.Marshal escapes HTML comments in values", func(t *testing.T) {
		html := `<script>window.__DATA__ = "__INJECTED_DATA__";</script>`
		data := map[string]string{"name": "<!--injection"}
		result := injectData(html, data)
		// Go escapes < to \u003c, so <!-- becomes \u003c!--
		assert.Contains(t, result, `\u003c!--injection`)
	})
}

func TestResourceMIMEType(t *testing.T) {
	t.Run("MIME type matches MCP Apps spec", func(t *testing.T) {
		assert.Equal(t, "text/html;profile=mcp-app", ResourceMIMEType)
	})
}
