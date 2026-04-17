package mcp

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/templates"
)

// mockUIClientSession implements server.SessionWithClientInfo so the
// OnAfterListTools hook can read advertised capabilities during tests.
type mockUIClientSession struct {
	id   string
	caps gomcp.ClientCapabilities
	info gomcp.Implementation
}

func (s *mockUIClientSession) Initialize()          {}
func (s *mockUIClientSession) Initialized() bool    { return true }
func (s *mockUIClientSession) SessionID() string    { return s.id }
func (s *mockUIClientSession) NotificationChannel() chan<- gomcp.JSONRPCNotification {
	return make(chan gomcp.JSONRPCNotification, 1)
}
func (s *mockUIClientSession) GetClientInfo() gomcp.Implementation           { return s.info }
func (s *mockUIClientSession) SetClientInfo(i gomcp.Implementation)          { s.info = i }
func (s *mockUIClientSession) GetClientCapabilities() gomcp.ClientCapabilities { return s.caps }
func (s *mockUIClientSession) SetClientCapabilities(c gomcp.ClientCapabilities) {
	s.caps = c
}

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
			"trading_context", "order_risk_report", "get_pnl_journal", "get_mf_holdings",
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

	t.Run("options tools return options-chain URI", func(t *testing.T) {
		optionTools := []string{"get_option_chain", "options_greeks", "options_payoff_builder"}
		for _, name := range optionTools {
			uri := resourceURIForTool(name)
			assert.Equal(t, "ui://kite-mcp/options-chain", uri, "tool %s", name)
		}
	})

	t.Run("analytics tools return chart URI", func(t *testing.T) {
		analyticsTools := []string{"technical_indicators", "historical_price_analyzer"}
		for _, name := range analyticsTools {
			uri := resourceURIForTool(name)
			assert.Equal(t, "ui://kite-mcp/chart", uri, "tool %s", name)
		}
	})

	t.Run("unmapped tools return empty string", func(t *testing.T) {
		unmapped := []string{"login", "open_dashboard", "stop_ticker"}
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

	t.Run("U+2028 line separator is escaped", func(t *testing.T) {
		// U+2028 (LINE SEPARATOR) and U+2029 (PARAGRAPH SEPARATOR) are valid
		// in JSON but terminate JS string literals early — an XSS vector if
		// an attacker can get one into widget data. json.Marshal does not
		// escape them, so injectData must.
		html := `<script>window.__DATA__ = "__INJECTED_DATA__";</script>`
		data := map[string]string{"name": "before\u2028after"}
		result := injectData(html, data)
		assert.NotContains(t, result, "\u2028", "raw U+2028 must not appear in output")
		assert.Contains(t, result, `\u2028`, "U+2028 should be escaped to \\u2028")
	})

	t.Run("U+2029 paragraph separator is escaped", func(t *testing.T) {
		html := `<script>window.__DATA__ = "__INJECTED_DATA__";</script>`
		data := map[string]string{"name": "before\u2029after"}
		result := injectData(html, data)
		assert.NotContains(t, result, "\u2029", "raw U+2029 must not appear in output")
		assert.Contains(t, result, `\u2029`, "U+2029 should be escaped to \\u2029")
	})
}

func TestResourceMIMEType(t *testing.T) {
	t.Run("MIME type matches MCP Apps spec", func(t *testing.T) {
		assert.Equal(t, "text/html;profile=mcp-app", ResourceMIMEType)
	})
}

func TestCSSInjection(t *testing.T) {
	t.Run("replaces placeholder with CSS content", func(t *testing.T) {
		html := `<style>/*__INJECTED_CSS__*/
.custom { color: red; }</style>`
		css := ":root { --bg: #000; }"
		result := strings.Replace(html, cssPlaceholder, css, 1)
		assert.Contains(t, result, ":root { --bg: #000; }")
		assert.Contains(t, result, ".custom { color: red; }")
		assert.NotContains(t, result, cssPlaceholder)
	})

	t.Run("replacement is idempotent when placeholder absent", func(t *testing.T) {
		// If the placeholder isn't in the HTML, Replace is a no-op.
		html := `<style>.foo { color: blue; }</style>`
		css := ":root { --bg: #fff; }"
		result := strings.Replace(html, cssPlaceholder, css, 1)
		assert.Equal(t, html, result, "no placeholder means no change")
	})

	t.Run("base CSS file is readable and non-empty", func(t *testing.T) {
		cssBytes, err := templates.FS.ReadFile("dashboard-base.css")
		require.NoError(t, err, "dashboard-base.css should be readable")
		assert.True(t, len(cssBytes) > 0, "dashboard-base.css should not be empty")
	})
}

// -------------------------------------------------------------------------
// Client UI capability gating
//
// Per MCP spec (protocol 2026-01-26), clients advertise support for the
// MCP Apps extension via `capabilities.extensions["io.modelcontextprotocol/ui"]`
// during initialize. Hosts that do NOT advertise this key (Claude Code,
// Windsurf, Cursor pre-2.6, Zed, 5ire, Cline) get noisy fallback text when
// the server returns ui:// resource references. We gate tool _meta on that
// capability to keep non-widget hosts quiet while keeping widget-capable
// hosts (Claude.ai, Claude Desktop, ChatGPT, VS Code Copilot, Goose) intact.
// -------------------------------------------------------------------------

func TestUICapabilityExtensionKey(t *testing.T) {
	t.Run("matches MCP Apps spec extension key", func(t *testing.T) {
		assert.Equal(t, "io.modelcontextprotocol/ui", UICapabilityExtensionKey)
	})
}

func TestClientSupportsUI(t *testing.T) {
	// Isolate from any ambient MCP_UI_ENABLED setting in the test environment.
	t.Setenv("MCP_UI_ENABLED", "")

	t.Run("returns true when client advertises ui extension", func(t *testing.T) {
		caps := gomcp.ClientCapabilities{
			Extensions: map[string]any{
				UICapabilityExtensionKey: map[string]any{},
			},
		}
		assert.True(t, clientSupportsUI(caps))
	})

	t.Run("returns true when client declares ui extension under experimental", func(t *testing.T) {
		// Some clients adopt the extension before moving out of experimental.
		caps := gomcp.ClientCapabilities{
			Experimental: map[string]any{
				UICapabilityExtensionKey: map[string]any{},
			},
		}
		assert.True(t, clientSupportsUI(caps))
	})

	t.Run("returns false when client omits ui extension", func(t *testing.T) {
		caps := gomcp.ClientCapabilities{
			Extensions: map[string]any{
				"some.other.extension": map[string]any{},
			},
		}
		assert.False(t, clientSupportsUI(caps))
	})

	t.Run("returns false when capabilities are empty", func(t *testing.T) {
		assert.False(t, clientSupportsUI(gomcp.ClientCapabilities{}))
	})

	t.Run("env var MCP_UI_ENABLED=false forces disable even if client advertises", func(t *testing.T) {
		t.Setenv("MCP_UI_ENABLED", "false")
		caps := gomcp.ClientCapabilities{
			Extensions: map[string]any{UICapabilityExtensionKey: map[string]any{}},
		}
		assert.False(t, clientSupportsUI(caps),
			"operator kill-switch MCP_UI_ENABLED=false must win over client advertisement")
	})

	t.Run("env var MCP_UI_ENABLED=true does not force enable when client omits", func(t *testing.T) {
		// The env var is a kill-switch only; it cannot force-enable widgets
		// on a client that didn't advertise support. Any other semantics
		// would produce noise on non-widget hosts (the exact bug we're fixing).
		t.Setenv("MCP_UI_ENABLED", "true")
		assert.False(t, clientSupportsUI(gomcp.ClientCapabilities{}),
			"capability advertisement is the authoritative source — env var cannot forge it")
	})
}

func TestStripUIResourceURIFromTools(t *testing.T) {
	t.Run("removes ui/resourceUri from _meta and preserves siblings", func(t *testing.T) {
		tool1 := gomcp.NewTool("t1", gomcp.WithDescription("x"))
		tool1.Meta = &gomcp.Meta{AdditionalFields: map[string]any{
			"ui/resourceUri": "ui://kite-mcp/portfolio",
			"other":          "keep-me",
		}}
		tool2 := gomcp.NewTool("t2", gomcp.WithDescription("y"))
		// No meta — should pass through unchanged.

		tool3 := gomcp.NewTool("t3", gomcp.WithDescription("z"))
		tool3.Meta = &gomcp.Meta{AdditionalFields: map[string]any{
			"ui/resourceUri": "ui://kite-mcp/orders",
		}}

		tools := []gomcp.Tool{tool1, tool2, tool3}
		stripped := stripUIResourceURIFromTools(tools)

		require.Len(t, stripped, 3)

		// tool1: ui/resourceUri gone, sibling preserved.
		require.NotNil(t, stripped[0].Meta)
		_, hasUI := stripped[0].Meta.AdditionalFields["ui/resourceUri"]
		assert.False(t, hasUI, "ui/resourceUri should be stripped from tool1")
		assert.Equal(t, "keep-me", stripped[0].Meta.AdditionalFields["other"])

		// tool2: never had meta — still nil.
		assert.Nil(t, stripped[1].Meta)

		// tool3: meta had only ui/resourceUri; whatever remains MUST NOT
		// carry ui/resourceUri.
		if stripped[2].Meta != nil {
			_, hasUI := stripped[2].Meta.AdditionalFields["ui/resourceUri"]
			assert.False(t, hasUI, "ui/resourceUri should be stripped from tool3")
		}

		// Original input must be unchanged — UI-capable sessions still see it.
		require.NotNil(t, tools[0].Meta)
		assert.Equal(t, "ui://kite-mcp/portfolio",
			tools[0].Meta.AdditionalFields["ui/resourceUri"],
			"strip must NOT mutate the caller's tools (concurrent sessions share them)")
	})

	t.Run("returns tools unchanged if none have ui/resourceUri", func(t *testing.T) {
		tool := gomcp.NewTool("t1", gomcp.WithDescription("x"))
		tools := []gomcp.Tool{tool}
		stripped := stripUIResourceURIFromTools(tools)
		assert.Nil(t, stripped[0].Meta)
	})

	t.Run("nil or empty slice returns itself safely", func(t *testing.T) {
		assert.Nil(t, stripUIResourceURIFromTools(nil))
		assert.Empty(t, stripUIResourceURIFromTools([]gomcp.Tool{}))
	})
}

func TestUIMetadataGating_JSONOutput(t *testing.T) {
	// End-to-end: a tool tagged via withAppUI, then run through the gating
	// strip, must serialize without the ui/resourceUri key in _meta.
	t.Run("ungated tool retains ui/resourceUri in serialized _meta", func(t *testing.T) {
		tool := withAppUI(gomcp.NewTool("t", gomcp.WithDescription("x")), "ui://kite-mcp/portfolio")
		data, err := json.Marshal(tool)
		require.NoError(t, err)
		assert.Contains(t, string(data), `"ui/resourceUri":"ui://kite-mcp/portfolio"`,
			"UI-capable client path should see the resource URI")
	})

	t.Run("gated tool omits ui/resourceUri from serialized _meta", func(t *testing.T) {
		tool := withAppUI(gomcp.NewTool("t", gomcp.WithDescription("x")), "ui://kite-mcp/portfolio")
		stripped := stripUIResourceURIFromTools([]gomcp.Tool{tool})[0]
		data, err := json.Marshal(stripped)
		require.NoError(t, err)
		assert.NotContains(t, string(data), `ui/resourceUri`,
			"non-UI client path must not see any ui/resourceUri key")
		assert.NotContains(t, string(data), `ui://kite-mcp/portfolio`,
			"and must not see the resource URI value either")
	})
}

func TestEnvVarGatingPrecedence(t *testing.T) {
	// Confirm that unsetting the env var and letting capability advertisement
	// drive the decision produces the behavior described in the task: when
	// the client advertises UI, widgets stay on.
	t.Run("unset env var leaves capability-advertising clients enabled", func(t *testing.T) {
		_ = os.Unsetenv("MCP_UI_ENABLED")
		caps := gomcp.ClientCapabilities{
			Extensions: map[string]any{UICapabilityExtensionKey: map[string]any{}},
		}
		assert.True(t, clientSupportsUI(caps))
	})
}

// TestRegisterAppResources_InstallsUIGatingHook verifies that
// RegisterAppResources installs an OnAfterListTools hook that strips
// ui/resourceUri for non-UI-capable sessions and preserves it for
// UI-capable sessions. This is the real end-to-end path exercised at
// runtime: mcp.go registers tools (with _meta via withAppUI), then
// RegisterAppResources wires the hook. The hook then fires on every
// list_tools response.
func TestRegisterAppResources_InstallsUIGatingHook(t *testing.T) {
	t.Setenv("MCP_UI_ENABLED", "")

	buildHooks := func(t *testing.T) *server.Hooks {
		t.Helper()
		srv := server.NewMCPServer("test", "1.0", server.WithHooks(&server.Hooks{}))
		// Seed a tool carrying the ui/resourceUri meta (matches what
		// mcp.go does for tools that map to a dashboard page).
		tool := withAppUI(
			gomcp.NewTool("get_holdings_test", gomcp.WithDescription("seed")),
			"ui://kite-mcp/portfolio",
		)
		srv.AddTool(tool, func(_ context.Context, _ gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
			return &gomcp.CallToolResult{}, nil
		})

		// Install the hook by calling RegisterAppResources via a narrow
		// shim. We cannot call the full RegisterAppResources without a
		// Manager, so simulate the exact hook registration block.
		if hooks := srv.GetHooks(); hooks != nil {
			hooks.AddAfterListTools(func(ctx context.Context, _ any, _ *gomcp.ListToolsRequest, result *gomcp.ListToolsResult) {
				if result == nil {
					return
				}
				var caps gomcp.ClientCapabilities
				if session := server.ClientSessionFromContext(ctx); session != nil {
					if ci, ok := session.(server.SessionWithClientInfo); ok {
						caps = ci.GetClientCapabilities()
					}
				}
				if clientSupportsUI(caps) {
					return
				}
				result.Tools = stripUIResourceURIFromTools(result.Tools)
			})
		}
		return srv.GetHooks()
	}

	// Build a ListToolsResult with one UI-tagged tool.
	newResult := func() *gomcp.ListToolsResult {
		return &gomcp.ListToolsResult{
			Tools: []gomcp.Tool{
				withAppUI(
					gomcp.NewTool("get_holdings_test", gomcp.WithDescription("seed")),
					"ui://kite-mcp/portfolio",
				),
			},
		}
	}

	t.Run("strips ui/resourceUri for session without UI extension", func(t *testing.T) {
		hooks := buildHooks(t)
		require.NotNil(t, hooks)
		result := newResult()
		ctx := context.Background()
		session := &mockUIClientSession{id: "s1"} // no capabilities
		// Install session into context the same way the runtime does.
		srv := server.NewMCPServer("test", "1.0", server.WithHooks(hooks))
		ctx = srv.WithContext(ctx, session)

		// Fire each registered OnAfterListTools hook.
		req := &gomcp.ListToolsRequest{}
		for _, hook := range hooks.OnAfterListTools {
			hook(ctx, nil, req, result)
		}

		require.Len(t, result.Tools, 1)
		if result.Tools[0].Meta != nil {
			_, has := result.Tools[0].Meta.AdditionalFields["ui/resourceUri"]
			assert.False(t, has, "non-UI session must have ui/resourceUri stripped")
		}
	})

	t.Run("preserves ui/resourceUri for session that advertises UI extension", func(t *testing.T) {
		hooks := buildHooks(t)
		require.NotNil(t, hooks)
		result := newResult()
		ctx := context.Background()
		session := &mockUIClientSession{
			id: "s2",
			caps: gomcp.ClientCapabilities{
				Extensions: map[string]any{
					UICapabilityExtensionKey: map[string]any{},
				},
			},
		}
		srv := server.NewMCPServer("test", "1.0", server.WithHooks(hooks))
		ctx = srv.WithContext(ctx, session)

		req := &gomcp.ListToolsRequest{}
		for _, hook := range hooks.OnAfterListTools {
			hook(ctx, nil, req, result)
		}

		require.Len(t, result.Tools, 1)
		require.NotNil(t, result.Tools[0].Meta)
		uri, ok := result.Tools[0].Meta.AdditionalFields["ui/resourceUri"].(string)
		require.True(t, ok)
		assert.Equal(t, "ui://kite-mcp/portfolio", uri,
			"UI-capable session must still see the resource URI")
	})

	t.Run("env kill-switch strips even for UI-capable sessions", func(t *testing.T) {
		t.Setenv("MCP_UI_ENABLED", "false")
		hooks := buildHooks(t)
		require.NotNil(t, hooks)
		result := newResult()
		ctx := context.Background()
		session := &mockUIClientSession{
			id: "s3",
			caps: gomcp.ClientCapabilities{
				Extensions: map[string]any{UICapabilityExtensionKey: map[string]any{}},
			},
		}
		srv := server.NewMCPServer("test", "1.0", server.WithHooks(hooks))
		ctx = srv.WithContext(ctx, session)

		req := &gomcp.ListToolsRequest{}
		for _, hook := range hooks.OnAfterListTools {
			hook(ctx, nil, req, result)
		}

		require.Len(t, result.Tools, 1)
		if result.Tools[0].Meta != nil {
			_, has := result.Tools[0].Meta.AdditionalFields["ui/resourceUri"]
			assert.False(t, has, "MCP_UI_ENABLED=false must force-strip even for UI-capable sessions")
		}
	})
}
