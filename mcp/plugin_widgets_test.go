package mcp

import (
	"context"
	"strings"
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegisterWidget_BasicRegistration confirms the happy path:
// a plugin registers a ui:// resource and it appears in the plugin
// widget registry, retrievable by URI.
func TestRegisterWidget_BasicRegistration(t *testing.T) {
	ClearPluginWidgets()
	defer ClearPluginWidgets()

	handler := func(ctx context.Context, req gomcp.ReadResourceRequest) ([]gomcp.ResourceContents, error) {
		return []gomcp.ResourceContents{
			gomcp.TextResourceContents{
				URI:      "ui://test-plugin/sample",
				MIMEType: ResourceMIMEType,
				Text:     "<html>hello from plugin</html>",
			},
		}, nil
	}

	err := RegisterWidget("ui://test-plugin/sample", "Sample Widget", handler)
	require.NoError(t, err)

	widgets := ListPluginWidgets()
	assert.Len(t, widgets, 1)
	assert.Equal(t, "ui://test-plugin/sample", widgets[0].URI)
	assert.Equal(t, "Sample Widget", widgets[0].Name)
	assert.NotNil(t, widgets[0].Handler)
}

// TestRegisterWidget_HandlerInvoked walks through the full
// "handler is called and its output is returned" flow. This is the
// behavioural test the brief asks for.
func TestRegisterWidget_HandlerInvoked(t *testing.T) {
	ClearPluginWidgets()
	defer ClearPluginWidgets()

	called := false
	RegisterWidget("ui://test-plugin/greeter", "Greeter", func(ctx context.Context, req gomcp.ReadResourceRequest) ([]gomcp.ResourceContents, error) {
		called = true
		return []gomcp.ResourceContents{
			gomcp.TextResourceContents{
				URI:      "ui://test-plugin/greeter",
				MIMEType: ResourceMIMEType,
				Text:     "<html>hi</html>",
			},
		}, nil
	})

	widgets := ListPluginWidgets()
	require.Len(t, widgets, 1)
	w := widgets[0]

	req := gomcp.ReadResourceRequest{}
	req.Params.URI = "ui://test-plugin/greeter"
	contents, err := w.Handler(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, called, "handler should have been invoked")
	require.Len(t, contents, 1)
	tc, ok := contents[0].(gomcp.TextResourceContents)
	require.True(t, ok, "expected TextResourceContents, got %T", contents[0])
	assert.Equal(t, "<html>hi</html>", tc.Text)
}

// TestRegisterWidget_RejectsInvalidURI enforces the ui:// prefix and
// non-empty constraints. Plugins that supply a bare string or HTTP
// URL are rejected so malformed registrations surface at wire-up
// rather than at first resource fetch.
func TestRegisterWidget_RejectsInvalidURI(t *testing.T) {
	ClearPluginWidgets()
	defer ClearPluginWidgets()

	cases := []struct {
		name string
		uri  string
	}{
		{"empty", ""},
		{"http", "http://example.com/widget"},
		{"https", "https://example.com/widget"},
		{"file", "file:///etc/passwd"},
		{"no scheme", "plugin/widget"},
		{"wrong scheme", "data://something"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := RegisterWidget(tc.uri, "Widget", func(ctx context.Context, req gomcp.ReadResourceRequest) ([]gomcp.ResourceContents, error) {
				return nil, nil
			})
			assert.Error(t, err, "expected error for URI %q", tc.uri)
		})
	}
}

// TestRegisterWidget_RejectsNilHandler — a nil handler is a programmer
// error that must fail loudly at registration rather than NPE on
// first access.
func TestRegisterWidget_RejectsNilHandler(t *testing.T) {
	ClearPluginWidgets()
	defer ClearPluginWidgets()

	err := RegisterWidget("ui://test-plugin/nil", "Nil", nil)
	assert.Error(t, err)
}

// TestRegisterWidget_RejectsEmptyName — widgets are listed in
// resources/list with their Name, which clients render in menus.
// An empty name would produce a blank menu entry.
func TestRegisterWidget_RejectsEmptyName(t *testing.T) {
	ClearPluginWidgets()
	defer ClearPluginWidgets()

	err := RegisterWidget("ui://test-plugin/noname", "", func(ctx context.Context, req gomcp.ReadResourceRequest) ([]gomcp.ResourceContents, error) {
		return nil, nil
	})
	assert.Error(t, err)
}

// TestRegisterWidget_DuplicateURI_LastWins — re-registering the same
// URI replaces the handler (matches the lifecycle pattern used by the
// Telegram plugin-commands registry).
func TestRegisterWidget_DuplicateURI_LastWins(t *testing.T) {
	ClearPluginWidgets()
	defer ClearPluginWidgets()

	_ = RegisterWidget("ui://test-plugin/dup", "First", func(ctx context.Context, req gomcp.ReadResourceRequest) ([]gomcp.ResourceContents, error) {
		return []gomcp.ResourceContents{gomcp.TextResourceContents{Text: "first"}}, nil
	})
	_ = RegisterWidget("ui://test-plugin/dup", "Second", func(ctx context.Context, req gomcp.ReadResourceRequest) ([]gomcp.ResourceContents, error) {
		return []gomcp.ResourceContents{gomcp.TextResourceContents{Text: "second"}}, nil
	})

	widgets := ListPluginWidgets()
	require.Len(t, widgets, 1, "duplicate URI should replace, not append")
	assert.Equal(t, "Second", widgets[0].Name)

	req := gomcp.ReadResourceRequest{}
	req.Params.URI = "ui://test-plugin/dup"
	contents, _ := widgets[0].Handler(context.Background(), req)
	tc, _ := contents[0].(gomcp.TextResourceContents)
	assert.Equal(t, "second", tc.Text)
}

// TestRegisterWidget_NoConflictWithBuiltins — plugin registration
// MUST NOT be able to shadow a built-in ui:// resource (portfolio,
// activity, orders, etc.). Built-ins are owned by RegisterAppResources;
// a plugin hijacking them could serve arbitrary HTML into the
// Claude.ai iframe, breaking our CSP guarantees.
func TestRegisterWidget_NoConflictWithBuiltins(t *testing.T) {
	ClearPluginWidgets()
	defer ClearPluginWidgets()

	// Try every built-in URI.
	for _, res := range appResources {
		err := RegisterWidget(res.URI, "Hijack Attempt", func(ctx context.Context, req gomcp.ReadResourceRequest) ([]gomcp.ResourceContents, error) {
			return nil, nil
		})
		assert.Error(t, err, "plugin registration of built-in URI %q should fail", res.URI)
	}
}

// TestRegisterWidget_AppearsInListPluginWidgets is a regression
// sentinel: the ListPluginWidgets API is what the wire-up layer uses
// to iterate registered widgets and install them on the MCP server.
// If ListPluginWidgets ever stops returning registered widgets, the
// server silently loses the feature.
func TestRegisterWidget_AppearsInListPluginWidgets(t *testing.T) {
	ClearPluginWidgets()
	defer ClearPluginWidgets()

	_ = RegisterWidget("ui://plugin-a/x", "A", func(ctx context.Context, req gomcp.ReadResourceRequest) ([]gomcp.ResourceContents, error) {
		return nil, nil
	})
	_ = RegisterWidget("ui://plugin-b/y", "B", func(ctx context.Context, req gomcp.ReadResourceRequest) ([]gomcp.ResourceContents, error) {
		return nil, nil
	})

	widgets := ListPluginWidgets()
	assert.Len(t, widgets, 2)

	uris := make(map[string]string)
	for _, w := range widgets {
		uris[w.URI] = w.Name
	}
	assert.Equal(t, "A", uris["ui://plugin-a/x"])
	assert.Equal(t, "B", uris["ui://plugin-b/y"])
}

// TestRegisterWidget_ConcurrentRegistration — the mutex-protected
// registry must tolerate concurrent RegisterWidget calls without
// deadlock or data race. Run under -race to validate.
func TestRegisterWidget_ConcurrentRegistration(t *testing.T) {
	ClearPluginWidgets()
	defer ClearPluginWidgets()

	const N = 20
	done := make(chan struct{}, N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			uri := "ui://concurrent/" + string(rune('a'+i))
			_ = RegisterWidget(uri, "Concurrent", func(ctx context.Context, req gomcp.ReadResourceRequest) ([]gomcp.ResourceContents, error) {
				return nil, nil
			})
		}(i)
	}
	for i := 0; i < N; i++ {
		<-done
	}
	widgets := ListPluginWidgets()
	assert.Len(t, widgets, N)
	// Sanity: every widget URI is prefixed correctly.
	for _, w := range widgets {
		assert.True(t, strings.HasPrefix(w.URI, "ui://concurrent/"))
	}
}
