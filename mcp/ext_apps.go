package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/templates"
)

// ResourceMIMEType is the MIME type that signals MCP App hosts (Cowork, claude.ai)
// to render the resource as an interactive iframe widget rather than displaying
// the raw HTML source.
const ResourceMIMEType = "text/html;profile=mcp-app"

// appResource defines a UI resource served as an MCP App.
type appResource struct {
	// URI is the ui:// URI for the resource (e.g. "ui://kite-mcp/portfolio").
	URI string
	// Name is the human-readable name shown in resource listings.
	Name string
	// TemplateFile is the filename inside the embedded kc/templates/ directory.
	TemplateFile string
}

// appResources lists all dashboard pages exposed as MCP App resources.
var appResources = []appResource{
	{URI: "ui://kite-mcp/portfolio", Name: "Portfolio Dashboard", TemplateFile: "dashboard.html"},
	{URI: "ui://kite-mcp/activity", Name: "Activity Timeline", TemplateFile: "activity.html"},
	{URI: "ui://kite-mcp/orders", Name: "Orders Dashboard", TemplateFile: "orders.html"},
	{URI: "ui://kite-mcp/alerts", Name: "Alerts Dashboard", TemplateFile: "alerts.html"},
	{URI: "ui://kite-mcp/ops", Name: "Ops Dashboard", TemplateFile: "ops.html"},
}

// pagePathToResourceURI maps dashboard URL paths (from toolDashboardPage) to
// ui:// resource URIs for MCP Apps.
var pagePathToResourceURI = map[string]string{
	"/dashboard":          "ui://kite-mcp/portfolio",
	"/dashboard/activity": "ui://kite-mcp/activity",
	"/dashboard/orders":   "ui://kite-mcp/orders",
	"/dashboard/alerts":   "ui://kite-mcp/alerts",
	"/admin/ops":          "ui://kite-mcp/ops",
}

// withAppUI returns a copy of the tool with _meta.ui.resourceUri set, which
// tells MCP App hosts (Cowork, claude.ai) to render the associated UI resource
// inline when the tool is called. If resourceURI is empty, the tool is returned
// unchanged.
func withAppUI(t gomcp.Tool, resourceURI string) gomcp.Tool {
	if resourceURI == "" {
		return t
	}
	t.Meta = &gomcp.Meta{
		AdditionalFields: map[string]any{
			"ui": map[string]any{
				"resourceUri": resourceURI,
			},
		},
	}
	return t
}

// resourceURIForTool returns the ui:// resource URI for a tool based on its
// dashboard page mapping, or empty string if the tool has no associated page.
func resourceURIForTool(toolName string) string {
	pagePath, ok := toolDashboardPage[toolName]
	if !ok {
		return ""
	}
	return pagePathToResourceURI[pagePath]
}

// injectBaseURL prepends a <base href> tag into the HTML so that relative
// fetch() calls in the dashboard pages resolve against the server's external
// URL when rendered inside an MCP App iframe.  If baseURL is empty the HTML
// is returned unchanged.
func injectBaseURL(html string, baseURL string) string {
	if baseURL == "" {
		return html
	}
	// Ensure trailing slash for <base href>.
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	// Insert <base> right after <head> or after the opening <meta charset> line.
	// We look for the first <meta charset line and inject after it.
	tag := fmt.Sprintf(`<base href="%s">`, baseURL)
	// Try inserting after <head> tag.
	if idx := strings.Index(html, "<head>"); idx >= 0 {
		insertAt := idx + len("<head>")
		return html[:insertAt] + "\n" + tag + "\n" + html[insertAt:]
	}
	// Fallback: prepend to the entire HTML.
	return tag + "\n" + html
}

// RegisterAppResources registers the dashboard HTML pages as MCP App resources
// using the ui:// URI scheme. When an MCP App host (Cowork, claude.ai) sees a
// tool with _meta.ui.resourceUri, it fetches the corresponding resource and
// renders it inline as an interactive iframe.
func RegisterAppResources(srv *server.MCPServer, manager *kc.Manager, logger *slog.Logger) {
	// Determine the base URL for injecting into HTML pages.
	baseURL := dashboardBaseURL(manager)

	registered := 0
	for _, res := range appResources {
		// Capture loop variable for closure.
		res := res

		// Read the embedded HTML template.
		htmlBytes, err := templates.FS.ReadFile(res.TemplateFile)
		if err != nil {
			logger.Warn("Failed to read template for MCP App resource",
				"uri", res.URI, "file", res.TemplateFile, "error", err)
			continue
		}

		// Inject base URL for cross-origin fetch resolution in iframe context.
		html := injectBaseURL(string(htmlBytes), baseURL)

		srv.AddResource(
			gomcp.Resource{
				URI:      res.URI,
				Name:     res.Name,
				MIMEType: ResourceMIMEType,
			},
			func(ctx context.Context, req gomcp.ReadResourceRequest) ([]gomcp.ResourceContents, error) {
				return []gomcp.ResourceContents{
					gomcp.TextResourceContents{
						URI:      res.URI,
						MIMEType: ResourceMIMEType,
						Text:     html,
					},
				}, nil
			},
		)
		registered++
	}

	logger.Info("MCP App resources registered", "count", registered)
}
