package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"testing"
)

// TestWidgetSurfaceLock_URIs locks the canonical sorted list of MCP App
// widget URIs from appResources against a SHA256. Failures here are
// backward-compat regressions — external MCP clients (Claude.ai,
// Claude Desktop, ChatGPT, VS Code Copilot, Goose) bind to the
// `ui://kite-mcp/<name>` resource URIs returned in tool _meta and
// resource listings.
//
// This is the widget analog of TestToolSurfaceLock_Names (which locks
// the tool name surface). Tool names and widget URIs are parallel
// wire-protocol contracts: both are looked up by external clients
// after `initialize`.
//
// HOW TO UPDATE: copy the actual hash from the failure log into
// expectedWidgetSurfaceHash and update lockedWidgetURIs. Reviewers
// must treat the diff as a wire-protocol change.
func TestWidgetSurfaceLock_URIs(t *testing.T) {
	t.Parallel()

	got := make([]string, 0, len(appResources))
	for _, r := range appResources {
		got = append(got, r.URI)
	}
	sort.Strings(got)

	sum := sha256.Sum256([]byte(strings.Join(got, "\n")))
	gotHash := hex.EncodeToString(sum[:])
	if gotHash == expectedWidgetSurfaceHash {
		return
	}

	lockSet := make(map[string]bool, len(lockedWidgetURIs))
	for _, n := range lockedWidgetURIs {
		lockSet[n] = true
	}
	gotSet := make(map[string]bool, len(got))
	var added, removed []string
	for _, n := range got {
		gotSet[n] = true
		if !lockSet[n] {
			added = append(added, n)
		}
	}
	for _, n := range lockedWidgetURIs {
		if !gotSet[n] {
			removed = append(removed, n)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	t.Errorf("widget surface drift detected.\n  expected: %s\n  actual:   %s\n  added:    %s\n  removed:  %s\nUpdate expectedWidgetSurfaceHash + lockedWidgetURIs.",
		expectedWidgetSurfaceHash, gotHash, strings.Join(added, ", "), strings.Join(removed, ", "))
}

// TestWidgetSurfaceLock_Templates locks the {URI -> TemplateFile} mapping
// — a routing contract that, when broken, can silently swap a widget's
// HTML payload (e.g., portfolio URI accidentally pointing at admin_users_app).
// Hashing the sorted "URI=>TemplateFile" pairs catches both ends.
func TestWidgetSurfaceLock_Templates(t *testing.T) {
	t.Parallel()

	pairs := make([]string, 0, len(appResources))
	for _, r := range appResources {
		pairs = append(pairs, r.URI+"=>"+r.TemplateFile)
	}
	sort.Strings(pairs)

	sum := sha256.Sum256([]byte(strings.Join(pairs, "\n")))
	gotHash := hex.EncodeToString(sum[:])
	if gotHash == expectedWidgetTemplateHash {
		return
	}

	t.Errorf("widget template binding drift detected.\n  expected: %s\n  actual:   %s\n  pairs:\n    %s\nUpdate expectedWidgetTemplateHash.",
		expectedWidgetTemplateHash, gotHash, strings.Join(pairs, "\n    "))
}

// TestWidgetSurfaceLock_PageMap locks the dashboard URL → resource URI
// mapping. Browser dashboards rely on this map to redirect to the right
// widget; widget hosts surface them through the same URIs. Drift here
// silently breaks navigation links.
func TestWidgetSurfaceLock_PageMap(t *testing.T) {
	t.Parallel()

	pairs := make([]string, 0, len(pagePathToResourceURI))
	for path, uri := range pagePathToResourceURI {
		pairs = append(pairs, path+"=>"+uri)
	}
	sort.Strings(pairs)

	sum := sha256.Sum256([]byte(strings.Join(pairs, "\n")))
	gotHash := hex.EncodeToString(sum[:])
	if gotHash == expectedWidgetPageMapHash {
		return
	}

	t.Errorf("widget page-map drift detected.\n  expected: %s\n  actual:   %s\n  pairs:\n    %s\nUpdate expectedWidgetPageMapHash.",
		expectedWidgetPageMapHash, gotHash, strings.Join(pairs, "\n    "))
}

// expectedWidgetSurfaceHash is SHA256 over strings.Join(sortedWidgetURIs, "\n").
const expectedWidgetSurfaceHash = "381be5ef67ffdeee8476612c46fe2cad11e4e142a21f150f671567abc9868662"

// expectedWidgetTemplateHash is SHA256 over strings.Join(sorted "URI=>Template" pairs, "\n").
const expectedWidgetTemplateHash = "8d5c776b81498098a1c3c16d779ff7d70ff017c90be95084104464d0cf25d0f9"

// expectedWidgetPageMapHash is SHA256 over strings.Join(sorted "path=>URI" pairs, "\n").
const expectedWidgetPageMapHash = "84dfc247413c7064515d3a82c0728b10fa7b52420b570a4c88fe9f59b4f3df33"

// lockedWidgetURIs is the sorted golden list — used only for diff-on-mismatch.
var lockedWidgetURIs = strings.Fields(`
ui://kite-mcp/activity
ui://kite-mcp/admin-metrics
ui://kite-mcp/admin-overview
ui://kite-mcp/admin-registry
ui://kite-mcp/admin-users
ui://kite-mcp/alerts
ui://kite-mcp/chart
ui://kite-mcp/credentials
ui://kite-mcp/hub
ui://kite-mcp/options-chain
ui://kite-mcp/order-form
ui://kite-mcp/orders
ui://kite-mcp/paper
ui://kite-mcp/portfolio
ui://kite-mcp/safety
ui://kite-mcp/setup
ui://kite-mcp/watchlist
`)
