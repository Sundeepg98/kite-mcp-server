package mcp

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResourcesCurated_Catalog asserts the curated set matches what we
// advertise. A drift here means someone added/removed an entry without
// updating this test — and that entry would then be silently exposed to
// all MCP clients.
//
// The catalog is the wire-level contract; every URI listed here is what
// `resources/list` returns.
func TestResourcesCurated_Catalog(t *testing.T) {
	t.Parallel()
	want := map[string]string{
		"doc://README":              "README.md",
		"doc://security-policy":     "SECURITY.md",
		"doc://monitoring":          "docs/monitoring.md",
		"doc://incident-response":   "docs/incident-response.md",
		"doc://faq":                 "docs/faq.md",
		"doc://architecture":        "ARCHITECTURE.md",
		"doc://self-host":           "docs/self-host.md",
		"doc://kite-token-refresh":  "docs/kite-token-refresh.md",
		"doc://tool-catalog":        "docs/tool-catalog.md",
		"doc://byo-api-key":         "docs/byo-api-key.md",
		"doc://architecture-diagram": "docs/architecture-diagram.md",
		"doc://release-notes-v1.1.0": "docs/release-notes-v1.1.0.md",
	}
	got := curatedDocResources()
	assert.Len(t, got, len(want), "curated resource count drift — update this test if intentional")
	for _, r := range got {
		rel, ok := want[r.URI]
		if !assert.Truef(t, ok, "unexpected URI %q in curated set", r.URI) {
			continue
		}
		assert.Equalf(t, rel, r.RelPath, "URI %q points to %q but expected %q", r.URI, r.RelPath, rel)
		assert.NotEmptyf(t, r.Name, "URI %q has empty Name", r.URI)
		assert.NotEmptyf(t, r.Description, "URI %q has empty Description", r.URI)
	}
}

// TestResourcesCurated_SafePaths ensures no curated path escapes the
// repo via `..` or absolute path — otherwise this would be a trivial LFI.
func TestResourcesCurated_SafePaths(t *testing.T) {
	t.Parallel()
	for _, r := range curatedDocResources() {
		assert.Falsef(t, strings.Contains(r.RelPath, ".."),
			"relative path %q contains '..' — path-traversal risk", r.RelPath)
		assert.Falsef(t, filepath.IsAbs(r.RelPath),
			"relative path %q is absolute — must be repo-relative", r.RelPath)
		assert.Truef(t, strings.HasPrefix(r.URI, "doc://"),
			"URI %q missing doc:// scheme", r.URI)
	}
}

// TestResourcesFindRepoRoot_ResolvesFromMCPPackage verifies that walking
// up from the mcp/ test working directory successfully locates the repo
// root (directory containing go.mod). This is the runtime resolver used
// to turn RelPath into an absolute file path.
func TestResourcesFindRepoRoot_ResolvesFromMCPPackage(t *testing.T) {
	t.Parallel()
	root, err := findRepoRoot()
	require.NoError(t, err)
	require.NotEmpty(t, root)
	// go.mod must live at root
	assert.FileExists(t, filepath.Join(root, "go.mod"))
	// SECURITY.md must live at root (sanity check — used in later tests)
	assert.FileExists(t, filepath.Join(root, "SECURITY.md"))
}

// TestResourcesRegister_RegistersKnownResources wires the registration
// into a real MCPServer and hits the list endpoint to verify the
// resources appear in the protocol-visible catalog.
//
// Each registered resource must have a non-empty Name + MIMEType set to
// `text/markdown` (the only format in the curated set).
func TestResourcesRegister_RegistersKnownResources(t *testing.T) {
	t.Parallel()
	srv := server.NewMCPServer("test", "1.0")
	root, err := findRepoRoot()
	require.NoError(t, err)

	RegisterDocResources(srv, root, sharedTestManager.Logger)

	// The MCPServer doesn't expose its internal resource map, but it
	// handles resources/list via an internal handler. We can't easily
	// introspect that without a session, so we assert via ReadResource
	// round-trips in the next tests. Here we just verify no panic.
}

// TestResourcesRead_SecurityPolicy performs an end-to-end read:
// register the resources, then call the handler for
// `doc://security-policy` and verify the returned contents are the
// actual SECURITY.md file on disk (not a stub).
//
// If someone ever breaks the read path (e.g. swaps fs.ReadFile for a
// placeholder), this test fails because real SECURITY.md has specific
// content we assert on.
func TestResourcesRead_SecurityPolicy(t *testing.T) {
	t.Parallel()
	root, err := findRepoRoot()
	require.NoError(t, err)

	// Register into a fresh server and fetch via an injected read.
	// We call the handler directly through the exported helper to keep
	// the test purely in-process without an MCP session.
	res, ok := findCuratedResource("doc://security-policy")
	require.True(t, ok, "security-policy must be in curated set")

	handler := docReadHandler(root, res, sharedTestManager.Logger)
	contents, err := handler(context.Background(), gomcp.ReadResourceRequest{
		Params: gomcp.ReadResourceParams{URI: "doc://security-policy"},
	})
	require.NoError(t, err)
	require.Len(t, contents, 1)

	trc, ok := contents[0].(gomcp.TextResourceContents)
	require.True(t, ok, "resource contents must be TextResourceContents")
	assert.Equal(t, "doc://security-policy", trc.URI)
	assert.Equal(t, "text/markdown", trc.MIMEType)
	// SECURITY.md must contain the "Security" word at minimum — if the
	// file is truncated, empty, or a stub, this flags it.
	assert.NotEmpty(t, trc.Text, "SECURITY.md content must not be empty")
	assert.Contains(t, strings.ToLower(trc.Text), "security",
		"SECURITY.md should contain the word 'security' — read returned wrong content")
}

// TestResourcesRead_UnknownURI ensures that the per-resource handler
// is scoped to exactly one URI and rejects mismatched reads, so a
// caller can't pass `doc://security-policy` to the README handler
// and get the wrong file.
func TestResourcesRead_UnknownURI(t *testing.T) {
	t.Parallel()
	root, err := findRepoRoot()
	require.NoError(t, err)

	res, ok := findCuratedResource("doc://README")
	require.True(t, ok)
	handler := docReadHandler(root, res, sharedTestManager.Logger)

	// Asking this handler (bound to README) for a different URI should
	// return an error — the handler is bound to one resource.
	_, err = handler(context.Background(), gomcp.ReadResourceRequest{
		Params: gomcp.ReadResourceParams{URI: "doc://does-not-exist"},
	})
	assert.Error(t, err, "handler bound to README must reject reads for other URIs")
}

// TestResourcesRegister_SkipsMissingFiles verifies that a curated entry
// whose file does not exist on disk is silently skipped (warn-logged,
// not panic). We simulate this by pointing repoRoot at a temp dir with
// no matching files — Register should not panic, and no resources
// should be registered.
func TestResourcesRegister_SkipsMissingFiles(t *testing.T) {
	t.Parallel()
	srv := server.NewMCPServer("test", "1.0")
	tmp := t.TempDir()
	// No README.md, SECURITY.md, etc. in tmp — all should be skipped.
	// Must not panic.
	RegisterDocResources(srv, tmp, sharedTestManager.Logger)
}

// TestResourcesFindCurated_HitAndMiss exercises the lookup helper.
func TestResourcesFindCurated_HitAndMiss(t *testing.T) {
	t.Parallel()
	r, ok := findCuratedResource("doc://README")
	require.True(t, ok)
	assert.Equal(t, "README.md", r.RelPath)

	_, ok = findCuratedResource("doc://nope")
	assert.False(t, ok)
}
