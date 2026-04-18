package mcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Curated MCP Resources: repo documentation exposed under the `doc://`
// scheme so LLM clients can discover them in-chat without the user
// having to paste URLs.
//
// Design notes:
//   - The set is CURATED and hard-coded. We do NOT expose arbitrary
//     file paths — exposing `file://` or similar broad schemes would
//     be a trivial LFI vector.
//   - Content is read from disk at request-time (small files, rarely
//     hit). For Dockerized / Fly.io deployments that do not ship the
//     source tree alongside the binary, the resources list will be
//     empty (a warning is logged per missing file at startup). This
//     is intentional: a remote-hosted server has no docs to surface.
//   - No write access is granted — handlers are read-only.
//
// Protocol reference: MCP resources spec (resources/list +
// resources/read endpoints).

// docMIMEType is the MIME advertised for all doc:// resources. Every
// entry in the curated set is a Markdown file.
const docMIMEType = "text/markdown"

// DocResource describes one entry in the curated set.
//
// RelPath is relative to the repo root; it is joined with the repo
// root at read-time. The set is validated at registration time (files
// that don't exist are logged and skipped, not registered).
type DocResource struct {
	URI         string // doc:// URI (wire identity)
	Name        string // human-readable name for UI
	Description string // short blurb for the LLM
	RelPath     string // path relative to repo root
}

// curatedDocResources returns the full curated set. Order is stable
// so tests and clients see consistent list ordering.
//
// To add a new doc: append an entry and update
// TestCuratedDocResources_Catalog in resources_test.go (the test is
// the registry contract — it will fail until both sides agree).
func curatedDocResources() []DocResource {
	return []DocResource{
		{
			URI:         "doc://README",
			Name:        "README",
			Description: "Project overview, quickstart, and supported MCP clients.",
			RelPath:     "README.md",
		},
		{
			URI:         "doc://security-policy",
			Name:         "Security Policy",
			Description:  "Disclosure process, threat model summary, hardened defaults.",
			RelPath:      "SECURITY.md",
		},
		{
			URI:         "doc://monitoring",
			Name:        "Monitoring & Observability",
			Description: "Metrics, alerting thresholds, and the server_metrics tool.",
			RelPath:     "docs/monitoring.md",
		},
		{
			URI:         "doc://incident-response",
			Name:        "Incident Response Runbook",
			Description: "5-minute regulator panic button, kill switch, and escalation paths.",
			RelPath:     "docs/incident-response.md",
		},
		{
			URI:         "doc://faq",
			Name:        "FAQ",
			Description: "Common questions — setup, auth, trading modes, SEBI compliance.",
			RelPath:     "docs/faq.md",
		},
		{
			URI:         "doc://architecture",
			Name:        "Architecture",
			Description: "High-level architecture — CQRS, clean arch, middleware chain.",
			RelPath:     "ARCHITECTURE.md",
		},
		{
			URI:         "doc://self-host",
			Name:        "Self-Hosting Guide",
			Description: "Running the server on your own infra (Docker, Fly.io, bare metal).",
			RelPath:     "docs/self-host.md",
		},
		{
			URI:         "doc://kite-token-refresh",
			Name:        "Kite Token Refresh",
			Description: "Daily ~6 AM IST token expiry and the re-auth flow.",
			RelPath:     "docs/kite-token-refresh.md",
		},
		{
			URI:         "doc://tool-catalog",
			Name:        "Tool Catalog",
			Description: "Every MCP tool this server exposes, with tier gating.",
			RelPath:     "docs/tool-catalog.md",
		},
		{
			URI:         "doc://byo-api-key",
			Name:        "BYO Kite API Key",
			Description: "Why each user needs a Kite developer app (per-user OAuth).",
			RelPath:     "docs/byo-api-key.md",
		},
		{
			URI:         "doc://architecture-diagram",
			Name:        "Architecture Diagram",
			Description: "Visual diagram of the auth, MCP, and broker layers.",
			RelPath:     "docs/architecture-diagram.md",
		},
		{
			URI:         "doc://release-notes-v1.1.0",
			Name:        "Release Notes v1.1.0",
			Description: "Latest release notes — what changed, known issues.",
			RelPath:     "docs/release-notes-v1.1.0.md",
		},
	}
}

// findCuratedResource returns the curated entry for the given URI and
// whether it was found.
func findCuratedResource(uri string) (DocResource, bool) {
	for _, r := range curatedDocResources() {
		if r.URI == uri {
			return r, true
		}
	}
	return DocResource{}, false
}

// findRepoRoot walks up from the current working directory looking for
// a `go.mod` file. This gives a robust anchor for resolving doc paths
// regardless of where the binary was invoked from — tests run inside
// mcp/, servers run from the repo root, Docker-run binaries won't
// find go.mod and will cause resources to be skipped (which is the
// correct behavior for a remote-hosted deployment that doesn't ship
// the source tree).
//
// Returns the absolute path to the directory containing go.mod, or
// an error if no go.mod was found walking up from CWD.
func findRepoRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getwd: %w", err)
	}
	dir := cwd
	for {
		candidate := filepath.Join(dir, "go.mod")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			// Hit the filesystem root without finding go.mod.
			return "", fmt.Errorf("go.mod not found walking up from %s", cwd)
		}
		dir = parent
	}
}

// docReadHandler returns a ResourceHandlerFunc bound to a single
// curated resource. The handler rejects mismatched URIs (defense-in-
// depth) and reads the file from disk on every call. Content is
// returned as TextResourceContents with MIME type text/markdown.
//
// Rationale for reading on every call: docs change rarely, and a
// cold read of a sub-500KB Markdown file is cheap. This keeps the
// handler stateless and picks up doc edits without a server restart.
func docReadHandler(repoRoot string, res DocResource, logger *slog.Logger) server.ResourceHandlerFunc {
	absPath := filepath.Join(repoRoot, filepath.FromSlash(res.RelPath))
	return func(_ context.Context, req gomcp.ReadResourceRequest) ([]gomcp.ResourceContents, error) {
		// Per-resource handler is bound to exactly one URI. Reject
		// mismatches so a mutable handler closure can't be used to
		// read an arbitrary file if the dispatcher is ever bypassed.
		if req.Params.URI != res.URI {
			return nil, fmt.Errorf("doc resource handler for %q called with URI %q", res.URI, req.Params.URI)
		}
		data, err := os.ReadFile(absPath) // #nosec G304 — path built from curated RelPath, not user input
		if err != nil {
			if logger != nil {
				logger.Warn("doc resource read failed", "uri", res.URI, "path", absPath, "error", err)
			}
			if errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("doc resource %s unavailable in this deployment", res.URI)
			}
			return nil, fmt.Errorf("read %s: %w", res.URI, err)
		}
		return []gomcp.ResourceContents{
			gomcp.TextResourceContents{
				URI:      res.URI,
				MIMEType: docMIMEType,
				Text:     string(data),
			},
		}, nil
	}
}

// RegisterDocResources registers the curated doc:// resources onto
// the given MCPServer. For each entry it checks whether the backing
// file exists at repoRoot/RelPath; missing entries are logged and
// skipped (not a panic — deployments that don't ship the source tree
// simply end up with an empty resource list).
//
// Safe to call once at server startup. This is the only entry point
// from mcp.RegisterTools — if you're reading this to add another
// resource type, prefer a separate Register function (see
// RegisterAppResources for the widget/ui:// pattern).
func RegisterDocResources(srv *server.MCPServer, repoRoot string, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}

	// Defensive path check: reject absolute or traversal-style
	// RelPaths. These would never appear in curatedDocResources() as
	// shipped, but the test suite pins this invariant so a future
	// edit can't silently regress it.
	registered := 0
	skipped := 0
	for _, res := range curatedDocResources() {
		if filepath.IsAbs(res.RelPath) || strings.Contains(res.RelPath, "..") {
			logger.Error("doc resource rejected: unsafe RelPath", "uri", res.URI, "rel_path", res.RelPath)
			skipped++
			continue
		}
		absPath := filepath.Join(repoRoot, filepath.FromSlash(res.RelPath))
		info, err := os.Stat(absPath)
		if err != nil || info.IsDir() {
			// File missing or is a directory — skip, log a warning
			// so operators can spot misconfigured deployments.
			logger.Warn("doc resource skipped: backing file not found",
				"uri", res.URI, "path", absPath)
			skipped++
			continue
		}

		srv.AddResource(
			gomcp.Resource{
				URI:         res.URI,
				Name:        res.Name,
				Description: res.Description,
				MIMEType:    docMIMEType,
			},
			docReadHandler(repoRoot, res, logger),
		)
		registered++
	}

	logger.Info("MCP doc resources registered",
		"registered", registered,
		"skipped", skipped,
		"scheme", "doc://")
}
