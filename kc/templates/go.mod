module github.com/algo2go/kite-mcp-templates

go 1.25.0

// kc/templates is a stdlib-only embed leaf — single 10-LOC templates.go
// that uses go:embed to surface all *.html files (dashboard, landing,
// admin pages, widgets, OAuth callback, etc.) for serving from the
// HTTP layer + MCP App widgets. Zero internal deps, zero external
// deps.
//
// Tier 1 zero-monolith path (.research/zero-monolith-roadmap.md
// commit a5e7e76): 6 zero-dep leaves extracted in a single dispatch.
