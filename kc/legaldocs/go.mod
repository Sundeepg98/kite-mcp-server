module github.com/algo2go/kite-mcp-legaldocs

go 1.25.0

// kc/legaldocs is a stdlib-only leaf — embeds the legal docs (terms,
// privacy, etc.) via go:embed for serving from /terms and /privacy
// routes. Zero internal deps, zero external deps.
//
// Tier 1 zero-monolith path (.research/zero-monolith-roadmap.md
// commit a5e7e76): 6 zero-dep leaves extracted in a single dispatch.
