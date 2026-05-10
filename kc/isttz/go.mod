module github.com/algo2go/kite-mcp-isttz

go 1.25.0

// kc/isttz is a zero-dep stdlib-only leaf — IST timezone constant +
// helper. Smallest possible Go module: no internal deps, no external
// deps, just `time.LoadLocation("Asia/Kolkata")` wrapped for reuse.
//
// Tier 1 zero-monolith path (.research/zero-monolith-roadmap.md
// commit a5e7e76): 6 zero-dep leaves extracted in a single dispatch.
