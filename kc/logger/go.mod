module github.com/zerodha/kite-mcp-server/kc/logger

go 1.25.0

// kc/logger is a stdlib-only leaf — context-aware logger port over
// log/slog. Defines the Logger interface that all packages depend on
// for structured ctx-threaded logging, plus three implementations:
// SlogAdapter (production wrapper around *slog.Logger), Noop (silent
// for tests/init), and Capture (in-memory accumulator for assertion).
//
// Tier 1 zero-monolith path (.research/zero-monolith-roadmap.md
// commit a5e7e76): 6 zero-dep leaves extracted in a single dispatch.
