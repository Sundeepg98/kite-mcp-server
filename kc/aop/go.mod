module github.com/zerodha/kite-mcp-server/kc/aop

go 1.25.0

// kc/aop is a research-tagged reflective Aspect-Oriented Programming
// surface gated by `//go:build research` on every .go file. Pure
// leaf — zero internal dependencies (verified empirically: only
// intra-package self-imports in *_test.go files; no production
// caller anywhere in the codebase). External dep: stretchr/testify
// for tests only.
//
// The build tag stays on individual files; this go.mod itself is
// a normal Go module. The CI research-tag matrix entry (per F7
// commit ca9996c) continues to exercise the package via
// `go test -tags=research ./kc/aop/...`. Production binaries
// (Fly.io Dockerfile + Dockerfile.selfhost) link without this
// package — empirically confirmed by the zero-non-test-imports
// invariant documented in aop.go's package comment.
//
// Tier 5 zero-monolith path (.research/zero-monolith-roadmap.md
// + 5fbd4a1 Tier 5 audit): research-only peripheral, lowest-risk
// extraction in the dispatch (zero reverse-deps). 25/27.
require github.com/stretchr/testify v1.10.0

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
