module github.com/zerodha/kite-mcp-server/kc/decorators

go 1.25.0

// kc/decorators is a stdlib-only generic-types decorator leaf —
// Decorator[Req, Resp] generic wrapper for the typed-middleware
// pattern (Path F closure of the Decorator dim per ADR-0008). The
// audit at .research/zero-monolith-roadmap.md (a5e7e76) classified
// this as Tier 2 (single-dep) because of the test file's external
// package self-import; empirically the production source has ZERO
// internal deps. Pure leaf — no replace block needed.
//
// Tier 2 zero-monolith path (.research/zero-monolith-roadmap.md
// commit a5e7e76): single-dep packages extracted in a single
// dispatch.
require github.com/stretchr/testify v1.10.0

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
