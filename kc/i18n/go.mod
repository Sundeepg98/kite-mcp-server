module github.com/algo2go/kite-mcp-i18n

go 1.25.0

// kc/i18n is a zero-internal-dep leaf — Hindi translations for landing,
// briefing, riskguard rejection messages, and OAuth flow. Pure
// translation lookup; no domain types, no broker, no transitive
// workspace-member reach. Same shape as kc/money (commit b7fedcc):
// pure leaf, no replace block needed.
//
// Tier 1 zero-monolith path (.research/zero-monolith-roadmap.md
// commit a5e7e76): 6 zero-dep leaves extracted in a single dispatch.
require github.com/stretchr/testify v1.10.0

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
