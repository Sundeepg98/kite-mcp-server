module github.com/zerodha/kite-mcp-server/kc/billing

go 1.25.0

// kc/billing has bidirectional cross-module deps with the root module:
// the root module requires kc/billing (12+ reverse-dep import sites
// per .research/disintegrate-and-holistic-architecture.md §1.2);
// kc/billing imports kc/alerts, kc/domain, kc/logger, oauth.
//
// PR 4.3 (Anchor 4): kc/domain was extracted at PR 4.1 stub-add
// (commit d4bb3e6). This PR adds an explicit `kc/domain => ../domain`
// replace + 5 transitive replaces (matching the kc/audit PR 4.2
// pattern at commit b614f39). ZERO behavior change at runtime.
//
// External: Stripe SDK (stripe-go/v82) for checkout/billingportal/
// webhook + mark3labs/mcp-go for the billing-tier middleware.
//
// In workspace mode (the canonical local + CI build path), all
// upstream packages are resolved via go.work + the root module path.
// The replace directives below short-circuit version lookup when
// GOWORK=off (Dockerfile build, vendored consumer). v0.0.0 pseudo-
// version is the conventional placeholder for "workspace-local-only".
require (
	github.com/mark3labs/mcp-go v0.46.0
	github.com/stretchr/testify v1.10.0
	github.com/stripe/stripe-go/v82 v82.5.1
	github.com/algo2go/kite-mcp-broker v0.1.0 // indirect
	github.com/algo2go/kite-mcp-money v0.1.0 // indirect
	go.uber.org/goleak v1.3.0
)

require (
	github.com/zerodha/kite-mcp-server/kc/alerts v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/domain v0.0.0-00010101000000-000000000000
	github.com/algo2go/kite-mcp-logger v0.1.0
	github.com/zerodha/kite-mcp-server/oauth v0.0.0-00010101000000-000000000000
)

require (
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-telegram-bot-api/telegram-bot-api/v5 v5.5.1 // indirect
	github.com/gocarina/gocsv v0.0.0-20180809181117-b8c38cb1ba36 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-querystring v1.0.0 // indirect
	github.com/google/jsonschema-go v0.4.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	github.com/zerodha/gokiteconnect/v4 v4.4.0 // indirect
	github.com/algo2go/kite-mcp-isttz v0.1.0 // indirect
	github.com/algo2go/kite-mcp-templates v0.1.0 // indirect
	github.com/zerodha/kite-mcp-server/kc/users v0.0.0-00010101000000-000000000000 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/exp v0.0.0-20251023183803-a4bb9ffd2546 // indirect
	golang.org/x/mod v0.32.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/libc v1.67.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.46.1 // indirect
)

// kc/billing transitively imports broker (via kc/domain → broker) and
// kc/money (via kc/domain → broker → kc/money). Each requires its own
// replace directive because Go's module resolver walks the dep graph
// from kc/billing's perspective, not from the root module's. Without
// these the resolver fails with "invalid version: unknown revision
// 000000000000" — the same pattern documented at commits 9ce2248
// (kc/audit) and 5982aff (kc/riskguard) earlier in the multi-module
// decomposition arc.
replace (
	github.com/zerodha/kite-mcp-server => ../..
	github.com/zerodha/kite-mcp-server/kc/alerts => ../alerts
	github.com/zerodha/kite-mcp-server/kc/domain => ../domain
	github.com/zerodha/kite-mcp-server/kc/users => ../users
	github.com/zerodha/kite-mcp-server/oauth => ../../oauth
	github.com/zerodha/kite-mcp-server/testutil => ../../testutil
)
