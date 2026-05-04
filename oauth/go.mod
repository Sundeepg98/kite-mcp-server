module github.com/zerodha/kite-mcp-server/oauth

go 1.25.0

// oauth is the OAuth 2.0 + dynamic client registration + JWT
// session + Google SSO + admin MFA surface for the kite-mcp-server.
// It bundles handlers (authorize, token, callback, registration),
// middleware (RequireAuth + token-expiry detection), JWT issuance/
// verification, the persistent ClientStore (AES-256-GCM encrypted
// client_secrets), Google SSO callback flow, and admin MFA TOTP
// management.
//
// Direct internal deps (verified empirically by grep on non-test
// .go files at HEAD before extraction):
//   - kc/templates — handlers.go embeds OAuth callback HTML +
//     dashboard pages for SSO redirect targets
//   - kc/users — handlers_admin_mfa.go consults the user store
//     for admin MFA enrolment + TOTP verification
//
// Replace block reach: 7 entries — root + kc/templates + kc/users
// (direct deps) + kc/alerts + broker + kc/isttz + kc/logger +
// kc/money (transitive via kc/users -> kc/alerts -> {broker,
// kc/domain, kc/isttz, kc/logger, kc/money} chain).
//
// Reverse-deps: 92 import sites across the codebase (per Tier 5
// audit 5fbd4a1). Direct reverse-deps from extracted modules:
// kc/audit (2), kc/billing (6), kc/papertrading (2), kc/riskguard
// (3) — each gets a replace directive added in this commit so
// their GOWORK=off resolution still works after oauth is its own
// module.
//
// Tier 5 zero-monolith path (.research/zero-monolith-roadmap.md
// + 5fbd4a1 Tier 5 audit): largest-blast-radius extraction in the
// dispatch, but the actual production-import surface (kc/templates +
// kc/users only) is small. The 92-import-site reverse-dep count is
// dominated by the root module's app/ + mcp/ packages which the
// workspace mode resolves transparently.
require (
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/uuid v1.6.0 // indirect
	github.com/stretchr/testify v1.10.0
	github.com/zerodha/gokiteconnect/v4 v4.4.0 // indirect
	github.com/zerodha/kite-mcp-server/kc/templates v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/users v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/oauth2 v0.36.0
	modernc.org/sqlite v1.46.1 // indirect
)

require (
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-telegram-bot-api/telegram-bot-api/v5 v5.5.1 // indirect
	github.com/gocarina/gocsv v0.0.0-20180809181117-b8c38cb1ba36 // indirect
	github.com/google/go-querystring v1.0.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/zerodha/kite-mcp-server/broker v0.0.0-00010101000000-000000000000 // indirect
	github.com/zerodha/kite-mcp-server/kc/alerts v0.0.0-00010101000000-000000000000 // indirect
	github.com/zerodha/kite-mcp-server/kc/domain v0.0.0-00010101000000-000000000000 // indirect
	github.com/zerodha/kite-mcp-server/kc/isttz v0.0.0-00010101000000-000000000000 // indirect
	github.com/zerodha/kite-mcp-server/kc/logger v0.0.0-00010101000000-000000000000 // indirect
	github.com/zerodha/kite-mcp-server/kc/money v0.0.0-00010101000000-000000000000 // indirect
	golang.org/x/exp v0.0.0-20251023183803-a4bb9ffd2546 // indirect
	golang.org/x/mod v0.32.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/libc v1.67.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

replace (
	github.com/zerodha/kite-mcp-server => ../
	github.com/zerodha/kite-mcp-server/broker => ../broker
	github.com/zerodha/kite-mcp-server/kc/alerts => ../kc/alerts
	github.com/zerodha/kite-mcp-server/kc/domain => ../kc/domain
	github.com/zerodha/kite-mcp-server/kc/isttz => ../kc/isttz
	github.com/zerodha/kite-mcp-server/kc/logger => ../kc/logger
	github.com/zerodha/kite-mcp-server/kc/money => ../kc/money
	github.com/zerodha/kite-mcp-server/kc/templates => ../kc/templates
	github.com/zerodha/kite-mcp-server/kc/users => ../kc/users
	github.com/zerodha/kite-mcp-server/testutil => ../testutil
)
