module github.com/zerodha/kite-mcp-server/testutil

go 1.25.0

// testutil is the shared test-helpers module — Clock/Ticker
// fakes (clock.go), MockKiteServer fixture (kiteserver.go),
// Capture/Noop logger (logger.go), and the kcfixture sub-package
// (kcfixture/manager.go) for building *kc.Manager test instances.
//
// Cross-module dependency graph:
//   testutil/                — imports kc/logger only (logport
//                              interface for Capture/Noop loggers).
//   testutil/kcfixture/      — imports root (kc/), kc/instruments,
//                              kc/riskguard, testutil. Sub-package
//                              isolated by design: only callers
//                              OUTSIDE the kc tree may import
//                              kcfixture (per its package comment),
//                              avoiding kc → testutil/kcfixture → kc
//                              import cycles within the root module.
//
// Replace block reach: 14 entries — root + kc/instruments + kc/risk-
// guard (direct kcfixture deps) + kc/logger (direct testutil dep)
// + transitive chain via kc/riskguard → kc/domain + broker + kc/money
// + kc/isttz + kc/alerts + kc/templates + kc/users + kc/i18n. Same
// transitive-walk pattern documented at commit 9ce2248 (kc/audit) and
// 5982aff (kc/riskguard).
//
// Tier 5 zero-monolith path (.research/zero-monolith-roadmap.md
// + 5fbd4a1 Tier 5 audit): cleanest leaf peripheral, 15 reverse-deps
// across the codebase but zero blast-radius — testutil is purely
// a test-helper surface plus one production usage in kc/fill_watcher
// (testutil.Clock/Ticker for fake-clock injection in fill polling).
require (
	github.com/stretchr/testify v1.10.0
	github.com/zerodha/kite-mcp-server v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/instruments v0.0.0-00010101000000-000000000000
	github.com/algo2go/kite-mcp-logger v0.1.0
	github.com/zerodha/kite-mcp-server/kc/riskguard v0.0.0-00010101000000-000000000000
)

require github.com/zerodha/gokiteconnect/v4 v4.4.0

require (
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fatih/color v1.13.0 // indirect
	github.com/go-telegram-bot-api/telegram-bot-api/v5 v5.5.1 // indirect
	github.com/gocarina/gocsv v0.0.0-20180809181117-b8c38cb1ba36 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/go-querystring v1.0.0 // indirect
	github.com/google/jsonschema-go v0.4.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/hashicorp/go-hclog v1.6.3 // indirect
	github.com/hashicorp/go-plugin v1.7.0 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/mark3labs/mcp-go v0.46.0 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/oklog/run v1.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/stripe/stripe-go/v82 v82.5.1 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	github.com/algo2go/kite-mcp-broker v0.1.0 // indirect
	github.com/algo2go/kite-mcp-alerts v0.1.0 // indirect
	github.com/zerodha/kite-mcp-server/kc/audit v0.0.0-00010101000000-000000000000 // indirect
	github.com/algo2go/kite-mcp-billing v0.1.0 // indirect
	github.com/zerodha/kite-mcp-server/kc/cqrs v0.0.0-00010101000000-000000000000 // indirect
	github.com/algo2go/kite-mcp-domain v0.1.0 // indirect
	github.com/zerodha/kite-mcp-server/kc/eventsourcing v0.0.0-00010101000000-000000000000 // indirect
	github.com/algo2go/kite-mcp-i18n v0.1.0 // indirect
	github.com/algo2go/kite-mcp-isttz v0.1.0 // indirect
	github.com/algo2go/kite-mcp-money v0.1.0 // indirect
	github.com/zerodha/kite-mcp-server/kc/papertrading v0.0.0-00010101000000-000000000000 // indirect
	github.com/zerodha/kite-mcp-server/kc/registry v0.0.0-00010101000000-000000000000 // indirect
	github.com/algo2go/kite-mcp-templates v0.1.0 // indirect
	github.com/zerodha/kite-mcp-server/kc/ticker v0.0.0-00010101000000-000000000000 // indirect
	github.com/zerodha/kite-mcp-server/kc/usecases v0.0.0-00010101000000-000000000000 // indirect
	github.com/algo2go/kite-mcp-users v0.1.0 // indirect
	github.com/algo2go/kite-mcp-watchlist v0.1.0 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/exp v0.0.0-20251023183803-a4bb9ffd2546 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/grpc v1.79.3 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/libc v1.67.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.46.1 // indirect
)

replace (
	github.com/zerodha/kite-mcp-server => ../
	github.com/zerodha/kite-mcp-server/kc/audit => ../kc/audit
	github.com/zerodha/kite-mcp-server/kc/cqrs => ../kc/cqrs
	github.com/zerodha/kite-mcp-server/kc/eventsourcing => ../kc/eventsourcing
	github.com/zerodha/kite-mcp-server/kc/instruments => ../kc/instruments
	github.com/zerodha/kite-mcp-server/kc/papertrading => ../kc/papertrading
	github.com/zerodha/kite-mcp-server/kc/registry => ../kc/registry
	github.com/zerodha/kite-mcp-server/kc/riskguard => ../kc/riskguard
	github.com/zerodha/kite-mcp-server/kc/ticker => ../kc/ticker
	github.com/zerodha/kite-mcp-server/kc/usecases => ../kc/usecases
	github.com/algo2go/kite-mcp-watchlist => ../kc/watchlist
)
