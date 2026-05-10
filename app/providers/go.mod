module github.com/zerodha/kite-mcp-server/app/providers

go 1.25.0

// app/providers is the Fx provider/recipe module — the dependency-injection
// composition root for kite-mcp-server. Each *.go file is an Fx provider
// returning a typed dependency: AlertSvc, AuditStore, BillingStore,
// CredentialSvc, EventDispatcher, FamilyService, LifecycleManager, LoggerPort,
// Manager, MCPServer, OrderSvc, PortfolioSvc, RiskGuard, Scheduler,
// SessionSvc, TelegramNotifier — all wired via go.uber.org/fx in app/wire.go.
//
// This is the 6th extracted module (Anchor 2 of the architecture roadmap;
// audits 7ac9d34/5fbd4a1/fd603f3). It joins broker/ + kc/{alerts, aop,
// audit, billing, cqrs, decorators, domain, eventsourcing, i18n,
// instruments, isttz, legaldocs, logger, money, papertrading, registry,
// riskguard, scheduler, telegram, templates, ticker, usecases, users,
// watchlist} + oauth/ + testutil/ as workspace members.
//
// Bidirectional cross-module deps with the root module:
//   - app/providers imports root packages: app/metrics, kc (parent),
//     mcp (parent). Resolved via `replace github.com/zerodha/kite-mcp-server
//     => ../..` so the root tree is reachable as one unit.
//   - The root module imports app/providers from app/wire.go and
//     cmd/event-graph/main.go. Resolved via go.work + the root go.mod's
//     `replace github.com/zerodha/kite-mcp-server/app/providers =>
//     ./app/providers` directive.
//
// Replace block: 28 entries — root + 27 already-extracted modules that
// are reachable transitively through kc parent / kc/alerts / kc/audit /
// kc/billing / kc/riskguard / mcp parent. Higher than kc/usecases's
// 16-entry plateau because app/providers imports both kc parent (heavy
// fan-out) AND mcp parent (heavy middleware fan-out) AND every
// individually-extracted module that providers wire. The full set
// covers every workspace member except app/providers itself — which is
// the empirical worst-case for replace count and the reason this
// extraction was queued for last among the bidirectional-dep modules.
//
// In workspace mode (the canonical local + CI build path), all upstream
// packages are resolved via go.work + the root module path. The replace
// directives below short-circuit version lookup when GOWORK=off (Dockerfile
// build, vendored consumer). v0.0.0 pseudo-version is the conventional
// placeholder for "workspace-local-only".

require (
	github.com/mark3labs/mcp-go v0.46.0
	github.com/zerodha/kite-mcp-server v0.0.0-00010101000000-000000000000
	github.com/algo2go/kite-mcp-alerts v0.1.0
	github.com/zerodha/kite-mcp-server/kc/audit v0.0.0-00010101000000-000000000000
	github.com/algo2go/kite-mcp-billing v0.1.0
	github.com/algo2go/kite-mcp-domain v0.1.0
	github.com/algo2go/kite-mcp-logger v0.1.0
	github.com/zerodha/kite-mcp-server/kc/riskguard v0.0.0-00010101000000-000000000000
	github.com/algo2go/kite-mcp-scheduler v0.1.0
	github.com/algo2go/kite-mcp-users v0.1.0
	go.uber.org/fx v1.24.0
)

require (
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fatih/color v1.13.0 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
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
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/oklog/run v1.1.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/stripe/stripe-go/v82 v82.5.1 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	github.com/zerodha/gokiteconnect/v4 v4.4.0 // indirect
	github.com/algo2go/kite-mcp-broker v0.1.0 // indirect
	github.com/zerodha/kite-mcp-server/kc/cqrs v0.0.0-00010101000000-000000000000 // indirect
	github.com/algo2go/kite-mcp-decorators v0.1.0 // indirect
	github.com/zerodha/kite-mcp-server/kc/eventsourcing v0.0.0-00010101000000-000000000000 // indirect
	github.com/algo2go/kite-mcp-i18n v0.1.0 // indirect
	github.com/zerodha/kite-mcp-server/kc/instruments v0.0.0-00010101000000-000000000000 // indirect
	github.com/algo2go/kite-mcp-isttz v0.1.0 // indirect
	github.com/algo2go/kite-mcp-money v0.1.0 // indirect
	github.com/zerodha/kite-mcp-server/kc/papertrading v0.0.0-00010101000000-000000000000 // indirect
	github.com/zerodha/kite-mcp-server/kc/registry v0.0.0-00010101000000-000000000000 // indirect
	github.com/algo2go/kite-mcp-templates v0.1.0 // indirect
	github.com/zerodha/kite-mcp-server/kc/ticker v0.0.0-00010101000000-000000000000 // indirect
	github.com/zerodha/kite-mcp-server/kc/usecases v0.0.0-00010101000000-000000000000 // indirect
	github.com/zerodha/kite-mcp-server/kc/watchlist v0.0.0-00010101000000-000000000000 // indirect
	github.com/algo2go/kite-mcp-oauth v0.1.0 // indirect
	github.com/zerodha/kite-mcp-server/testutil v0.0.0-00010101000000-000000000000 // indirect
	go.uber.org/dig v1.19.0 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	go.uber.org/zap v1.26.0 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/exp v0.0.0-20251023183803-a4bb9ffd2546 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/grpc v1.79.3 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
	modernc.org/libc v1.67.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.46.1 // indirect
)

replace (
	github.com/zerodha/kite-mcp-server => ../..
	github.com/zerodha/kite-mcp-server/kc/audit => ../../kc/audit
	github.com/algo2go/kite-mcp-billing => ../../kc/billing
	github.com/zerodha/kite-mcp-server/kc/cqrs => ../../kc/cqrs
	github.com/zerodha/kite-mcp-server/kc/eventsourcing => ../../kc/eventsourcing
	github.com/zerodha/kite-mcp-server/kc/instruments => ../../kc/instruments
	github.com/zerodha/kite-mcp-server/kc/papertrading => ../../kc/papertrading
	github.com/zerodha/kite-mcp-server/kc/registry => ../../kc/registry
	github.com/zerodha/kite-mcp-server/kc/riskguard => ../../kc/riskguard
	github.com/zerodha/kite-mcp-server/kc/telegram => ../../kc/telegram
	github.com/zerodha/kite-mcp-server/kc/ticker => ../../kc/ticker
	github.com/zerodha/kite-mcp-server/kc/usecases => ../../kc/usecases
	github.com/zerodha/kite-mcp-server/kc/watchlist => ../../kc/watchlist
	github.com/zerodha/kite-mcp-server/testutil => ../../testutil
)
