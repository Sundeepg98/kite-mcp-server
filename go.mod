module github.com/zerodha/kite-mcp-server

go 1.25.0

require (
	github.com/fsnotify/fsnotify v1.9.0
	github.com/go-telegram-bot-api/telegram-bot-api/v5 v5.5.1
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/uuid v1.6.0
	github.com/hashicorp/go-hclog v1.6.3
	github.com/hashicorp/go-plugin v1.7.0
	github.com/mark3labs/mcp-go v0.46.0
	github.com/stretchr/testify v1.10.0
	github.com/stripe/stripe-go/v82 v82.5.1
	github.com/yuin/goldmark v1.8.2
	github.com/zerodha/gokiteconnect/v4 v4.4.0
	github.com/zerodha/kite-mcp-server/broker v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/alerts v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/audit v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/billing v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/cqrs v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/decorators v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/domain v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/eventsourcing v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/i18n v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/instruments v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/isttz v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/legaldocs v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/logger v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/money v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/registry v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/riskguard v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/scheduler v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/templates v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/ticker v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/users v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/watchlist v0.0.0-00010101000000-000000000000
	go.uber.org/fx v1.24.0
	go.uber.org/goleak v1.3.0
	golang.org/x/crypto v0.48.0
	golang.org/x/oauth2 v0.36.0
	golang.org/x/time v0.15.0
	modernc.org/sqlite v1.46.1
	pgregory.net/rapid v1.2.0
)

// Workspace-extracted modules — see go.work. Replace directives keep the
// root module buildable from a tagged release tarball that omits go.work
// (e.g., when goreleaser creates source archives) AND keep `GOWORK=off`
// builds working for diagnostics. Without these, the root module's
// imports of broker + kc/money + kc/audit + kc/riskguard + kc/billing
// would fail to resolve outside workspace mode. Drop a replace once
// the corresponding module has its own published tag. 5/5 multi-module
// decomposition complete (commit 5 = kc/billing).
replace (
	github.com/zerodha/kite-mcp-server/broker => ./broker
	github.com/zerodha/kite-mcp-server/kc/alerts => ./kc/alerts
	github.com/zerodha/kite-mcp-server/kc/audit => ./kc/audit
	github.com/zerodha/kite-mcp-server/kc/billing => ./kc/billing
	github.com/zerodha/kite-mcp-server/kc/cqrs => ./kc/cqrs
	github.com/zerodha/kite-mcp-server/kc/decorators => ./kc/decorators
	github.com/zerodha/kite-mcp-server/kc/domain => ./kc/domain
	github.com/zerodha/kite-mcp-server/kc/eventsourcing => ./kc/eventsourcing
	github.com/zerodha/kite-mcp-server/kc/i18n => ./kc/i18n
	github.com/zerodha/kite-mcp-server/kc/instruments => ./kc/instruments
	github.com/zerodha/kite-mcp-server/kc/isttz => ./kc/isttz
	github.com/zerodha/kite-mcp-server/kc/legaldocs => ./kc/legaldocs
	github.com/zerodha/kite-mcp-server/kc/logger => ./kc/logger
	github.com/zerodha/kite-mcp-server/kc/money => ./kc/money
	github.com/zerodha/kite-mcp-server/kc/registry => ./kc/registry
	github.com/zerodha/kite-mcp-server/kc/riskguard => ./kc/riskguard
	github.com/zerodha/kite-mcp-server/kc/scheduler => ./kc/scheduler
	github.com/zerodha/kite-mcp-server/kc/templates => ./kc/templates
	github.com/zerodha/kite-mcp-server/kc/ticker => ./kc/ticker
	github.com/zerodha/kite-mcp-server/kc/users => ./kc/users
	github.com/zerodha/kite-mcp-server/kc/watchlist => ./kc/watchlist
)

require (
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fatih/color v1.13.0 // indirect
	github.com/gocarina/gocsv v0.0.0-20180809181117-b8c38cb1ba36 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/go-querystring v1.0.0 // indirect
	github.com/google/jsonschema-go v0.4.2 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/oklog/run v1.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	go.uber.org/dig v1.19.0 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	go.uber.org/zap v1.26.0 // indirect
	golang.org/x/exp v0.0.0-20251023183803-a4bb9ffd2546 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/grpc v1.79.3 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/libc v1.67.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)
