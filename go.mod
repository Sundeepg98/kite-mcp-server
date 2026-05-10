module github.com/zerodha/kite-mcp-server

go 1.25.0

require (
	github.com/algo2go/kite-mcp-alerts v0.6.0
	github.com/algo2go/kite-mcp-audit v0.1.0
	github.com/algo2go/kite-mcp-billing v0.3.0
	github.com/algo2go/kite-mcp-broker v0.1.0
	github.com/algo2go/kite-mcp-clockport v0.1.0
	github.com/algo2go/kite-mcp-cqrs v0.1.0
	github.com/algo2go/kite-mcp-decorators v0.1.0
	github.com/algo2go/kite-mcp-domain v0.1.0
	github.com/algo2go/kite-mcp-eventsourcing v0.1.0
	github.com/algo2go/kite-mcp-i18n v0.1.0
	github.com/algo2go/kite-mcp-instruments v0.1.0
	github.com/algo2go/kite-mcp-isttz v0.1.0
	github.com/algo2go/kite-mcp-legaldocs v0.1.0
	github.com/algo2go/kite-mcp-logger v0.1.0
	github.com/algo2go/kite-mcp-money v0.1.0
	github.com/algo2go/kite-mcp-oauth v0.1.0
	github.com/algo2go/kite-mcp-papertrading v0.1.0
	github.com/algo2go/kite-mcp-registry v0.1.0
	github.com/algo2go/kite-mcp-riskguard v0.1.0
	github.com/algo2go/kite-mcp-scheduler v0.1.0
	github.com/algo2go/kite-mcp-sectors v0.1.0
	github.com/algo2go/kite-mcp-telegram v0.1.0
	github.com/algo2go/kite-mcp-templates v0.1.0
	github.com/algo2go/kite-mcp-ticker v0.1.0
	github.com/algo2go/kite-mcp-usecases v0.1.0
	github.com/algo2go/kite-mcp-users v0.1.0
	github.com/algo2go/kite-mcp-watchlist v0.1.0
	github.com/fsnotify/fsnotify v1.9.0
	github.com/go-telegram-bot-api/telegram-bot-api/v5 v5.5.1
	github.com/google/uuid v1.6.0
	github.com/hashicorp/go-plugin v1.7.0
	github.com/mark3labs/mcp-go v0.46.0
	github.com/stretchr/testify v1.11.1
	github.com/stripe/stripe-go/v82 v82.5.1
	github.com/yuin/goldmark v1.8.2
	github.com/zerodha/gokiteconnect/v4 v4.4.0
	github.com/zerodha/kite-mcp-server/app/providers v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/plugins v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/testutil v0.0.0-00010101000000-000000000000
	go.uber.org/fx v1.24.0
	go.uber.org/goleak v1.3.0
	golang.org/x/crypto v0.48.0
	golang.org/x/time v0.15.0
	modernc.org/sqlite v1.46.1
	pgregory.net/rapid v1.2.0
)

// Workspace-extracted modules — see go.work. Replace directives keep the
// root module buildable from a tagged release tarball that omits go.work
// (e.g., when goreleaser creates source archives) AND keep `GOWORK=off`
// builds working for diagnostics. Without these, the root module's
// imports of kc/audit + kc/riskguard + kc/billing + app/providers would
// fail to resolve outside workspace mode. Drop a replace once the
// corresponding module has its own published tag.
// Anchor 2 added app/providers as the first non-kc-prefixed extracted
// module (Fx provider/recipe composition root for the DI graph).
// Path A inauguration extracted broker (commit 6626812), kc/money
// (commit b92173b), kc/decorators (commit 7f71ccf), kc/i18n (commit
// c25e37f), kc/legaldocs (commit 568895e), kc/isttz (commit bbb31da
// — Path A.6.1 foundation), kc/scheduler (commit b2315cd —
// Path A.6.2 dependent), kc/logger (commit e6231a9 — Path A.7),
// kc/templates (commit 1db565a — Path A.8' after Path A.8 kc/billing
// halt at 71f17eb on deep-cluster cliff), kc/aop (commit 5db5165 —
// Path A.9 research-tag-gated leaf), kc/domain (commit 9ee8212 —
// Path A.10 foundation for kc/billing chain), kc/alerts (commit
// fd9d9fb — Path A.11 step 1 of billing chain), and kc/users (commit
// e96b1c0 — Path A.12 step 2 of billing chain) to algo2go GitHub
// repos. Phase B canary deletions (broker+money @ commit bef0b31,
// decorators @ commit c19bca9, i18n @ commit 84aab63, legaldocs @
// commit 326c045, isttz+scheduler @ commit b72a7e9, kc/logger @
// commit 1d977b7, kc/templates @ commit 10b30a3, kc/aop @ commit
// ad137cf, kc/domain @ commit da3f9ee, kc/alerts @ commit f30b1d5,
// and kc/users @ this commit) drop their replace directives — all
// thirteen are now fetched from
// algo2go/kite-mcp-broker@v0.1.0 + algo2go/kite-mcp-money@v0.1.0 +
// algo2go/kite-mcp-decorators@v0.1.0 + algo2go/kite-mcp-i18n@v0.1.0
// + algo2go/kite-mcp-legaldocs@v0.1.0 + algo2go/kite-mcp-isttz@v0.1.0
// + algo2go/kite-mcp-scheduler@v0.1.0 + algo2go/kite-mcp-logger@v0.1.0
// + algo2go/kite-mcp-templates@v0.1.0 + algo2go/kite-mcp-aop@v0.1.0
// + algo2go/kite-mcp-domain@v0.1.0 + algo2go/kite-mcp-alerts@v0.1.0
// + algo2go/kite-mcp-users@v0.1.0
// via GOPROXY. The require lines at the top of this go.mod are the
// operative source for those modules.
replace (
	github.com/zerodha/kite-mcp-server/app/providers => ./app/providers
	github.com/zerodha/kite-mcp-server/plugins => ./plugins
	github.com/zerodha/kite-mcp-server/testutil => ./testutil
)

require (
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.0 // indirect
	github.com/coder/websocket v1.8.12 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fatih/color v1.13.0 // indirect
	github.com/gocarina/gocsv v0.0.0-20180809181117-b8c38cb1ba36 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/go-querystring v1.0.0 // indirect
	github.com/google/jsonschema-go v0.4.2 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/hashicorp/go-hclog v1.6.3 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.9.2 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/oklog/run v1.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/tursodatabase/libsql-client-go v0.0.0-20251219100830-236aa1ff8acc // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	go.uber.org/dig v1.19.0 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	go.uber.org/zap v1.26.0 // indirect
	golang.org/x/exp v0.0.0-20251023183803-a4bb9ffd2546 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
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
