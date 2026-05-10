module github.com/zerodha/kite-mcp-server/plugins

go 1.25.0

// plugins is the external-tool / before-after hook module — the public
// extension surface for kite-mcp-server. It contains:
//   - example/   : ServerTimeTool sample plugin demonstrating how to
//                  register a new MCP tool via mcp.RegisterPlugin.
//                  Imports kc (parent) for the *kc.Manager handler param.
//                  NOT wired in production app/wire.go; documentation only.
//   - rolegate/  : First production consumer of OnBeforeToolExecution.
//                  Enforces RBAC by blocking write tools (place_/modify_/
//                  cancel_/etc.) for users with role=Viewer. Imports
//                  kc/users + mcp (parent) + oauth.
//   - telegramnotify/ : Second production consumer; uses
//                  OnAfterToolExecution to DM family admins on trade-
//                  affecting tool successes. Imports kc/users + mcp
//                  (parent) + oauth.
//
// Tier 6 zero-monolith path (.research/zero-monolith-roadmap.md +
// 5fbd4a1 Tier 6 audit): final architectural roadmap item. Was
// originally deferred because plugins/ imports kc parent + mcp parent
// (both god-structs at the time). Anchor 6 (commit ea34058) collapsed
// the kc-parent god-struct to constructors only; Anchor 2 (commit
// e87cd38) extracted app/providers as a separate module — closing
// both blockers. Empirically: plugins/example still references
// *kc.Manager but that struct is now a thin Fx-injectable receiver.
//
// Bidirectional cross-module deps with the root module (same shape
// as app/providers):
//   - plugins imports root packages: kc (parent) + mcp (parent).
//     Resolved via `replace github.com/zerodha/kite-mcp-server =>
//     ../` so the root tree is reachable as one unit.
//   - The root module imports plugins/rolegate + plugins/telegramnotify
//     from app/wire.go. Resolved via go.work + the root go.mod's
//     `replace github.com/zerodha/kite-mcp-server/plugins =>
//     ./plugins` directive.
//
// Replace block mirrors app/providers's 28-entry pattern: root + 27
// already-extracted modules reachable transitively through kc parent /
// kc/users / mcp parent / oauth. In workspace mode (canonical local +
// CI build path), all upstream packages are resolved via go.work + the
// root module path. The replace directives short-circuit version lookup
// when GOWORK=off (Dockerfile build, vendored consumer).

require (
	github.com/mark3labs/mcp-go v0.46.0
	github.com/stretchr/testify v1.10.0
	github.com/zerodha/kite-mcp-server v0.0.0-00010101000000-000000000000
	github.com/algo2go/kite-mcp-users v0.1.0
	github.com/algo2go/kite-mcp-oauth v0.1.0
)

require (
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
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
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/stripe/stripe-go/v82 v82.5.1 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	github.com/zerodha/gokiteconnect/v4 v4.4.0 // indirect
	github.com/algo2go/kite-mcp-broker v0.1.0 // indirect
	github.com/algo2go/kite-mcp-alerts v0.1.0 // indirect
	github.com/algo2go/kite-mcp-audit v0.1.0 // indirect
	github.com/algo2go/kite-mcp-billing v0.1.0 // indirect
	github.com/algo2go/kite-mcp-cqrs v0.1.0 // indirect
	github.com/algo2go/kite-mcp-decorators v0.1.0 // indirect
	github.com/algo2go/kite-mcp-domain v0.1.0 // indirect
	github.com/algo2go/kite-mcp-eventsourcing v0.1.0 // indirect
	github.com/algo2go/kite-mcp-i18n v0.1.0 // indirect
	github.com/algo2go/kite-mcp-instruments v0.1.0 // indirect
	github.com/algo2go/kite-mcp-isttz v0.1.0 // indirect
	github.com/algo2go/kite-mcp-logger v0.1.0 // indirect
	github.com/algo2go/kite-mcp-money v0.1.0 // indirect
	github.com/zerodha/kite-mcp-server/kc/papertrading v0.0.0-00010101000000-000000000000 // indirect
	github.com/algo2go/kite-mcp-registry v0.1.0 // indirect
	github.com/algo2go/kite-mcp-riskguard v0.1.0 // indirect
	github.com/algo2go/kite-mcp-scheduler v0.1.0 // indirect
	github.com/algo2go/kite-mcp-templates v0.1.0 // indirect
	github.com/algo2go/kite-mcp-ticker v0.1.0 // indirect
	github.com/zerodha/kite-mcp-server/kc/usecases v0.0.0-00010101000000-000000000000 // indirect
	github.com/algo2go/kite-mcp-watchlist v0.1.0 // indirect
	github.com/zerodha/kite-mcp-server/testutil v0.0.0-00010101000000-000000000000 // indirect
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
	github.com/zerodha/kite-mcp-server/app/providers => ../app/providers
	github.com/zerodha/kite-mcp-server/kc/papertrading => ../kc/papertrading
	github.com/algo2go/kite-mcp-riskguard => ../kc/riskguard
	github.com/zerodha/kite-mcp-server/kc/telegram => ../kc/telegram
	github.com/zerodha/kite-mcp-server/kc/usecases => ../kc/usecases
	github.com/zerodha/kite-mcp-server/testutil => ../testutil
)
