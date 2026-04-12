# Monolith Split — DONE

## dashboard.go (2284 lines -> 3 files)

| File | Lines | Contents |
|------|-------|----------|
| `kc/ops/dashboard.go` | 169 | DashboardHandler struct, New(), SetAdminCheck, SetBillingStore, RegisterRoutes, writeJSON, writeJSONError, intParam |
| `kc/ops/api_handlers.go` | 1892 | All JSON API endpoint handlers (activityAPI, ordersAPI, portfolio, alerts, status, marketIndices, pnlChartAPI, orderAttributionAPI, alertsEnrichedAPI, sectorExposureAPI, taxAnalysisAPI, paper*, safetyStatus, selfDeleteAccount, selfManageCredentials) + their response types |
| `kc/ops/page_handlers.go` | 236 | serveBillingPage SSR handler + tierDisplayName helper |

## app.go (2022 lines -> 4 files)

| File | Lines | Contents |
|------|-------|----------|
| `app/app.go` | 416 | App struct, Config, StatusPageData, NewApp, SetVersion, SetLogBuffer, LoadConfig, RunServer, buildServerURL, httpClient, configureHTTPClient, pricingPageHTML, checkoutSuccessHTML |
| `app/wire.go` | 393 | initializeServices (Kite manager + MCP server wiring), initScheduler |
| `app/http.go` | 827 | setupMux (route registration), createHTTPServer, setupGracefulShutdown, startServer, all start* variants (hybrid/SSE/HTTP/StdIO), registerTelegramWebhook, serveStatusPage, serveLegalPages, registerSSEEndpoints, securityHeaders, initStatusPageTemplate |
| `app/adapters.go` | 436 | All adapter types (signerAdapter, kiteExchangerAdapter, clientPersisterAdapter, registryAdapter, telegramManagerAdapter, briefingTokenAdapter, briefingCredAdapter, paperLTPAdapter, instrumentsFreezeAdapter) + makeEventPersister, deriveAggregateID |

## Verification
- `go vet ./...` — clean
- `go build ./...` — clean
- No behavioral changes — pure file reorganization
