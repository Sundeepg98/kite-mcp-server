# Multi-Broker Architecture: Upstox Implementation Spec

## Executive Summary

Concrete blueprint for adding Upstox as second broker. Architecture is 8/10 ready. Effort: 5-6 weeks, ~1,650 LOC adapter. Key insight: `Manager.brokerFactory` field (unused) already declared—wire it + add factory dispatch eliminates 80% overhead.

## 1. New Code Required

### broker/upstox/ (~1,670 LOC)
- factory.go (120 LOC) - Parallel zerodha/factory.go
- sdk_interface.go (80 LOC) - Abstract Upstox SDK
- sdk_adapter.go (140 LOC) - Thin adapter
- client.go (550 LOC) - All 31 broker.Client methods
- convert.go (400 LOC) - Upstox→broker.* mapping, instrument_key conversion
- retry.go (80 LOC) - Exponential backoff (copy from Zerodha)
- Tests: 300 LOC (80%+ coverage)

### kc/broker_credentials.go (~200 LOC new)
Abstract credential store: per-email per-broker instead of just per-email

### kc/session_service.go (~50 LOC modified)
Lines 136, 215, 249: Replace hardcoded `zerodha.New(kc.Client)` with broker selection via factory

### kc/manager.go (~30 LOC)
Wire unused `brokerFactory` field (line 32)

### oauth/handlers_oauth.go (~100 LOC)
Add broker router: Zerodha → Kite login, Upstox → Upstox login (https://api.upstox.com/v2/login/authorization/dialog)

### MCP Tools (~370 LOC)
- register_broker: Store new broker credentials
- list_brokers: Show all registered brokers
- switch_broker: Set preferred broker (default)
- remove_broker: Unregister

### Total: ~3,200 LOC (code + tests + docs)

## 2. Critical Data Gaps

Upstox uses instrument_key (NSE_EQ|INE002A01018) vs Zerodha's EXCHANGE:TRADINGSYMBOL.

### **BLOCKERS**
- **ConvertPosition**: NOT AVAILABLE in Upstox. Return ErrFeatureNotAvailable
- **Mutual Funds** (GetMFOrders, GetMFHoldings, GetMFSIPs): NOT EXPOSED. Return empty slices
- **Margin Calculators** (GetOrderMargins, GetBasketMargins, GetOrderCharges): NOT EXPOSED. Mock return available ≈ total

### **Key Endpoints**
| Method | Zerodha | Upstox | Note |
|--------|---------|--------|------|
| GetMargins | /user/margins | /user/get-funds-and-margin?segment=SEC | Call both SEC + COM |
| GetPositions | /portfolio/positions | /portfolio/positions | Map instrument_key→symbol |
| GetLTP | /quote/ltp | /market-quote/ltp | Max 500/call, 25 req/sec |
| GetHistoricalData | /instruments/historical/{token} | /market-quote/candlestick?interval=1m|5m|daily | Different interval format |
| PlaceOrder | POST /orders | POST /order/place-order | Need ISIN for instrument_key |
| ConvertPosition | POST /portfolio/positions | ❌ NOT AVAILABLE | BLOCKER |

### **Rate Limits**
- Zerodha: 10 req/sec per IP
- **Upstox: 25 req/sec per API key** (not global, API-specific)

### **Instrument Key Resolution**
Must map NSE:RELIANCE → NSE_EQ|INE002A01018. Upstox /instruments endpoint provides master. Recommend caching.

## 3. Session & OAuth Flow

### Session Creation
```
SessionService.createKiteSessionData(sessionID, email, brokerName?)
  ↓
credentialStore.GetPreferredBroker(email)  [if brokerName empty]
  ↓
brokerFactory.CreateWithToken(apiKey, accessToken)
  ↓
session.Broker = ZerodhaClient | UpstoxClient
```

Tools don't change—they call session.Broker.GetHoldings() (interface).

### OAuth Dispatch (Phase 5)
```
/oauth/authorize?broker=upstox
  ↓
redirectToBrokerLogin(broker, clientID, stateData)
  ↓
if broker == "zerodha": redirect to https://kite.zerodha.com/connect/login
if broker == "upstox": redirect to https://api.upstox.com/v2/login/authorization/dialog
```

Per https://upstox.com/developer/api-documentation/authentication/: OAuth 2.0 standard (PKCE via code_challenge).

## 4. Phased Rollout: 6 Weeks

| Week | Focus | LOC | Risk |
|------|-------|-----|------|
| 1 | Factory wiring + session routing | 350 | Low |
| 2–3 | Upstox adapter (client, convert, retry) | 1,670 | Medium |
| 4 | Credential abstraction + OAuth dispatch | 300 | Medium |
| 5 | MCP tools + dashboard widget | 470 | Low |
| 6 | Testing (E2E, regression), docs, hardening | 200 | Low |

## 5. Risk & Go/No-Go

| Risk | Severity | Mitigation |
|------|----------|-----------|
| Instrument key complexity | HIGH | Cache /instruments on first call |
| Rate limits under load | MEDIUM | Backpressure queue; test 50+ sessions |
| ConvertPosition gap | MEDIUM | Hide button in widget for Upstox |
| SDK maturity (v2 new) | MEDIUM | Community active; plan SDK bug patches |
| Token expiry | LOW | Per-broker refresh logic |

**Recommendation: GO**
- Defensive against Zerodha official MCP
- Prevents refactoring debt for future brokers (Angel One, Dhan)
- Architecture ready; 80% of work is credential abstraction (reusable)
- Effort well-scoped: 5-6 weeks, 1 engineer, ~3,200 LOC

## 6. Success Metrics (Post-Deployment)

✓ 80%+ coverage on broker/upstox/  
✓ 0 regression failures in Zerodha suite  
✓ register_broker, list_brokers tools live  
✓ Zerodha users see zero impact (default broker)  
✓ Upstox users complete onboarding without code changes  
✓ ConvertPosition, MF gaps documented + gracefully handled  

