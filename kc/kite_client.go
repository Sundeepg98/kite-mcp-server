package kc

import (
	"github.com/algo2go/kite-mcp-broker/zerodha"
)

// KiteClientFactory creates Kite API clients. Inject a mock in tests by
// returning any zerodha.KiteSDK implementation (e.g. zerodha.MockKiteSDK)
// that replays canned responses without touching HTTP.
//
// This factory is used by background services (briefing, pnl snapshots,
// telegram bot) that run outside MCP tool handlers and therefore don't
// have access to a session-pinned broker. The return type is the
// broker-owned zerodha.KiteSDK interface, NOT the raw SDK
// *kiteconnect.Client — the concrete kiteconnect.New call site is
// confined to broker/zerodha (the single-seam guarantee that the
// hexagonal-100 claim always promised).
//
// F4 consolidation (Phase B/D close-out): canonical declaration moved
// to broker/zerodha (commit-this). kc.KiteClientFactory is now a Go
// type alias preserving the historical name + import path while
// pointing at the single source of truth. kc/telegram.KiteClientFactory
// got the same alias treatment. kc/alerts.KiteClientFactory stays as a
// narrow 1-method subset (intentional ISP narrowness — briefing only
// needs NewClientWithToken).
type KiteClientFactory = zerodha.KiteClientFactory

// defaultKiteClientFactory is the production implementation. It
// delegates to broker/zerodha.NewKiteSDK so every SDK client — MCP
// tool path and background-service path alike — originates from the
// same seam. Returning zerodha.KiteSDK (an interface) means consumers
// depend on the port, not on *kiteconnect.Client directly.
type defaultKiteClientFactory struct{}

func (f *defaultKiteClientFactory) NewClient(apiKey string) zerodha.KiteSDK {
	return zerodha.NewKiteSDK(apiKey)
}

func (f *defaultKiteClientFactory) NewClientWithToken(apiKey, accessToken string) zerodha.KiteSDK {
	sdk := zerodha.NewKiteSDK(apiKey)
	sdk.SetAccessToken(accessToken)
	return sdk
}
