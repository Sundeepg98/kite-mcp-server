package kc

import (
	"github.com/zerodha/kite-mcp-server/broker/zerodha"
)

// KiteClientFactory creates Kite API clients. Inject a mock in tests by
// returning any zerodha.KiteSDK implementation (e.g. zerodha.MockKiteSDK)
// that replays canned responses without touching HTTP.
//
// This factory is used by background services (briefing, pnl snapshots,
// telegram bot) that run outside MCP tool handlers and therefore don't
// have access to a session-pinned broker. The return type is now the
// broker-owned zerodha.KiteSDK interface rather than the raw SDK
// *kiteconnect.Client. Collapsing the SDK type behind an interface was
// the residual Hexagonal-100 gap flagged by path-to-100-final:
// background services can now be exercised off-HTTP with the same mock
// the broker adapter uses, and the concrete kiteconnect.New call site
// is confined to broker/zerodha — the single-seam guarantee the
// hexagonal claim always promised.
type KiteClientFactory interface {
	NewClient(apiKey string) zerodha.KiteSDK
	NewClientWithToken(apiKey, accessToken string) zerodha.KiteSDK
}

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
