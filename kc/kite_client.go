package kc

import (
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/broker/zerodha"
)

// KiteClientFactory creates Kite API clients. Inject a mock in tests by
// pointing the returned *kiteconnect.Client at an httptest server.
//
// This factory is used by background services (briefing, pnl snapshots,
// telegram bot) that run outside MCP tool handlers and therefore don't
// have access to a session-pinned broker. All three consumers still take
// *kiteconnect.Client directly; the honest type-layer consolidation
// (converting them to broker.Client) is multi-day follow-up work.
//
// For now this factory routes through broker/zerodha.NewKiteClient so
// the kiteconnect.New call site is exactly one in the whole codebase —
// matching the hexagonal-100 claim the path-to-100-final research said
// was a lie when there were two parallel factories.
type KiteClientFactory interface {
	NewClient(apiKey string) *kiteconnect.Client
	NewClientWithToken(apiKey, accessToken string) *kiteconnect.Client
}

// defaultKiteClientFactory is the production implementation. It
// delegates to broker/zerodha.NewKiteClient so every concrete SDK
// client — MCP tool path and background-service path alike —
// originates from the same seam.
type defaultKiteClientFactory struct{}

func (f *defaultKiteClientFactory) NewClient(apiKey string) *kiteconnect.Client {
	return zerodha.NewKiteClient(apiKey)
}

func (f *defaultKiteClientFactory) NewClientWithToken(apiKey, accessToken string) *kiteconnect.Client {
	kc := zerodha.NewKiteClient(apiKey)
	kc.SetAccessToken(accessToken)
	return kc
}
