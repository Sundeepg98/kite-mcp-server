package kc

import (
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
)

// KiteClientFactory creates Kite API clients. Inject a mock in tests by
// pointing the returned *kiteconnect.Client at an httptest server.
type KiteClientFactory interface {
	NewClient(apiKey string) *kiteconnect.Client
	NewClientWithToken(apiKey, accessToken string) *kiteconnect.Client
}

// defaultKiteClientFactory is the production implementation that delegates to
// the real kiteconnect SDK.
type defaultKiteClientFactory struct{}

func (f *defaultKiteClientFactory) NewClient(apiKey string) *kiteconnect.Client {
	return kiteconnect.New(apiKey)
}

func (f *defaultKiteClientFactory) NewClientWithToken(apiKey, accessToken string) *kiteconnect.Client {
	kc := kiteconnect.New(apiKey)
	kc.SetAccessToken(accessToken)
	return kc
}
