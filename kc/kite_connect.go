package kc

import (
	"github.com/algo2go/kite-mcp-broker/zerodha"
)

// KiteConnect wraps the Kite Connect client.
//
// The Client field holds a zerodha.KiteSDK (interface) rather than a
// concrete *kiteconnect.Client so background services and tool handlers
// both consume the same hexagonal port — the broker-owned interface
// collapses the former two SDK construction sites (kc/kite_client.go
// and broker/zerodha/sdk_adapter.go) into one, and lets tests swap in
// zerodha.MockKiteSDK without touching HTTP.
//
// Anchor 6 PR 6.15 relocated this from kc/manager.go to keep manager.go
// focused on the constructor surface only.
type KiteConnect struct {
	// Client is the authenticated Kite SDK. Exported because 23+ tool handlers access it directly.
	Client zerodha.KiteSDK
}

// NewKiteConnect creates a new KiteConnect instance.
// All SDK instantiation routes through the KiteClientFactory interface.
func NewKiteConnect(apiKey string, factory ...KiteClientFactory) *KiteConnect {
	var f KiteClientFactory
	if len(factory) > 0 && factory[0] != nil {
		f = factory[0]
	} else {
		f = &defaultKiteClientFactory{}
	}
	return &KiteConnect{
		Client: f.NewClient(apiKey),
	}
}
