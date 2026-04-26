package mcp

import "github.com/zerodha/kite-mcp-server/kc"

// OrderDepsFields is the order-context subset of ToolHandlerDeps:
// risk-guard pre-trade checks, broker-client resolution per email,
// paper-trading interception, and the domain-event dispatcher (used for
// OrderPlaced/Filled emission downstream of the place_order pipeline).
//
// Investment K — see session_deps.go for rationale.
type OrderDepsFields struct {
	RiskGuard      kc.RiskGuardProvider
	BrokerResolver kc.BrokerResolverProvider
	Paper          kc.PaperEngineProvider
	Events         kc.EventDispatcherProvider
}

func newOrderDeps(manager *kc.Manager) OrderDepsFields {
	return OrderDepsFields{
		RiskGuard:      manager,
		BrokerResolver: manager,
		Paper:          manager,
		Events:         manager,
	}
}
