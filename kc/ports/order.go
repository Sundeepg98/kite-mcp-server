package ports

import (
	"github.com/algo2go/kite-mcp-riskguard"
)

// OrderPort is the bounded-context contract for order-placement access.
//
// Order placement, modification, cancellation, GTT, and MF paths do not
// hang direct methods off *kc.Manager — they route through the CommandBus
// (see kc/manager_cqrs_register.go) and OrderService. The Manager-level
// surface that matters for orders is therefore:
//
//   - OrderSvc() *kc.OrderService — the focused order service (write-side)
//   - RiskGuard() *riskguard.Guard — pre-trade safety checks (may be nil)
//   - PaperEngine() — paper trading intercept (lives on PaperEngineProvider)
//
// Consumers should ask for the narrowest contract they need; this port
// groups the two Manager-level accessors a full order-execution caller
// reaches for. The concrete *OrderService return is preserved so call
// sites that need its whole method set (OrderService has 12+ methods
// itself) do not have to widen the port every time a new method is added
// downstream.
//
// Call sites that previously reached through *kc.Manager for orders:
//   - kc/manager_queries_remaining.go, manager_commands_orders.go
//   - mcp/order_tool.go, modify_order_tool.go, cancel_order_tool.go
//   - mcp/gtt_tool.go, mf_order_tool.go
// (all of these currently access the service through Manager accessors;
// no consumer migration is required because *Manager already satisfies
// this composite port — callers can swap the dependency type at leisure.)
//
// The concrete *kc.OrderService return type is used because wrapping it
// in a narrow interface right now would break unexposed fields that
// Phase D must redesign anyway; keeping it concrete here minimises the
// blast radius.
// Anchor 6 PR 6.8: OrderSvc() *kc.OrderService removed from this
// interface. Manager.OrderSvc() method was deleted alongside the
// rest of the per-service accessor cluster (PR 6.2 CredentialSvc,
// PR 6.4 SessionSvc, PR 6.6 PortfolioSvc, PR 6.10 AlertSvc, etc.).
// The OrderService is now reachable as a public field on *kc.Manager
// (the kc-root god-struct cleanup leaves direct field access until
// PR 6.15 final cleanup introduces narrower bounded ports). Empirical
// scope: zero non-test callers ever reached for OrderPort.OrderSvc()
// in production — the interface was a compile-time satisfaction
// pin without a runtime consumer.
type OrderPort interface {
	RiskGuard() *riskguard.Guard
}
