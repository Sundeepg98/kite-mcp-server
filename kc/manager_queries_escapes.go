package kc

import (
	"context"
	"reflect"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
)

// registerEscapeQueries wires the remaining direct-usecase call sites
// discovered in the path-to-100-final research into the QueryBus. Before
// this file, these queries had struct types defined in kc/cqrs/queries.go
// but no bus handler registered, so every caller was dispatching directly
// via `usecases.NewXxx(...).Execute(ctx, query)` — invisible to the
// bus-level observability, riskguard, billing, and elicitation layers.
//
// Covered here:
//   - GetOrderMarginsQuery, GetBasketMarginsQuery, GetOrderChargesQuery
//     (margin_tools.go)
//
// Not covered — intentionally left as direct calls:
//   - mcp/common.go:88 — WithTokenRefresh middleware helper, hot path that
//     runs before every tool dispatch; adding bus dispatch adds latency to
//     every call for no observability win.
//   - mcp/setup_tools.go:269 — LoginUseCase.Validate() pre-dispatch check
//     (its own comment explains the pattern: pure validation before the
//     real CommandBus dispatch later in the same handler).
//   - mcp/setup_tools.go:455 — OpenDashboard is already a Query via the
//     earlier CQRS migration; the direct call here is inside a redirect
//     flow that runs synchronously in HTTP, not a tool handler.
//   - mcp/ext_apps.go × 4 widget DataFuncs — take auditStore as an explicit
//     caller parameter for test isolation; bus dispatch would have to
//     resolve the store off the Manager, breaking the test contract.
//     Documented in ext_apps.go above the DataFunc definitions.
//
// Called from Manager.registerCQRSHandlers, after the batch D remaining
// queries are registered.
func (m *Manager) registerEscapeQueries() error {
	// --- Margin queries ---

	if err := m.queryBus.Register(reflect.TypeOf(cqrs.GetOrderMarginsQuery{}), func(ctx context.Context, msg any) (any, error) {
		q := msg.(cqrs.GetOrderMarginsQuery)
		uc := usecases.NewGetOrderMarginsUseCase(m.resolverFromContext(ctx), m.Logger)
		return uc.Execute(ctx, q)
	}); err != nil {
		return err
	}

	if err := m.queryBus.Register(reflect.TypeOf(cqrs.GetBasketMarginsQuery{}), func(ctx context.Context, msg any) (any, error) {
		q := msg.(cqrs.GetBasketMarginsQuery)
		uc := usecases.NewGetBasketMarginsUseCase(m.resolverFromContext(ctx), m.Logger)
		return uc.Execute(ctx, q)
	}); err != nil {
		return err
	}

	if err := m.queryBus.Register(reflect.TypeOf(cqrs.GetOrderChargesQuery{}), func(ctx context.Context, msg any) (any, error) {
		q := msg.(cqrs.GetOrderChargesQuery)
		uc := usecases.NewGetOrderChargesUseCase(m.resolverFromContext(ctx), m.Logger)
		return uc.Execute(ctx, q)
	}); err != nil {
		return err
	}
	return nil
}
