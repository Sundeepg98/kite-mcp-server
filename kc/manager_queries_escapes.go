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
//   - GetPortfolioForWidgetQuery, GetActivityForWidgetQuery,
//     GetOrdersForWidgetQuery, GetAlertsForWidgetQuery
//     (mcp/ext_apps.go widget DataFuncs)
//   - ValidateLoginQuery, OpenDashboardQuery
//     (mcp/setup_tools.go Login pre-dispatch + OpenDashboard validate)
//
// Out of CQRS scope (not an escape):
//   - mcp/common.go WithTokenRefresh — a pre-dispatch session-validity
//     probe that runs inside WithSession's composition, before the handler
//     closure. The profile call here is infrastructure (is the token still
//     valid?) not a business-value read, analogous to auth or circuit
//     breaker middleware. Queries on QueryBus are reads for the *profile
//     tool*, *orders tool*, etc. — not for session validation. See the
//     function's doc comment in mcp/common.go for the long-form
//     architectural reasoning.
//
// Widget handlers resolve the audit store in a two-step fallback:
//  1. cqrs.WidgetAuditStoreFromContext — populated by the ext_apps
//     DataFuncs to honor a test-scoped store that isn't attached to the
//     Manager (the widget tests construct a local audit.Store and pass it
//     as a parameter; the bus must respect that).
//  2. m.AuditStoreConcrete() — production fallback when ctx carries no
//     explicit store (e.g. future non-widget callers of these queries).
//
// Called from Manager.registerCQRSHandlers, after the batch D remaining
// queries are registered.
func (m *Manager) registerEscapeQueries() error {
	// --- Margin queries (Wave D Slice D5: hoisted to startup-once) ---

	if err := m.queryBus.Register(reflect.TypeFor[cqrs.GetOrderMarginsQuery](), func(ctx context.Context, msg any) (any, error) {
		q := msg.(cqrs.GetOrderMarginsQuery)
		return m.getOrderMarginsUC.Execute(ctx, q)
	}); err != nil {
		return err
	}

	if err := m.queryBus.Register(reflect.TypeFor[cqrs.GetBasketMarginsQuery](), func(ctx context.Context, msg any) (any, error) {
		q := msg.(cqrs.GetBasketMarginsQuery)
		return m.getBasketMarginsUC.Execute(ctx, q)
	}); err != nil {
		return err
	}

	if err := m.queryBus.Register(reflect.TypeFor[cqrs.GetOrderChargesQuery](), func(ctx context.Context, msg any) (any, error) {
		q := msg.(cqrs.GetOrderChargesQuery)
		return m.getOrderChargesUC.Execute(ctx, q)
	}); err != nil {
		return err
	}

	// --- Widget queries (Wave D Slice D6) ---
	//
	// Portfolio + Alerts are hoisted to startup-once Manager fields.
	// Orders + Activity keep per-dispatch construction because their
	// audit-store dependency can be ctx-overridden for tests; see
	// manager_use_cases.go for the design rationale.

	if err := m.queryBus.Register(reflect.TypeFor[cqrs.GetPortfolioForWidgetQuery](), func(ctx context.Context, msg any) (any, error) {
		q := msg.(cqrs.GetPortfolioForWidgetQuery)
		return m.getPortfolioForWidgetUC.Execute(ctx, cqrs.GetWidgetPortfolioQuery{Email: q.Email})
	}); err != nil {
		return err
	}

	// Activity is NOT a Wave D site (no broker resolver) but stays per-
	// dispatch because the audit store can come from ctx (test contract).
	if err := m.queryBus.Register(reflect.TypeFor[cqrs.GetActivityForWidgetQuery](), func(ctx context.Context, msg any) (any, error) {
		q := msg.(cqrs.GetActivityForWidgetQuery)
		store := m.widgetAuditStoreFromCtxOrManager(ctx)
		if store == nil {
			return nil, nil
		}
		uc := usecases.NewGetActivityForWidgetUseCase(store, m.Logger)
		return uc.Execute(ctx, cqrs.GetWidgetActivityQuery{Email: q.Email})
	}); err != nil {
		return err
	}

	// Orders keeps per-dispatch construction because the audit store
	// dependency can be ctx-overridden (test-isolation contract via
	// cqrs.WithWidgetAuditStore). The broker resolver is m.sessionSvc
	// — the per-request optimization that previously rode on ctx was
	// removed in Slice D7.
	if err := m.queryBus.Register(reflect.TypeFor[cqrs.GetOrdersForWidgetQuery](), func(ctx context.Context, msg any) (any, error) {
		q := msg.(cqrs.GetOrdersForWidgetQuery)
		store := m.widgetAuditStoreFromCtxOrManager(ctx)
		if store == nil {
			return nil, nil
		}
		uc := usecases.NewGetOrdersForWidgetUseCase(m.sessionSvc, store, m.Logger)
		return uc.Execute(ctx, cqrs.GetWidgetOrdersQuery{Email: q.Email})
	}); err != nil {
		return err
	}

	// Alerts: hoisted (alertStore is a Manager field). When the
	// startup-time alertStore was nil (no DB / pre-init Manager), the
	// hoisted UC will be nil too — nil-result fallback matches the
	// pre-D6 handler contract.
	if err := m.queryBus.Register(reflect.TypeFor[cqrs.GetAlertsForWidgetQuery](), func(ctx context.Context, msg any) (any, error) {
		q := msg.(cqrs.GetAlertsForWidgetQuery)
		if m.getAlertsForWidgetUC == nil {
			return nil, nil
		}
		return m.getAlertsForWidgetUC.Execute(ctx, cqrs.GetWidgetAlertsQuery{Email: q.Email})
	}); err != nil {
		return err
	}

	// --- Setup validation queries ---
	//
	// ValidateLoginQuery routes the pre-dispatch Login validation through the
	// QueryBus. The real URL-generation happens via LoginCommand on the
	// CommandBus later in the same tool handler; this query is the validation
	// hop that runs before credential-side-effects so observability and
	// correlation wrap it uniformly with the rest of the bus surface.
	if err := m.queryBus.Register(reflect.TypeFor[cqrs.ValidateLoginQuery](), func(ctx context.Context, msg any) (any, error) {
		q := msg.(cqrs.ValidateLoginQuery)
		uc := usecases.NewLoginUseCase(m, m.Logger)
		// Reuse the LoginCommand validation surface so we share one rule set
		// with the CommandBus handler. A nil return means "valid".
		return nil, uc.Validate(ctx, cqrs.LoginCommand{
			Email:     q.Email,
			APIKey:    q.APIKey,
			APISecret: q.APISecret,
		})
	}); err != nil {
		return err
	}

	// OpenDashboardQuery routes the pre-resolution page validation through
	// the QueryBus. The URL construction itself remains in the tool handler
	// because it depends on infrastructure concerns (IsLocalMode, ExternalURL,
	// query-param composition) that sit above the use-case boundary.
	if err := m.queryBus.Register(reflect.TypeFor[cqrs.OpenDashboardQuery](), func(ctx context.Context, msg any) (any, error) {
		q := msg.(cqrs.OpenDashboardQuery)
		uc := usecases.NewOpenDashboardUseCase(m.Logger)
		return nil, uc.Validate(ctx, q)
	}); err != nil {
		return err
	}

	return nil
}

// widgetAuditStoreFromCtxOrManager returns the audit store attached to ctx
// by the ext_apps widget DataFuncs (to honor a test-scoped store), falling
// back to the Manager's attached audit store. Returns nil when neither is
// present; widget handlers short-circuit to a nil result so the upstream
// MCP App widget renders its empty state.
func (m *Manager) widgetAuditStoreFromCtxOrManager(ctx context.Context) usecases.WidgetAuditStore {
	if v := cqrs.WidgetAuditStoreFromContext(ctx); v != nil {
		if s, ok := v.(usecases.WidgetAuditStore); ok {
			return s
		}
	}
	if s := m.AuditStoreConcrete(); s != nil {
		// Return the concrete store which satisfies WidgetAuditStore.
		return s
	}
	return nil
}
