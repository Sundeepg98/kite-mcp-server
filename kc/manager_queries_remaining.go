package kc

import (
	"context"
	"fmt"
	"reflect"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
)

// registerRemainingQueries wires the 22 read tools migrated in batch D into
// the QueryBus. It is called from registerCQRSHandlers so every Manager
// gets these handlers regardless of how it was constructed.
//
// The split-file layout exists to avoid merge conflicts with parallel CQRS
// batches editing manager.go / registerCQRSHandlers directly.
func (m *Manager) registerRemainingQueries() error {
	// --- Watchlist queries ---

	if err := m.queryBus.Register(reflect.TypeOf(cqrs.GetWatchlistQuery{}), func(ctx context.Context, msg any) (any, error) {
		if m.watchlistStore == nil {
			return nil, fmt.Errorf("cqrs: watchlist store not configured")
		}
		uc := usecases.NewGetWatchlistUseCase(m.watchlistStore, m.Logger)
		return uc.Execute(ctx, msg.(cqrs.GetWatchlistQuery))
	}); err != nil {
		return err
	}

	if err := m.queryBus.Register(reflect.TypeOf(cqrs.ListWatchlistsQuery{}), func(ctx context.Context, msg any) (any, error) {
		if m.watchlistStore == nil {
			return nil, fmt.Errorf("cqrs: watchlist store not configured")
		}
		uc := usecases.NewListWatchlistsUseCase(m.watchlistStore, m.Logger)
		return uc.Execute(ctx, msg.(cqrs.ListWatchlistsQuery))
	}); err != nil {
		return err
	}

	// --- Alert queries ---

	// GetAlertsQuery is shared with the legacy list_alerts tool; the handler
	// above (in registerCQRSHandlers) may not exist in batch D's parallel
	// world, so we register defensively here. Register is last-write-wins on
	// the reflect type key, matching the existing bus behavior.
	if err := m.queryBus.Register(reflect.TypeOf(cqrs.GetAlertsQuery{}), func(ctx context.Context, msg any) (any, error) {
		if m.alertStore == nil {
			return nil, fmt.Errorf("cqrs: alert store not configured")
		}
		uc := usecases.NewListAlertsUseCase(m.alertStore, m.Logger)
		return uc.Execute(ctx, msg.(cqrs.GetAlertsQuery))
	}); err != nil {
		return err
	}

	// --- Native alert queries (session-scoped NativeAlertClient via ctx) ---

	if err := m.queryBus.Register(reflect.TypeOf(cqrs.ListNativeAlertsQuery{}), func(ctx context.Context, msg any) (any, error) {
		raw := cqrs.NativeAlertClientFromContext(ctx)
		if raw == nil {
			return nil, fmt.Errorf("cqrs: native alert client not attached to context")
		}
		client, ok := raw.(usecases.NativeAlertClient)
		if !ok {
			return nil, fmt.Errorf("cqrs: native alert client has wrong type %T", raw)
		}
		uc := usecases.NewListNativeAlertsUseCase(m.Logger)
		return uc.Execute(ctx, client, msg.(cqrs.ListNativeAlertsQuery))
	}); err != nil {
		return err
	}

	if err := m.queryBus.Register(reflect.TypeOf(cqrs.GetNativeAlertHistoryQuery{}), func(ctx context.Context, msg any) (any, error) {
		raw := cqrs.NativeAlertClientFromContext(ctx)
		if raw == nil {
			return nil, fmt.Errorf("cqrs: native alert client not attached to context")
		}
		client, ok := raw.(usecases.NativeAlertClient)
		if !ok {
			return nil, fmt.Errorf("cqrs: native alert client has wrong type %T", raw)
		}
		uc := usecases.NewGetNativeAlertHistoryUseCase(m.Logger)
		return uc.Execute(ctx, client, msg.(cqrs.GetNativeAlertHistoryQuery))
	}); err != nil {
		return err
	}

	// --- Mutual fund queries ---

	if err := m.queryBus.Register(reflect.TypeOf(cqrs.GetMFHoldingsQuery{}), func(ctx context.Context, msg any) (any, error) {
		uc := usecases.NewGetMFHoldingsUseCase(m.sessionSvc, m.Logger)
		return uc.Execute(ctx, msg.(cqrs.GetMFHoldingsQuery))
	}); err != nil {
		return err
	}

	if err := m.queryBus.Register(reflect.TypeOf(cqrs.GetMFOrdersQuery{}), func(ctx context.Context, msg any) (any, error) {
		uc := usecases.NewGetMFOrdersUseCase(m.sessionSvc, m.Logger)
		return uc.Execute(ctx, msg.(cqrs.GetMFOrdersQuery))
	}); err != nil {
		return err
	}

	if err := m.queryBus.Register(reflect.TypeOf(cqrs.GetMFSIPsQuery{}), func(ctx context.Context, msg any) (any, error) {
		uc := usecases.NewGetMFSIPsUseCase(m.sessionSvc, m.Logger)
		return uc.Execute(ctx, msg.(cqrs.GetMFSIPsQuery))
	}); err != nil {
		return err
	}

	// --- Admin queries (risk + users) ---
	// AdminListUsersQuery / AdminGetUserQuery are reused from existing defs;
	// AdminGetRiskStatusQuery is the closest match for the "risk status" read.

	if err := m.queryBus.Register(reflect.TypeOf(cqrs.AdminGetRiskStatusQuery{}), func(ctx context.Context, msg any) (any, error) {
		if m.riskGuard == nil {
			return nil, fmt.Errorf("cqrs: risk guard not configured")
		}
		uc := usecases.NewAdminGetRiskStatusUseCase(m.riskGuard, m.Logger)
		return uc.Execute(ctx, msg.(cqrs.AdminGetRiskStatusQuery))
	}); err != nil {
		return err
	}

	if err := m.queryBus.Register(reflect.TypeOf(cqrs.AdminListUsersQuery{}), func(ctx context.Context, msg any) (any, error) {
		if m.userStore == nil {
			return nil, fmt.Errorf("cqrs: user store not configured")
		}
		uc := usecases.NewAdminListUsersUseCase(m.userStore, m.Logger)
		return uc.Execute(ctx, msg.(cqrs.AdminListUsersQuery))
	}); err != nil {
		return err
	}

	if err := m.queryBus.Register(reflect.TypeOf(cqrs.AdminGetUserQuery{}), func(ctx context.Context, msg any) (any, error) {
		if m.userStore == nil {
			return nil, fmt.Errorf("cqrs: user store not configured")
		}
		uc := usecases.NewAdminGetUserUseCase(m.userStore, m.riskGuard, m.Logger)
		return uc.Execute(ctx, msg.(cqrs.AdminGetUserQuery))
	}); err != nil {
		return err
	}

	// --- Observability ---

	if err := m.queryBus.Register(reflect.TypeOf(cqrs.ServerMetricsQuery{}), func(ctx context.Context, msg any) (any, error) {
		if m.auditStore == nil {
			return nil, fmt.Errorf("cqrs: audit store not configured")
		}
		uc := usecases.NewServerMetricsUseCase(m.auditStore, m.Logger)
		return uc.Execute(ctx, msg.(cqrs.ServerMetricsQuery))
	}); err != nil {
		return err
	}

	// --- PnL ---

	if err := m.queryBus.Register(reflect.TypeOf(cqrs.GetPnLJournalQuery{}), func(ctx context.Context, msg any) (any, error) {
		svc := m.PnLService()
		if svc == nil {
			return nil, fmt.Errorf("cqrs: pnl service not configured")
		}
		uc := usecases.NewGetPnLJournalUseCase(svc, m.Logger)
		return uc.Execute(ctx, msg.(cqrs.GetPnLJournalQuery))
	}); err != nil {
		return err
	}

	// --- Trading context + pre-trade (BrokerResolver via sessionSvc) ---

	if err := m.queryBus.Register(reflect.TypeOf(cqrs.TradingContextQuery{}), func(ctx context.Context, msg any) (any, error) {
		uc := usecases.NewTradingContextUseCase(m.sessionSvc, m.Logger)
		return uc.Execute(ctx, msg.(cqrs.TradingContextQuery))
	}); err != nil {
		return err
	}

	if err := m.queryBus.Register(reflect.TypeOf(cqrs.PreTradeCheckQuery{}), func(ctx context.Context, msg any) (any, error) {
		uc := usecases.NewPreTradeCheckUseCase(m.sessionSvc, m.Logger)
		return uc.Execute(ctx, msg.(cqrs.PreTradeCheckQuery))
	}); err != nil {
		return err
	}

	// --- Paper trading status ---

	if err := m.queryBus.Register(reflect.TypeOf(cqrs.PaperTradingStatusQuery{}), func(ctx context.Context, msg any) (any, error) {
		if m.paperEngine == nil {
			return nil, fmt.Errorf("cqrs: paper engine not configured")
		}
		uc := usecases.NewPaperTradingStatusUseCase(m.paperEngine, m.Logger)
		return uc.Execute(ctx, msg.(cqrs.PaperTradingStatusQuery))
	}); err != nil {
		return err
	}

	// --- Trailing stops ---

	if err := m.queryBus.Register(reflect.TypeOf(cqrs.ListTrailingStopsQuery{}), func(ctx context.Context, msg any) (any, error) {
		if m.trailingStopMgr == nil {
			return nil, fmt.Errorf("cqrs: trailing stop manager not configured")
		}
		uc := usecases.NewListTrailingStopsUseCase(m.trailingStopMgr, m.Logger)
		return uc.Execute(ctx, msg.(cqrs.ListTrailingStopsQuery))
	}); err != nil {
		return err
	}

	// --- Ticker status ---

	if err := m.queryBus.Register(reflect.TypeOf(cqrs.TickerStatusQuery{}), func(ctx context.Context, msg any) (any, error) {
		if m.tickerService == nil {
			return nil, fmt.Errorf("cqrs: ticker service not configured")
		}
		uc := usecases.NewTickerStatusUseCase(m.tickerService, m.Logger)
		return uc.Execute(ctx, msg.(cqrs.TickerStatusQuery))
	}); err != nil {
		return err
	}
	return nil
}
