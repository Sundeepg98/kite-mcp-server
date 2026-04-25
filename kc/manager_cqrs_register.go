package kc

import (
	"context"
	"fmt"
	"reflect"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
)

// registerCQRSHandlers wires use cases into the command/query buses. Called
// from New() so every Manager (including test managers) has a fully-routed bus.
// Returns an error on any duplicate registration — previously the bus panicked
// mid-startup, which made programmer mistakes surface as opaque process crashes.
//
// Extracted from manager.go in the SOLID-S split so the constructor sits
// alongside the struct definition and the (large) bus wiring lives next to
// the per-batch handler files (manager_commands_*.go, manager_queries_*.go).
// Behavior is unchanged — pure file move.
func (m *Manager) registerCQRSHandlers() error {
	// GetPortfolioQuery -> GetPortfolioUseCase
	portfolioUC := usecases.NewGetPortfolioUseCase(m.sessionSvc, m.Logger)
	if err := m.queryBus.Register(reflect.TypeFor[cqrs.GetPortfolioQuery](), func(ctx context.Context, msg any) (any, error) {
		return portfolioUC.Execute(ctx, msg.(cqrs.GetPortfolioQuery))
	}); err != nil {
		return err
	}

	// GetOrdersQuery -> GetOrdersUseCase, with optimistic projection fallback.
	//
	// When Kite returns a transient failure (rate limit, 503, timeout,
	// connection error — classified by isBrokerUnavailable), the handler
	// substitutes the aggregate-projection view of the caller's orders so
	// downstream tools get a best-effort answer instead of a hard failure.
	// This is the "full Aggregate Root pattern" unlock: the event-sourced
	// projection becomes a read-side source of truth when the broker is
	// unavailable, matching how papertrading already works.
	//
	// Auth errors (expired token, forbidden) and validation errors are
	// NOT caught by the fallback — those must propagate so users know to
	// re-authenticate. isBrokerUnavailable's trigger list is conservative
	// for this reason.
	ordersUC := usecases.NewGetOrdersUseCase(m.sessionSvc, m.Logger)
	if err := m.queryBus.Register(reflect.TypeFor[cqrs.GetOrdersQuery](), func(ctx context.Context, msg any) (any, error) {
		q := msg.(cqrs.GetOrdersQuery)
		orders, err := ordersUC.Execute(ctx, q)
		if err == nil {
			return orders, nil
		}
		if !isBrokerUnavailable(err) {
			return nil, err
		}
		fallback := m.projectionOrdersForEmail(q.Email)
		if len(fallback) == 0 {
			// No projection data to serve either — surface the original
			// broker error so the caller knows what's actually wrong.
			return nil, err
		}
		m.Logger.Warn("Serving orders from projection fallback (broker unavailable)",
			"email", q.Email,
			"broker_error", err.Error(),
			"projection_count", len(fallback),
		)
		return fallback, nil
	}); err != nil {
		return err
	}

	// GetOrderHistoryQuery -> GetOrderHistoryUseCase
	orderHistoryUC := usecases.NewGetOrderHistoryUseCase(m.sessionSvc, m.Logger)
	if err := m.queryBus.Register(reflect.TypeFor[cqrs.GetOrderHistoryQuery](), func(ctx context.Context, msg any) (any, error) {
		return orderHistoryUC.Execute(ctx, msg.(cqrs.GetOrderHistoryQuery))
	}); err != nil {
		return err
	}

	// GetOrderTradesQuery -> GetOrderTradesUseCase
	orderTradesUC := usecases.NewGetOrderTradesUseCase(m.sessionSvc, m.Logger)
	if err := m.queryBus.Register(reflect.TypeFor[cqrs.GetOrderTradesQuery](), func(ctx context.Context, msg any) (any, error) {
		return orderTradesUC.Execute(ctx, msg.(cqrs.GetOrderTradesQuery))
	}); err != nil {
		return err
	}

	// GetProfileQuery -> GetProfileUseCase
	profileUC := usecases.NewGetProfileUseCase(m.sessionSvc, m.Logger)
	if err := m.queryBus.Register(reflect.TypeFor[cqrs.GetProfileQuery](), func(ctx context.Context, msg any) (any, error) {
		return profileUC.Execute(ctx, msg.(cqrs.GetProfileQuery))
	}); err != nil {
		return err
	}

	// GetMarginsQuery -> GetMarginsUseCase
	marginsUC := usecases.NewGetMarginsUseCase(m.sessionSvc, m.Logger)
	if err := m.queryBus.Register(reflect.TypeFor[cqrs.GetMarginsQuery](), func(ctx context.Context, msg any) (any, error) {
		return marginsUC.Execute(ctx, msg.(cqrs.GetMarginsQuery))
	}); err != nil {
		return err
	}

	// GetTradesQuery -> GetTradesUseCase
	tradesUC := usecases.NewGetTradesUseCase(m.sessionSvc, m.Logger)
	if err := m.queryBus.Register(reflect.TypeFor[cqrs.GetTradesQuery](), func(ctx context.Context, msg any) (any, error) {
		return tradesUC.Execute(ctx, msg.(cqrs.GetTradesQuery))
	}); err != nil {
		return err
	}

	// GetGTTsQuery -> GetGTTsUseCase
	gttsUC := usecases.NewGetGTTsUseCase(m.sessionSvc, m.Logger)
	if err := m.queryBus.Register(reflect.TypeFor[cqrs.GetGTTsQuery](), func(ctx context.Context, msg any) (any, error) {
		return gttsUC.Execute(ctx, msg.(cqrs.GetGTTsQuery))
	}); err != nil {
		return err
	}

	// Market data queries take an email alongside the query (per usecase signature).
	// We carry email via a dedicated envelope type so the bus can dispatch uniformly.
	ltpUC := usecases.NewGetLTPUseCase(m.sessionSvc, m.Logger)
	if err := m.queryBus.Register(reflect.TypeFor[cqrs.GetLTPQuery](), func(ctx context.Context, msg any) (any, error) {
		q := msg.(cqrs.GetLTPQuery)
		return ltpUC.Execute(ctx, q.Email, q)
	}); err != nil {
		return err
	}

	ohlcUC := usecases.NewGetOHLCUseCase(m.sessionSvc, m.Logger)
	if err := m.queryBus.Register(reflect.TypeFor[cqrs.GetOHLCQuery](), func(ctx context.Context, msg any) (any, error) {
		q := msg.(cqrs.GetOHLCQuery)
		return ohlcUC.Execute(ctx, q.Email, q)
	}); err != nil {
		return err
	}

	quotesUC := usecases.NewGetQuotesUseCase(m.sessionSvc, m.Logger)
	if err := m.queryBus.Register(reflect.TypeFor[cqrs.GetQuotesQuery](), func(ctx context.Context, msg any) (any, error) {
		q := msg.(cqrs.GetQuotesQuery)
		return quotesUC.Execute(ctx, q.Email, q)
	}); err != nil {
		return err
	}

	histUC := usecases.NewGetHistoricalDataUseCase(m.sessionSvc, m.Logger)
	if err := m.queryBus.Register(reflect.TypeFor[cqrs.GetHistoricalDataQuery](), func(ctx context.Context, msg any) (any, error) {
		q := msg.(cqrs.GetHistoricalDataQuery)
		return histUC.Execute(ctx, q.Email, q)
	}); err != nil {
		return err
	}

	// --- Family CQRS wiring (first real CommandBus dispatch) ---
	// FamilyService is assigned via SetFamilyService() after wire.go builds it,
	// so it's nil at this point. Handlers resolve m.familyService lazily per
	// dispatch, returning an error when the service is still unconfigured.
	if err := m.queryBus.Register(reflect.TypeFor[cqrs.AdminListFamilyQuery](), func(ctx context.Context, msg any) (any, error) {
		if m.familyService == nil {
			return nil, fmt.Errorf("cqrs: family service not configured")
		}
		uc := usecases.NewAdminListFamilyUseCase(m.familyService, m.invitationStore, m.Logger)
		return uc.Execute(ctx, msg.(cqrs.AdminListFamilyQuery))
	}); err != nil {
		return err
	}

	if err := m.commandBus.Register(reflect.TypeFor[cqrs.AdminInviteFamilyMemberCommand](), func(ctx context.Context, msg any) (any, error) {
		if m.familyService == nil {
			return nil, fmt.Errorf("cqrs: family service not configured")
		}
		uc := usecases.NewAdminInviteFamilyMemberUseCase(m.familyService, m.invitationStore, m.eventing.Dispatcher(), m.Logger)
		return uc.Execute(ctx, msg.(cqrs.AdminInviteFamilyMemberCommand))
	}); err != nil {
		return err
	}

	if err := m.commandBus.Register(reflect.TypeFor[cqrs.AdminRemoveFamilyMemberCommand](), func(ctx context.Context, msg any) (any, error) {
		if m.familyService == nil {
			return nil, fmt.Errorf("cqrs: family service not configured")
		}
		uc := usecases.NewAdminRemoveFamilyMemberUseCase(m.familyService, m.eventing.Dispatcher(), m.Logger)
		return uc.Execute(ctx, msg.(cqrs.AdminRemoveFamilyMemberCommand))
	}); err != nil {
		return err
	}

	// GetOrderProjectionQuery -> read-side Projector lookup.
	// The projector is in-process and fed by the domain event dispatcher.
	if err := m.queryBus.Register(reflect.TypeFor[cqrs.GetOrderProjectionQuery](), func(ctx context.Context, msg any) (any, error) {
		q := msg.(cqrs.GetOrderProjectionQuery)
		if m.projector == nil {
			return nil, fmt.Errorf("cqrs: projector not configured")
		}
		agg, ok := m.projector.GetOrder(q.OrderID)
		if !ok {
			return cqrs.OrderProjectionResult{OrderID: q.OrderID, Found: false}, nil
		}
		return orderAggregateToProjectionResult(agg), nil
	}); err != nil {
		return err
	}

	// GetOrderHistoryReconstitutedQuery -> replay persisted domain events.
	// Unlike the in-process Projector (lost on restart), this reads the
	// append-only EventStore and reconstitutes the order lifecycle from the
	// persisted log. First production caller of LoadOrderFromEvents.
	if err := m.queryBus.Register(reflect.TypeFor[cqrs.GetOrderHistoryReconstitutedQuery](), func(ctx context.Context, msg any) (any, error) {
		q := msg.(cqrs.GetOrderHistoryReconstitutedQuery)
		if m.eventStore == nil {
			return nil, fmt.Errorf("cqrs: event store not configured")
		}
		events, err := m.eventStore.LoadEvents(q.OrderID)
		if err != nil {
			return nil, fmt.Errorf("cqrs: load events for %s: %w", q.OrderID, err)
		}
		if len(events) == 0 {
			return cqrs.OrderHistoryResult{OrderID: q.OrderID, Found: false, States: []cqrs.OrderStateSnapshot{}}, nil
		}
		return reconstituteOrderHistory(q.OrderID, events)
	}); err != nil {
		return err
	}

	// GetPositionHistoryReconstitutedQuery -> replay persisted position events
	// keyed by the natural (email, exchange, symbol, product) tuple. First
	// production caller of LoadPositionFromEvents. Unlike orders/alerts where
	// the aggregate ID is the order or alert ID, positions have no broker-
	// assigned unique ID so we use PositionAggregateID() to join open and
	// close events for the same user-instrument-product.
	if err := m.queryBus.Register(reflect.TypeFor[cqrs.GetPositionHistoryReconstitutedQuery](), func(ctx context.Context, msg any) (any, error) {
		q := msg.(cqrs.GetPositionHistoryReconstitutedQuery)
		if m.eventStore == nil {
			return nil, fmt.Errorf("cqrs: event store not configured")
		}
		aggregateID := domain.PositionAggregateID(q.Email, domain.NewInstrumentKey(q.Exchange, q.Tradingsymbol), q.Product)
		events, err := m.eventStore.LoadEvents(aggregateID)
		if err != nil {
			return nil, fmt.Errorf("cqrs: load events for %s: %w", aggregateID, err)
		}
		if len(events) == 0 {
			return cqrs.PositionHistoryResult{AggregateID: aggregateID, Found: false, States: []cqrs.PositionStateSnapshot{}}, nil
		}
		return reconstitutePositionHistory(aggregateID, events)
	}); err != nil {
		return err
	}

	// GetAlertHistoryReconstitutedQuery -> replay persisted alert events.
	// Solves the "did my alert fire?" problem when Telegram DMs drop — the
	// event log is the immutable source of truth. First production caller of
	// LoadAlertFromEvents (previously only used in round-trip tests).
	if err := m.queryBus.Register(reflect.TypeFor[cqrs.GetAlertHistoryReconstitutedQuery](), func(ctx context.Context, msg any) (any, error) {
		q := msg.(cqrs.GetAlertHistoryReconstitutedQuery)
		if m.eventStore == nil {
			return nil, fmt.Errorf("cqrs: event store not configured")
		}
		events, err := m.eventStore.LoadEvents(q.AlertID)
		if err != nil {
			return nil, fmt.Errorf("cqrs: load events for %s: %w", q.AlertID, err)
		}
		if len(events) == 0 {
			return cqrs.AlertHistoryResult{AlertID: q.AlertID, Found: false, States: []cqrs.AlertStateSnapshot{}}, nil
		}
		return reconstituteAlertHistory(q.AlertID, events)
	}); err != nil {
		return err
	}

	// --- CommandBus batch A: Account + Watchlist + Paper writes (STEP 8) ---
	if err := m.registerAccountCommands(); err != nil {
		return err
	}

	// --- CommandBus batch B: Order + GTT + Position + Trailing writes (STEP 9) ---
	if err := m.registerOrderCommands(); err != nil {
		return err
	}

	// --- CommandBus batch C: Admin + Alerts + MF + Ticker + Native alerts (STEP 10) ---
	if err := m.registerAdminCommands(); err != nil {
		return err
	}

	// --- CommandBus batch E: exit_tools (close_position, close_all_positions) (STEP 13) ---
	if err := m.registerExitCommands(); err != nil {
		return err
	}

	// --- CommandBus batch F: setup_tools (login) (STEP 14) ---
	if err := m.registerSetupCommands(); err != nil {
		return err
	}

	// --- CommandBus batch G: OAuth/login bridge (Block 1 CQRS round-up) ---
	// Replaces 8 direct store mutations in app/adapters.go (kiteExchanger
	// Adapter and clientPersisterAdapter) with bus-routed commands so every
	// write hits LoggingMiddleware uniformly.
	if err := m.registerOAuthBridgeCommands(); err != nil {
		return err
	}

	// --- QueryBus batch D: remaining read tool migrations ---
	if err := m.registerRemainingQueries(); err != nil {
		return err
	}

	// --- QueryBus escape-hatch migration (path-to-100 final research) ---
	// Margin queries + widget DataFunc queries that had struct types but no
	// bus handlers — callers were dispatching directly via usecases.NewXxx.
	if err := m.registerEscapeQueries(); err != nil {
		return err
	}
	return nil
}
