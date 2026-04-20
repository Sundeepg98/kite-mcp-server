package kc

import (
	"context"
	"fmt"
	"reflect"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
)

// registerAdminCommands wires CommandBus handlers for the Admin (user +
// risk), Alerts, Mutual Funds, Ticker, and Native Alerts domains
// (CommandBus batch C — STEP 10). Each handler constructs its use case
// lazily from the Manager's concrete stores/services, mirroring the Family
// and Account patterns. Use cases are not deleted — handlers call them,
// keeping the single source of business logic.
func (m *Manager) registerAdminCommands() error {
	if err := m.registerAdminUserCommands(); err != nil {
		return err
	}
	if err := m.registerAdminRiskCommands(); err != nil {
		return err
	}
	if err := m.registerAlertCommands(); err != nil {
		return err
	}
	if err := m.registerMFCommands(); err != nil {
		return err
	}
	if err := m.registerTickerCommands(); err != nil {
		return err
	}
	if err := m.registerNativeAlertCommands(); err != nil {
		return err
	}
	return nil
}

// --- Admin: user lifecycle (suspend/activate/change-role) ------------------

func (m *Manager) registerAdminUserCommands() error {
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.AdminSuspendUserCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.AdminSuspendUserCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if m.userStore == nil {
			return nil, fmt.Errorf("cqrs: user store not configured")
		}
		uc := usecases.NewAdminSuspendUserUseCase(
			m.userStore,
			m.RiskGuard(),
			m.sessionManager,
			m.eventing.Dispatcher(),
			m.Logger,
		)
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := m.commandBus.Register(reflect.TypeFor[cqrs.AdminActivateUserCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.AdminActivateUserCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if m.userStore == nil {
			return nil, fmt.Errorf("cqrs: user store not configured")
		}
		uc := usecases.NewAdminActivateUserUseCase(m.userStore, m.Logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := m.commandBus.Register(reflect.TypeFor[cqrs.AdminChangeRoleCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.AdminChangeRoleCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if m.userStore == nil {
			return nil, fmt.Errorf("cqrs: user store not configured")
		}
		uc := usecases.NewAdminChangeRoleUseCase(m.userStore, m.Logger)
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}
	return nil
}

// --- Admin: risk guard (freeze/unfreeze user + global) ---------------------

func (m *Manager) registerAdminRiskCommands() error {
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.AdminFreezeUserCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.AdminFreezeUserCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		guard := m.RiskGuard()
		if guard == nil {
			return nil, fmt.Errorf("cqrs: risk guard not configured")
		}
		uc := usecases.NewAdminFreezeUserUseCase(guard, m.Logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := m.commandBus.Register(reflect.TypeFor[cqrs.AdminUnfreezeUserCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.AdminUnfreezeUserCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		guard := m.RiskGuard()
		if guard == nil {
			return nil, fmt.Errorf("cqrs: risk guard not configured")
		}
		uc := usecases.NewAdminUnfreezeUserUseCase(guard, m.Logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := m.commandBus.Register(reflect.TypeFor[cqrs.AdminFreezeGlobalCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.AdminFreezeGlobalCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		guard := m.RiskGuard()
		if guard == nil {
			return nil, fmt.Errorf("cqrs: risk guard not configured")
		}
		uc := usecases.NewAdminFreezeGlobalUseCase(guard, m.Logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := m.commandBus.Register(reflect.TypeFor[cqrs.AdminUnfreezeGlobalCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.AdminUnfreezeGlobalCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		guard := m.RiskGuard()
		if guard == nil {
			return nil, fmt.Errorf("cqrs: risk guard not configured")
		}
		uc := usecases.NewAdminUnfreezeGlobalUseCase(guard, m.Logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}
	return nil
}

// --- Alerts: create / delete / setup telegram -----------------------------

// adminBatchInstrumentResolver adapts *instruments.Manager to
// usecases.InstrumentResolver. It lives alongside the batch-C handler so
// the handler stays self-contained; the mcp layer has its own adapter of
// the same shape that is retained for mcp-internal use.
type adminBatchInstrumentResolver struct {
	m *Manager
}

func (r *adminBatchInstrumentResolver) GetInstrumentToken(exchange, tradingsymbol string) (uint32, error) {
	if r.m == nil || r.m.Instruments == nil {
		return 0, fmt.Errorf("cqrs: instruments manager not configured")
	}
	inst, err := r.m.Instruments.GetByTradingsymbol(exchange, tradingsymbol)
	if err != nil {
		return 0, err
	}
	return inst.InstrumentToken, nil
}

func (m *Manager) registerAlertCommands() error {
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.CreateAlertCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.CreateAlertCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if m.alertStore == nil {
			return nil, fmt.Errorf("cqrs: alert store not configured")
		}
		uc := usecases.NewCreateAlertUseCase(
			m.alertStore,
			&adminBatchInstrumentResolver{m: m},
			m.Logger,
		)
		if m.eventDispatcher != nil {
			uc.SetEventDispatcher(m.eventDispatcher)
		}
		// Phase C ES: audit-log appender so alert.created lands in domain_events
		// without going through dispatcher→persister (prevents double-emit).
		if m.eventStore != nil {
			uc.SetEventStore(m.eventStore)
		}
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := m.commandBus.Register(reflect.TypeFor[cqrs.DeleteAlertCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.DeleteAlertCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if m.alertStore == nil {
			return nil, fmt.Errorf("cqrs: alert store not configured")
		}
		uc := usecases.NewDeleteAlertUseCase(m.alertStore, m.Logger)
		if m.eventDispatcher != nil {
			uc.SetEventDispatcher(m.eventDispatcher)
		}
		// Phase C ES: audit-log appender owns alert.deleted persistence.
		if m.eventStore != nil {
			uc.SetEventStore(m.eventStore)
		}
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// CreateCompositeAlertCommand — composite alert persistence wired per
	// the Option B design (shared alerts table with alert_type='composite').
	// Shares the same instrument resolver as single alerts.
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.CreateCompositeAlertCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.CreateCompositeAlertCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if m.alertStore == nil {
			return nil, fmt.Errorf("cqrs: alert store not configured")
		}
		uc := usecases.NewCreateCompositeAlertUseCase(
			m.alertStore,
			&adminBatchInstrumentResolver{m: m},
			m.Logger,
		)
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := m.commandBus.Register(reflect.TypeFor[cqrs.SetupTelegramCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.SetupTelegramCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if m.alertStore == nil {
			return nil, fmt.Errorf("cqrs: telegram (alert) store not configured")
		}
		uc := usecases.NewSetupTelegramUseCase(m.alertStore, m.Logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}
	return nil
}

// --- Mutual Funds: place / cancel order + SIP ------------------------------

func (m *Manager) registerMFCommands() error {
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.PlaceMFOrderCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.PlaceMFOrderCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewPlaceMFOrderUseCase(m.SessionSvc(), m.Logger)
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := m.commandBus.Register(reflect.TypeFor[cqrs.CancelMFOrderCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.CancelMFOrderCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewCancelMFOrderUseCase(m.SessionSvc(), m.Logger)
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := m.commandBus.Register(reflect.TypeFor[cqrs.PlaceMFSIPCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.PlaceMFSIPCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewPlaceMFSIPUseCase(m.SessionSvc(), m.Logger)
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := m.commandBus.Register(reflect.TypeFor[cqrs.CancelMFSIPCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.CancelMFSIPCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewCancelMFSIPUseCase(m.SessionSvc(), m.Logger)
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}
	return nil
}

// --- Ticker: start / stop / subscribe / unsubscribe ------------------------

func (m *Manager) registerTickerCommands() error {
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.StartTickerCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.StartTickerCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if m.tickerService == nil {
			return nil, fmt.Errorf("cqrs: ticker service not configured")
		}
		uc := usecases.NewStartTickerUseCase(m.tickerService, m.Logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := m.commandBus.Register(reflect.TypeFor[cqrs.StopTickerCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.StopTickerCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if m.tickerService == nil {
			return nil, fmt.Errorf("cqrs: ticker service not configured")
		}
		uc := usecases.NewStopTickerUseCase(m.tickerService, m.Logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := m.commandBus.Register(reflect.TypeFor[cqrs.SubscribeInstrumentsCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.SubscribeInstrumentsCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if m.tickerService == nil {
			return nil, fmt.Errorf("cqrs: ticker service not configured")
		}
		uc := usecases.NewSubscribeInstrumentsUseCase(m.tickerService, m.Logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := m.commandBus.Register(reflect.TypeFor[cqrs.UnsubscribeInstrumentsCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.UnsubscribeInstrumentsCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if m.tickerService == nil {
			return nil, fmt.Errorf("cqrs: ticker service not configured")
		}
		uc := usecases.NewUnsubscribeInstrumentsUseCase(m.tickerService, m.Logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}
	return nil
}

// --- Native Alerts: place / modify / delete --------------------------------

// nativeAlertBusAdapter bridges broker.NativeAlertCapable to
// usecases.NativeAlertClient. It mirrors the mcp-layer adapter in
// mcp/native_alert_tools.go — duplicated here so the bus handler stays
// self-contained and does not depend on mcp package code.
type nativeAlertBusAdapter struct {
	nac broker.NativeAlertCapable
}

func (a *nativeAlertBusAdapter) CreateAlert(params any) (any, error) {
	p, ok := params.(broker.NativeAlertParams)
	if !ok {
		return nil, fmt.Errorf("cqrs: native alert params must be broker.NativeAlertParams, got %T", params)
	}
	return a.nac.CreateNativeAlert(p)
}

func (a *nativeAlertBusAdapter) ModifyAlert(uuid string, params any) (any, error) {
	p, ok := params.(broker.NativeAlertParams)
	if !ok {
		return nil, fmt.Errorf("cqrs: native alert params must be broker.NativeAlertParams, got %T", params)
	}
	return a.nac.ModifyNativeAlert(uuid, p)
}

func (a *nativeAlertBusAdapter) DeleteAlerts(uuids ...string) error {
	return a.nac.DeleteNativeAlerts(uuids...)
}

func (a *nativeAlertBusAdapter) GetAlerts(filters map[string]string) (any, error) {
	return a.nac.GetNativeAlerts(filters)
}

func (a *nativeAlertBusAdapter) GetAlertHistory(uuid string) (any, error) {
	return a.nac.GetNativeAlertHistory(uuid)
}

// resolveNativeAlertClient looks up the Kite client for the given email and
// returns an adapter that satisfies usecases.NativeAlertClient. Callers that
// hit a broker without native alert support receive a clear error.
func (m *Manager) resolveNativeAlertClient(email string) (usecases.NativeAlertClient, error) {
	client, err := m.SessionSvc().GetBrokerForEmail(email)
	if err != nil {
		return nil, fmt.Errorf("cqrs: resolve broker for %s: %w", email, err)
	}
	nac, ok := client.(broker.NativeAlertCapable)
	if !ok {
		return nil, fmt.Errorf("cqrs: broker does not support native alerts")
	}
	return &nativeAlertBusAdapter{nac: nac}, nil
}

func (m *Manager) registerNativeAlertCommands() error {
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.PlaceNativeAlertCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.PlaceNativeAlertCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		client, err := m.resolveNativeAlertClient(cmd.Email)
		if err != nil {
			return nil, err
		}
		uc := usecases.NewPlaceNativeAlertUseCase(m.Logger)
		return uc.Execute(ctx, client, cmd)
	}); err != nil {
		return err
	}

	if err := m.commandBus.Register(reflect.TypeFor[cqrs.ModifyNativeAlertCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.ModifyNativeAlertCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		client, err := m.resolveNativeAlertClient(cmd.Email)
		if err != nil {
			return nil, err
		}
		uc := usecases.NewModifyNativeAlertUseCase(m.Logger)
		return uc.Execute(ctx, client, cmd)
	}); err != nil {
		return err
	}

	if err := m.commandBus.Register(reflect.TypeFor[cqrs.DeleteNativeAlertCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.DeleteNativeAlertCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		client, err := m.resolveNativeAlertClient(cmd.Email)
		if err != nil {
			return nil, err
		}
		uc := usecases.NewDeleteNativeAlertUseCase(m.Logger)
		return nil, uc.Execute(ctx, client, cmd)
	}); err != nil {
		return err
	}
	return nil
}
