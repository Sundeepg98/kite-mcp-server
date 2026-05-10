package kc

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"

	"github.com/algo2go/kite-mcp-alerts"
	"github.com/algo2go/kite-mcp-broker"
	"github.com/algo2go/kite-mcp-cqrs"
	"github.com/algo2go/kite-mcp-domain"
	"github.com/algo2go/kite-mcp-eventsourcing"
	"github.com/algo2go/kite-mcp-instruments"
	"github.com/algo2go/kite-mcp-riskguard"
	"github.com/algo2go/kite-mcp-ticker"
	"github.com/algo2go/kite-mcp-usecases"
	"github.com/algo2go/kite-mcp-users"
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

// AdminUserRegistrarDeps holds the dependencies for the user-lifecycle
// admin command handlers (suspend/activate/change-role). All deps default
// to closure-getters per the Tier 2.2 lesson (preserve laziness semantics
// at fixture-incomplete tests; eager dereference at registration time can
// change panic-reachability profiles).
type AdminUserRegistrarDeps struct {
	UserStore         *users.Store
	RiskGuardGetter   func() *riskguard.Guard      // may return nil; handler nil-safes
	SessionManager    *SessionRegistry             // may be nil at very-minimal fixtures
	DispatcherGetter  func() *domain.EventDispatcher
}

// registerAdminUserCommandsOnBus is the package-level pure-function
// registrar for user-lifecycle admin commands. Called from
// (m *Manager) registerAdminUserCommands which constructs deps from
// Manager fields.
func registerAdminUserCommandsOnBus(
	bus *cqrs.InMemoryBus,
	deps AdminUserRegistrarDeps,
	logger *slog.Logger,
) error {
	if err := bus.Register(reflect.TypeFor[cqrs.AdminSuspendUserCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.AdminSuspendUserCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if deps.UserStore == nil {
			return nil, fmt.Errorf("cqrs: user store not configured")
		}
		// Avoid passing typed-nil through an interface: if RiskGuard() is
		// nil, send the use case an untyped-nil so its `!= nil` guard fires
		// correctly. Same defence the account commands use.
		var rg usecases.RiskGuardService
		if deps.RiskGuardGetter != nil {
			if guard := deps.RiskGuardGetter(); guard != nil {
				rg = guard
			}
		}
		var dispatcher *domain.EventDispatcher
		if deps.DispatcherGetter != nil {
			dispatcher = deps.DispatcherGetter()
		}
		uc := usecases.NewAdminSuspendUserUseCase(
			deps.UserStore,
			rg,
			deps.SessionManager,
			dispatcher,
			logger,
		)
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := bus.Register(reflect.TypeFor[cqrs.AdminActivateUserCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.AdminActivateUserCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if deps.UserStore == nil {
			return nil, fmt.Errorf("cqrs: user store not configured")
		}
		uc := usecases.NewAdminActivateUserUseCase(deps.UserStore, logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := bus.Register(reflect.TypeFor[cqrs.AdminChangeRoleCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.AdminChangeRoleCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if deps.UserStore == nil {
			return nil, fmt.Errorf("cqrs: user store not configured")
		}
		uc := usecases.NewAdminChangeRoleUseCase(deps.UserStore, logger)
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}
	return nil
}

// registerAdminUserCommands delegates to the package-level pure-function
// registrar (Tier 2.3, mirrors Tier 2.2 OAuth pattern). Constructs deps
// from Manager fields with closure-getters preserving laziness.
func (m *Manager) registerAdminUserCommands() error {
	return registerAdminUserCommandsOnBus(m.commandBus, AdminUserRegistrarDeps{
		UserStore:        m.userStore,
		RiskGuardGetter:  m.RiskGuard,
		SessionManager:   m.sessionManager,
		DispatcherGetter: m.eventing.Dispatcher,
	}, m.Logger)
}

// --- Admin: risk guard (freeze/unfreeze user + global) ---------------------

// AdminRiskRegistrarDeps holds the dependencies for risk-guard admin
// command handlers (freeze/unfreeze user + global; 4 commands). Single
// dep — RiskGuardGetter — because every handler in this group requires
// the guard and errors out cleanly if it's nil.
type AdminRiskRegistrarDeps struct {
	RiskGuardGetter func() *riskguard.Guard // required at command-dispatch time
}

// registerAdminRiskCommandsOnBus is the package-level pure-function
// registrar for risk-guard admin commands.
func registerAdminRiskCommandsOnBus(
	bus *cqrs.InMemoryBus,
	deps AdminRiskRegistrarDeps,
	logger *slog.Logger,
) error {
	if err := bus.Register(reflect.TypeFor[cqrs.AdminFreezeUserCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.AdminFreezeUserCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if deps.RiskGuardGetter == nil {
			return nil, fmt.Errorf("cqrs: risk guard not configured")
		}
		guard := deps.RiskGuardGetter()
		if guard == nil {
			return nil, fmt.Errorf("cqrs: risk guard not configured")
		}
		uc := usecases.NewAdminFreezeUserUseCase(guard, logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := bus.Register(reflect.TypeFor[cqrs.AdminUnfreezeUserCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.AdminUnfreezeUserCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if deps.RiskGuardGetter == nil {
			return nil, fmt.Errorf("cqrs: risk guard not configured")
		}
		guard := deps.RiskGuardGetter()
		if guard == nil {
			return nil, fmt.Errorf("cqrs: risk guard not configured")
		}
		uc := usecases.NewAdminUnfreezeUserUseCase(guard, logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := bus.Register(reflect.TypeFor[cqrs.AdminFreezeGlobalCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.AdminFreezeGlobalCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if deps.RiskGuardGetter == nil {
			return nil, fmt.Errorf("cqrs: risk guard not configured")
		}
		guard := deps.RiskGuardGetter()
		if guard == nil {
			return nil, fmt.Errorf("cqrs: risk guard not configured")
		}
		uc := usecases.NewAdminFreezeGlobalUseCase(guard, logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := bus.Register(reflect.TypeFor[cqrs.AdminUnfreezeGlobalCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.AdminUnfreezeGlobalCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if deps.RiskGuardGetter == nil {
			return nil, fmt.Errorf("cqrs: risk guard not configured")
		}
		guard := deps.RiskGuardGetter()
		if guard == nil {
			return nil, fmt.Errorf("cqrs: risk guard not configured")
		}
		uc := usecases.NewAdminUnfreezeGlobalUseCase(guard, logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}
	return nil
}

// registerAdminRiskCommands delegates to the package-level pure-function
// registrar (Tier 2.3 slice 2/6).
func (m *Manager) registerAdminRiskCommands() error {
	return registerAdminRiskCommandsOnBus(m.commandBus, AdminRiskRegistrarDeps{
		RiskGuardGetter: m.RiskGuard,
	}, m.Logger)
}

// --- Alerts: create / delete / setup telegram -----------------------------

// adminBatchInstrumentResolver adapts *instruments.Manager to
// usecases.InstrumentResolver. It lives alongside the batch-C handler so
// the handler stays self-contained; the mcp layer has its own adapter of
// the same shape that is retained for mcp-internal use.
//
// Tier 2.3 slice 3/6: the adapter now reads from a closure-captured
// instruments getter rather than a *Manager back-pointer, so the
// Alerts registrar can be tested without a full Manager fixture.
type adminBatchInstrumentResolver struct {
	getInstruments func() *instruments.Manager
}

func (r *adminBatchInstrumentResolver) GetInstrumentToken(exchange, tradingsymbol string) (uint32, error) {
	if r.getInstruments == nil {
		return 0, fmt.Errorf("cqrs: instruments manager not configured")
	}
	im := r.getInstruments()
	if im == nil {
		return 0, fmt.Errorf("cqrs: instruments manager not configured")
	}
	inst, err := im.GetByTradingsymbol(exchange, tradingsymbol)
	if err != nil {
		return 0, err
	}
	return inst.InstrumentToken, nil
}

// AdminAlertsRegistrarDeps holds the dependencies for the alert-lifecycle
// admin commands (create/delete/composite/setup-telegram; 4 commands).
// All deps default to closure-getters per the Tier 2.2 lesson.
type AdminAlertsRegistrarDeps struct {
	AlertStore         *alerts.Store
	InstrumentsGetter  func() *instruments.Manager      // for adminBatchInstrumentResolver
	DispatcherGetter   func() *domain.EventDispatcher
	EventStoreGetter   func() *eventsourcing.EventStore
}

// registerAdminAlertsCommandsOnBus is the package-level pure-function
// registrar for alert-lifecycle admin commands.
func registerAdminAlertsCommandsOnBus(
	bus *cqrs.InMemoryBus,
	deps AdminAlertsRegistrarDeps,
	logger *slog.Logger,
) error {
	if err := bus.Register(reflect.TypeFor[cqrs.CreateAlertCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.CreateAlertCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if deps.AlertStore == nil {
			return nil, fmt.Errorf("cqrs: alert store not configured")
		}
		uc := usecases.NewCreateAlertUseCase(
			deps.AlertStore,
			&adminBatchInstrumentResolver{getInstruments: deps.InstrumentsGetter},
			logger,
		)
		if deps.DispatcherGetter != nil {
			if d := deps.DispatcherGetter(); d != nil {
				uc.SetEventDispatcher(d)
			}
		}
		// Phase C ES: audit-log appender so alert.created lands in domain_events
		// without going through dispatcher→persister (prevents double-emit).
		if deps.EventStoreGetter != nil {
			if es := deps.EventStoreGetter(); es != nil {
				uc.SetEventStore(es)
			}
		}
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := bus.Register(reflect.TypeFor[cqrs.DeleteAlertCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.DeleteAlertCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if deps.AlertStore == nil {
			return nil, fmt.Errorf("cqrs: alert store not configured")
		}
		uc := usecases.NewDeleteAlertUseCase(deps.AlertStore, logger)
		if deps.DispatcherGetter != nil {
			if d := deps.DispatcherGetter(); d != nil {
				uc.SetEventDispatcher(d)
			}
		}
		// Phase C ES: audit-log appender owns alert.deleted persistence.
		if deps.EventStoreGetter != nil {
			if es := deps.EventStoreGetter(); es != nil {
				uc.SetEventStore(es)
			}
		}
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// CreateCompositeAlertCommand — composite alert persistence wired per
	// the Option B design (shared alerts table with alert_type='composite').
	// Shares the same instrument resolver as single alerts.
	if err := bus.Register(reflect.TypeFor[cqrs.CreateCompositeAlertCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.CreateCompositeAlertCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if deps.AlertStore == nil {
			return nil, fmt.Errorf("cqrs: alert store not configured")
		}
		uc := usecases.NewCreateCompositeAlertUseCase(
			deps.AlertStore,
			&adminBatchInstrumentResolver{getInstruments: deps.InstrumentsGetter},
			logger,
		)
		// Phase C-Audit: composite alert.created event.
		if deps.EventStoreGetter != nil {
			if es := deps.EventStoreGetter(); es != nil {
				uc.SetEventStore(es)
			}
		}
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := bus.Register(reflect.TypeFor[cqrs.SetupTelegramCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.SetupTelegramCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if deps.AlertStore == nil {
			return nil, fmt.Errorf("cqrs: telegram (alert) store not configured")
		}
		uc := usecases.NewSetupTelegramUseCase(deps.AlertStore, logger)
		// ES: typed TelegramSubscribed/ChatBound dispatch for runtime
		// subscribers (projector etc.). Pattern mirrors watchlist
		// command-bus wiring (commit aeb3e8c).
		if deps.DispatcherGetter != nil {
			if d := deps.DispatcherGetter(); d != nil {
				uc.SetEventDispatcher(d)
			}
		}
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}
	return nil
}

// registerAlertCommands delegates to the package-level pure-function
// registrar (Tier 2.3 slice 3/6).
func (m *Manager) registerAlertCommands() error {
	return registerAdminAlertsCommandsOnBus(m.commandBus, AdminAlertsRegistrarDeps{
		AlertStore:        m.alertStore,
		InstrumentsGetter: func() *instruments.Manager { return m.Instruments },
		DispatcherGetter:  m.eventing.Dispatcher,
		EventStoreGetter:  m.eventing.Store,
	}, m.Logger)
}

// --- Mutual Funds: place / cancel order + SIP ------------------------------

// AdminMFRegistrarDeps holds the dependencies for mutual-fund admin
// commands (PlaceMFOrder, CancelMFOrder, PlaceMFSIP, CancelMFSIP — 4
// commands).
type AdminMFRegistrarDeps struct {
	SessionSvc       *SessionService
	DispatcherGetter func() *domain.EventDispatcher
	EventStoreGetter func() *eventsourcing.EventStore
}

// registerAdminMFCommandsOnBus is the package-level pure-function
// registrar for mutual-fund admin commands.
func registerAdminMFCommandsOnBus(
	bus *cqrs.InMemoryBus,
	deps AdminMFRegistrarDeps,
	logger *slog.Logger,
) error {
	if err := bus.Register(reflect.TypeFor[cqrs.PlaceMFOrderCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.PlaceMFOrderCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewPlaceMFOrderUseCase(deps.SessionSvc, logger)
		if deps.EventStoreGetter != nil {
			if es := deps.EventStoreGetter(); es != nil {
				uc.SetEventStore(es)
			}
		}
		if deps.DispatcherGetter != nil {
			if d := deps.DispatcherGetter(); d != nil {
				uc.SetEventDispatcher(d)
			}
		}
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := bus.Register(reflect.TypeFor[cqrs.CancelMFOrderCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.CancelMFOrderCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewCancelMFOrderUseCase(deps.SessionSvc, logger)
		if deps.EventStoreGetter != nil {
			if es := deps.EventStoreGetter(); es != nil {
				uc.SetEventStore(es)
			}
		}
		if deps.DispatcherGetter != nil {
			if d := deps.DispatcherGetter(); d != nil {
				uc.SetEventDispatcher(d)
			}
		}
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := bus.Register(reflect.TypeFor[cqrs.PlaceMFSIPCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.PlaceMFSIPCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewPlaceMFSIPUseCase(deps.SessionSvc, logger)
		if deps.EventStoreGetter != nil {
			if es := deps.EventStoreGetter(); es != nil {
				uc.SetEventStore(es)
			}
		}
		if deps.DispatcherGetter != nil {
			if d := deps.DispatcherGetter(); d != nil {
				uc.SetEventDispatcher(d)
			}
		}
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := bus.Register(reflect.TypeFor[cqrs.CancelMFSIPCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.CancelMFSIPCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewCancelMFSIPUseCase(deps.SessionSvc, logger)
		if deps.EventStoreGetter != nil {
			if es := deps.EventStoreGetter(); es != nil {
				uc.SetEventStore(es)
			}
		}
		if deps.DispatcherGetter != nil {
			if d := deps.DispatcherGetter(); d != nil {
				uc.SetEventDispatcher(d)
			}
		}
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}
	return nil
}

// registerMFCommands delegates to the package-level pure-function
// registrar (Tier 2.3 slice 4/6).
func (m *Manager) registerMFCommands() error {
	return registerAdminMFCommandsOnBus(m.commandBus, AdminMFRegistrarDeps{
		SessionSvc:       m.SessionSvc,
		DispatcherGetter: m.eventing.Dispatcher,
		EventStoreGetter: m.eventing.Store,
	}, m.Logger)
}

// --- Ticker: start / stop / subscribe / unsubscribe ------------------------

// AdminTickerRegistrarDeps holds the dependencies for ticker admin
// commands (Start/Stop/Subscribe/Unsubscribe; 4 commands). Single dep
// — TickerServiceGetter — because every handler in this group requires
// the ticker service and errors if nil.
type AdminTickerRegistrarDeps struct {
	TickerServiceGetter func() *ticker.Service // required at command-dispatch time
}

// registerAdminTickerCommandsOnBus is the package-level pure-function
// registrar for ticker admin commands.
func registerAdminTickerCommandsOnBus(
	bus *cqrs.InMemoryBus,
	deps AdminTickerRegistrarDeps,
	logger *slog.Logger,
) error {
	if err := bus.Register(reflect.TypeFor[cqrs.StartTickerCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.StartTickerCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if deps.TickerServiceGetter == nil {
			return nil, fmt.Errorf("cqrs: ticker service not configured")
		}
		ts := deps.TickerServiceGetter()
		if ts == nil {
			return nil, fmt.Errorf("cqrs: ticker service not configured")
		}
		uc := usecases.NewStartTickerUseCase(ts, logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := bus.Register(reflect.TypeFor[cqrs.StopTickerCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.StopTickerCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if deps.TickerServiceGetter == nil {
			return nil, fmt.Errorf("cqrs: ticker service not configured")
		}
		ts := deps.TickerServiceGetter()
		if ts == nil {
			return nil, fmt.Errorf("cqrs: ticker service not configured")
		}
		uc := usecases.NewStopTickerUseCase(ts, logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := bus.Register(reflect.TypeFor[cqrs.SubscribeInstrumentsCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.SubscribeInstrumentsCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if deps.TickerServiceGetter == nil {
			return nil, fmt.Errorf("cqrs: ticker service not configured")
		}
		ts := deps.TickerServiceGetter()
		if ts == nil {
			return nil, fmt.Errorf("cqrs: ticker service not configured")
		}
		uc := usecases.NewSubscribeInstrumentsUseCase(ts, logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := bus.Register(reflect.TypeFor[cqrs.UnsubscribeInstrumentsCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.UnsubscribeInstrumentsCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if deps.TickerServiceGetter == nil {
			return nil, fmt.Errorf("cqrs: ticker service not configured")
		}
		ts := deps.TickerServiceGetter()
		if ts == nil {
			return nil, fmt.Errorf("cqrs: ticker service not configured")
		}
		uc := usecases.NewUnsubscribeInstrumentsUseCase(ts, logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}
	return nil
}

// registerTickerCommands delegates to the package-level pure-function
// registrar (Tier 2.3 slice 5/6).
func (m *Manager) registerTickerCommands() error {
	return registerAdminTickerCommandsOnBus(m.commandBus, AdminTickerRegistrarDeps{
		TickerServiceGetter: func() *ticker.Service { return m.tickerService },
	}, m.Logger)
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

// AdminNativeAlertsRegistrarDeps holds the dependencies for native-alert
// admin commands (Place/Modify/Delete; 3 commands).
type AdminNativeAlertsRegistrarDeps struct {
	SessionSvc       *SessionService
	DispatcherGetter func() *domain.EventDispatcher
	EventStoreGetter func() *eventsourcing.EventStore
}

// resolveNativeAlertClientForBus looks up the Kite client for the given
// email via SessionSvc and returns an adapter that satisfies
// usecases.NativeAlertClient. Package-level helper used by the
// native-alert command handlers below; callers that hit a broker without
// native alert support receive a clear error.
func resolveNativeAlertClientForBus(sessionSvc *SessionService, email string) (usecases.NativeAlertClient, error) {
	if sessionSvc == nil {
		return nil, fmt.Errorf("cqrs: session service not configured")
	}
	client, err := sessionSvc.GetBrokerForEmail(email)
	if err != nil {
		return nil, fmt.Errorf("cqrs: resolve broker for %s: %w", email, err)
	}
	nac, ok := client.(broker.NativeAlertCapable)
	if !ok {
		return nil, fmt.Errorf("cqrs: broker does not support native alerts")
	}
	return &nativeAlertBusAdapter{nac: nac}, nil
}

// resolveNativeAlertClient is the Manager-method wrapper preserved for the
// case where Manager methods (other than the registrar) need to resolve
// native-alert clients. Currently a 1-line delegator to the package-level
// helper.
func (m *Manager) resolveNativeAlertClient(email string) (usecases.NativeAlertClient, error) {
	return resolveNativeAlertClientForBus(m.SessionSvc, email)
}

// registerAdminNativeAlertsCommandsOnBus is the package-level pure-function
// registrar for native-alert admin commands.
func registerAdminNativeAlertsCommandsOnBus(
	bus *cqrs.InMemoryBus,
	deps AdminNativeAlertsRegistrarDeps,
	logger *slog.Logger,
) error {
	if err := bus.Register(reflect.TypeFor[cqrs.PlaceNativeAlertCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.PlaceNativeAlertCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		client, err := resolveNativeAlertClientForBus(deps.SessionSvc, cmd.Email)
		if err != nil {
			return nil, err
		}
		uc := usecases.NewPlaceNativeAlertUseCase(logger)
		if deps.EventStoreGetter != nil {
			if es := deps.EventStoreGetter(); es != nil {
				uc.SetEventStore(es)
			}
		}
		if deps.DispatcherGetter != nil {
			if d := deps.DispatcherGetter(); d != nil {
				uc.SetEventDispatcher(d)
			}
		}
		return uc.Execute(ctx, client, cmd)
	}); err != nil {
		return err
	}

	if err := bus.Register(reflect.TypeFor[cqrs.ModifyNativeAlertCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.ModifyNativeAlertCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		client, err := resolveNativeAlertClientForBus(deps.SessionSvc, cmd.Email)
		if err != nil {
			return nil, err
		}
		uc := usecases.NewModifyNativeAlertUseCase(logger)
		if deps.EventStoreGetter != nil {
			if es := deps.EventStoreGetter(); es != nil {
				uc.SetEventStore(es)
			}
		}
		if deps.DispatcherGetter != nil {
			if d := deps.DispatcherGetter(); d != nil {
				uc.SetEventDispatcher(d)
			}
		}
		return uc.Execute(ctx, client, cmd)
	}); err != nil {
		return err
	}

	if err := bus.Register(reflect.TypeFor[cqrs.DeleteNativeAlertCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.DeleteNativeAlertCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		client, err := resolveNativeAlertClientForBus(deps.SessionSvc, cmd.Email)
		if err != nil {
			return nil, err
		}
		uc := usecases.NewDeleteNativeAlertUseCase(logger)
		if deps.EventStoreGetter != nil {
			if es := deps.EventStoreGetter(); es != nil {
				uc.SetEventStore(es)
			}
		}
		if deps.DispatcherGetter != nil {
			if d := deps.DispatcherGetter(); d != nil {
				uc.SetEventDispatcher(d)
			}
		}
		return nil, uc.Execute(ctx, client, cmd)
	}); err != nil {
		return err
	}
	return nil
}

// registerNativeAlertCommands delegates to the package-level pure-function
// registrar (Tier 2.3 slice 6/6).
func (m *Manager) registerNativeAlertCommands() error {
	return registerAdminNativeAlertsCommandsOnBus(m.commandBus, AdminNativeAlertsRegistrarDeps{
		SessionSvc:       m.SessionSvc,
		DispatcherGetter: m.eventing.Dispatcher,
		EventStoreGetter: m.eventing.Store,
	}, m.Logger)
}
