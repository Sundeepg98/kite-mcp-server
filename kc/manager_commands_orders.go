package kc

import (
	"context"
	"fmt"
	"reflect"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
)

// instrumentLookupAdapter wraps the concrete *instruments.Manager so it
// satisfies usecases.InstrumentLookup. The port wants Get(exchange, symbol)
// → (lotSize, tickSize, ok); the concrete manager exposes
// GetByID("EXCH:SYM") → (Instrument, error). This adapter bridges the two
// shapes so PlaceOrderUseCase can enforce domain.InstrumentRules (lot-size
// divisibility + tick-size alignment) in production without changing
// instruments.Manager's public API.
type instrumentLookupAdapter struct {
	mgr *instruments.Manager
}

// Get satisfies usecases.InstrumentLookup. Returns ok=false if the
// manager is nil, the instrument is unknown, or the metadata is
// unusable (lotSize <= 0). All three cases are treated by
// PlaceOrderUseCase as "skip lot/tick enforcement" rather than a hard
// failure, matching the off-hours / bootstrap contract.
//
// lotSize=0 is treated as "metadata unavailable" rather than a rule
// because domain.ValidateLotSize treats it as a config error — we'd
// rather let the broker reject a bad order than fail with a cryptic
// domain error on unpopulated instruments (test fixtures, pre-fetch).
func (a *instrumentLookupAdapter) Get(exchange, tradingsymbol string) (int, float64, bool) {
	if a.mgr == nil {
		return 0, 0, false
	}
	inst, err := a.mgr.GetByID(exchange + ":" + tradingsymbol)
	if err != nil || inst.LotSize <= 0 {
		return 0, 0, false
	}
	return inst.LotSize, inst.TickSize, true
}

// registerOrderCommands wires CommandBus handlers for write-side order,
// GTT, position, and trailing-stop commands (CommandBus batch B).
//
// Handlers build the use case lazily from the Manager's stores. Where the
// use case needs a broker.Client, the handler resolves it via
// resolverFromContext(ctx): the MCP tool layer attaches the session-pinned
// client via WithBroker before DispatchWithResult, so we re-use that
// already-resolved client instead of paying for another credential lookup.
// Handlers dispatched from tests without an attached broker transparently
// fall back to the Manager's SessionService.
func (m *Manager) registerOrderCommands() error {
	// --- Order: PlaceOrderCommand ---
	//
	// Wave D Slice D2: the use case is now startup-constructed by
	// initOrderUseCases (kc/manager_use_cases.go) and held on the
	// Manager. The handler is a thin dispatcher — type-asserts the
	// message and forwards to the pre-built use case. EventStore +
	// InstrumentLookup wiring moved to construction time. The
	// resolverFromContext / WithBroker hot-path optimization is no
	// longer applied for this command; broker resolution flows
	// through m.sessionSvc on every dispatch (one extra in-memory
	// session-cache lookup, ~100ns; see scoping doc §5).
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.PlaceOrderCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.PlaceOrderCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		return m.placeOrderUC.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// --- Order: ModifyOrderCommand ---
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.ModifyOrderCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.ModifyOrderCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		return m.modifyOrderUC.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// --- Order: CancelOrderCommand ---
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.CancelOrderCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.CancelOrderCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		return m.cancelOrderUC.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// --- GTT: PlaceGTTCommand ---
	//
	// Wave D Slice D3: GTT use cases hoisted to startup-once Manager
	// fields, same pattern as the order triple above. The event
	// dispatcher is wired post-construction via EventingService.SetDispatcher
	// when app/wire.go finishes its own setup.
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.PlaceGTTCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.PlaceGTTCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		return m.placeGTTUC.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// --- GTT: ModifyGTTCommand ---
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.ModifyGTTCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.ModifyGTTCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		return m.modifyGTTUC.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// --- GTT: DeleteGTTCommand ---
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.DeleteGTTCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.DeleteGTTCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		return m.deleteGTTUC.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// --- Position: ConvertPositionCommand ---
	// convert_position is unique in batch B: the existing MCP handler already
	// resolves through the Manager's SessionService rather than a pinned
	// broker, so we register it the same way — sessionSvc satisfies
	// usecases.BrokerResolver on its own.
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.ConvertPositionCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.ConvertPositionCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewConvertPositionUseCase(m.sessionSvc, m.Logger)
		if m.eventStore != nil {
			uc.SetEventStore(m.eventStore)
		}
		if m.eventDispatcher != nil {
			uc.SetEventDispatcher(m.eventDispatcher)
		}
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// --- Trailing stop: SetTrailingStopCommand ---
	// SetTrailingStop talks to TrailingStopManager, not a broker, so no
	// resolver needed. We still guard against nil manager because the
	// trailing-stop feature depends on SQLite persistence being wired in.
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.SetTrailingStopCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.SetTrailingStopCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if m.trailingStopMgr == nil {
			return nil, fmt.Errorf("cqrs: trailing stop manager not configured")
		}
		uc := usecases.NewSetTrailingStopUseCase(m.trailingStopMgr, m.Logger)
		if m.eventStore != nil {
			uc.SetEventStore(m.eventStore)
		}
		if m.eventDispatcher != nil {
			uc.SetEventDispatcher(m.eventDispatcher)
		}
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// --- Trailing stop: CancelTrailingStopCommand ---
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.CancelTrailingStopCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.CancelTrailingStopCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if m.trailingStopMgr == nil {
			return nil, fmt.Errorf("cqrs: trailing stop manager not configured")
		}
		uc := usecases.NewCancelTrailingStopUseCase(m.trailingStopMgr, m.Logger)
		if m.eventStore != nil {
			uc.SetEventStore(m.eventStore)
		}
		if m.eventDispatcher != nil {
			uc.SetEventDispatcher(m.eventDispatcher)
		}
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}
	return nil
}
