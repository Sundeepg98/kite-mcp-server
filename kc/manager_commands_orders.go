package kc

import (
	"context"
	"fmt"
	"reflect"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
)

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
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.PlaceOrderCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.PlaceOrderCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewPlaceOrderUseCase(
			m.resolverFromContext(ctx),
			m.riskGuard,
			m.eventing.Dispatcher(),
			m.Logger,
		)
		// Phase C ES: direct audit-log append on order.placed.
		if m.eventStore != nil {
			uc.SetEventStore(m.eventStore)
		}
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// --- Order: ModifyOrderCommand ---
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.ModifyOrderCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.ModifyOrderCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewModifyOrderUseCase(
			m.resolverFromContext(ctx),
			m.riskGuard,
			m.eventing.Dispatcher(),
			m.Logger,
		)
		// Phase C ES: direct audit-log append on order.modified.
		if m.eventStore != nil {
			uc.SetEventStore(m.eventStore)
		}
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// --- Order: CancelOrderCommand ---
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.CancelOrderCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.CancelOrderCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewCancelOrderUseCase(
			m.resolverFromContext(ctx),
			m.eventing.Dispatcher(),
			m.Logger,
		)
		// Phase C ES: direct audit-log append on order.cancelled.
		if m.eventStore != nil {
			uc.SetEventStore(m.eventStore)
		}
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// --- GTT: PlaceGTTCommand ---
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.PlaceGTTCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.PlaceGTTCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewPlaceGTTUseCase(m.resolverFromContext(ctx), m.Logger)
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// --- GTT: ModifyGTTCommand ---
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.ModifyGTTCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.ModifyGTTCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewModifyGTTUseCase(m.resolverFromContext(ctx), m.Logger)
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// --- GTT: DeleteGTTCommand ---
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.DeleteGTTCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.DeleteGTTCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewDeleteGTTUseCase(m.resolverFromContext(ctx), m.Logger)
		return uc.Execute(ctx, cmd)
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
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}
	return nil
}
