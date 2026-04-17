package kc

import (
	"context"
	"fmt"
	"reflect"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
)

// registerExitCommands wires CommandBus handlers for the position-exit
// commands (CommandBus batch E): close_position and close_all_positions.
//
// Both handlers use resolverFromContext(ctx): the MCP tool layer attaches
// the session-pinned broker client via WithBroker before DispatchWithResult,
// so we re-use it instead of paying for another credential lookup. Tests that
// dispatch without an attached broker fall back to the Manager's
// SessionService transparently.
func (m *Manager) registerExitCommands() error {
	// --- Exit: ClosePositionCommand ---
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.ClosePositionCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.ClosePositionCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewClosePositionUseCase(
			m.resolverFromContext(ctx),
			m.riskGuard,
			m.eventing.Dispatcher(),
			m.Logger,
		)
		return uc.ExecuteCommand(ctx, cmd)
	}); err != nil {
		return err
	}

	// --- Exit: CloseAllPositionsCommand ---
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.CloseAllPositionsCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.CloseAllPositionsCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewCloseAllPositionsUseCase(
			m.resolverFromContext(ctx),
			m.riskGuard,
			m.eventing.Dispatcher(),
			m.Logger,
		)
		return uc.ExecuteCommand(ctx, cmd)
	}); err != nil {
		return err
	}
	return nil
}
