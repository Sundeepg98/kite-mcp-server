package kc

import (
	"context"
	"fmt"
	"reflect"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// registerExitCommands wires CommandBus handlers for the position-exit
// commands (CommandBus batch E): close_position and close_all_positions.
//
// Wave D Slice D4: use cases are now startup-constructed by
// initOrderUseCases (kc/manager_use_cases.go) and held on the Manager.
// The handler is a thin dispatcher — no per-request resolver lookup,
// no per-request use case construction. Broker resolution flows through
// m.sessionSvc on every dispatch (one in-memory session-cache lookup,
// ~100ns; see .research/wave-d-resolver-refactor-plan.md §5).
func (m *Manager) registerExitCommands() error {
	// --- Exit: ClosePositionCommand ---
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.ClosePositionCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.ClosePositionCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		return m.closePositionUC.ExecuteCommand(ctx, cmd)
	}); err != nil {
		return err
	}

	// --- Exit: CloseAllPositionsCommand ---
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.CloseAllPositionsCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.CloseAllPositionsCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		return m.closeAllPositionsUC.ExecuteCommand(ctx, cmd)
	}); err != nil {
		return err
	}
	return nil
}
