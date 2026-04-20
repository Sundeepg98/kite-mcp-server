package kc

import (
	"context"
	"fmt"
	"reflect"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
)

// registerSetupCommands wires CommandBus handlers for setup-related commands
// (CommandBus batch F): LoginCommand.
//
// OpenDashboard is intentionally NOT in this batch — it is annotated as a
// read-only tool (`mcp.WithReadOnlyHintAnnotation(true)`) and uses
// `cqrs.OpenDashboardQuery`, so it rides the QueryBus, not the CommandBus.
//
// The Manager itself satisfies usecases.SessionLoginURLProvider via its
// existing SessionLoginURL accessor, so no adapter struct is needed — we pass
// `m` directly as the narrow port.
func (m *Manager) registerSetupCommands() error {
	// --- Setup: LoginCommand ---
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.LoginCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.LoginCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewLoginUseCase(m, m.Logger)
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// --- Session: ClearSessionDataCommand ---
	// Round-5 Phase B (Sessions): direct manager.ClearSessionData(id) sites in
	// mcp/setup_tools.go route through this handler so every session-data
	// clear gets the bus's observability layer (LoggingMiddleware + future
	// audit). The Manager itself satisfies usecases.SessionDataClearer via its
	// existing ClearSessionData accessor, so no adapter is needed.
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.ClearSessionDataCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.ClearSessionDataCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewClearSessionDataUseCase(m, m.Logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}
	return nil
}
