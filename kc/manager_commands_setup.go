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
func (m *Manager) registerSetupCommands() {
	// --- Setup: LoginCommand ---
	m.commandBus.Register(reflect.TypeOf(cqrs.LoginCommand{}), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.LoginCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewLoginUseCase(m, m.Logger)
		return uc.Execute(ctx, cmd)
	})
}
