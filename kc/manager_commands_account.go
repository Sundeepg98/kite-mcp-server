package kc

import (
	"context"
	"fmt"
	"reflect"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
)

// registerAccountCommands wires CommandBus handlers for the Account, Watchlist,
// and Paper Trading domains (CommandBus batch A). Each handler constructs its
// use case lazily from the Manager's concrete stores, mirroring the Family
// pattern in registerCQRSHandlers(). Use cases are not deleted — handlers call
// them, keeping the single source of business logic.
func (m *Manager) registerAccountCommands() error {
	// --- Account: DeleteMyAccountCommand ---
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.DeleteMyAccountCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.DeleteMyAccountCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		// Nil-pointer check before boxing into interface — boxing a typed-nil
		// concrete into an interface produces a non-nil interface value, which
		// defeats the use case's `!= nil` guard. Assign only live stores.
		deps := usecases.AccountDependencies{}
		if m.credentialStore != nil {
			deps.CredentialStore = m.credentialStore
		}
		if m.tokenStore != nil {
			deps.TokenStore = m.tokenStore
		}
		if m.alertStore != nil {
			deps.AlertDeleter = m.alertStore
		}
		if m.watchlistStore != nil {
			deps.WatchlistStore = m.watchlistStore
		}
		if m.trailingStopMgr != nil {
			deps.TrailingStops = m.trailingStopMgr
		}
		if m.paperEngine != nil {
			deps.PaperEngine = m.paperEngine
		}
		if m.userStore != nil {
			deps.UserStore = m.userStore
		}
		if m.sessionManager != nil {
			deps.Sessions = m.sessionManager
		}
		uc := usecases.NewDeleteMyAccountUseCase(deps, m.Logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// --- Account: UpdateMyCredentialsCommand ---
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.UpdateMyCredentialsCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.UpdateMyCredentialsCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewUpdateMyCredentialsUseCase(m.credentialStore, m.tokenStore, m.Logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// --- Watchlist: CreateWatchlistCommand ---
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.CreateWatchlistCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.CreateWatchlistCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewCreateWatchlistUseCase(m.watchlistStore, m.Logger)
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// --- Watchlist: DeleteWatchlistCommand ---
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.DeleteWatchlistCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.DeleteWatchlistCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewDeleteWatchlistUseCase(m.watchlistStore, m.Logger)
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// --- Watchlist: AddToWatchlistCommand ---
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.AddToWatchlistCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.AddToWatchlistCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewAddToWatchlistUseCase(m.watchlistStore, m.Logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// --- Watchlist: RemoveFromWatchlistCommand ---
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.RemoveFromWatchlistCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.RemoveFromWatchlistCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewRemoveFromWatchlistUseCase(m.watchlistStore, m.Logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// --- Paper: PaperTradingToggleCommand ---
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.PaperTradingToggleCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.PaperTradingToggleCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if m.paperEngine == nil {
			return nil, fmt.Errorf("cqrs: paper engine not configured")
		}
		uc := usecases.NewPaperTradingToggleUseCase(m.paperEngine, m.Logger)
		return uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// --- Paper: PaperTradingResetCommand ---
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.PaperTradingResetCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.PaperTradingResetCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		if m.paperEngine == nil {
			return nil, fmt.Errorf("cqrs: paper engine not configured")
		}
		uc := usecases.NewPaperTradingResetUseCase(m.paperEngine, m.Logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}
	return nil
}
