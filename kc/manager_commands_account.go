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
			deps.CredentialStore = &credentialStoreWriterAdapter{store: m.credentialStore}
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
		if m.eventStore != nil {
			uc.SetEventStore(m.eventStore)
		}
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
		// credentialStoreAdapter bridges the concrete *KiteCredentialStore.Set(email,
		// *KiteCredentialEntry) signature to the usecases.CredentialUpdater port's
		// Set(email, apiKey, apiSecret string) signature. Keeps usecases free of
		// kc-internal types.
		credAdapter := &credentialStoreWriterAdapter{store: m.credentialStore}
		uc := usecases.NewUpdateMyCredentialsUseCase(credAdapter, m.tokenStore, m.Logger)
		if m.eventStore != nil {
			uc.SetEventStore(m.eventStore)
		}
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// --- Account: RevokeCredentialsCommand ---
	// Phase B-Audit #25: narrow credential + cached-token revoke for the
	// dashboard credential DELETE and admin force-revoke endpoints.
	// Distinct from DeleteMyAccountCommand (which also tears down alerts/
	// watchlists/paper-trading and marks offboarded) — use when the intent
	// is strictly "cut Kite access" while preserving account state.
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.RevokeCredentialsCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.RevokeCredentialsCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		credAdapter := &credentialStoreWriterAdapter{store: m.credentialStore}
		uc := usecases.NewRevokeCredentialsUseCase(credAdapter, m.tokenStore, m.Logger)
		if m.eventStore != nil {
			uc.SetEventStore(m.eventStore)
		}
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// --- Account: InvalidateTokenCommand ---
	// Round-5 Phase B: direct manager.TokenStore().Delete(email) sites in
	// mcp/setup_tools.go route through this handler so every token-invalidation
	// gets the bus's observability layer (LoggingMiddleware + future audit).
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.InvalidateTokenCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.InvalidateTokenCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewInvalidateTokenUseCase(m.tokenStore, m.Logger)
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
		if m.eventStore != nil {
			uc.SetEventStore(m.eventStore)
		}
		// ES pilot: typed WatchlistCreatedEvent dispatch for runtime
		// subscribers (projector etc.). Audit persistence stays on the
		// SetEventStore direct path; wire.go does NOT subscribe the
		// persister for watchlist.* event types (would double-write).
		if m.eventDispatcher != nil {
			uc.SetEventDispatcher(m.eventDispatcher)
		}
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

	// --- Watchlist: AddToWatchlistCommand ---
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.AddToWatchlistCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.AddToWatchlistCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewAddToWatchlistUseCase(m.watchlistStore, m.Logger)
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

	// --- Watchlist: RemoveFromWatchlistCommand ---
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.RemoveFromWatchlistCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.RemoveFromWatchlistCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewRemoveFromWatchlistUseCase(m.watchlistStore, m.Logger)
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

// credentialStoreWriterAdapter adapts the concrete *KiteCredentialStore to the
// usecases.CredentialUpdater port. The port's Set(email, apiKey, apiSecret
// string) signature takes primitive strings so use cases stay decoupled from
// kc-internal types (kc.KiteCredentialEntry). The underlying store's Set
// takes a *KiteCredentialEntry; the adapter constructs one.
//
// Delete passes through unchanged. Only Set needs the signature bridge.
type credentialStoreWriterAdapter struct {
	store *KiteCredentialStore
}

func (a *credentialStoreWriterAdapter) Delete(email string) {
	if a.store == nil {
		return
	}
	a.store.Delete(email)
}

func (a *credentialStoreWriterAdapter) Set(email, apiKey, apiSecret string) {
	if a.store == nil {
		return
	}
	a.store.Set(email, &KiteCredentialEntry{APIKey: apiKey, APISecret: apiSecret})
}

// Has reports whether a credential entry already exists for email. Used by
// UpdateMyCredentialsUseCase to distinguish first-time registration
// (CredentialRegisteredEvent) from rotation (CredentialRotatedEvent).
// Nil-safe — a nil underlying store is treated as "no prior entry".
func (a *credentialStoreWriterAdapter) Has(email string) bool {
	if a.store == nil {
		return false
	}
	_, ok := a.store.Get(email)
	return ok
}
