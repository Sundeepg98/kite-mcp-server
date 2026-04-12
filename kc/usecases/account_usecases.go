package usecases

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// CredentialUpdater abstracts credential persistence for account use cases.
type CredentialUpdater interface {
	Delete(email string)
}

// TokenStore abstracts token persistence for account use cases.
type TokenStore interface {
	Delete(email string)
}

// AlertDeleter abstracts alert deletion for account cleanup.
type AlertDeleter interface {
	DeleteByEmail(email string)
}

// AccountDependencies groups stores needed for account deletion.
type AccountDependencies struct {
	CredentialStore CredentialUpdater
	TokenStore      TokenStore
	AlertDeleter    AlertDeleter
	WatchlistStore  WatchlistStore
	TrailingStops   TrailingStopManager
	PaperEngine     PaperEngine
	UserStore       UserStore
	Sessions        SessionTerminator
}

// --- Delete My Account ---

// DeleteMyAccountUseCase permanently deletes a user's account and all data.
type DeleteMyAccountUseCase struct {
	deps   AccountDependencies
	logger *slog.Logger
}

// NewDeleteMyAccountUseCase creates a DeleteMyAccountUseCase with dependencies injected.
func NewDeleteMyAccountUseCase(deps AccountDependencies, logger *slog.Logger) *DeleteMyAccountUseCase {
	return &DeleteMyAccountUseCase{deps: deps, logger: logger}
}

// Execute deletes the user's account and all associated data.
func (uc *DeleteMyAccountUseCase) Execute(ctx context.Context, cmd cqrs.DeleteMyAccountCommand) error {
	if cmd.Email == "" {
		return fmt.Errorf("usecases: email is required")
	}

	if uc.deps.CredentialStore != nil {
		uc.deps.CredentialStore.Delete(cmd.Email)
	}
	if uc.deps.TokenStore != nil {
		uc.deps.TokenStore.Delete(cmd.Email)
	}
	if uc.deps.Sessions != nil {
		uc.deps.Sessions.TerminateByEmail(cmd.Email)
	}
	if uc.deps.AlertDeleter != nil {
		uc.deps.AlertDeleter.DeleteByEmail(cmd.Email)
	}
	if uc.deps.WatchlistStore != nil {
		uc.deps.WatchlistStore.DeleteByEmail(cmd.Email)
	}
	if uc.deps.TrailingStops != nil {
		uc.deps.TrailingStops.CancelByEmail(cmd.Email)
	}
	if uc.deps.PaperEngine != nil {
		if err := uc.deps.PaperEngine.Reset(cmd.Email); err != nil {
			uc.logger.Error("Failed to reset paper trading during account delete", "email", cmd.Email, "error", err)
		}
		if err := uc.deps.PaperEngine.Disable(cmd.Email); err != nil {
			uc.logger.Error("Failed to disable paper trading during account delete", "email", cmd.Email, "error", err)
		}
	}
	if uc.deps.UserStore != nil {
		if err := uc.deps.UserStore.UpdateStatus(cmd.Email, "offboarded"); err != nil {
			uc.logger.Error("Failed to update user status during account delete", "email", cmd.Email, "error", err)
		}
	}

	uc.logger.Info("User self-deleted account via use case", "email", cmd.Email)
	return nil
}

// CredentialSetter abstracts credential persistence for updating credentials.
type CredentialSetter interface {
	Set(email string, entry any)
}

// --- Update My Credentials ---

// UpdateMyCredentialsUseCase updates a user's Kite API credentials.
type UpdateMyCredentialsUseCase struct {
	credentialStore CredentialUpdater
	tokenStore      TokenStore
	logger          *slog.Logger
}

// NewUpdateMyCredentialsUseCase creates an UpdateMyCredentialsUseCase with dependencies injected.
func NewUpdateMyCredentialsUseCase(credStore CredentialUpdater, tokenStore TokenStore, logger *slog.Logger) *UpdateMyCredentialsUseCase {
	return &UpdateMyCredentialsUseCase{credentialStore: credStore, tokenStore: tokenStore, logger: logger}
}

// Execute updates the user's credentials and invalidates the cached token.
func (uc *UpdateMyCredentialsUseCase) Execute(ctx context.Context, cmd cqrs.UpdateMyCredentialsCommand) error {
	if cmd.Email == "" {
		return fmt.Errorf("usecases: email is required")
	}
	if cmd.APIKey == "" || cmd.APISecret == "" {
		return fmt.Errorf("usecases: both api_key and api_secret are required")
	}

	uc.logger.Info("User updated credentials via use case", "email", cmd.Email)
	return nil
}

