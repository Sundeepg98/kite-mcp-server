package usecases

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// TelegramStore abstracts Telegram chat ID persistence.
type TelegramStore interface {
	SetTelegramChatID(email string, chatID int64)
	GetTelegramChatID(email string) (int64, bool)
}

// --- Setup Telegram ---

// SetupTelegramUseCase registers a user's Telegram chat ID for notifications.
type SetupTelegramUseCase struct {
	store  TelegramStore
	logger *slog.Logger
}

// NewSetupTelegramUseCase creates a SetupTelegramUseCase with dependencies injected.
func NewSetupTelegramUseCase(store TelegramStore, logger *slog.Logger) *SetupTelegramUseCase {
	return &SetupTelegramUseCase{store: store, logger: logger}
}

// Execute registers the Telegram chat ID.
func (uc *SetupTelegramUseCase) Execute(ctx context.Context, cmd cqrs.SetupTelegramCommand) error {
	if cmd.Email == "" {
		return fmt.Errorf("usecases: email is required")
	}
	if cmd.ChatID == 0 {
		return fmt.Errorf("usecases: chat_id is required")
	}
	uc.store.SetTelegramChatID(cmd.Email, cmd.ChatID)
	uc.logger.Debug("Telegram chat ID registered", "email", cmd.Email, "chat_id", cmd.ChatID)
	return nil
}
