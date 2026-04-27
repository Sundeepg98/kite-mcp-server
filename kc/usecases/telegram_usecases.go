package usecases

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
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
	events *domain.EventDispatcher
	logger logport.Logger
}

// NewSetupTelegramUseCase creates a SetupTelegramUseCase with dependencies injected.
func NewSetupTelegramUseCase(store TelegramStore, logger *slog.Logger) *SetupTelegramUseCase {
	return &SetupTelegramUseCase{store: store, logger: logport.NewSlog(logger)}
}

// SetEventDispatcher wires the domain event dispatcher so a typed
// domain.TelegramSubscribedEvent (first-time bind) or
// domain.TelegramChatBoundEvent (re-bind to a different chat ID) is
// dispatched on every successful subscription mutation. The dispatcher
// path is for runtime subscribers (read-side projector, future
// consumers); audit persistence is handled by the existing
// LoggingMiddleware on the command bus. Pattern mirrors
// CreateWatchlistUseCase.SetEventDispatcher (commit aeb3e8c). Nil-safe.
//
// First-time vs re-bind distinction: Execute snapshots
// GetTelegramChatID BEFORE the Set so it can tell onboarding from
// rotation. The store mutation is non-transactional with the event
// dispatch but this check-then-act race is acceptable — worst case a
// concurrent re-setup emits two Subscribed events, which is still
// auditor-correct (they describe two distinct lifecycle moments).
// Same race tolerance as UpdateMyCredentialsUseCase's
// CredentialRegistered/Rotated split.
func (uc *SetupTelegramUseCase) SetEventDispatcher(d *domain.EventDispatcher) { uc.events = d }

// Execute registers the Telegram chat ID.
func (uc *SetupTelegramUseCase) Execute(ctx context.Context, cmd cqrs.SetupTelegramCommand) error {
	if cmd.Email == "" {
		return fmt.Errorf("usecases: email is required")
	}
	if cmd.ChatID == 0 {
		return fmt.Errorf("usecases: chat_id is required")
	}

	// Snapshot the prior chat ID BEFORE the Set so the typed event
	// emitted below correctly distinguishes first-time subscribe (no
	// prior entry) from rebind (prior entry, different chat ID) and
	// stays silent on no-op writes (prior entry, same chat ID).
	priorChatID, hadPrior := uc.store.GetTelegramChatID(cmd.Email)

	uc.store.SetTelegramChatID(cmd.Email, cmd.ChatID)
	uc.logger.Debug(ctx, "Telegram chat ID registered", "email", cmd.Email, "chat_id", cmd.ChatID)

	if uc.events != nil {
		now := time.Now()
		switch {
		case !hadPrior:
			uc.events.Dispatch(domain.TelegramSubscribedEvent{
				UserEmail: cmd.Email,
				ChatID:    cmd.ChatID,
				Timestamp: now,
			})
		case priorChatID != cmd.ChatID:
			uc.events.Dispatch(domain.TelegramChatBoundEvent{
				UserEmail: cmd.Email,
				OldChatID: priorChatID,
				NewChatID: cmd.ChatID,
				Timestamp: now,
			})
			// else: same chat ID — no-op write, silent (matches
			// TierChangedEvent contract: real transitions only).
		}
	}
	return nil
}
