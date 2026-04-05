package usecases

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// AlertStore is the interface needed by CreateAlertUseCase.
// It matches the subset of kc.AlertStoreInterface used here.
type AlertStore interface {
	Add(email, tradingsymbol, exchange string, instrumentToken uint32, targetPrice float64, direction alerts.Direction) (string, error)
	AddWithReferencePrice(email, tradingsymbol, exchange string, instrumentToken uint32, targetPrice float64, direction alerts.Direction, referencePrice float64) (string, error)
}

// InstrumentResolver looks up instrument tokens by exchange and symbol.
type InstrumentResolver interface {
	GetInstrumentToken(exchange, tradingsymbol string) (uint32, error)
}

// CreateAlertUseCase creates a new price alert for a user.
type CreateAlertUseCase struct {
	alertStore  AlertStore
	instruments InstrumentResolver
	logger      *slog.Logger
}

// NewCreateAlertUseCase creates a CreateAlertUseCase with all dependencies injected.
func NewCreateAlertUseCase(
	store AlertStore,
	instruments InstrumentResolver,
	logger *slog.Logger,
) *CreateAlertUseCase {
	return &CreateAlertUseCase{
		alertStore:  store,
		instruments: instruments,
		logger:      logger,
	}
}

// Execute creates an alert and returns the alert ID.
func (uc *CreateAlertUseCase) Execute(ctx context.Context, cmd cqrs.CreateAlertCommand) (string, error) {
	if cmd.Email == "" {
		return "", fmt.Errorf("usecases: email is required")
	}
	if cmd.Tradingsymbol == "" {
		return "", fmt.Errorf("usecases: tradingsymbol is required")
	}
	if cmd.TargetPrice <= 0 {
		return "", fmt.Errorf("usecases: target_price must be positive")
	}
	if cmd.Direction == "" {
		return "", fmt.Errorf("usecases: direction is required")
	}

	// Resolve instrument token.
	token, err := uc.instruments.GetInstrumentToken(cmd.Exchange, cmd.Tradingsymbol)
	if err != nil {
		return "", fmt.Errorf("usecases: resolve instrument: %w", err)
	}

	direction := alerts.Direction(cmd.Direction)

	// Use reference price variant if provided.
	var alertID string
	if cmd.ReferencePrice > 0 {
		alertID, err = uc.alertStore.AddWithReferencePrice(
			cmd.Email, cmd.Tradingsymbol, cmd.Exchange,
			token, cmd.TargetPrice, direction, cmd.ReferencePrice,
		)
	} else {
		alertID, err = uc.alertStore.Add(
			cmd.Email, cmd.Tradingsymbol, cmd.Exchange,
			token, cmd.TargetPrice, direction,
		)
	}
	if err != nil {
		uc.logger.Error("Failed to create alert",
			"email", cmd.Email,
			"tradingsymbol", cmd.Tradingsymbol,
			"error", err,
		)
		return "", fmt.Errorf("usecases: create alert: %w", err)
	}

	uc.logger.Info("Alert created",
		"email", cmd.Email,
		"alert_id", alertID,
		"tradingsymbol", cmd.Tradingsymbol,
		"target_price", cmd.TargetPrice,
		"direction", cmd.Direction,
	)

	return alertID, nil
}
