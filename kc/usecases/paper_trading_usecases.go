package usecases

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// PaperEngine abstracts the paper trading engine for use cases.
type PaperEngine interface {
	Enable(email string, initialCash float64) error
	Disable(email string) error
	Reset(email string) error
	Status(email string) (map[string]any, error)
}

// --- Paper Trading Toggle ---

// PaperTradingToggleUseCase enables or disables paper trading mode.
type PaperTradingToggleUseCase struct {
	engine PaperEngine
	logger *slog.Logger
}

// NewPaperTradingToggleUseCase creates a PaperTradingToggleUseCase with dependencies injected.
func NewPaperTradingToggleUseCase(engine PaperEngine, logger *slog.Logger) *PaperTradingToggleUseCase {
	return &PaperTradingToggleUseCase{engine: engine, logger: logger}
}

// Execute enables or disables paper trading.
func (uc *PaperTradingToggleUseCase) Execute(ctx context.Context, cmd cqrs.PaperTradingToggleCommand) (string, error) {
	if cmd.Email == "" {
		return "", fmt.Errorf("usecases: email is required")
	}

	if cmd.Enable {
		if cmd.InitialCash <= 0 {
			cmd.InitialCash = 10000000 // Default Rs 1 crore
		}
		if err := uc.engine.Enable(cmd.Email, cmd.InitialCash); err != nil {
			uc.logger.Error("Failed to enable paper trading", "email", cmd.Email, "error", err)
			return "", fmt.Errorf("usecases: enable paper trading: %w", err)
		}
		return fmt.Sprintf("Paper trading ENABLED. Virtual cash: Rs %.0f. All orders now execute against your virtual portfolio.", cmd.InitialCash), nil
	}

	if err := uc.engine.Disable(cmd.Email); err != nil {
		uc.logger.Error("Failed to disable paper trading", "email", cmd.Email, "error", err)
		return "", fmt.Errorf("usecases: disable paper trading: %w", err)
	}
	return "Paper trading DISABLED. Orders now execute against the real Kite API.", nil
}

// --- Paper Trading Status ---

// PaperTradingStatusUseCase retrieves paper trading status.
type PaperTradingStatusUseCase struct {
	engine PaperEngine
	logger *slog.Logger
}

// NewPaperTradingStatusUseCase creates a PaperTradingStatusUseCase with dependencies injected.
func NewPaperTradingStatusUseCase(engine PaperEngine, logger *slog.Logger) *PaperTradingStatusUseCase {
	return &PaperTradingStatusUseCase{engine: engine, logger: logger}
}

// Execute retrieves the paper trading status.
func (uc *PaperTradingStatusUseCase) Execute(ctx context.Context, query cqrs.PaperTradingStatusQuery) (map[string]any, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}

	status, err := uc.engine.Status(query.Email)
	if err != nil {
		uc.logger.Error("Failed to get paper trading status", "email", query.Email, "error", err)
		return nil, fmt.Errorf("usecases: paper trading status: %w", err)
	}

	return status, nil
}

// --- Paper Trading Reset ---

// PaperTradingResetUseCase resets the virtual portfolio.
type PaperTradingResetUseCase struct {
	engine PaperEngine
	logger *slog.Logger
}

// NewPaperTradingResetUseCase creates a PaperTradingResetUseCase with dependencies injected.
func NewPaperTradingResetUseCase(engine PaperEngine, logger *slog.Logger) *PaperTradingResetUseCase {
	return &PaperTradingResetUseCase{engine: engine, logger: logger}
}

// Execute resets the paper trading portfolio.
func (uc *PaperTradingResetUseCase) Execute(ctx context.Context, cmd cqrs.PaperTradingResetCommand) error {
	if cmd.Email == "" {
		return fmt.Errorf("usecases: email is required")
	}

	if err := uc.engine.Reset(cmd.Email); err != nil {
		uc.logger.Error("Failed to reset paper trading", "email", cmd.Email, "error", err)
		return fmt.Errorf("usecases: reset paper trading: %w", err)
	}

	return nil
}
