package usecases

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
	"github.com/zerodha/kite-mcp-server/kc/ticker"
)

// TickerService abstracts the WebSocket ticker for use cases.
type TickerService interface {
	Start(email, apiKey, accessToken string) error
	Stop(email string) error
	Subscribe(email string, tokens []uint32, mode ticker.Mode) error
	Unsubscribe(email string, tokens []uint32) error
	GetStatus(email string) (*ticker.Status, error)
	IsRunning(email string) bool
}

// --- Start Ticker ---

// StartTickerUseCase starts a WebSocket ticker.
type StartTickerUseCase struct {
	ticker TickerService
	logger logport.Logger
}

// NewStartTickerUseCase creates a StartTickerUseCase with dependencies injected.
func NewStartTickerUseCase(ticker TickerService, logger *slog.Logger) *StartTickerUseCase {
	return &StartTickerUseCase{ticker: ticker, logger: logport.NewSlog(logger)}
}

// Execute starts a ticker for the user.
func (uc *StartTickerUseCase) Execute(ctx context.Context, cmd cqrs.StartTickerCommand) error {
	if cmd.Email == "" {
		return fmt.Errorf("usecases: email is required")
	}
	if cmd.AccessToken == "" {
		return fmt.Errorf("usecases: access_token is required")
	}

	if err := uc.ticker.Start(cmd.Email, cmd.APIKey, cmd.AccessToken); err != nil {
		uc.logger.Error(ctx, "Failed to start ticker", err, "email", cmd.Email)
		return fmt.Errorf("usecases: start ticker: %w", err)
	}

	return nil
}

// --- Stop Ticker ---

// StopTickerUseCase stops a WebSocket ticker.
type StopTickerUseCase struct {
	ticker TickerService
	logger logport.Logger
}

// NewStopTickerUseCase creates a StopTickerUseCase with dependencies injected.
func NewStopTickerUseCase(ticker TickerService, logger *slog.Logger) *StopTickerUseCase {
	return &StopTickerUseCase{ticker: ticker, logger: logport.NewSlog(logger)}
}

// Execute stops the user's ticker.
func (uc *StopTickerUseCase) Execute(ctx context.Context, cmd cqrs.StopTickerCommand) error {
	if cmd.Email == "" {
		return fmt.Errorf("usecases: email is required")
	}

	if err := uc.ticker.Stop(cmd.Email); err != nil {
		uc.logger.Error(ctx, "Failed to stop ticker", err, "email", cmd.Email)
		return fmt.Errorf("usecases: stop ticker: %w", err)
	}

	return nil
}

// --- Ticker Status ---

// TickerStatusUseCase retrieves ticker status.
type TickerStatusUseCase struct {
	ticker TickerService
	logger logport.Logger
}

// NewTickerStatusUseCase creates a TickerStatusUseCase with dependencies injected.
func NewTickerStatusUseCase(ticker TickerService, logger *slog.Logger) *TickerStatusUseCase {
	return &TickerStatusUseCase{ticker: ticker, logger: logport.NewSlog(logger)}
}

// Execute retrieves the ticker status.
func (uc *TickerStatusUseCase) Execute(ctx context.Context, query cqrs.TickerStatusQuery) (*ticker.Status, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}

	status, err := uc.ticker.GetStatus(query.Email)
	if err != nil {
		uc.logger.Error(ctx, "Failed to get ticker status", err, "email", query.Email)
		return nil, fmt.Errorf("usecases: get ticker status: %w", err)
	}

	return status, nil
}

// --- Subscribe Instruments ---

// SubscribeInstrumentsUseCase subscribes to instrument tick data.
type SubscribeInstrumentsUseCase struct {
	ticker TickerService
	logger logport.Logger
}

// NewSubscribeInstrumentsUseCase creates a SubscribeInstrumentsUseCase with dependencies injected.
func NewSubscribeInstrumentsUseCase(ticker TickerService, logger *slog.Logger) *SubscribeInstrumentsUseCase {
	return &SubscribeInstrumentsUseCase{ticker: ticker, logger: logport.NewSlog(logger)}
}

// Execute subscribes to instruments.
func (uc *SubscribeInstrumentsUseCase) Execute(ctx context.Context, cmd cqrs.SubscribeInstrumentsCommand) error {
	if cmd.Email == "" {
		return fmt.Errorf("usecases: email is required")
	}
	if len(cmd.Tokens) == 0 {
		return fmt.Errorf("usecases: at least one token is required")
	}

	mode := resolveMode(cmd.Mode)
	if err := uc.ticker.Subscribe(cmd.Email, cmd.Tokens, mode); err != nil {
		uc.logger.Error(ctx, "Failed to subscribe instruments", err, "email", cmd.Email)
		return fmt.Errorf("usecases: subscribe instruments: %w", err)
	}

	return nil
}

// --- Unsubscribe Instruments ---

// UnsubscribeInstrumentsUseCase removes instrument subscriptions.
type UnsubscribeInstrumentsUseCase struct {
	ticker TickerService
	logger logport.Logger
}

// NewUnsubscribeInstrumentsUseCase creates an UnsubscribeInstrumentsUseCase with dependencies injected.
func NewUnsubscribeInstrumentsUseCase(ticker TickerService, logger *slog.Logger) *UnsubscribeInstrumentsUseCase {
	return &UnsubscribeInstrumentsUseCase{ticker: ticker, logger: logport.NewSlog(logger)}
}

// Execute unsubscribes from instruments.
func (uc *UnsubscribeInstrumentsUseCase) Execute(ctx context.Context, cmd cqrs.UnsubscribeInstrumentsCommand) error {
	if cmd.Email == "" {
		return fmt.Errorf("usecases: email is required")
	}
	if len(cmd.Tokens) == 0 {
		return fmt.Errorf("usecases: at least one token is required")
	}

	if err := uc.ticker.Unsubscribe(cmd.Email, cmd.Tokens); err != nil {
		uc.logger.Error(ctx, "Failed to unsubscribe instruments", err, "email", cmd.Email)
		return fmt.Errorf("usecases: unsubscribe instruments: %w", err)
	}

	return nil
}

// resolveMode converts a mode string to the ticker.Mode type.
func resolveMode(mode string) ticker.Mode {
	switch mode {
	case "ltp":
		return ticker.ModeLTP
	case "quote":
		return ticker.ModeQuote
	default:
		return ticker.ModeFull
	}
}
