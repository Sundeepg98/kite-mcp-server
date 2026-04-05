package usecases

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// PortfolioResult contains the combined holdings and positions for a user.
type PortfolioResult struct {
	Holdings  []broker.Holding  `json:"holdings"`
	Positions broker.Positions  `json:"positions"`
}

// GetPortfolioUseCase retrieves a user's full portfolio (holdings + positions).
type GetPortfolioUseCase struct {
	brokerResolver BrokerResolver
	logger         *slog.Logger
}

// NewGetPortfolioUseCase creates a GetPortfolioUseCase with all dependencies injected.
func NewGetPortfolioUseCase(resolver BrokerResolver, logger *slog.Logger) *GetPortfolioUseCase {
	return &GetPortfolioUseCase{
		brokerResolver: resolver,
		logger:         logger,
	}
}

// Execute retrieves holdings and positions for the user.
func (uc *GetPortfolioUseCase) Execute(ctx context.Context, query cqrs.GetPortfolioQuery) (*PortfolioResult, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(query.Email)
	if err != nil {
		return nil, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	holdings, err := client.GetHoldings()
	if err != nil {
		uc.logger.Error("Failed to get holdings", "email", query.Email, "error", err)
		return nil, fmt.Errorf("usecases: get holdings: %w", err)
	}

	positions, err := client.GetPositions()
	if err != nil {
		uc.logger.Error("Failed to get positions", "email", query.Email, "error", err)
		return nil, fmt.Errorf("usecases: get positions: %w", err)
	}

	return &PortfolioResult{
		Holdings:  holdings,
		Positions: positions,
	}, nil
}
