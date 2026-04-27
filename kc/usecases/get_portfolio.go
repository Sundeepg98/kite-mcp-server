package usecases

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// PortfolioResult contains the combined holdings and positions for a user.
type PortfolioResult struct {
	Holdings  []broker.Holding  `json:"holdings"`
	Positions broker.Positions  `json:"positions"`
}

// GetPortfolioUseCase retrieves a user's full portfolio (holdings + positions).
//
// Wave D Phase 3 Package 5 (Logger sweep): logger is the kc/logger.Logger
// port; constructor takes *slog.Logger and converts via logport.NewSlog.
type GetPortfolioUseCase struct {
	brokerResolver BrokerResolver
	logger         logport.Logger
}

// NewGetPortfolioUseCase creates a GetPortfolioUseCase with all dependencies injected.
func NewGetPortfolioUseCase(resolver BrokerResolver, logger *slog.Logger) *GetPortfolioUseCase {
	return &GetPortfolioUseCase{
		brokerResolver: resolver,
		logger:         logport.NewSlog(logger),
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
		uc.logger.Error(ctx, "Failed to get holdings", err, "email", query.Email)
		return nil, fmt.Errorf("usecases: get holdings: %w", err)
	}

	positions, err := client.GetPositions()
	if err != nil {
		uc.logger.Error(ctx, "Failed to get positions", err, "email", query.Email)
		return nil, fmt.Errorf("usecases: get positions: %w", err)
	}

	return &PortfolioResult{
		Holdings:  holdings,
		Positions: positions,
	}, nil
}
