package kc

import (
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/broker"
)

// PortfolioService owns portfolio queries: holdings, positions, margins, profile.
// It resolves a broker.Client per user and delegates to the broker interface.
// Extracted from Manager as part of Clean Architecture / SOLID refactoring.
type PortfolioService struct {
	sessionSvc *SessionService
	logger     *slog.Logger
}

// NewPortfolioService creates a new PortfolioService.
func NewPortfolioService(sessionSvc *SessionService, logger *slog.Logger) *PortfolioService {
	return &PortfolioService{
		sessionSvc: sessionSvc,
		logger:     logger,
	}
}

// getBroker resolves a broker.Client for the given email.
func (ps *PortfolioService) getBroker(email string) (broker.Client, error) {
	b, err := ps.sessionSvc.GetBrokerForEmail(email)
	if err != nil {
		return nil, fmt.Errorf("portfolio: %w", err)
	}
	return b, nil
}

// GetHoldings returns the user's stock holdings.
func (ps *PortfolioService) GetHoldings(email string) ([]broker.Holding, error) {
	b, err := ps.getBroker(email)
	if err != nil {
		return nil, err
	}
	holdings, err := b.GetHoldings()
	if err != nil {
		ps.logger.Error("Failed to get holdings", "email", email, "error", err)
		return nil, fmt.Errorf("failed to get holdings: %w", err)
	}
	return holdings, nil
}

// GetPositions returns the user's current positions.
func (ps *PortfolioService) GetPositions(email string) (broker.Positions, error) {
	b, err := ps.getBroker(email)
	if err != nil {
		return broker.Positions{}, err
	}
	positions, err := b.GetPositions()
	if err != nil {
		ps.logger.Error("Failed to get positions", "email", email, "error", err)
		return broker.Positions{}, fmt.Errorf("failed to get positions: %w", err)
	}
	return positions, nil
}

// GetMargins returns the user's account margins.
func (ps *PortfolioService) GetMargins(email string) (broker.Margins, error) {
	b, err := ps.getBroker(email)
	if err != nil {
		return broker.Margins{}, err
	}
	margins, err := b.GetMargins()
	if err != nil {
		ps.logger.Error("Failed to get margins", "email", email, "error", err)
		return broker.Margins{}, fmt.Errorf("failed to get margins: %w", err)
	}
	return margins, nil
}

// GetProfile returns the user's profile information.
func (ps *PortfolioService) GetProfile(email string) (broker.Profile, error) {
	b, err := ps.getBroker(email)
	if err != nil {
		return broker.Profile{}, err
	}
	profile, err := b.GetProfile()
	if err != nil {
		ps.logger.Error("Failed to get profile", "email", email, "error", err)
		return broker.Profile{}, fmt.Errorf("failed to get profile: %w", err)
	}
	return profile, nil
}
