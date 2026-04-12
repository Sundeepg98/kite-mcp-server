package usecases

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// PnLService abstracts P&L snapshot retrieval for use cases.
type PnLService interface {
	GetJournal(email, fromDate, toDate string) (*alerts.PnLJournalResult, error)
}

// --- Get P&L Journal ---

// GetPnLJournalUseCase retrieves P&L journal data.
type GetPnLJournalUseCase struct {
	service PnLService
	logger  *slog.Logger
}

// NewGetPnLJournalUseCase creates a GetPnLJournalUseCase with dependencies injected.
func NewGetPnLJournalUseCase(service PnLService, logger *slog.Logger) *GetPnLJournalUseCase {
	return &GetPnLJournalUseCase{service: service, logger: logger}
}

// Execute retrieves the P&L journal.
func (uc *GetPnLJournalUseCase) Execute(ctx context.Context, query cqrs.GetPnLJournalQuery) (*alerts.PnLJournalResult, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}
	if query.FromDate == "" {
		return nil, fmt.Errorf("usecases: from_date is required")
	}
	if query.ToDate == "" {
		return nil, fmt.Errorf("usecases: to_date is required")
	}

	result, err := uc.service.GetJournal(query.Email, query.FromDate, query.ToDate)
	if err != nil {
		uc.logger.Error("Failed to get P&L journal", "email", query.Email, "error", err)
		return nil, fmt.Errorf("usecases: get pnl journal: %w", err)
	}

	return result, nil
}
