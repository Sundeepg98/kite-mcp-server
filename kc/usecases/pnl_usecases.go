package usecases

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// PnLService abstracts P&L snapshot retrieval for use cases.
type PnLService interface {
	GetJournal(email, fromDate, toDate string) (*alerts.PnLJournalResult, error)
}

// --- Get P&L Journal ---

// GetPnLJournalUseCase retrieves P&L journal data.
type GetPnLJournalUseCase struct {
	service PnLService
	logger  logport.Logger
}

// NewGetPnLJournalUseCase creates a GetPnLJournalUseCase with dependencies injected.
func NewGetPnLJournalUseCase(service PnLService, logger *slog.Logger) *GetPnLJournalUseCase {
	return &GetPnLJournalUseCase{service: service, logger: logport.NewSlog(logger)}
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
		uc.logger.Error(ctx, "Failed to get P&L journal", err, "email", query.Email)
		return nil, fmt.Errorf("usecases: get pnl journal: %w", err)
	}

	return result, nil
}
