package alerts

import (
	"fmt"
	"log/slog"
	"time"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
)

// PnLJournalResult holds the result of a P&L journal query.
type PnLJournalResult struct {
	Entries       []*DailyPnLEntry `json:"entries"`
	TotalDays     int              `json:"total_days"`
	CumulativePnL float64          `json:"cumulative_pnl"`
	BestDay       *DailyPnLEntry   `json:"best_day,omitempty"`
	WorstDay      *DailyPnLEntry   `json:"worst_day,omitempty"`
	WinDays       int              `json:"win_days"`
	LossDays      int              `json:"loss_days"`
	CurrentStreak int              `json:"current_streak"` // positive = winning, negative = losing
	BestStreak    int              `json:"best_streak"`
	WorstStreak   int              `json:"worst_streak"`
	AvgDailyPnL   float64          `json:"avg_daily_pnl"`
}

// PnLSnapshotService takes daily P&L snapshots and provides journal queries.
type PnLSnapshotService struct {
	db     *DB
	tokens TokenChecker
	creds  CredentialGetter
	logger *slog.Logger
}

// NewPnLSnapshotService creates a new P&L snapshot service.
// Returns nil if db is nil.
func NewPnLSnapshotService(db *DB, tokens TokenChecker, creds CredentialGetter, logger *slog.Logger) *PnLSnapshotService {
	if db == nil {
		return nil
	}
	return &PnLSnapshotService{
		db:     db,
		tokens: tokens,
		creds:  creds,
		logger: logger,
	}
}

// TakeSnapshots captures daily P&L for all users with valid Kite tokens.
// Called by the scheduler at 3:40 PM IST.
func (s *PnLSnapshotService) TakeSnapshots() {
	chatIDs, err := s.db.LoadTelegramChatIDs()
	if err != nil {
		s.logger.Error("Failed to load users for P&L snapshot", "error", err)
		return
	}

	// Also check for users with tokens but no Telegram
	tokens, err := s.db.LoadTokens()
	if err != nil {
		s.logger.Error("Failed to load tokens for P&L snapshot", "error", err)
		return
	}

	// Build unique email set
	emails := make(map[string]bool)
	for email := range chatIDs {
		emails[email] = true
	}
	for _, t := range tokens {
		emails[t.Email] = true
	}

	today := time.Now().In(kolkataLoc).Format("2006-01-02")
	snapshotCount := 0

	for email := range emails {
		accessToken, storedAt, ok := s.tokens.GetToken(email)
		if !ok || s.tokens.IsExpired(storedAt) {
			continue
		}

		apiKey := s.creds.GetAPIKey(email)
		if apiKey == "" {
			continue
		}

		client := kiteconnect.New(apiKey)
		client.SetAccessToken(accessToken)

		entry := &DailyPnLEntry{
			Date:  today,
			Email: email,
		}

		// Fetch holdings P&L
		holdings, err := client.GetHoldings()
		if err != nil {
			s.logger.Warn("Failed to fetch holdings for P&L snapshot", "email", email, "error", err)
		} else {
			entry.HoldingsCount = len(holdings)
			for _, h := range holdings {
				entry.HoldingsPnL += h.DayChange
			}
		}

		// Fetch positions P&L
		positions, err := client.GetPositions()
		if err != nil {
			s.logger.Warn("Failed to fetch positions for P&L snapshot", "email", email, "error", err)
		} else {
			for _, p := range positions.Day {
				entry.PositionsPnL += p.PnL
				if p.Quantity != 0 || p.DayBuyQuantity > 0 || p.DaySellQuantity > 0 {
					entry.TradesCount++
				}
			}
		}

		entry.NetPnL = entry.HoldingsPnL + entry.PositionsPnL

		if err := s.db.SaveDailyPnL(entry); err != nil {
			s.logger.Error("Failed to save P&L snapshot", "email", email, "error", err)
			continue
		}
		snapshotCount++
	}

	if snapshotCount > 0 {
		s.logger.Info("Daily P&L snapshots saved", "count", snapshotCount, "date", today)
	}
}

// GetJournal retrieves P&L journal data for a user within a date range.
func (s *PnLSnapshotService) GetJournal(email, fromDate, toDate string) (*PnLJournalResult, error) {
	entries, err := s.db.LoadDailyPnL(email, fromDate, toDate)
	if err != nil {
		return nil, fmt.Errorf("load daily pnl: %w", err)
	}

	result := &PnLJournalResult{
		Entries:   entries,
		TotalDays: len(entries),
	}

	if len(entries) == 0 {
		return result, nil
	}

	// Compute stats
	var cumulative float64
	var bestDay, worstDay *DailyPnLEntry
	bestStreak := 0
	worstStreak := 0
	runStreak := 0

	for _, e := range entries {
		cumulative += e.NetPnL

		if e.NetPnL >= 0 {
			result.WinDays++
		} else {
			result.LossDays++
		}

		if bestDay == nil || e.NetPnL > bestDay.NetPnL {
			cp := *e
			bestDay = &cp
		}
		if worstDay == nil || e.NetPnL < worstDay.NetPnL {
			cp := *e
			worstDay = &cp
		}

		// Streak tracking
		if e.NetPnL >= 0 {
			if runStreak >= 0 {
				runStreak++
			} else {
				runStreak = 1
			}
		} else {
			if runStreak <= 0 {
				runStreak--
			} else {
				runStreak = -1
			}
		}

		if runStreak > bestStreak {
			bestStreak = runStreak
		}
		if runStreak < worstStreak {
			worstStreak = runStreak
		}
	}

	result.CumulativePnL = cumulative
	result.BestDay = bestDay
	result.WorstDay = worstDay
	result.CurrentStreak = runStreak
	result.BestStreak = bestStreak
	result.WorstStreak = worstStreak
	result.AvgDailyPnL = cumulative / float64(len(entries))

	return result, nil
}
