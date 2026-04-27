package alerts

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
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
//
// Wave D Phase 3 Package 4 (Logger sweep): logger is typed as the
// kc/logger.Logger port. NewPnLSnapshotService takes *slog.Logger for
// caller compatibility (kc/manager_init.go) and converts at the
// boundary via logport.NewSlog. Internal log calls use
// context.Background() — TakeSnapshots is invoked from scheduler
// goroutines with no request ctx in scope.
type PnLSnapshotService struct {
	db                *DB
	tokens            TokenChecker
	creds             CredentialGetter
	logger            logport.Logger
	brokerProvider    BrokerDataProvider // nil = use default via kiteClientFactory
	kiteClientFactory KiteClientFactory  // required for defaultBrokerProvider fallback
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
		logger: logport.NewSlog(logger),
	}
}

// SetBrokerProvider overrides the default Kite API client (for testing).
func (s *PnLSnapshotService) SetBrokerProvider(p BrokerDataProvider) {
	if s != nil {
		s.brokerProvider = p
	}
}

// SetKiteClientFactory wires the factory used by the default broker provider.
// Production wires this during app bootstrap; tests may leave it nil when they
// override the broker provider via SetBrokerProvider.
func (s *PnLSnapshotService) SetKiteClientFactory(f KiteClientFactory) {
	if s != nil {
		s.kiteClientFactory = f
	}
}

// broker returns the BrokerDataProvider, defaulting to a factory-backed provider.
func (s *PnLSnapshotService) broker() BrokerDataProvider {
	if s.brokerProvider != nil {
		return s.brokerProvider
	}
	return &defaultBrokerProvider{factory: s.kiteClientFactory}
}

// buildPnLEntry builds a DailyPnLEntry from broker data. Pure logic, testable.
//
// Currency labelling (Slice 6d): gokiteconnect emits INR-priced floats
// by contract, so the entry's *PnLCurrency fields are stamped with
// "INR" at construction time. This keeps the cross-currency rejection
// in GetJournal meaningful — a future multi-currency emitter would
// supply a non-INR value here, and the aggregation would surface the
// mismatch rather than silently coercing.
func buildPnLEntry(date, email string, holdings []kiteconnect.Holding, holdingsErr error,
	positions kiteconnect.Positions, positionsErr error) *DailyPnLEntry {
	entry := &DailyPnLEntry{
		Date:                 date,
		Email:                email,
		HoldingsPnLCurrency:  "INR",
		PositionsPnLCurrency: "INR",
		NetPnLCurrency:       "INR",
	}
	if holdingsErr == nil {
		entry.HoldingsCount = len(holdings)
		for _, h := range holdings {
			entry.HoldingsPnL += h.DayChange
		}
	}
	if positionsErr == nil {
		for _, p := range positions.Day {
			entry.PositionsPnL += p.PnL
			if p.Quantity != 0 || p.DayBuyQuantity > 0 || p.DaySellQuantity > 0 {
				entry.TradesCount++
			}
		}
	}
	entry.NetPnL = entry.HoldingsPnL + entry.PositionsPnL
	return entry
}

// TakeSnapshots captures daily P&L for all users with valid Kite tokens.
// Called by the scheduler at 3:40 PM IST.
func (s *PnLSnapshotService) TakeSnapshots() {
	chatIDs, err := s.db.LoadTelegramChatIDs()
	if err != nil {
		s.logger.Error(context.Background(), "Failed to load users for P&L snapshot", err)
		return
	}

	// Also check for users with tokens but no Telegram
	tokens, err := s.db.LoadTokens()
	if err != nil {
		s.logger.Error(context.Background(), "Failed to load tokens for P&L snapshot", err)
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

	bp := s.broker()
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

		holdings, holdingsErr := bp.GetHoldings(apiKey, accessToken)
		if holdingsErr != nil {
			s.logger.Warn(context.Background(), "Failed to fetch holdings for P&L snapshot", "email", email, "error", holdingsErr)
		}

		positions, positionsErr := bp.GetPositions(apiKey, accessToken)
		if positionsErr != nil {
			s.logger.Warn(context.Background(), "Failed to fetch positions for P&L snapshot", "email", email, "error", positionsErr)
		}

		entry := buildPnLEntry(today, email, holdings, holdingsErr, positions, positionsErr)

		if err := s.db.SaveDailyPnL(entry); err != nil {
			s.logger.Error(context.Background(), "Failed to save P&L snapshot", err, "email", email)
			continue
		}
		snapshotCount++
	}

	if snapshotCount > 0 {
		s.logger.Info(context.Background(), "Daily P&L snapshots saved", "count", snapshotCount, "date", today)
	}
}

// GetJournal retrieves P&L journal data for a user within a date range.
//
// Currency-aware aggregation (Slice 6d): NetPnL summation routes through
// domain.Money.Add so cross-currency entries surface as a typed error
// rather than silently coercing INR + USD as a bare float. Production
// is INR-only by gokiteconnect contract — this is forward-compat
// guardrail for multi-currency Kite accounts.
//
// Cumulative + AvgDailyPnL still surface as float64 on the result
// (JSON wire compat); the Money pipeline is the validation oracle, the
// scalar values come from .Float64() at the boundary.
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

	// Compute stats. Anchor cumulative on the first entry's currency so
	// subsequent .Add calls validate against it; mismatch returns a
	// typed error naming "currency".
	cumMoney := entries[0].NetPnLMoney()
	// First entry contributes 0 to delta-from-itself; subsequent entries
	// add to cumMoney via Money.Add. Reset cumMoney to zero in that
	// currency for the proper sum semantics.
	cumMoney = domain.Money{Amount: 0, Currency: cumMoney.Currency}

	var bestDay, worstDay *DailyPnLEntry
	bestStreak := 0
	worstStreak := 0
	runStreak := 0

	for _, e := range entries {
		next, addErr := cumMoney.Add(e.NetPnLMoney())
		if addErr != nil {
			return nil, fmt.Errorf("aggregate daily pnl: currency mismatch: %w", addErr)
		}
		cumMoney = next

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

		bestStreak = max(bestStreak, runStreak)
		worstStreak = min(worstStreak, runStreak)
	}

	cumulative := cumMoney.Float64()
	result.CumulativePnL = cumulative
	result.BestDay = bestDay
	result.WorstDay = worstDay
	result.CurrentStreak = runStreak
	result.BestStreak = bestStreak
	result.WorstStreak = worstStreak
	result.AvgDailyPnL = cumulative / float64(len(entries))

	return result, nil
}
