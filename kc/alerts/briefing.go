package alerts

import (
	"fmt"
	"html"
	"log/slog"
	"math"
	"sort"
	"strings"
	"time"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
)

// kolkataLoc is the cached Asia/Kolkata timezone for briefing formatting.
var kolkataLoc = func() *time.Location {
	loc, err := time.LoadLocation("Asia/Kolkata")
	if err != nil {
		panic("failed to load Asia/Kolkata timezone: " + err.Error())
	}
	return loc
}()

// TokenChecker abstracts the ability to look up a user's Kite token and check expiry.
type TokenChecker interface {
	// GetToken returns the access token and stored-at time for an email.
	// ok is false if no token exists.
	GetToken(email string) (accessToken string, storedAt time.Time, ok bool)
	// IsExpired returns true if a token stored at the given time has expired.
	IsExpired(storedAt time.Time) bool
}

// CredentialGetter abstracts looking up per-user Kite credentials.
type CredentialGetter interface {
	// GetAPIKey returns the API key for the given email, falling back to global.
	GetAPIKey(email string) string
}

// BriefingService generates and sends morning briefings and daily P&L summaries
// via Telegram for users who have a registered chat ID and valid Kite token.
type BriefingService struct {
	notifier   *TelegramNotifier
	alertStore *Store
	tokens     TokenChecker
	creds      CredentialGetter
	logger     *slog.Logger
}

// NewBriefingService creates a BriefingService. Returns nil if notifier is nil.
func NewBriefingService(
	notifier *TelegramNotifier,
	alertStore *Store,
	tokens TokenChecker,
	creds CredentialGetter,
	logger *slog.Logger,
) *BriefingService {
	if notifier == nil {
		return nil
	}
	return &BriefingService{
		notifier:   notifier,
		alertStore: alertStore,
		tokens:     tokens,
		creds:      creds,
		logger:     logger,
	}
}

// SendMorningBriefings sends a morning briefing to every user with a Telegram chat ID.
func (b *BriefingService) SendMorningBriefings() {
	if b == nil {
		return
	}

	chatIDs := b.alertStore.ListAllTelegram()
	if len(chatIDs) == 0 {
		b.logger.Info("Briefing: no users with Telegram chat IDs, skipping morning briefing")
		return
	}

	now := time.Now().In(kolkataLoc)
	dateStr := now.Format("January 2, 2006")

	for email, chatID := range chatIDs {
		msg := b.buildMorningBriefing(email, dateStr, now)
		if err := b.notifier.SendHTMLMessage(chatID, msg); err != nil {
			b.logger.Error("Briefing: failed to send morning briefing",
				"email", email, "chat_id", chatID, "error", err)
		} else {
			b.logger.Info("Briefing: morning briefing sent", "email", email)
		}
	}
}

// buildMorningBriefing generates the morning briefing message for one user.
func (b *BriefingService) buildMorningBriefing(email, dateStr string, now time.Time) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\U0001F305 <b>Morning Briefing — %s</b>\n\n", html.EscapeString(dateStr)))

	// Triggered alerts since yesterday's close (3:30 PM IST previous trading day).
	prevClose := previousTradingDayClose(now)
	triggered := b.recentlyTriggeredAlerts(email, prevClose)
	if len(triggered) > 0 {
		sb.WriteString(fmt.Sprintf("Alerts triggered overnight: %d\n", len(triggered)))
		for _, a := range triggered {
			sb.WriteString(fmt.Sprintf("  \u2022 %s crossed \u20B9%.2f (%s) at %s\n",
				html.EscapeString(a.Tradingsymbol),
				a.TriggeredPrice,
				a.Direction,
				a.TriggeredAt.In(kolkataLoc).Format("15:04")))
		}
	} else {
		sb.WriteString("No alerts triggered overnight.\n")
	}
	sb.WriteString("\n")

	// Token status
	_, storedAt, hasToken := b.tokens.GetToken(email)
	if hasToken && !b.tokens.IsExpired(storedAt) {
		sb.WriteString("Token status: Valid \u2713\n")
	} else if hasToken {
		sb.WriteString("Token status: <b>Expired</b> \u2717 (re-login required)\n")
	} else {
		sb.WriteString("Token status: <b>Not found</b> \u2717\n")
	}

	// Portfolio day P&L, margin available, and index levels (if token valid)
	accessToken, storedAt, hasToken := b.tokens.GetToken(email)
	if hasToken && !b.tokens.IsExpired(storedAt) {
		apiKey := b.creds.GetAPIKey(email)
		if apiKey != "" {
			client := kiteconnect.New(apiKey)
			client.SetAccessToken(accessToken)

			// Portfolio day P&L from holdings
			holdings, err := client.GetHoldings()
			if err == nil && len(holdings) > 0 {
				var dayPnL float64
				for _, h := range holdings {
					dayPnL += h.DayChange
				}
				sb.WriteString(fmt.Sprintf("\nPortfolio: %s day P&amp;L (%d stocks)\n", formatRupee(dayPnL), len(holdings)))
			}

			// Margin available
			margins, err := client.GetUserMargins()
			if err == nil {
				sb.WriteString(fmt.Sprintf("Margin available: \u20B9%.0f\n", margins.Equity.Net))
			}

			// Index levels (NIFTY 50, BANK NIFTY)
			ltpResp, err := client.GetLTP("NSE:NIFTY 50", "NSE:NIFTY BANK")
			if err == nil {
				sb.WriteString("\n<b>Indices:</b>\n")
				if nifty, ok := ltpResp["NSE:NIFTY 50"]; ok {
					sb.WriteString(fmt.Sprintf("  NIFTY 50: \u20B9%.2f\n", nifty.LastPrice))
				}
				if bankNifty, ok := ltpResp["NSE:NIFTY BANK"]; ok {
					sb.WriteString(fmt.Sprintf("  BANK NIFTY: \u20B9%.2f\n", bankNifty.LastPrice))
				}
			}
		}
	}
	sb.WriteString("\n")

	// Market timing
	marketOpen := time.Date(now.Year(), now.Month(), now.Day(), 9, 15, 0, 0, kolkataLoc)
	if now.Before(marketOpen) {
		diff := marketOpen.Sub(now)
		if diff > time.Hour {
			sb.WriteString(fmt.Sprintf("Market opens in %dh %dm.\n", int(diff.Hours()), int(diff.Minutes())%60))
		} else {
			sb.WriteString(fmt.Sprintf("Market opens in %d minutes.\n", int(diff.Minutes())))
		}
	} else {
		sb.WriteString("Market is open.\n")
	}

	return sb.String()
}

// SendDailySummaries sends a post-market P&L summary to every eligible user.
func (b *BriefingService) SendDailySummaries() {
	if b == nil {
		return
	}

	chatIDs := b.alertStore.ListAllTelegram()
	if len(chatIDs) == 0 {
		b.logger.Info("Briefing: no users with Telegram chat IDs, skipping daily summary")
		return
	}

	now := time.Now().In(kolkataLoc)
	dateStr := now.Format("January 2, 2006")

	for email, chatID := range chatIDs {
		// Need a valid token to fetch portfolio data.
		accessToken, storedAt, hasToken := b.tokens.GetToken(email)
		if !hasToken || b.tokens.IsExpired(storedAt) {
			b.logger.Warn("Briefing: skipping daily summary (no valid token)", "email", email)
			continue
		}

		apiKey := b.creds.GetAPIKey(email)
		if apiKey == "" {
			b.logger.Warn("Briefing: skipping daily summary (no API key)", "email", email)
			continue
		}

		msg := b.buildDailySummary(email, apiKey, accessToken, dateStr)
		if err := b.notifier.SendHTMLMessage(chatID, msg); err != nil {
			b.logger.Error("Briefing: failed to send daily summary",
				"email", email, "chat_id", chatID, "error", err)
		} else {
			b.logger.Info("Briefing: daily summary sent", "email", email)
		}
	}
}

// buildDailySummary generates the daily P&L summary for one user.
func (b *BriefingService) buildDailySummary(email, apiKey, accessToken, dateStr string) string {
	client := kiteconnect.New(apiKey)
	client.SetAccessToken(accessToken)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\U0001F4CA <b>Daily Summary — %s</b>\n\n", html.EscapeString(dateStr)))

	var holdingsDayPnL float64
	var holdingsCount int
	var changes []stockChange

	holdings, err := client.GetHoldings()
	if err != nil {
		b.logger.Error("Briefing: failed to fetch holdings", "email", email, "error", err)
		sb.WriteString("Holdings P&amp;L: <i>unavailable</i>\n")
	} else {
		holdingsCount = len(holdings)
		for _, h := range holdings {
			holdingsDayPnL += h.DayChange
			if h.DayChangePercentage != 0 {
				changes = append(changes, stockChange{Symbol: h.Tradingsymbol, Percent: h.DayChangePercentage})
			}
		}
		sb.WriteString(fmt.Sprintf("Holdings P&amp;L: %s (%d stocks)\n",
			formatRupee(holdingsDayPnL), holdingsCount))
	}

	var positionsPnL float64
	var positionsCount int
	positions, err := client.GetPositions()
	if err != nil {
		b.logger.Error("Briefing: failed to fetch positions", "email", email, "error", err)
		sb.WriteString("Positions P&amp;L: <i>unavailable</i>\n")
	} else {
		positionsCount = len(positions.Day)
		for _, p := range positions.Day {
			positionsPnL += p.PnL
		}
		sb.WriteString(fmt.Sprintf("Positions P&amp;L: %s (%d positions)\n",
			formatRupee(positionsPnL), positionsCount))
	}

	netPnL := holdingsDayPnL + positionsPnL
	sb.WriteString(fmt.Sprintf("<b>Net Day P&amp;L: %s</b>\n", formatRupee(netPnL)))

	// Top gainers and losers from holdings.
	if len(changes) > 0 {
		sort.Slice(changes, func(i, j int) bool { return changes[i].Percent > changes[j].Percent })
		sb.WriteString("\n")

		// Top gainers (up to 3)
		gainers := filterPositiveChanges(changes, 3)
		if len(gainers) > 0 {
			sb.WriteString("Top Gainers: ")
			parts := make([]string, len(gainers))
			for i, g := range gainers {
				parts[i] = fmt.Sprintf("%s %+.1f%%", html.EscapeString(g.Symbol), g.Percent)
			}
			sb.WriteString(strings.Join(parts, ", "))
			sb.WriteString("\n")
		}

		// Top losers (up to 3)
		losers := filterNegativeChanges(changes, 3)
		if len(losers) > 0 {
			sb.WriteString("Top Losers: ")
			parts := make([]string, len(losers))
			for i, l := range losers {
				parts[i] = fmt.Sprintf("%s %.1f%%", html.EscapeString(l.Symbol), l.Percent)
			}
			sb.WriteString(strings.Join(parts, ", "))
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

// --- helpers ---

// formatRupee formats a float as an INR string with sign.
func formatRupee(v float64) string {
	sign := "+"
	if v < 0 {
		sign = "-"
		v = math.Abs(v)
	}
	return fmt.Sprintf("%s\u20B9%.0f", sign, v)
}

// previousTradingDayClose returns the 3:30 PM IST of the previous trading day.
func previousTradingDayClose(now time.Time) time.Time {
	d := now
	for {
		d = d.AddDate(0, 0, -1)
		if d.Weekday() != time.Saturday && d.Weekday() != time.Sunday {
			break
		}
	}
	return time.Date(d.Year(), d.Month(), d.Day(), 15, 30, 0, 0, kolkataLoc)
}

// recentlyTriggeredAlerts returns alerts for the email that triggered after cutoff.
func (b *BriefingService) recentlyTriggeredAlerts(email string, after time.Time) []*Alert {
	all := b.alertStore.List(email)
	var result []*Alert
	for _, a := range all {
		if a.Triggered && a.TriggeredAt.After(after) {
			result = append(result, a)
		}
	}
	return result
}

type stockChange struct {
	Symbol  string
	Percent float64
}

// filterPositiveChanges returns the top N positive changes (already sorted desc).
func filterPositiveChanges(changes []stockChange, n int) []stockChange {
	var out []stockChange
	for _, c := range changes {
		if c.Percent > 0 {
			out = append(out, c)
			if len(out) >= n {
				break
			}
		}
	}
	return out
}

// filterNegativeChanges returns the bottom N negative changes (input sorted desc,
// so negatives are at the end).
func filterNegativeChanges(changes []stockChange, n int) []stockChange {
	var negatives []stockChange
	for i := len(changes) - 1; i >= 0; i-- {
		if changes[i].Percent < 0 {
			negatives = append(negatives, changes[i])
			if len(negatives) >= n {
				break
			}
		}
	}
	return negatives
}

// SendMISWarnings sends a Telegram warning to users who have open MIS positions.
// Intended to run at 2:30 PM IST, giving ~45 minutes before auto square-off.
func (b *BriefingService) SendMISWarnings() {
	if b == nil {
		return
	}

	chatIDs := b.alertStore.ListAllTelegram()
	if len(chatIDs) == 0 {
		b.logger.Info("Briefing: no users with Telegram chat IDs, skipping MIS warning")
		return
	}

	for email, chatID := range chatIDs {
		accessToken, storedAt, hasToken := b.tokens.GetToken(email)
		if !hasToken || b.tokens.IsExpired(storedAt) {
			continue
		}

		apiKey := b.creds.GetAPIKey(email)
		if apiKey == "" {
			continue
		}

		client := kiteconnect.New(apiKey)
		client.SetAccessToken(accessToken)

		positions, err := client.GetPositions()
		if err != nil {
			b.logger.Error("MIS warning: failed to fetch positions", "email", email, "error", err)
			continue
		}

		// Filter MIS positions with non-zero quantity
		type misPos struct {
			Symbol   string
			Quantity int
			PnL      float64
		}
		var open []misPos
		for _, p := range positions.Net {
			if p.Quantity != 0 && strings.ToUpper(p.Product) == "MIS" {
				open = append(open, misPos{Symbol: p.Tradingsymbol, Quantity: p.Quantity, PnL: p.PnL})
			}
		}

		if len(open) == 0 {
			continue
		}

		// Build warning message
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("\u26A0\uFE0F <b>MIS Square-Off Warning</b>\n\n"))
		sb.WriteString(fmt.Sprintf("You have <b>%d open MIS position(s)</b> that will be auto-squared off around 3:15-3:20 PM IST.\n\n", len(open)))

		var totalPnL float64
		for _, p := range open {
			direction := "LONG"
			if p.Quantity < 0 {
				direction = "SHORT"
			}
			sb.WriteString(fmt.Sprintf("  \u2022 %s: %s %d @ %s\n",
				html.EscapeString(p.Symbol), direction, abs(p.Quantity), formatRupee(p.PnL)))
			totalPnL += p.PnL
		}
		sb.WriteString(fmt.Sprintf("\nMIS P&amp;L: <b>%s</b>\n", formatRupee(totalPnL)))
		sb.WriteString("\nAction: Close manually or convert to CNC/NRML to carry overnight.")

		if err := b.notifier.SendHTMLMessage(chatID, sb.String()); err != nil {
			b.logger.Error("MIS warning: failed to send", "email", email, "error", err)
		} else {
			b.logger.Info("MIS warning: sent", "email", email, "open_mis", len(open))
		}
	}
}

// abs returns the absolute value of an int.
func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
