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

	"github.com/zerodha/kite-mcp-server/broker/zerodha"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/isttz"
)

// BrokerDataProvider abstracts broker API calls for testability.
// When set on BriefingService via SetBrokerProvider, these methods are used
// instead of creating kiteconnect.Client directly.
type BrokerDataProvider interface {
	// GetHoldings returns holdings for the user.
	GetHoldings(apiKey, accessToken string) ([]kiteconnect.Holding, error)
	// GetPositions returns positions for the user.
	GetPositions(apiKey, accessToken string) (kiteconnect.Positions, error)
	// GetUserMargins returns margin info for the user.
	GetUserMargins(apiKey, accessToken string) (kiteconnect.AllMargins, error)
	// GetLTP returns last traded prices for the given instruments.
	GetLTP(apiKey, accessToken string, instruments ...string) (kiteconnect.QuoteLTP, error)
}

// defaultBrokerProvider uses the KiteClientFactory to create clients.
type defaultBrokerProvider struct {
	factory KiteClientFactory
}

// KiteClientFactory creates Kite API clients (mirrors kc.KiteClientFactory
// for briefing use). Returns the hexagonal zerodha.KiteSDK port rather
// than the concrete *kiteconnect.Client so briefing + pnl services can
// be exercised off-HTTP with zerodha.MockKiteSDK.
type KiteClientFactory interface {
	NewClientWithToken(apiKey, accessToken string) zerodha.KiteSDK
}

// errNoKiteClientFactory is returned when defaultBrokerProvider is used without a factory.
// Production code always wires a factory via the Manager; only misconfigured tests hit this.
var errNoKiteClientFactory = fmt.Errorf("alerts: no KiteClientFactory configured")

func (d *defaultBrokerProvider) newClient(apiKey, accessToken string) (zerodha.KiteSDK, error) {
	if d.factory == nil {
		return nil, errNoKiteClientFactory
	}
	return d.factory.NewClientWithToken(apiKey, accessToken), nil
}

func (d *defaultBrokerProvider) GetHoldings(apiKey, accessToken string) ([]kiteconnect.Holding, error) {
	c, err := d.newClient(apiKey, accessToken)
	if err != nil {
		return nil, err
	}
	return c.GetHoldings()
}

func (d *defaultBrokerProvider) GetPositions(apiKey, accessToken string) (kiteconnect.Positions, error) {
	c, err := d.newClient(apiKey, accessToken)
	if err != nil {
		return kiteconnect.Positions{}, err
	}
	return c.GetPositions()
}

func (d *defaultBrokerProvider) GetUserMargins(apiKey, accessToken string) (kiteconnect.AllMargins, error) {
	c, err := d.newClient(apiKey, accessToken)
	if err != nil {
		return kiteconnect.AllMargins{}, err
	}
	return c.GetUserMargins()
}

func (d *defaultBrokerProvider) GetLTP(apiKey, accessToken string, instruments ...string) (kiteconnect.QuoteLTP, error) {
	c, err := d.newClient(apiKey, accessToken)
	if err != nil {
		return nil, err
	}
	return c.GetLTP(instruments...)
}

// kolkataLoc is an alias for the shared IST timezone (kc/isttz leaf package).
var kolkataLoc = isttz.Location

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
	notifier          *TelegramNotifier
	alertStore        *Store
	tokens            TokenChecker
	creds             CredentialGetter
	logger            *slog.Logger
	brokerProvider    BrokerDataProvider // nil = use default via kiteClientFactory
	kiteClientFactory KiteClientFactory  // required for defaultBrokerProvider fallback
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

// SetBrokerProvider overrides the default Kite API client with a custom provider (for testing).
func (b *BriefingService) SetBrokerProvider(p BrokerDataProvider) {
	if b != nil {
		b.brokerProvider = p
	}
}

// SetKiteClientFactory wires the factory used by the default broker provider.
// Production wires this during app bootstrap; tests may leave it nil when they
// override the broker provider via SetBrokerProvider.
func (b *BriefingService) SetKiteClientFactory(f KiteClientFactory) {
	if b != nil {
		b.kiteClientFactory = f
	}
}

// broker returns the BrokerDataProvider, defaulting to the real kiteconnect client.
func (b *BriefingService) broker() BrokerDataProvider {
	if b.brokerProvider != nil {
		return b.brokerProvider
	}
	return &defaultBrokerProvider{factory: b.kiteClientFactory}
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
	// Triggered alerts since yesterday's close (3:30 PM IST previous trading day).
	prevClose := previousTradingDayClose(now)
	triggered := b.recentlyTriggeredAlerts(email, prevClose)

	// Token status
	_, storedAt, hasToken := b.tokens.GetToken(email)
	tokenValid := hasToken && !b.tokens.IsExpired(storedAt)
	tokenStatus := "not_found"
	if hasToken && tokenValid {
		tokenStatus = "valid"
	} else if hasToken {
		tokenStatus = "expired"
	}

	// Fetch portfolio data if token is valid
	var data morningBriefingData
	data.DateStr = dateStr
	data.Triggered = triggered
	data.TokenStatus = tokenStatus
	data.Now = now

	accessToken, storedAt, hasToken := b.tokens.GetToken(email)
	if hasToken && !b.tokens.IsExpired(storedAt) {
		apiKey := b.creds.GetAPIKey(email)
		if apiKey != "" {
			bp := b.broker()

			// Portfolio day P&L from holdings
			holdings, err := bp.GetHoldings(apiKey, accessToken)
			if err == nil && len(holdings) > 0 {
				// Aggregate broker DayChange (float64) into Money. Wrap
				// once at the assignment seam — broker types stay primitive
				// (out-of-scope for Slice 3); Money entry happens here.
				var dayPnL float64
				for _, h := range holdings {
					dayPnL += h.DayChange
				}
				data.HoldingsDayPnL = domain.NewINR(dayPnL)
				data.HoldingsCount = len(holdings)
				data.HasHoldings = true
			}

			// Margin available
			margins, err := bp.GetUserMargins(apiKey, accessToken)
			if err == nil {
				data.MarginAvailable = margins.Equity.Net
				data.HasMargin = true
			}

			// Index levels (NIFTY 50, BANK NIFTY)
			ltpResp, err := bp.GetLTP(apiKey, accessToken, "NSE:NIFTY 50", "NSE:NIFTY BANK")
			if err == nil {
				if nifty, ok := ltpResp["NSE:NIFTY 50"]; ok {
					data.NiftyLTP = nifty.LastPrice
					data.HasNifty = true
				}
				if bankNifty, ok := ltpResp["NSE:NIFTY BANK"]; ok {
					data.BankNiftyLTP = bankNifty.LastPrice
					data.HasBankNifty = true
				}
			}
		}
	}

	return formatMorningBriefing(data)
}

// morningBriefingData holds pre-fetched data for morning briefing formatting.
//
// HoldingsDayPnL is typed Money (Slice 3 of the Money sweep). Internal
// aggregation uses primitive sum (broker DayChange is float64) and wraps
// once at the assignment seam; format helper drops to float at boundary.
type morningBriefingData struct {
	DateStr        string
	Triggered      []*Alert
	TokenStatus    string // "valid", "expired", "not_found"
	Now            time.Time
	HasHoldings    bool
	HoldingsDayPnL domain.Money
	HoldingsCount  int
	HasMargin      bool
	MarginAvailable float64
	HasNifty       bool
	NiftyLTP       float64
	HasBankNifty   bool
	BankNiftyLTP   float64
}

// formatMorningBriefing formats a morning briefing from pre-fetched data. Pure function, testable.
func formatMorningBriefing(data morningBriefingData) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\U0001F305 <b>Morning Briefing — %s</b>\n\n", html.EscapeString(data.DateStr)))

	// Triggered alerts
	if len(data.Triggered) > 0 {
		sb.WriteString(fmt.Sprintf("Alerts triggered overnight: %d\n", len(data.Triggered)))
		for _, a := range data.Triggered {
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
	switch data.TokenStatus {
	case "valid":
		sb.WriteString("Token status: Valid \u2713\n")
	case "expired":
		sb.WriteString("Token status: <b>Expired</b> \u2717 (re-login required)\n")
	default:
		sb.WriteString("Token status: <b>Not found</b> \u2717\n")
	}

	// Portfolio data
	if data.HasHoldings {
		sb.WriteString(fmt.Sprintf("\nPortfolio: %s day P&amp;L (%d stocks)\n", formatRupee(data.HoldingsDayPnL.Float64()), data.HoldingsCount))
	}
	if data.HasMargin {
		sb.WriteString(fmt.Sprintf("Margin available: \u20B9%.0f\n", data.MarginAvailable))
	}
	if data.HasNifty || data.HasBankNifty {
		sb.WriteString("\n<b>Indices:</b>\n")
		if data.HasNifty {
			sb.WriteString(fmt.Sprintf("  NIFTY 50: \u20B9%.2f\n", data.NiftyLTP))
		}
		if data.HasBankNifty {
			sb.WriteString(fmt.Sprintf("  BANK NIFTY: \u20B9%.2f\n", data.BankNiftyLTP))
		}
	}
	sb.WriteString("\n")

	// Market timing
	now := data.Now
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
	bp := b.broker()

	var data dailySummaryData
	data.DateStr = dateStr

	holdings, err := bp.GetHoldings(apiKey, accessToken)
	if err != nil {
		b.logger.Error("Briefing: failed to fetch holdings", "email", email, "error", err)
		data.HoldingsErr = true
	} else {
		data.HoldingsCount = len(holdings)
		// Aggregate broker DayChange (float64) into Money. Sum primitive
		// then wrap once — avoids Money.Add roundtrip per holding (typical
		// 10-100 holdings per user).
		var dayPnL float64
		for _, h := range holdings {
			dayPnL += h.DayChange
			if h.DayChangePercentage != 0 {
				data.Changes = append(data.Changes, stockChange{Symbol: h.Tradingsymbol, Percent: h.DayChangePercentage})
			}
		}
		data.HoldingsDayPnL = domain.NewINR(dayPnL)
	}

	positions, err := bp.GetPositions(apiKey, accessToken)
	if err != nil {
		b.logger.Error("Briefing: failed to fetch positions", "email", email, "error", err)
		data.PositionsErr = true
	} else {
		data.PositionsCount = len(positions.Day)
		// Aggregate broker PnL (signed float64) into Money. Sign is
		// preserved through Money — losses are negative, profits positive.
		var positionsPnL float64
		for _, p := range positions.Day {
			positionsPnL += p.PnL
		}
		data.PositionsPnL = domain.NewINR(positionsPnL)
	}

	return formatDailySummary(data)
}

// dailySummaryData holds pre-fetched data for daily summary formatting.
//
// HoldingsDayPnL + PositionsPnL are typed Money (Slice 3 of the Money
// sweep). The format helper boundary drops to float64 via .Float64();
// internal aggregation uses primitive sum + Money wrap at assignment.
type dailySummaryData struct {
	DateStr        string
	HoldingsErr    bool
	HoldingsDayPnL domain.Money
	HoldingsCount  int
	Changes        []stockChange
	PositionsErr   bool
	PositionsPnL   domain.Money
	PositionsCount int
}

// formatDailySummary formats a daily P&L summary from pre-fetched data. Pure function, testable.
func formatDailySummary(data dailySummaryData) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\U0001F4CA <b>Daily Summary — %s</b>\n\n", html.EscapeString(data.DateStr)))

	if data.HoldingsErr {
		sb.WriteString("Holdings P&amp;L: <i>unavailable</i>\n")
	} else {
		sb.WriteString(fmt.Sprintf("Holdings P&amp;L: %s (%d stocks)\n",
			formatRupee(data.HoldingsDayPnL.Float64()), data.HoldingsCount))
	}

	if data.PositionsErr {
		sb.WriteString("Positions P&amp;L: <i>unavailable</i>\n")
	} else {
		sb.WriteString(fmt.Sprintf("Positions P&amp;L: %s (%d positions)\n",
			formatRupee(data.PositionsPnL.Float64()), data.PositionsCount))
	}

	// Net = Holdings + Positions. Money.Add is currency-aware; on
	// mismatch (impossible here, both INR) fall back to primitive sum.
	var netPnL domain.Money
	if sum, err := data.HoldingsDayPnL.Add(data.PositionsPnL); err == nil {
		netPnL = sum
	} else {
		netPnL = domain.NewINR(data.HoldingsDayPnL.Float64() + data.PositionsPnL.Float64())
	}
	sb.WriteString(fmt.Sprintf("<b>Net Day P&amp;L: %s</b>\n", formatRupee(netPnL.Float64())))

	// Top gainers and losers from holdings.
	if len(data.Changes) > 0 {
		sort.Slice(data.Changes, func(i, j int) bool { return data.Changes[i].Percent > data.Changes[j].Percent })
		sb.WriteString("\n")

		// Top gainers (up to 3)
		gainers := filterPositiveChanges(data.Changes, 3)
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
		losers := filterNegativeChanges(data.Changes, 3)
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

// misPosition holds a single MIS position for formatting.
//
// PnL is typed Money (Slice 3); sign-preserving — domain.NewINR accepts
// any sign so losses (negative) are preserved through the wrap.
type misPosition struct {
	Symbol   string
	Quantity int
	PnL      domain.Money
}

// filterMISPositions extracts open MIS positions from a Kite Positions response.
func filterMISPositions(positions kiteconnect.Positions) []misPosition {
	var open []misPosition
	for _, p := range positions.Net {
		if p.Quantity != 0 && strings.ToUpper(p.Product) == "MIS" {
			open = append(open, misPosition{Symbol: p.Tradingsymbol, Quantity: p.Quantity, PnL: domain.NewINR(p.PnL)})
		}
	}
	return open
}

// formatMISWarning formats a MIS square-off warning message. Pure function, testable.
func formatMISWarning(open []misPosition) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\u26A0\uFE0F <b>MIS Square-Off Warning</b>\n\n"))
	sb.WriteString(fmt.Sprintf("You have <b>%d open MIS position(s)</b> that will be auto-squared off around 3:15-3:20 PM IST.\n\n", len(open)))

	// totalPnL accumulates Money via primitive sum then formats once at the
	// end. Same pattern as buildDailySummary aggregation seam.
	var totalPnL float64
	for _, p := range open {
		direction := "LONG"
		if p.Quantity < 0 {
			direction = "SHORT"
		}
		sb.WriteString(fmt.Sprintf("  \u2022 %s: %s %d @ %s\n",
			html.EscapeString(p.Symbol), direction, abs(p.Quantity), formatRupee(p.PnL.Float64())))
		totalPnL += p.PnL.Float64()
	}
	sb.WriteString(fmt.Sprintf("\nMIS P&amp;L: <b>%s</b>\n", formatRupee(totalPnL)))
	sb.WriteString("\nAction: Close manually or convert to CNC/NRML to carry overnight.")
	return sb.String()
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

	bp := b.broker()

	for email, chatID := range chatIDs {
		accessToken, storedAt, hasToken := b.tokens.GetToken(email)
		if !hasToken || b.tokens.IsExpired(storedAt) {
			continue
		}

		apiKey := b.creds.GetAPIKey(email)
		if apiKey == "" {
			continue
		}

		positions, err := bp.GetPositions(apiKey, accessToken)
		if err != nil {
			b.logger.Error("MIS warning: failed to fetch positions", "email", email, "error", err)
			continue
		}

		open := filterMISPositions(positions)
		if len(open) == 0 {
			continue
		}

		msg := formatMISWarning(open)
		if err := b.notifier.SendHTMLMessage(chatID, msg); err != nil {
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
