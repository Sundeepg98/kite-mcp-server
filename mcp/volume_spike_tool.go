package mcp

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// VolumeSpikeDetectorTool scans a list of instruments (defaulting to the
// user's current watchlist items) for unusual volume. An instrument is
// flagged when its current-session volume is >= `threshold` x the mean
// volume over the last `lookback_days` completed trading days.
//
// Intended as a pre-market / morning-scan helper: the trader sees which
// names on their watchlist are already trading above typical volume so
// they can decide which to monitor intraday.
type VolumeSpikeDetectorTool struct{}

// Defaults for volume-spike scan parameters. Chosen to work on a
// mid-sized watchlist without overloading Kite's historical endpoint.
const (
	volumeSpikeDefaultThreshold = 2.0
	volumeSpikeDefaultLookback  = 10
	volumeSpikeMaxLookback      = 60  // hard cap: beyond this the "typical" signal drifts
	volumeSpikeMaxInstruments   = 100 // matches the practical size of a power-user watchlist
	// volumeSpikeHistoricalPause is a small per-instrument delay to avoid
	// hammering Kite's historical endpoint (rate-limited at ~3 req/sec
	// per app). We're sequential here; this 50ms spacing keeps us well
	// under that ceiling even if the caller supplies ~100 instruments.
	volumeSpikeHistoricalPause = 50 * time.Millisecond
)

// volumeSpikeFlag describes a single instrument whose current volume
// crossed the threshold. Fields match the task brief exactly, plus a
// small `note` for anything interesting we want to surface (e.g., price
// above/below the lookback average).
type volumeSpikeFlag struct {
	Symbol               string  `json:"symbol"`
	Exchange             string  `json:"exchange"`
	CurrentVolume        int     `json:"current_volume"`
	AvgVolume            float64 `json:"avg_volume"`
	Ratio                float64 `json:"ratio"`
	CurrentPrice         float64 `json:"current_price"`
	AvgPriceLastNDays    float64 `json:"avg_price_last_n_days"`
	PriceChangeFromAvg   float64 `json:"price_change_from_avg_pct"`
	Note                 string  `json:"note,omitempty"`
}

// volumeSpikeSkipped records an instrument we couldn't scan (bad
// symbol, no historical data, suspended etc.) so the caller has
// visibility without the whole request failing.
type volumeSpikeSkipped struct {
	Instrument string `json:"instrument"`
	Reason     string `json:"reason"`
}

// volumeSpikeResponse is the structured payload returned to the caller.
type volumeSpikeResponse struct {
	Threshold    float64              `json:"threshold"`
	LookbackDays int                  `json:"lookback_days"`
	Scanned      int                  `json:"scanned"`
	Flagged      []volumeSpikeFlag    `json:"flagged"`
	Skipped      []volumeSpikeSkipped `json:"skipped,omitempty"`
	Message      string               `json:"message,omitempty"`
}

func (*VolumeSpikeDetectorTool) Tool() mcp.Tool {
	return mcp.NewTool("volume_spike_detector",
		mcp.WithDescription("Scan instruments for unusual volume. Returns instruments where current volume exceeds the rolling average by a configurable threshold (default 2x). Useful for morning scans. Not investment advice."),
		mcp.WithTitleAnnotation("Volume Spike Detector"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithArray("instruments",
			mcp.Description("Optional list of instruments in EXCHANGE:SYMBOL format (e.g. ['NSE:RELIANCE', 'NSE:TCS']). If omitted, scans every item across all of the caller's watchlists."),
			mcp.Items(map[string]any{
				"type": "string",
			}),
		),
		mcp.WithNumber("threshold",
			mcp.Description("Volume ratio threshold — an instrument is flagged when current_volume >= threshold x avg_volume. Default 2.0."),
		),
		mcp.WithNumber("lookback_days",
			mcp.Description("Rolling window (in completed trading days) used to compute the average volume. Default 10, max 60."),
		),
	)
}

func (*VolumeSpikeDetectorTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "volume_spike_detector")

		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return mcp.NewToolResultError("Email required (OAuth must be enabled)"), nil
		}

		p := NewArgParser(request.GetArguments())
		requested := p.StringArray("instruments")
		threshold := p.Float("threshold", volumeSpikeDefaultThreshold)
		lookback := p.Int("lookback_days", volumeSpikeDefaultLookback)

		if threshold <= 0 {
			return mcp.NewToolResultError("threshold must be > 0"), nil
		}
		if lookback < 2 {
			return mcp.NewToolResultError("lookback_days must be >= 2"), nil
		}
		if lookback > volumeSpikeMaxLookback {
			lookback = volumeSpikeMaxLookback
		}

		return handler.WithSession(ctx, "volume_spike_detector", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			// Resolve the list of instruments to scan. Either the
			// caller-supplied list, or everything on their watchlists.
			instrumentIDs, skipped := resolveVolumeSpikeInstruments(handler, email, requested)
			if len(instrumentIDs) == 0 {
				if len(requested) == 0 {
					return mcp.NewToolResultText("No watchlist items to scan. Add instruments to a watchlist or pass 'instruments' explicitly."), nil
				}
				return mcp.NewToolResultText("No valid instruments to scan."), nil
			}
			if len(instrumentIDs) > volumeSpikeMaxInstruments {
				return mcp.NewToolResultError(fmt.Sprintf("too many instruments: got %d, max is %d", len(instrumentIDs), volumeSpikeMaxInstruments)), nil
			}

			// One batched quotes call covers every instrument's current
			// volume + price. Kite supports up to 500 symbols per call;
			// we're capped at 100 above so this is always a single RPC.
			quotesRaw, err := manager.QueryBus().DispatchWithResult(ctx, cqrs.GetQuotesQuery{
				Email:       session.Email,
				Instruments: instrumentIDs,
			})
			if err != nil {
				handler.trackToolError(ctx, "volume_spike_detector", "quotes_error")
				return mcp.NewToolResultError(fmt.Sprintf("failed to fetch current quotes: %s", err.Error())), nil
			}
			quotes, ok := quotesRaw.(map[string]broker.Quote)
			if !ok {
				return mcp.NewToolResultError("internal: unexpected quotes result type"), nil
			}

			// Compute the from/to window for historical fetches. We add
			// a small weekend/holiday buffer (1.7x days) so a 10-day
			// lookback reliably gets 10 *trading* days of candles.
			now := time.Now()
			from := now.AddDate(0, 0, -int(math.Ceil(float64(lookback)*1.7))-1)

			flagged := make([]volumeSpikeFlag, 0, len(instrumentIDs))
			for i, id := range instrumentIDs {
				// Throttle sequential historical calls — Kite's
				// historical endpoint is rate-limited per app. 50ms
				// spacing keeps us safely under 3 req/sec even if the
				// watchlist has ~100 names.
				if i > 0 {
					time.Sleep(volumeSpikeHistoricalPause)
				}

				q, qok := quotes[id]
				if !qok {
					skipped = append(skipped, volumeSpikeSkipped{Instrument: id, Reason: "no current quote"})
					continue
				}
				if q.Volume <= 0 {
					skipped = append(skipped, volumeSpikeSkipped{Instrument: id, Reason: "current volume is zero (not trading?)"})
					continue
				}

				// Resolve the instrument token needed by the historical
				// endpoint. We got it from the caller as a string ID so
				// go via the instruments manager.
				instMgr := handler.deps.Instruments.InstrumentsManager()
				if instMgr == nil {
					skipped = append(skipped, volumeSpikeSkipped{Instrument: id, Reason: "instruments store not available"})
					continue
				}
				inst, err := instMgr.GetByID(id)
				if err != nil {
					skipped = append(skipped, volumeSpikeSkipped{Instrument: id, Reason: "instrument not found"})
					continue
				}

				histRaw, err := manager.QueryBus().DispatchWithResult(ctx, cqrs.GetHistoricalDataQuery{
					Email:           session.Email,
					InstrumentToken: int(inst.InstrumentToken),
					Interval:        "day",
					From:            from,
					To:              now,
				})
				if err != nil {
					// Skip, don't fail the whole scan — a single
					// suspended / newly-listed instrument shouldn't take
					// out the rest of the run.
					handler.deps.Logger.Warn("volume_spike_detector: historical fetch failed",
						"instrument", id,
						"error", err)
					skipped = append(skipped, volumeSpikeSkipped{Instrument: id, Reason: fmt.Sprintf("historical data unavailable: %s", err.Error())})
					continue
				}
				candles, ok := histRaw.([]broker.HistoricalCandle)
				if !ok {
					skipped = append(skipped, volumeSpikeSkipped{Instrument: id, Reason: "historical: unexpected result type"})
					continue
				}

				// Drop today's in-progress candle if the broker returned
				// it — we only want completed sessions for the average.
				completed := filterCompletedCandles(candles, now)
				if len(completed) < 2 {
					skipped = append(skipped, volumeSpikeSkipped{Instrument: id, Reason: fmt.Sprintf("insufficient history: %d completed candles", len(completed))})
					continue
				}
				// Trim to the requested lookback window (tail-end).
				if len(completed) > lookback {
					completed = completed[len(completed)-lookback:]
				}

				avgVol, avgPrice := averageVolumeAndClose(completed)
				if avgVol <= 0 {
					skipped = append(skipped, volumeSpikeSkipped{Instrument: id, Reason: "avg volume is zero over lookback window"})
					continue
				}

				ratio := float64(q.Volume) / avgVol
				if ratio < threshold {
					continue
				}

				flag := volumeSpikeFlag{
					Symbol:            inst.Tradingsymbol,
					Exchange:          inst.Exchange,
					CurrentVolume:     q.Volume,
					AvgVolume:         avgVol,
					Ratio:             ratio,
					CurrentPrice:      q.LastPrice,
					AvgPriceLastNDays: avgPrice,
				}
				if avgPrice > 0 {
					flag.PriceChangeFromAvg = (q.LastPrice - avgPrice) / avgPrice * 100
					if flag.PriceChangeFromAvg > 2 {
						flag.Note = "price up vs recent average"
					} else if flag.PriceChangeFromAvg < -2 {
						flag.Note = "price down vs recent average"
					}
				}
				flagged = append(flagged, flag)
			}

			resp := &volumeSpikeResponse{
				Threshold:    threshold,
				LookbackDays: lookback,
				Scanned:      len(instrumentIDs),
				Flagged:      flagged,
				Skipped:      skipped,
			}

			// Friendly message when we couldn't get useful data for
			// anything — matches the task brief's "insufficient history"
			// UX.
			if len(flagged) == 0 && len(skipped) == len(instrumentIDs) {
				resp.Message = "insufficient history — no instruments had enough completed candles to compute a baseline"
			}

			return handler.MarshalResponse(resp, "volume_spike_detector")
		})
	}
}

// resolveVolumeSpikeInstruments returns the list of EXCHANGE:SYMBOL
// identifiers to scan. If `requested` is non-empty it's normalised and
// returned as-is; otherwise every item across every watchlist owned by
// `email` is used.
//
// Returns (ids, skipped). `skipped` captures malformed entries in the
// caller-supplied list so we can surface them to the user without
// failing the whole call.
func resolveVolumeSpikeInstruments(handler *ToolHandler, email string, requested []string) ([]string, []volumeSpikeSkipped) {
	seen := make(map[string]bool)
	ids := make([]string, 0)
	skipped := make([]volumeSpikeSkipped, 0)

	if len(requested) > 0 {
		for _, raw := range requested {
			id := strings.ToUpper(strings.TrimSpace(raw))
			if id == "" {
				continue
			}
			if !strings.Contains(id, ":") {
				skipped = append(skipped, volumeSpikeSkipped{Instrument: raw, Reason: "invalid format (expected EXCHANGE:SYMBOL)"})
				continue
			}
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
		return ids, skipped
	}

	// Fallback: use the caller's watchlist items.
	wstore := handler.deps.Watchlist.WatchlistStore()
	if wstore == nil {
		return ids, skipped
	}
	items := wstore.GetAllItems(email)
	for _, it := range items {
		id := it.Exchange + ":" + it.Tradingsymbol
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids, skipped
}

// filterCompletedCandles drops the final candle if its date is today
// (an in-progress session is not a fair member of the "average volume"
// baseline). Candles are returned in the same order the broker supplied
// them.
func filterCompletedCandles(candles []broker.HistoricalCandle, now time.Time) []broker.HistoricalCandle {
	if len(candles) == 0 {
		return candles
	}
	last := candles[len(candles)-1]
	if sameYMD(last.Date, now) {
		return candles[:len(candles)-1]
	}
	return candles
}

// sameYMD returns true if a and b fall on the same calendar day,
// ignoring any time-of-day difference. We don't care about timezones
// because the broker consistently returns dates in IST market time.
func sameYMD(a, b time.Time) bool {
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	return ay == by && am == bm && ad == bd
}

// averageVolumeAndClose returns the arithmetic mean of volumes and
// closing prices across the supplied candles. Returns (0, 0) if the
// slice is empty.
func averageVolumeAndClose(candles []broker.HistoricalCandle) (float64, float64) {
	if len(candles) == 0 {
		return 0, 0
	}
	var volSum, priceSum float64
	for _, c := range candles {
		volSum += float64(c.Volume)
		priceSum += c.Close
	}
	n := float64(len(candles))
	return volSum / n, priceSum / n
}
