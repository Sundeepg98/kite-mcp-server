package mcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
)

// ltpCache caches LTP responses for 30 seconds to reduce API calls.
var ltpCache = NewToolCache(30 * time.Second)

// ShutdownLtpCache stops the ltpCache background cleanup goroutine. Called
// from TestMain in packages that import mcp/ so goleak-style sentinels see
// a clean goroutine dump at process exit. Production never calls this —
// the singleton lives for the process lifetime by design.
//
// Exported (not internal package-level) so tests in dependent packages
// (app/, and any future package that imports mcp/) can call it via their
// own TestMain. See mcp/test_main_test.go for the canonical usage.
func ShutdownLtpCache() {
	ltpCache.Close()
}

type QuotesTool struct{}

func (*QuotesTool) Tool() mcp.Tool {
	return mcp.NewTool("get_quotes",
		mcp.WithDescription("Get market data quotes for a list of instruments"),
		mcp.WithTitleAnnotation("Get Quotes"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithArray("instruments",
			mcp.Description("Eg. ['NSE:INFY', 'NSE:SBIN']. This API returns the complete market data snapshot of up to 500 instruments in one go. It includes the quantity, OHLC, and Open Interest fields, and the complete bid/ask market depth amongst others. Instruments are identified by the exchange:tradingsymbol combination and are passed as values to the query parameter i which is repeated for every instrument. If there is no data available for a given key, the key will be absent from the response."),
			mcp.Required(),
			mcp.Items(map[string]any{
				"type": "string",
			}),
		),
	)
}

func (*QuotesTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "get_quotes")
		p := NewArgParser(request.GetArguments())

		// Validate required parameters
		if err := p.Required("instruments"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		instruments := p.StringArray("instruments")
		if len(instruments) == 0 {
			return mcp.NewToolResultError("At least one instrument must be specified"), nil
		}
		if len(instruments) > 500 {
			return mcp.NewToolResultError("Too many instruments: maximum 500 allowed per request"), nil
		}

		return handler.WithSession(ctx, "get_quotes", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			raw, err := manager.QueryBus().DispatchWithResult(ctx, cqrs.GetQuotesQuery{Email: session.Email, Instruments: instruments})
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to get quotes: %s", err.Error())), nil
			}
			quotes := raw.(map[string]broker.Quote)

			return handler.MarshalResponse(quotes, "get_quotes")
		})
	}
}

type InstrumentsSearchTool struct{}

func (*InstrumentsSearchTool) Tool() mcp.Tool {
	return mcp.NewTool("search_instruments", // The filter_on parameter already supports multiple search modes (id, name, isin, tradingsymbol, underlying). Additional instruments.Manager queries can be exposed via new filter_on enum values if needed.
		mcp.WithDescription("Search instruments. Supports pagination for large result sets."),
		mcp.WithTitleAnnotation("Search Instruments"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("query",
			mcp.Description("Search query"),
			mcp.Required(),
		),
		mcp.WithString("filter_on",
			mcp.Description("Filter on a specific field. (Optional). [id(default)=exch:tradingsymbol, name=nice name of the instrument, tradingsymbol=used to trade in a specific exchange, isin=universal identifier for an instrument across exchanges], underlying=[query=underlying instrument, result=futures and options. note=query format -> exch:tradingsymbol where NSE/BSE:PNB converted to -> NFO/BFO:PNB for query since futures and options available under them]"),
			mcp.Enum("id", "name", "isin", "tradingsymbol", "underlying"),
		),
		mcp.WithNumber("from",
			mcp.Description("Starting index for pagination (0-based). Default: 0"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum number of instruments to return. If not specified, returns all matching instruments. When specified, response includes pagination metadata."),
		),
	)
}

func (*InstrumentsSearchTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "search_instruments")
		p := NewArgParser(request.GetArguments())

		// Validate required parameters
		if err := p.Required("query"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		query := p.String("query", "")
		filterOn := p.String("filter_on", "id")

		// Don't call UpdateInstruments() here since it might already be happening in another thread
		// But we do need to ensure instruments are loaded
		if manager.Instruments.Count() == 0 {
			manager.Logger.Warn("No instruments loaded, search may return incomplete results")
		}

		var out []instruments.Instrument

		switch filterOn {
		case "underlying":
			// query needs to be split by `:` into exch and underlying.
			if strings.Contains(query, ":") {
				parts := strings.Split(query, ":")
				if len(parts) != 2 {
					return mcp.NewToolResultError("Invalid query format, specify exch:underlying, where exchange is BFO/NFO"), nil
				}

				exch := parts[0]
				underlying := parts[1]

				instruments, _ := manager.Instruments.GetAllByUnderlying(exch, underlying)
				out = instruments
			} else {
				// Assume query is just the underlying symbol and try. Just to save prompt calls.
				exch := "NFO"
				underlying := query

				instruments, _ := manager.Instruments.GetAllByUnderlying(exch, underlying)
				out = instruments
			}
		default:
			instruments := manager.Instruments.Filter(func(instrument instruments.Instrument) bool {
				switch filterOn {
				case "name":
					return strings.Contains(strings.ToLower(instrument.Name), strings.ToLower(query))
				case "tradingsymbol":
					return strings.Contains(strings.ToLower(instrument.Tradingsymbol), strings.ToLower(query))
				case "isin":
					return strings.Contains(strings.ToLower(instrument.ISIN), strings.ToLower(query))
				case "id":
					return strings.Contains(strings.ToLower(instrument.ID), strings.ToLower(query))
				default:
					return strings.Contains(strings.ToLower(instrument.ID), strings.ToLower(query))
				}
			})

			out = instruments
		}

		// Parse pagination parameters
		params := ParsePaginationParams(p.Raw())

		// Apply pagination if limit is specified
		originalLength := len(out)
		paginatedData := ApplyPagination(out, params)

		// Create response with pagination metadata if pagination was applied
		var responseData any
		if params.Limit > 0 {
			// Convert to []any for pagination response
			interfaceData := make([]any, len(paginatedData))
			for i, instrument := range paginatedData {
				interfaceData[i] = instrument
			}
			responseData = CreatePaginatedResponse(out, interfaceData, params, originalLength)
		} else {
			responseData = paginatedData
		}

		return handler.MarshalResponse(responseData, "search_instruments")
	}
}

type HistoricalDataTool struct{}

func (*HistoricalDataTool) Tool() mcp.Tool {
	return mcp.NewTool("get_historical_data",
		mcp.WithDescription("Get historical price data for an instrument"),
		mcp.WithTitleAnnotation("Get Historical Data"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithNumber("instrument_token",
			mcp.Description("Instrument token (can be obtained from search_instruments tool)"),
			mcp.Required(),
		),
		mcp.WithString("from_date",
			mcp.Description("From date in YYYY-MM-DD HH:MM:SS format"),
			mcp.Required(),
		),
		mcp.WithString("to_date",
			mcp.Description("To date in YYYY-MM-DD HH:MM:SS format"),
			mcp.Required(),
		),
		mcp.WithString("interval",
			mcp.Description("Candle interval"),
			mcp.Required(),
			mcp.Enum("minute", "day", "3minute", "5minute", "10minute", "15minute", "30minute", "60minute"),
		),
		mcp.WithBoolean("continuous",
			mcp.Description("Get continuous data (for futures and options)"),
			mcp.DefaultBool(false),
		),
		mcp.WithBoolean("oi",
			mcp.Description("Include open interest data"),
			mcp.DefaultBool(false),
		),
	)
}

func (*HistoricalDataTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "get_historical_data")
		p := NewArgParser(request.GetArguments())

		// Validate required parameters
		if err := p.Required("instrument_token", "from_date", "to_date", "interval"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		// Parse instrument token
		instrumentToken := p.Int("instrument_token", 0)

		// Parse from_date and to_date
		fromDate, err := time.Parse("2006-01-02 15:04:05", p.String("from_date", ""))
		if err != nil {
			return mcp.NewToolResultError("Failed to parse from_date, use format YYYY-MM-DD HH:MM:SS"), nil
		}

		toDate, err := time.Parse("2006-01-02 15:04:05", p.String("to_date", ""))
		if err != nil {
			return mcp.NewToolResultError("Failed to parse to_date, use format YYYY-MM-DD HH:MM:SS"), nil
		}

		if fromDate.After(toDate) {
			return mcp.NewToolResultError("from_date must be before to_date"), nil
		}

		// Get other parameters
		interval := p.String("interval", "")
		// Note: continuous and oi params are accepted by the tool schema
		// but are Zerodha-specific; the broker.Client interface does not
		// expose them. They are silently ignored for now.

		return handler.WithSession(ctx, "get_historical_data", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			raw, err := manager.QueryBus().DispatchWithResult(ctx, cqrs.GetHistoricalDataQuery{
				Email:           session.Email,
				InstrumentToken: instrumentToken,
				Interval:        interval,
				From:            fromDate,
				To:              toDate,
			})
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to get historical data: %s", err.Error())), nil
			}
			historicalData := raw.([]broker.HistoricalCandle)

			return handler.MarshalResponse(historicalData, "get_historical_data")
		})
	}
}

type LTPTool struct{}

func (*LTPTool) Tool() mcp.Tool {
	return mcp.NewTool("get_ltp",
		mcp.WithDescription("Get latest trading prices for a list of instruments"),
		mcp.WithTitleAnnotation("Get LTP"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithArray("instruments",
			mcp.Description("Eg. ['NSE:INFY', 'NSE:SBIN']. This API returns the lastest price for the given list of instruments in the format of exchange:tradingsymbol."),
			mcp.Required(),
			mcp.Items(map[string]any{
				"type": "string",
			}),
		),
	)
}

func (*LTPTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "get_ltp")
		p := NewArgParser(request.GetArguments())

		// Validate required parameters
		if err := p.Required("instruments"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		instruments := p.StringArray("instruments")
		if len(instruments) == 0 {
			return mcp.NewToolResultError("At least one instrument must be specified"), nil
		}
		if len(instruments) > 500 {
			return mcp.NewToolResultError("Too many instruments: maximum 500 allowed per request"), nil
		}

		return handler.WithSession(ctx, "get_ltp", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			cacheKey := CacheKey("get_ltp", session.Email, strings.Join(instruments, ","))
			if cached, ok := ltpCache.Get(cacheKey); ok {
				return handler.MarshalResponse(cached, "get_ltp")
			}

			raw, err := manager.QueryBus().DispatchWithResult(ctx, cqrs.GetLTPQuery{Email: session.Email, Instruments: instruments})
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to get latest trading prices: %s", err.Error())), nil
			}
			ltp := raw.(map[string]broker.LTP)

			ltpCache.Set(cacheKey, ltp)
			return handler.MarshalResponse(ltp, "get_ltp")
		})
	}
}

type OHLCTool struct{}

func (*OHLCTool) Tool() mcp.Tool {
	return mcp.NewTool("get_ohlc",
		mcp.WithDescription("Get OHLC (Open, High, Low, Close) data for a list of instruments"),
		mcp.WithTitleAnnotation("Get OHLC"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithArray("instruments",
			mcp.Description("Eg. ['NSE:INFY', 'NSE:SBIN']. This API returns OHLC data for the given list of instruments in the format of exchange:tradingsymbol."),
			mcp.Required(),
			mcp.Items(map[string]any{
				"type": "string",
			}),
		),
	)
}

func (*OHLCTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "get_ohlc")
		p := NewArgParser(request.GetArguments())

		// Validate required parameters
		if err := p.Required("instruments"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		instruments := p.StringArray("instruments")
		if len(instruments) == 0 {
			return mcp.NewToolResultError("At least one instrument must be specified"), nil
		}
		if len(instruments) > 500 {
			return mcp.NewToolResultError("Too many instruments: maximum 500 allowed per request"), nil
		}

		return handler.WithSession(ctx, "get_ohlc", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			raw, err := manager.QueryBus().DispatchWithResult(ctx, cqrs.GetOHLCQuery{Email: session.Email, Instruments: instruments})
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to get OHLC data: %s", err.Error())), nil
			}
			ohlc := raw.(map[string]broker.OHLC)

			return handler.MarshalResponse(ohlc, "get_ohlc")
		})
	}
}
