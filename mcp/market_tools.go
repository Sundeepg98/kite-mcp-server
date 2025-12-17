package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
)

type QuotesTool struct{}

var quotesSchema = json.RawMessage(`{
	"type": "object",
	"properties": {
		"instruments": {
			"type": "array",
			"description": "Eg. ['NSE:INFY', 'NSE:SBIN']. This API returns the complete market data snapshot of up to 500 instruments in one go. It includes the quantity, OHLC, and Open Interest fields, and the complete bid/ask market depth amongst others. Instruments are identified by the exchange:tradingsymbol combination and are passed as values to the query parameter i which is repeated for every instrument. If there is no data available for a given key, the key will be absent from the response.",
			"items": {
				"type": "string"
			}
		}
	},
	"required": ["instruments"]
}`)

func (*QuotesTool) Definition() *mcp.Tool {
	return NewTool("get_quotes", "Get market data quotes for a list of instruments", quotesSchema)
}

func (*QuotesTool) Handler(manager *kc.Manager) ToolHandler {
	handler := NewToolHandler(manager)
	return func(request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := GetArguments(request)
		if err := ValidateRequired(args, "instruments"); err != nil {
			return NewToolResultError(err.Error()), nil
		}
		instrumentsList := SafeAssertStringArray(args["instruments"])
		return handler.WithKiteClient(request, "get_quotes", func(client *kiteconnect.Client) (*mcp.CallToolResult, error) {
			quotes, err := client.GetQuote(instrumentsList...)
			if err != nil {
				return NewToolResultError("Failed to get quotes"), nil
			}
			return handler.MarshalResponse(quotes, "get_quotes")
		})
	}
}

type InstrumentsSearchTool struct{}

var instrumentsSearchSchema = json.RawMessage(`{
	"type": "object",
	"properties": {
		"mode": {
			"type": "string",
			"description": "Search mode: 'search' for filtering/searching, 'get_by_id' for exact ID lookup, 'get_by_tradingsymbol' for exchange+tradingsymbol lookup, 'get_by_isin' for ISIN lookup, 'get_by_inst_token' for instrument token lookup, 'get_by_exch_token' for exchange token lookup",
			"default": "search",
			"enum": ["search", "get_by_id", "get_by_tradingsymbol", "get_by_isin", "get_by_inst_token", "get_by_exch_token"]
		},
		"verbosity": {
			"type": "string",
			"description": "Response verbosity: 'compact' returns essential fields only (recommended for initial searches), 'full' returns complete instrument details",
			"default": "compact",
			"enum": ["compact", "full"]
		},
		"query": {
			"type": "string",
			"description": "Search query (required for 'search' mode)"
		},
		"filter_on": {
			"type": "string",
			"description": "Filter on a specific field for 'search' mode. (Optional). [id(default)=exch:tradingsymbol, name=nice name of the instrument, tradingsymbol=used to trade in a specific exchange, isin=universal identifier for an instrument across exchanges], underlying=[query=underlying instrument, result=futures and options. note=query format -> exch:tradingsymbol where NSE/BSE:PNB converted to -> NFO/BFO:PNB for query since futures and options available under them]",
			"enum": ["id", "name", "isin", "tradingsymbol", "underlying"]
		},
		"id": {
			"type": "string",
			"description": "Instrument ID in format 'EXCHANGE:TRADINGSYMBOL' (required for 'get_by_id' mode)"
		},
		"exchange": {
			"type": "string",
			"description": "Exchange code (required for 'get_by_tradingsymbol' and 'get_by_exch_token' modes)"
		},
		"tradingsymbol": {
			"type": "string",
			"description": "Trading symbol (required for 'get_by_tradingsymbol' mode)"
		},
		"isin": {
			"type": "string",
			"description": "ISIN identifier (required for 'get_by_isin' mode)"
		},
		"inst_token": {
			"type": "number",
			"description": "Instrument token (required for 'get_by_inst_token' mode)"
		},
		"exch_token": {
			"type": "number",
			"description": "Exchange token (required for 'get_by_exch_token' mode)"
		},
		"from": {
			"type": "number",
			"description": "Starting index for pagination (0-based). Default: 0"
		},
		"limit": {
			"type": "number",
			"description": "Maximum number of instruments to return. If not specified, returns all matching instruments. When specified, response includes pagination metadata."
		}
	}
}`)

func (*InstrumentsSearchTool) Definition() *mcp.Tool {
	return NewTool("search_instruments",
		"Search instruments or get specific instruments by various identifiers. Use 'compact' verbosity for faster responses with essential fields only. Switch to 'full' when you need complete instrument details. Supports pagination for large result sets.",
		instrumentsSearchSchema,
	)
}

func (*InstrumentsSearchTool) Handler(manager *kc.Manager) ToolHandler {
	handler := NewToolHandler(manager)
	return func(request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := GetArguments(request)
		mode := SafeAssertString(args["mode"], "search")
		verbosity := SafeAssertString(args["verbosity"], "compact")

		// Track metrics for tool usage
		if manager.Metrics() != nil {
			manager.Metrics().IncrementDailyWithLabels("tool_calls", map[string]string{
				"tool": "search_instruments",
			})
			// Track mode and verbosity usage
			manager.Metrics().IncrementDailyWithLabels("instruments_search_mode", map[string]string{
				"mode": mode,
			})
			manager.Metrics().IncrementDailyWithLabels("instruments_search_verbosity", map[string]string{
				"verbosity": verbosity,
			})
		}

		if manager.Instruments == nil {
			return NewToolResultError("Instrument manager is not initialized."), nil
		}

		if manager.Instruments.Count() == 0 {
			manager.Logger.Warn("No instruments loaded, search may return incomplete results")
		}

		var out []instruments.Instrument
		var err error

		switch mode {
		case "get_by_id":
			if err := ValidateRequired(args, "id"); err != nil {
				return NewToolResultError(err.Error()), nil
			}
			id := SafeAssertString(args["id"], "")
			var instrument instruments.Instrument
			instrument, err = manager.Instruments.GetByID(id)
			if err == nil {
				out = []instruments.Instrument{instrument}
			}

		case "get_by_tradingsymbol":
			if err := ValidateRequired(args, "exchange", "tradingsymbol"); err != nil {
				return NewToolResultError(err.Error()), nil
			}
			exchange := SafeAssertString(args["exchange"], "")
			tradingsymbol := SafeAssertString(args["tradingsymbol"], "")
			var instrument instruments.Instrument
			instrument, err = manager.Instruments.GetByTradingsymbol(exchange, tradingsymbol)
			if err == nil {
				out = []instruments.Instrument{instrument}
			}

		case "get_by_isin":
			if err := ValidateRequired(args, "isin"); err != nil {
				return NewToolResultError(err.Error()), nil
			}
			isn := SafeAssertString(args["isin"], "")
			out, err = manager.Instruments.GetByISIN(isn)

		case "get_by_inst_token":
			if err := ValidateRequired(args, "inst_token"); err != nil {
				return NewToolResultError(err.Error()), nil
			}
			token := SafeAssertInt(args["inst_token"], 0)
			var instrument instruments.Instrument
			instrument, err = manager.Instruments.GetByInstToken(uint32(token))
			if err == nil {
				out = []instruments.Instrument{instrument}
			}

		case "get_by_exch_token":
			if err := ValidateRequired(args, "exchange", "exch_token"); err != nil {
				return NewToolResultError(err.Error()), nil
			}
			exchange := SafeAssertString(args["exchange"], "")
			exchToken := SafeAssertInt(args["exch_token"], 0)
			var instrument instruments.Instrument
			instrument, err = manager.Instruments.GetByExchToken(exchange, uint32(exchToken))
			if err == nil {
				out = []instruments.Instrument{instrument}
			}

		default: // "search" mode
			if err := ValidateRequired(args, "query"); err != nil {
				return NewToolResultError(err.Error()), nil
			}
			query := SafeAssertString(args["query"], "")
			filterOn := SafeAssertString(args["filter_on"], "id")

			switch filterOn {
			case "underlying":
				if strings.Contains(query, ":") {
					parts := strings.Split(query, ":")
					if len(parts) != 2 {
						return NewToolResultError("Invalid query format, specify exch:underlying, where exchange is BFO/NFO"), nil
					}
					exch := parts[0]
					underlying := parts[1]
					instrumentsList, _ := manager.Instruments.GetAllByUnderlying(exch, underlying)
					out = instrumentsList
				} else {
					exch := "NFO"
					underlying := query
					instrumentsList, _ := manager.Instruments.GetAllByUnderlying(exch, underlying)
					out = instrumentsList
				}
			default:
				instrumentsList := manager.Instruments.Filter(func(instrument instruments.Instrument) bool {
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
				out = instrumentsList
			}
		}

		if err != nil {
			return NewToolResultError("Instrument not found"), nil
		}

		params := ParsePaginationParams(args)
		originalLength := len(out)
		paginatedData := ApplyPagination(out, params)

		// Convert to appropriate format based on verbosity
		var finalData []interface{}
		if verbosity == "compact" {
			compacts := make([]instruments.Compact, len(paginatedData))
			for i, instrument := range paginatedData {
				compacts[i] = instrument.ToCompact()
			}
			finalData = make([]interface{}, len(compacts))
			for i, compact := range compacts {
				finalData[i] = compact
			}
		} else {
			finalData = make([]interface{}, len(paginatedData))
			for i, instrument := range paginatedData {
				finalData[i] = instrument
			}
		}

		var responseData interface{}
		if params.Limit > 0 {
			responseData = CreatePaginatedResponse(out, finalData, params, originalLength)
		} else {
			responseData = finalData
		}

		// Track result metrics
		if manager.Metrics() != nil {
			resultCount := len(out)
			manager.Metrics().IncrementDailyWithLabels("instruments_search_results", map[string]string{
				"mode":      mode,
				"verbosity": verbosity,
				"count":     fmt.Sprintf("%d", resultCount),
			})
		}

		return handler.MarshalResponse(responseData, "search_instruments")
	}
}

type HistoricalDataTool struct{}

var historicalDataSchema = json.RawMessage(`{
	"type": "object",
	"properties": {
		"instrument_token": {
			"type": "number",
			"description": "Instrument token (can be obtained from search_instruments tool)"
		},
		"from_date": {
			"type": "string",
			"description": "From date in YYYY-MM-DD HH:MM:SS format"
		},
		"to_date": {
			"type": "string",
			"description": "To date in YYYY-MM-DD HH:MM:SS format"
		},
		"interval": {
			"type": "string",
			"description": "Candle interval",
			"enum": ["minute", "day", "3minute", "5minute", "10minute", "15minute", "30minute", "60minute"]
		},
		"continuous": {
			"type": "boolean",
			"description": "Get continuous data (for futures and options)",
			"default": false
		},
		"oi": {
			"type": "boolean",
			"description": "Include open interest data",
			"default": false
		}
	},
	"required": ["instrument_token", "from_date", "to_date", "interval"]
}`)

func (*HistoricalDataTool) Definition() *mcp.Tool {
	return NewTool("get_historical_data", "Get historical price data for an instrument", historicalDataSchema)
}

func (*HistoricalDataTool) Handler(manager *kc.Manager) ToolHandler {
	handler := NewToolHandler(manager)
	return func(request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := GetArguments(request)
		if err := ValidateRequired(args, "instrument_token", "from_date", "to_date", "interval"); err != nil {
			return NewToolResultError(err.Error()), nil
		}
		instrumentToken := SafeAssertInt(args["instrument_token"], 0)
		fromDate, err := time.Parse("2006-01-02 15:04:05", SafeAssertString(args["from_date"], ""))
		if err != nil {
			return NewToolResultError("Failed to parse from_date, use format YYYY-MM-DD HH:MM:SS"), nil
		}
		toDate, err := time.Parse("2006-01-02 15:04:05", SafeAssertString(args["to_date"], ""))
		if err != nil {
			return NewToolResultError("Failed to parse to_date, use format YYYY-MM-DD HH:MM:SS"), nil
		}
		interval := SafeAssertString(args["interval"], "")
		continuous := SafeAssertBool(args["continuous"], false)
		oi := SafeAssertBool(args["oi"], false)

		return handler.WithKiteClient(request, "get_historical_data", func(client *kiteconnect.Client) (*mcp.CallToolResult, error) {
			historicalData, err := client.GetHistoricalData(
				instrumentToken,
				interval,
				fromDate,
				toDate,
				continuous,
				oi,
			)
			if err != nil {
				return NewToolResultError("Failed to get historical data"), nil
			}
			return handler.MarshalResponse(historicalData, "get_historical_data")
		})
	}
}

type LTPTool struct{}

var ltpSchema = json.RawMessage(`{
	"type": "object",
	"properties": {
		"instruments": {
			"type": "array",
			"description": "Eg. ['NSE:INFY', 'NSE:SBIN']. This API returns the lastest price for the given list of instruments in the format of exchange:tradingsymbol.",
			"items": {
				"type": "string"
			}
		}
	},
	"required": ["instruments"]
}`)

func (*LTPTool) Definition() *mcp.Tool {
	return NewTool("get_ltp", "Get latest trading prices for a list of instruments", ltpSchema)
}

func (*LTPTool) Handler(manager *kc.Manager) ToolHandler {
	handler := NewToolHandler(manager)
	return func(request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := GetArguments(request)
		if err := ValidateRequired(args, "instruments"); err != nil {
			return NewToolResultError(err.Error()), nil
		}
		instrumentsList := SafeAssertStringArray(args["instruments"])
		if len(instrumentsList) == 0 {
			return NewToolResultError("At least one instrument must be specified"), nil
		}
		return handler.WithKiteClient(request, "get_ltp", func(client *kiteconnect.Client) (*mcp.CallToolResult, error) {
			ltp, err := client.GetLTP(instrumentsList...)
			if err != nil {
				return NewToolResultError("Failed to get latest trading prices"), nil
			}
			return handler.MarshalResponse(ltp, "get_ltp")
		})
	}
}

type OHLCTool struct{}

var ohlcSchema = json.RawMessage(`{
	"type": "object",
	"properties": {
		"instruments": {
			"type": "array",
			"description": "Eg. ['NSE:INFY', 'NSE:SBIN']. This API returns OHLC data for the given list of instruments in the format of exchange:tradingsymbol.",
			"items": {
				"type": "string"
			}
		}
	},
	"required": ["instruments"]
}`)

func (*OHLCTool) Definition() *mcp.Tool {
	return NewTool("get_ohlc", "Get OHLC (Open, High, Low, Close) data for a list of instruments", ohlcSchema)
}

func (*OHLCTool) Handler(manager *kc.Manager) ToolHandler {
	handler := NewToolHandler(manager)
	return func(request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := GetArguments(request)
		if err := ValidateRequired(args, "instruments"); err != nil {
			return NewToolResultError(err.Error()), nil
		}
		instrumentsList := SafeAssertStringArray(args["instruments"])
		if len(instrumentsList) == 0 {
			return NewToolResultError("At least one instrument must be specified"), nil
		}
		return handler.WithKiteClient(request, "get_ohlc", func(client *kiteconnect.Client) (*mcp.CallToolResult, error) {
			ohlc, err := client.GetOHLC(instrumentsList...)
			if err != nil {
				return NewToolResultError("Failed to get OHLC data"), nil
			}
			return handler.MarshalResponse(ohlc, "get_ohlc")
		})
	}
}
