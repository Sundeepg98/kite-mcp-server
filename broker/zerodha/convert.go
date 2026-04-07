package zerodha

import (
	"fmt"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/broker"
)

// --- Profile ---

func convertProfile(p kiteconnect.UserProfile) broker.Profile {
	return broker.Profile{
		UserID:    p.UserID,
		UserName:  p.UserName,
		Email:     p.Email,
		Broker:    broker.Zerodha,
		Exchanges: p.Exchanges,
		Products:  p.Products,
	}
}

// --- Margins ---

func convertMargins(m kiteconnect.AllMargins) broker.Margins {
	return broker.Margins{
		Equity:    convertSegmentMargin(m.Equity),
		Commodity: convertSegmentMargin(m.Commodity),
	}
}

func convertSegmentMargin(m kiteconnect.Margins) broker.SegmentMargin {
	avail := m.Available
	used := m.Used

	available := avail.Cash + avail.Collateral + avail.IntradayPayin + avail.OpeningBalance
	usedTotal := used.Debits + used.Exposure + used.Span + used.OptionPremium
	total := available + usedTotal

	return broker.SegmentMargin{
		Available: available,
		Used:      usedTotal,
		Total:     total,
	}
}

// --- Holdings ---

func convertHoldings(holdings kiteconnect.Holdings) []broker.Holding {
	out := make([]broker.Holding, len(holdings))
	for i, h := range holdings {
		out[i] = broker.Holding{
			Tradingsymbol: h.Tradingsymbol,
			Exchange:      h.Exchange,
			ISIN:          h.ISIN,
			Quantity:      h.Quantity,
			AveragePrice:  h.AveragePrice,
			LastPrice:     h.LastPrice,
			PnL:           h.PnL,
			DayChangePct:  h.DayChangePercentage,
			Product:       h.Product,
		}
	}
	return out
}

// --- Positions ---

func convertPositions(p kiteconnect.Positions) broker.Positions {
	return broker.Positions{
		Day: convertPositionSlice(p.Day),
		Net: convertPositionSlice(p.Net),
	}
}

func convertPositionSlice(positions []kiteconnect.Position) []broker.Position {
	out := make([]broker.Position, len(positions))
	for i, p := range positions {
		out[i] = broker.Position{
			Tradingsymbol: p.Tradingsymbol,
			Exchange:      p.Exchange,
			Product:       p.Product,
			Quantity:      p.Quantity,
			AveragePrice:  p.AveragePrice,
			LastPrice:     p.LastPrice,
			PnL:           p.PnL,
		}
	}
	return out
}

// --- Orders ---

func convertOrders(orders kiteconnect.Orders) []broker.Order {
	out := make([]broker.Order, len(orders))
	for i, o := range orders {
		out[i] = broker.Order{
			OrderID:         o.OrderID,
			Exchange:        o.Exchange,
			Tradingsymbol:   o.TradingSymbol,
			TransactionType: o.TransactionType,
			OrderType:       o.OrderType,
			Product:         o.Product,
			Quantity:        int(o.Quantity),
			Price:           o.Price,
			TriggerPrice:    o.TriggerPrice,
			Status:          o.Status,
			FilledQuantity:  int(o.FilledQuantity),
			AveragePrice:    o.AveragePrice,
			OrderTimestamp:  o.OrderTimestamp.Time,
			StatusMessage:   o.StatusMessage,
			Tag:             o.Tag,
		}
	}
	return out
}

// --- Trades ---

func convertTrades(trades kiteconnect.Trades) []broker.Trade {
	out := make([]broker.Trade, len(trades))
	for i, t := range trades {
		out[i] = broker.Trade{
			TradeID:         t.TradeID,
			OrderID:         t.OrderID,
			Exchange:        t.Exchange,
			Tradingsymbol:   t.TradingSymbol,
			TransactionType: t.TransactionType,
			Quantity:        int(t.Quantity),
			Price:           t.AveragePrice,
			Product:         t.Product,
		}
	}
	return out
}

// --- OrderParams (broker -> kite) ---

func convertOrderParamsToKite(p broker.OrderParams) (string, kiteconnect.OrderParams) {
	variety := p.Variety
	if variety == "" {
		variety = kiteconnect.VarietyRegular
	}

	return variety, kiteconnect.OrderParams{
		Exchange:          p.Exchange,
		Tradingsymbol:     p.Tradingsymbol,
		TransactionType:   p.TransactionType,
		OrderType:         p.OrderType,
		Product:           p.Product,
		Quantity:          p.Quantity,
		Price:             p.Price,
		TriggerPrice:      p.TriggerPrice,
		Validity:          p.Validity,
		Tag:               p.Tag,
		DisclosedQuantity: p.DisclosedQty,
		MarketProtection:  p.MarketProtection,
	}
}

// --- LTP ---

func convertLTP(q kiteconnect.QuoteLTP) map[string]broker.LTP {
	out := make(map[string]broker.LTP, len(q))
	for key, val := range q {
		out[key] = broker.LTP{
			LastPrice: val.LastPrice,
		}
	}
	return out
}

// --- OHLC ---

func convertOHLC(q kiteconnect.QuoteOHLC) map[string]broker.OHLC {
	out := make(map[string]broker.OHLC, len(q))
	for key, val := range q {
		out[key] = broker.OHLC{
			Open:      val.OHLC.Open,
			High:      val.OHLC.High,
			Low:       val.OHLC.Low,
			Close:     val.OHLC.Close,
			LastPrice: val.LastPrice,
		}
	}
	return out
}

// --- Quotes ---

func convertQuotes(q kiteconnect.Quote) map[string]broker.Quote {
	out := make(map[string]broker.Quote, len(q))
	for key, val := range q {
		bq := broker.Quote{
			InstrumentToken:   val.InstrumentToken,
			LastPrice:         val.LastPrice,
			LastQuantity:      val.LastQuantity,
			AveragePrice:      val.AveragePrice,
			Volume:            val.Volume,
			BuyQuantity:       val.BuyQuantity,
			SellQuantity:      val.SellQuantity,
			NetChange:         val.NetChange,
			OI:                val.OI,
			OIDayHigh:         val.OIDayHigh,
			OIDayLow:          val.OIDayLow,
			LowerCircuitLimit: val.LowerCircuitLimit,
			UpperCircuitLimit: val.UpperCircuitLimit,
			OHLC: broker.OHLC{
				Open:  val.OHLC.Open,
				High:  val.OHLC.High,
				Low:   val.OHLC.Low,
				Close: val.OHLC.Close,
			},
		}
		// Convert market depth.
		for i, d := range val.Depth.Buy {
			bq.Depth.Buy[i] = broker.DepthItem{
				Price:    d.Price,
				Quantity: int(d.Quantity),
				Orders:   int(d.Orders),
			}
		}
		for i, d := range val.Depth.Sell {
			bq.Depth.Sell[i] = broker.DepthItem{
				Price:    d.Price,
				Quantity: int(d.Quantity),
				Orders:   int(d.Orders),
			}
		}
		out[key] = bq
	}
	return out
}

// --- Historical Data ---

func convertHistoricalData(data []kiteconnect.HistoricalData) []broker.HistoricalCandle {
	out := make([]broker.HistoricalCandle, len(data))
	for i, d := range data {
		out[i] = broker.HistoricalCandle{
			Date:   d.Date.Time,
			Open:   d.Open,
			High:   d.High,
			Low:    d.Low,
			Close:  d.Close,
			Volume: d.Volume,
		}
	}
	return out
}

// --- GTT (kite -> broker) ---

func convertGTTs(gtts kiteconnect.GTTs) []broker.GTTOrder {
	out := make([]broker.GTTOrder, len(gtts))
	for i, g := range gtts {
		out[i] = convertGTT(g)
	}
	return out
}

func convertGTT(g kiteconnect.GTT) broker.GTTOrder {
	legs := make([]broker.GTTOrderLeg, len(g.Orders))
	for i, o := range g.Orders {
		legs[i] = broker.GTTOrderLeg{
			Exchange:        o.Exchange,
			Tradingsymbol:   o.TradingSymbol,
			TransactionType: o.TransactionType,
			Quantity:        int(o.Quantity),
			OrderType:       o.OrderType,
			Price:           o.Price,
			Product:         o.Product,
		}
	}
	return broker.GTTOrder{
		ID:   g.ID,
		Type: string(g.Type),
		Condition: broker.GTTCondition{
			Exchange:      g.Condition.Exchange,
			Tradingsymbol: g.Condition.Tradingsymbol,
			TriggerValues: g.Condition.TriggerValues,
			LastPrice:     g.Condition.LastPrice,
		},
		Orders:    legs,
		Status:    g.Status,
		CreatedAt: g.CreatedAt.Time.Format("2006-01-02 15:04:05"),
		UpdatedAt: g.UpdatedAt.Time.Format("2006-01-02 15:04:05"),
		ExpiresAt: g.ExpiresAt.Time.Format("2006-01-02 15:04:05"),
	}
}

// --- GTTParams (broker -> kite) ---

func convertGTTParamsToKite(p broker.GTTParams) (kiteconnect.GTTParams, error) {
	kp := kiteconnect.GTTParams{
		Exchange:        p.Exchange,
		Tradingsymbol:   p.Tradingsymbol,
		LastPrice:       p.LastPrice,
		TransactionType: p.TransactionType,
		Product:         p.Product,
	}

	switch p.Type {
	case "single":
		kp.Trigger = &kiteconnect.GTTSingleLegTrigger{
			TriggerParams: kiteconnect.TriggerParams{
				TriggerValue: p.TriggerValue,
				Quantity:     p.Quantity,
				LimitPrice:   p.LimitPrice,
			},
		}
	case "two-leg":
		kp.Trigger = &kiteconnect.GTTOneCancelsOtherTrigger{
			Upper: kiteconnect.TriggerParams{
				TriggerValue: p.UpperTriggerValue,
				Quantity:     p.UpperQuantity,
				LimitPrice:   p.UpperLimitPrice,
			},
			Lower: kiteconnect.TriggerParams{
				TriggerValue: p.LowerTriggerValue,
				Quantity:     p.LowerQuantity,
				LimitPrice:   p.LowerLimitPrice,
			},
		}
	default:
		return kp, fmt.Errorf("invalid GTT type: %q (must be \"single\" or \"two-leg\")", p.Type)
	}

	return kp, nil
}
