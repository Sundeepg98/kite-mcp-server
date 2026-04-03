package telegram

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/ticker"
)

// confirmKeyboard returns the inline keyboard with Confirm/Cancel buttons.
func confirmKeyboard() tgbotapi.InlineKeyboardMarkup {
	return tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("\u2705 Confirm", "confirm_order"),
			tgbotapi.NewInlineKeyboardButtonData("\u274C Cancel", "cancel_order"),
		),
	)
}

// handleBuy parses /buy SYMBOL QTY [PRICE] and shows a confirmation prompt.
func (h *BotHandler) handleBuy(chatID int64, email, args string) {
	h.handleOrderCommand(chatID, email, args, "BUY")
}

// handleSell parses /sell SYMBOL QTY [PRICE] and shows a confirmation prompt.
func (h *BotHandler) handleSell(chatID int64, email, args string) {
	h.handleOrderCommand(chatID, email, args, "SELL")
}

// handleOrderCommand is the shared implementation for /buy and /sell.
func (h *BotHandler) handleOrderCommand(chatID int64, email, args, side string) {
	cmdName := strings.ToLower(side)
	parts := strings.Fields(args)
	if len(parts) < 2 || len(parts) > 3 {
		h.sendHTML(chatID, fmt.Sprintf(
			"Usage: /%s SYMBOL QTY [PRICE]\n\nExamples:\n<code>/%s RELIANCE 10</code> (market)\n<code>/%s INFY 5 1500</code> (limit @ 1500)",
			cmdName, cmdName, cmdName))
		return
	}

	symbol := strings.ToUpper(parts[0])
	qty, err := strconv.Atoi(parts[1])
	if err != nil || qty <= 0 {
		h.sendHTML(chatID, "Quantity must be a positive integer.")
		return
	}

	var price float64
	orderType := "MARKET"
	if len(parts) == 3 {
		price, err = strconv.ParseFloat(parts[2], 64)
		if err != nil || price <= 0 {
			h.sendHTML(chatID, "Price must be a positive number.")
			return
		}
		orderType = "LIMIT"
	}

	order := &pendingOrder{
		Email:           email,
		Exchange:        "NSE",
		Tradingsymbol:   symbol,
		TransactionType: side,
		Quantity:        qty,
		Price:           price,
		OrderType:       orderType,
		Product:         "CNC",
		CreatedAt:       time.Now(),
	}

	h.setPendingOrder(chatID, order)

	// Build confirmation message.
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("<b>%s Order Confirmation</b>\n\n", side))
	sb.WriteString(fmt.Sprintf("Symbol: <b>%s</b>\n", escapeHTML(symbol)))
	sb.WriteString(fmt.Sprintf("Qty: <b>%d</b>\n", qty))
	sb.WriteString(fmt.Sprintf("Type: <b>%s</b>\n", orderType))
	if orderType == "LIMIT" {
		sb.WriteString(fmt.Sprintf("Price: <b>\u20B9%.2f</b>\n", price))
	}
	sb.WriteString(fmt.Sprintf("Product: <b>CNC</b>\n"))

	// Check paper mode.
	if pe := h.manager.PaperEngine(); pe != nil && pe.IsEnabled(email) {
		sb.WriteString("\n\u26A0\uFE0F <i>Paper trading mode — order will be simulated.</i>\n")
	}

	sb.WriteString("\nThis order expires in 60 seconds.")

	h.sendHTMLWithKeyboard(chatID, sb.String(), confirmKeyboard())
}

// handleQuick parses /quick SYMBOL QTY SIDE TYPE [PRICE] and shows a confirmation prompt.
func (h *BotHandler) handleQuick(chatID int64, email, args string) {
	parts := strings.Fields(args)
	if len(parts) < 4 || len(parts) > 5 {
		h.sendHTML(chatID, "Usage: /quick SYMBOL QTY SIDE TYPE [PRICE]\n\n"+
			"Examples:\n"+
			"<code>/quick RELIANCE 10 BUY MARKET</code>\n"+
			"<code>/quick INFY 5 SELL LIMIT 1500</code>")
		return
	}

	symbol := strings.ToUpper(parts[0])
	qty, err := strconv.Atoi(parts[1])
	if err != nil || qty <= 0 {
		h.sendHTML(chatID, "Quantity must be a positive integer.")
		return
	}

	side := strings.ToUpper(parts[2])
	if side != "BUY" && side != "SELL" {
		h.sendHTML(chatID, "Side must be BUY or SELL.")
		return
	}

	orderType := strings.ToUpper(parts[3])
	if orderType != "MARKET" && orderType != "LIMIT" {
		h.sendHTML(chatID, "Type must be MARKET or LIMIT.")
		return
	}

	var price float64
	if orderType == "LIMIT" {
		if len(parts) < 5 {
			h.sendHTML(chatID, "LIMIT orders require a price. Example:\n<code>/quick INFY 5 SELL LIMIT 1500</code>")
			return
		}
		price, err = strconv.ParseFloat(parts[4], 64)
		if err != nil || price <= 0 {
			h.sendHTML(chatID, "Price must be a positive number.")
			return
		}
	}

	order := &pendingOrder{
		Email:           email,
		Exchange:        "NSE",
		Tradingsymbol:   symbol,
		TransactionType: side,
		Quantity:        qty,
		Price:           price,
		OrderType:       orderType,
		Product:         "CNC",
		CreatedAt:       time.Now(),
	}

	h.setPendingOrder(chatID, order)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("<b>Quick %s %s Order</b>\n\n", side, orderType))
	sb.WriteString(fmt.Sprintf("Symbol: <b>%s</b> | Qty: <b>%d</b>\n", escapeHTML(symbol), qty))
	if orderType == "LIMIT" {
		sb.WriteString(fmt.Sprintf("Price: <b>\u20B9%.2f</b>\n", price))
	}
	sb.WriteString("Product: <b>CNC</b>\n")

	if pe := h.manager.PaperEngine(); pe != nil && pe.IsEnabled(email) {
		sb.WriteString("\n\u26A0\uFE0F <i>Paper trading mode — order will be simulated.</i>\n")
	}

	sb.WriteString("\nThis order expires in 60 seconds.")

	h.sendHTMLWithKeyboard(chatID, sb.String(), confirmKeyboard())
}

// executeConfirmedOrder runs riskguard checks and places the confirmed order.
func (h *BotHandler) executeConfirmedOrder(chatID int64, email string, cq *tgbotapi.CallbackQuery) {
	order := h.popPendingOrder(chatID)
	if order == nil {
		h.answerCallback(cq.ID, "Order expired or already processed.")
		if cq.Message != nil {
			h.editMessage(chatID, cq.Message.MessageID, "\u23F3 <i>Order expired or already processed.</i>")
		}
		return
	}

	// Verify the order belongs to this user.
	if order.Email != email {
		h.answerCallback(cq.ID, "Authentication mismatch.")
		return
	}

	h.answerCallback(cq.ID, "Processing order...")

	// Run riskguard checks.
	if guard := h.manager.RiskGuard(); guard != nil {
		result := guard.CheckOrder(riskguard.OrderCheckRequest{
			Email:           email,
			ToolName:        "telegram_order",
			Exchange:        order.Exchange,
			Tradingsymbol:   order.Tradingsymbol,
			TransactionType: order.TransactionType,
			Quantity:        order.Quantity,
			Price:           order.Price,
			OrderType:       order.OrderType,
		})
		if !result.Allowed {
			msg := fmt.Sprintf("\u274C <b>Order blocked by risk guard</b>\nReason: %s\n%s", result.Reason, escapeHTML(result.Message))
			if cq.Message != nil {
				h.editMessage(chatID, cq.Message.MessageID, msg)
			} else {
				h.sendHTML(chatID, msg)
			}
			return
		}
	}

	// Route to paper engine or real Kite API.
	var resultMsg string
	if pe := h.manager.PaperEngine(); pe != nil && pe.IsEnabled(email) {
		resp, err := pe.PlaceOrder(email, map[string]any{
			"exchange":         order.Exchange,
			"tradingsymbol":    order.Tradingsymbol,
			"transaction_type": order.TransactionType,
			"order_type":       order.OrderType,
			"product":          order.Product,
			"quantity":         order.Quantity,
			"price":            order.Price,
			"variety":          "regular",
		})
		if err != nil {
			resultMsg = fmt.Sprintf("\u274C <b>Paper order failed</b>\n%s", escapeHTML(err.Error()))
		} else {
			orderID, _ := resp["order_id"].(string)
			resultMsg = fmt.Sprintf("\u2705 <b>Paper %s order placed</b>\n%s %d x %s\nOrder ID: <code>%s</code>",
				order.TransactionType, order.OrderType, order.Quantity, escapeHTML(order.Tradingsymbol), orderID)
		}
	} else {
		client, errMsg := h.newKiteClient(email)
		if client == nil {
			if cq.Message != nil {
				h.editMessage(chatID, cq.Message.MessageID, errMsg)
			} else {
				h.sendHTML(chatID, errMsg)
			}
			return
		}

		orderParams := kiteconnect.OrderParams{
			Exchange:         order.Exchange,
			Tradingsymbol:    order.Tradingsymbol,
			TransactionType:  order.TransactionType,
			OrderType:        order.OrderType,
			Product:          order.Product,
			Quantity:         order.Quantity,
			Price:            order.Price,
			Validity:         "DAY",
			MarketProtection: kiteconnect.MarketProtectionAuto,
		}

		resp, err := client.PlaceOrder("regular", orderParams)
		if err != nil {
			resultMsg = fmt.Sprintf("\u274C <b>Order failed</b>\n%s", escapeHTML(err.Error()))
		} else {
			resultMsg = fmt.Sprintf("\u2705 <b>%s order placed</b>\n%s %d x %s\nOrder ID: <code>%s</code>",
				order.TransactionType, order.OrderType, order.Quantity,
				escapeHTML(order.Tradingsymbol), resp.OrderID)

			// Record in riskguard for duplicate/rate detection.
			if guard := h.manager.RiskGuard(); guard != nil {
				guard.RecordOrder(email, riskguard.OrderCheckRequest{
					Email:           email,
					ToolName:        "telegram_order",
					Exchange:        order.Exchange,
					Tradingsymbol:   order.Tradingsymbol,
					TransactionType: order.TransactionType,
					Quantity:        order.Quantity,
					Price:           order.Price,
					OrderType:       order.OrderType,
				})
			}
		}
	}

	h.logger.Info("Telegram order executed",
		"email", email, "chat_id", chatID,
		"side", order.TransactionType, "symbol", order.Tradingsymbol,
		"qty", order.Quantity, "type", order.OrderType, "price", order.Price)

	if cq.Message != nil {
		h.editMessage(chatID, cq.Message.MessageID, resultMsg)
	} else {
		h.sendHTML(chatID, resultMsg)
	}
}

// cancelPendingOrder removes the pending order and updates the message.
func (h *BotHandler) cancelPendingOrder(chatID int64, cq *tgbotapi.CallbackQuery) {
	h.popPendingOrder(chatID) // discard
	h.answerCallback(cq.ID, "Order cancelled.")
	if cq.Message != nil {
		h.editMessage(chatID, cq.Message.MessageID, "\U0001F6AB <i>Order cancelled.</i>")
	}
}

// handleSetAlert parses /setalert SYMBOL DIRECTION PRICE and creates a price alert.
func (h *BotHandler) handleSetAlert(_ int64, email, args string) string {
	parts := strings.Fields(args)
	if len(parts) != 3 {
		return "Usage: /setalert SYMBOL DIRECTION PRICE\n\n" +
			"Direction: above, below\n\n" +
			"Examples:\n" +
			"<code>/setalert RELIANCE above 2700</code>\n" +
			"<code>/setalert NIFTY below 22000</code>"
	}

	symbol := strings.ToUpper(parts[0])
	directionStr := strings.ToLower(parts[1])
	priceStr := parts[2]

	direction := alerts.Direction(directionStr)
	if !alerts.ValidDirections[direction] {
		return "Direction must be one of: above, below, drop_pct, rise_pct"
	}

	targetPrice, err := strconv.ParseFloat(priceStr, 64)
	if err != nil || targetPrice <= 0 {
		return "Price must be a positive number."
	}

	// For percentage alerts, validate threshold.
	if alerts.IsPercentageDirection(direction) && targetPrice > 100 {
		return "Percentage threshold cannot exceed 100%."
	}

	// Resolve instrument to get token.
	instrumentID := "NSE:" + symbol
	im := h.manager.InstrumentsManager()
	if im == nil {
		return "Instruments data not available."
	}

	inst, err := im.GetByID(instrumentID)
	if err != nil {
		// Try BSE if NSE fails.
		instrumentID = "BSE:" + symbol
		inst, err = im.GetByID(instrumentID)
		if err != nil {
			return fmt.Sprintf("Instrument not found: <b>%s</b> (tried NSE and BSE)", escapeHTML(symbol))
		}
	}

	exchange := inst.Exchange
	tradingsymbol := inst.Tradingsymbol

	alertID, err := h.manager.AlertStore().Add(email, tradingsymbol, exchange, inst.InstrumentToken, targetPrice, direction)
	if err != nil {
		return fmt.Sprintf("Failed to set alert: %s", escapeHTML(err.Error()))
	}

	// Auto-subscribe to ticker for real-time monitoring.
	tickerMsg := ""
	ts := h.manager.TickerService()
	if ts != nil {
		if ts.IsRunning(email) {
			if subErr := ts.Subscribe(email, []uint32{inst.InstrumentToken}, ticker.ModeLTP); subErr == nil {
				tickerMsg = "\nSubscribed for real-time alerts."
			}
		}
	}

	if alerts.IsPercentageDirection(direction) {
		return fmt.Sprintf("\u2705 Alert set: <b>%s:%s</b> %s %.2f%%\nID: <code>%s</code>%s",
			escapeHTML(exchange), escapeHTML(tradingsymbol), directionStr, targetPrice, alertID, tickerMsg)
	}
	return fmt.Sprintf("\u2705 Alert set: <b>%s:%s</b> %s \u20B9%.2f\nID: <code>%s</code>%s",
		escapeHTML(exchange), escapeHTML(tradingsymbol), directionStr, targetPrice, alertID, tickerMsg)
}
