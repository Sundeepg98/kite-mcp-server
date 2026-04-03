package mcp

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/kc"
)

type MFOrdersTool struct{}

func (*MFOrdersTool) Tool() mcp.Tool {
	return mcp.NewTool("get_mf_orders",
		mcp.WithDescription("Get all mutual fund orders. Supports pagination for large datasets."),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithNumber("from",
			mcp.Description("Starting index for pagination (0-based). Default: 0"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum number of MF orders to return. If not specified, returns all orders. When specified, response includes pagination metadata."),
		),
	)
}

func (*MFOrdersTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	return PaginatedToolHandler(manager, "get_mf_orders", func(session *kc.KiteSessionData) ([]interface{}, error) {
		orders, err := session.Kite.Client.GetMFOrders()
		if err != nil {
			return nil, err
		}

		result := make([]interface{}, len(orders))
		for i, order := range orders {
			result[i] = order
		}
		return result, nil
	})
}

type MFSIPsTool struct{}

func (*MFSIPsTool) Tool() mcp.Tool {
	return mcp.NewTool("get_mf_sips",
		mcp.WithDescription("Get all mutual fund SIPs (Systematic Investment Plans). Supports pagination for large datasets."),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithNumber("from",
			mcp.Description("Starting index for pagination (0-based). Default: 0"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum number of SIPs to return. If not specified, returns all SIPs. When specified, response includes pagination metadata."),
		),
	)
}

func (*MFSIPsTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	return PaginatedToolHandler(manager, "get_mf_sips", func(session *kc.KiteSessionData) ([]interface{}, error) {
		sips, err := session.Kite.Client.GetMFSIPs()
		if err != nil {
			return nil, err
		}

		result := make([]interface{}, len(sips))
		for i, sip := range sips {
			result[i] = sip
		}
		return result, nil
	})
}

type MFHoldingsTool struct{}

func (*MFHoldingsTool) Tool() mcp.Tool {
	return mcp.NewTool("get_mf_holdings",
		mcp.WithDescription("Get all mutual fund holdings. Supports pagination for large datasets."),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithNumber("from",
			mcp.Description("Starting index for pagination (0-based). Default: 0"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum number of MF holdings to return. If not specified, returns all holdings. When specified, response includes pagination metadata."),
		),
	)
}

func (*MFHoldingsTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	return PaginatedToolHandler(manager, "get_mf_holdings", func(session *kc.KiteSessionData) ([]interface{}, error) {
		holdings, err := session.Kite.Client.GetMFHoldings()
		if err != nil {
			return nil, err
		}

		// Convert to []interface{} for generic pagination
		result := make([]interface{}, len(holdings))
		for i, holding := range holdings {
			result[i] = holding
		}
		return result, nil
	})
}

// --- MF Write Tools ---

type PlaceMFOrderTool struct{}

func (*PlaceMFOrderTool) Tool() mcp.Tool {
	return mcp.NewTool("place_mf_order",
		mcp.WithDescription("Place a mutual fund order (buy or redeem). Use BUY with amount, or SELL with quantity."),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithString("tradingsymbol",
			mcp.Description("ISIN of the mutual fund (e.g., INF209K01YS2)"),
			mcp.Required(),
		),
		mcp.WithString("transaction_type",
			mcp.Description("Transaction type"),
			mcp.Required(),
			mcp.Enum("BUY", "SELL"),
		),
		mcp.WithNumber("amount",
			mcp.Description("Amount in INR (required for BUY orders)"),
		),
		mcp.WithNumber("quantity",
			mcp.Description("Number of units to redeem (required for SELL orders)"),
		),
		mcp.WithString("tag",
			mcp.Description("An optional tag to identify the order (alphanumeric, max 20 chars)"),
			mcp.MaxLength(20),
		),
	)
}

func (*PlaceMFOrderTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "place_mf_order")
		args := request.GetArguments()

		if err := ValidateRequired(args, "tradingsymbol", "transaction_type"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		// Request user confirmation via elicitation before placing the MF order.
		if srv := manager.MCPServer(); srv != nil {
			msg := buildOrderConfirmMessage("place_mf_order", args)
			if err := requestConfirmation(ctx, srv, msg); err != nil {
				handler.trackToolError(ctx, "place_mf_order", "user_declined")
				return mcp.NewToolResultError(err.Error()), nil
			}
		}

		txnType := SafeAssertString(args["transaction_type"], "")
		amount := SafeAssertFloat64(args["amount"], 0)
		quantity := SafeAssertFloat64(args["quantity"], 0)

		// Validate: BUY needs amount, SELL needs quantity
		if txnType == "BUY" && amount <= 0 {
			return mcp.NewToolResultError("amount is required and must be greater than 0 for BUY orders"), nil
		}
		if txnType == "SELL" && quantity <= 0 {
			return mcp.NewToolResultError("quantity is required and must be greater than 0 for SELL orders"), nil
		}

		orderParams := kiteconnect.MFOrderParams{
			Tradingsymbol:   SafeAssertString(args["tradingsymbol"], ""),
			TransactionType: txnType,
			Amount:          amount,
			Quantity:        quantity,
			Tag:             SafeAssertString(args["tag"], ""),
		}

		return handler.WithSession(ctx, "place_mf_order", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			resp, err := session.Kite.Client.PlaceMFOrder(orderParams)
			if err != nil {
				handler.manager.Logger.Error("Failed to place MF order", "error", err)
				return mcp.NewToolResultError(fmt.Sprintf("place_mf_order: %s", err.Error())), nil
			}
			return handler.MarshalResponse(resp, "place_mf_order")
		})
	}
}

type CancelMFOrderTool struct{}

func (*CancelMFOrderTool) Tool() mcp.Tool {
	return mcp.NewTool("cancel_mf_order",
		mcp.WithDescription("Cancel a pending mutual fund order"),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithString("order_id",
			mcp.Description("The MF order ID to cancel"),
			mcp.Required(),
		),
	)
}

func (*CancelMFOrderTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "cancel_mf_order")
		args := request.GetArguments()

		if err := ValidateRequired(args, "order_id"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		orderID := SafeAssertString(args["order_id"], "")

		return handler.WithSession(ctx, "cancel_mf_order", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			resp, err := session.Kite.Client.CancelMFOrder(orderID)
			if err != nil {
				handler.manager.Logger.Error("Failed to cancel MF order", "error", err)
				return mcp.NewToolResultError(fmt.Sprintf("cancel_mf_order: %s", err.Error())), nil
			}
			return handler.MarshalResponse(resp, "cancel_mf_order")
		})
	}
}

type PlaceMFSIPTool struct{}

func (*PlaceMFSIPTool) Tool() mcp.Tool {
	return mcp.NewTool("place_mf_sip",
		mcp.WithDescription("Start a new mutual fund SIP (Systematic Investment Plan)"),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithString("tradingsymbol",
			mcp.Description("ISIN of the mutual fund (e.g., INF209K01YS2)"),
			mcp.Required(),
		),
		mcp.WithNumber("amount",
			mcp.Description("SIP instalment amount in INR"),
			mcp.Required(),
		),
		mcp.WithString("frequency",
			mcp.Description("SIP frequency"),
			mcp.Required(),
			mcp.Enum("monthly", "weekly", "quarterly"),
		),
		mcp.WithNumber("instalments",
			mcp.Description("Total number of instalments (-1 for perpetual)"),
			mcp.Required(),
		),
		mcp.WithNumber("initial_amount",
			mcp.Description("Initial lump-sum amount (optional, for first instalment)"),
		),
		mcp.WithNumber("instalment_day",
			mcp.Description("Day of the month/week for instalment (optional)"),
		),
		mcp.WithString("tag",
			mcp.Description("An optional tag to identify the SIP (alphanumeric, max 20 chars)"),
			mcp.MaxLength(20),
		),
	)
}

func (*PlaceMFSIPTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "place_mf_sip")
		args := request.GetArguments()

		if err := ValidateRequired(args, "tradingsymbol", "amount", "frequency", "instalments"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		// Request user confirmation via elicitation before placing the SIP.
		if srv := manager.MCPServer(); srv != nil {
			msg := buildOrderConfirmMessage("place_mf_sip", args)
			if err := requestConfirmation(ctx, srv, msg); err != nil {
				handler.trackToolError(ctx, "place_mf_sip", "user_declined")
				return mcp.NewToolResultError(err.Error()), nil
			}
		}

		amount := SafeAssertFloat64(args["amount"], 0)
		if amount <= 0 {
			return mcp.NewToolResultError("amount must be greater than 0"), nil
		}

		sipParams := kiteconnect.MFSIPParams{
			Tradingsymbol: SafeAssertString(args["tradingsymbol"], ""),
			Amount:        amount,
			Frequency:     SafeAssertString(args["frequency"], ""),
			Instalments:   SafeAssertInt(args["instalments"], 0),
			InitialAmount: SafeAssertFloat64(args["initial_amount"], 0),
			InstalmentDay: SafeAssertInt(args["instalment_day"], 0),
			Tag:           SafeAssertString(args["tag"], ""),
		}

		return handler.WithSession(ctx, "place_mf_sip", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			resp, err := session.Kite.Client.PlaceMFSIP(sipParams)
			if err != nil {
				handler.manager.Logger.Error("Failed to place MF SIP", "error", err)
				return mcp.NewToolResultError(fmt.Sprintf("place_mf_sip: %s", err.Error())), nil
			}
			return handler.MarshalResponse(resp, "place_mf_sip")
		})
	}
}

type CancelMFSIPTool struct{}

func (*CancelMFSIPTool) Tool() mcp.Tool {
	return mcp.NewTool("cancel_mf_sip",
		mcp.WithDescription("Cancel an existing mutual fund SIP"),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithString("sip_id",
			mcp.Description("The SIP ID to cancel"),
			mcp.Required(),
		),
	)
}

func (*CancelMFSIPTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "cancel_mf_sip")
		args := request.GetArguments()

		if err := ValidateRequired(args, "sip_id"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		sipID := SafeAssertString(args["sip_id"], "")

		return handler.WithSession(ctx, "cancel_mf_sip", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			resp, err := session.Kite.Client.CancelMFSIP(sipID)
			if err != nil {
				handler.manager.Logger.Error("Failed to cancel MF SIP", "error", err)
				return mcp.NewToolResultError(fmt.Sprintf("cancel_mf_sip: %s", err.Error())), nil
			}
			return handler.MarshalResponse(resp, "cancel_mf_sip")
		})
	}
}
