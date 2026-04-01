package mcp

import (
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
)

type MFOrdersTool struct{}

func (*MFOrdersTool) Tool() mcp.Tool {
	return mcp.NewTool("get_mf_orders",
		mcp.WithDescription("Get all mutual fund orders. Supports pagination for large datasets."),
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
