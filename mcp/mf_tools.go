package mcp

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/kc"
)

type MFHoldingsTool struct{}

func (*MFHoldingsTool) Definition() *mcp.Tool {
	return NewTool("get_mf_holdings",
		"Get all mutual fund holdings. Supports pagination for large datasets.",
		paginationSchema,
	)
}

func (*MFHoldingsTool) Handler(manager *kc.Manager) ToolHandler {
	return PaginatedToolHandler(manager, "get_mf_holdings", func(client *kiteconnect.Client) ([]interface{}, error) {
		holdings, err := client.GetMFHoldings()
		if err != nil {
			return nil, err
		}
		result := make([]interface{}, len(holdings))
		for i, holding := range holdings {
			result[i] = holding
		}
		return result, nil
	})
}
