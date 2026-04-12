package cqrs

// queries_ext.go contains query types added by cqrs-200 to avoid
// merge conflicts with queries.go (owned by cqrs-100).

// --- Dashboard queries ---

// OpenDashboardQuery requests a dashboard URL for a specific page.
type OpenDashboardQuery struct {
	Email string `json:"email"`
	Page  string `json:"page"`
}

// --- Trading context queries ---

// TradingContextQuery requests a unified trading context snapshot.
type TradingContextQuery struct {
	Email string `json:"email"`
}

// --- Server metrics queries ---

// ServerMetricsQuery requests server observability metrics.
type ServerMetricsQuery struct {
	AdminEmail string `json:"admin_email"`
	Period     string `json:"period"` // "1h", "24h", "7d", "30d"
}

// --- Pre-trade queries ---

// PreTradeCheckQuery requests pre-trade validation for a proposed order.
type PreTradeCheckQuery struct {
	Email           string  `json:"email"`
	Exchange        string  `json:"exchange"`
	Tradingsymbol   string  `json:"tradingsymbol"`
	TransactionType string  `json:"transaction_type"`
	Quantity        float64 `json:"quantity"`
	Product         string  `json:"product"`
	OrderType       string  `json:"order_type"`
	Price           float64 `json:"price,omitempty"`
}
