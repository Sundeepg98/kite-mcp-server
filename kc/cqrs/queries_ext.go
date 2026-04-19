package cqrs

// queries_ext.go contains query types added by cqrs-200 to avoid
// merge conflicts with queries.go (owned by cqrs-100).

// --- Setup validation queries ---
//
// ValidateLoginQuery is the pre-dispatch validation hop for Login. The real
// URL-generation path is LoginCommand on the CommandBus; this query exists so
// the pre-credential-storage validation in setup_tools.go routes through the
// bus rather than instantiating LoginUseCase directly in the handler.
// Observability, correlation, and future middleware wrap all bus dispatches
// uniformly — this closes the last tool-layer escape hatch for Login.
type ValidateLoginQuery struct {
	Email     string `json:"email"`
	APIKey    string `json:"api_key,omitempty"`
	APISecret string `json:"api_secret,omitempty"`
}

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
