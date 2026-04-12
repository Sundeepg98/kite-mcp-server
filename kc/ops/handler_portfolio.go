package ops

// PortfolioHandler serves the portfolio page, holdings/positions APIs,
// market indices, and sector exposure.
type PortfolioHandler struct {
	core *DashboardHandler
}

func newPortfolioHandler(core *DashboardHandler) *PortfolioHandler {
	return &PortfolioHandler{core: core}
}
