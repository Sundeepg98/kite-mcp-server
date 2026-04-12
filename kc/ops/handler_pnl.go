package ops

// PnLHandler serves the P&L chart API and tax-analysis API.
type PnLHandler struct {
	core *DashboardHandler
}

func newPnLHandler(core *DashboardHandler) *PnLHandler {
	return &PnLHandler{core: core}
}
