package ops

// TaxHandler serves the tax analysis JSON API.
type TaxHandler struct {
	core *DashboardHandler
}

func newTaxHandler(core *DashboardHandler) *TaxHandler {
	return &TaxHandler{core: core}
}
