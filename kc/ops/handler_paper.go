package ops

// PaperHandler serves the paper-trading page and paper trading JSON APIs.
type PaperHandler struct {
	core *DashboardHandler
}

func newPaperHandler(core *DashboardHandler) *PaperHandler {
	return &PaperHandler{core: core}
}
