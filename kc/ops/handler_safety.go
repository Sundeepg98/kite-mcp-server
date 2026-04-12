package ops

// SafetyHandler serves the safety/risk-controls page and safety status APIs.
type SafetyHandler struct {
	core *DashboardHandler
}

func newSafetyHandler(core *DashboardHandler) *SafetyHandler {
	return &SafetyHandler{core: core}
}
