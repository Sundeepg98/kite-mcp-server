package ops

// AccountHandler serves user account status and self-service account management.
type AccountHandler struct {
	core *DashboardHandler
}

func newAccountHandler(core *DashboardHandler) *AccountHandler {
	return &AccountHandler{core: core}
}
