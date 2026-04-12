package ops

// AlertsHandler serves the alerts page, alerts JSON API, and enriched alerts.
type AlertsHandler struct {
	core *DashboardHandler
}

func newAlertsHandler(core *DashboardHandler) *AlertsHandler {
	return &AlertsHandler{core: core}
}
