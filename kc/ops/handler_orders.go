package ops

// OrdersHandler serves the orders page and the orders/order-attribution JSON APIs.
type OrdersHandler struct {
	core *DashboardHandler
}

func newOrdersHandler(core *DashboardHandler) *OrdersHandler {
	return &OrdersHandler{core: core}
}
