package cqrs

// --- Exit commands (close positions) ---

// ClosePositionCommand requests closing a single open position by placing
// an opposite MARKET order. Routed through ClosePositionUseCase which applies
// riskguard + dispatches PositionClosedEvent.
type ClosePositionCommand struct {
	Email         string `json:"email"`
	Exchange      string `json:"exchange"`
	Symbol        string `json:"symbol"`
	ProductFilter string `json:"product_filter,omitempty"` // MIS/CNC/NRML or empty
}

// CloseAllPositionsCommand requests closing every open position (optionally
// filtered by product type). Routed through CloseAllPositionsUseCase which
// applies riskguard per position + dispatches PositionClosedEvent per fill.
type CloseAllPositionsCommand struct {
	Email         string `json:"email"`
	ProductFilter string `json:"product_filter,omitempty"` // MIS/CNC/NRML/ALL
}
