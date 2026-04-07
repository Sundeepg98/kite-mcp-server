package usecases

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// --- Account queries ---

// GetProfileUseCase retrieves the user's broker profile.
type GetProfileUseCase struct {
	brokerResolver BrokerResolver
	logger         *slog.Logger
}

// NewGetProfileUseCase creates a GetProfileUseCase with all dependencies injected.
func NewGetProfileUseCase(resolver BrokerResolver, logger *slog.Logger) *GetProfileUseCase {
	return &GetProfileUseCase{
		brokerResolver: resolver,
		logger:         logger,
	}
}

// Execute retrieves the user's broker profile.
func (uc *GetProfileUseCase) Execute(ctx context.Context, query cqrs.GetProfileQuery) (broker.Profile, error) {
	if query.Email == "" {
		return broker.Profile{}, fmt.Errorf("usecases: email is required")
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(query.Email)
	if err != nil {
		return broker.Profile{}, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	profile, err := client.GetProfile()
	if err != nil {
		uc.logger.Error("Failed to get profile", "email", query.Email, "error", err)
		return broker.Profile{}, fmt.Errorf("usecases: get profile: %w", err)
	}

	return profile, nil
}

// GetMarginsUseCase retrieves the user's account margins.
type GetMarginsUseCase struct {
	brokerResolver BrokerResolver
	logger         *slog.Logger
}

// NewGetMarginsUseCase creates a GetMarginsUseCase with all dependencies injected.
func NewGetMarginsUseCase(resolver BrokerResolver, logger *slog.Logger) *GetMarginsUseCase {
	return &GetMarginsUseCase{
		brokerResolver: resolver,
		logger:         logger,
	}
}

// Execute retrieves the user's margins.
func (uc *GetMarginsUseCase) Execute(ctx context.Context, query cqrs.GetMarginsQuery) (broker.Margins, error) {
	if query.Email == "" {
		return broker.Margins{}, fmt.Errorf("usecases: email is required")
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(query.Email)
	if err != nil {
		return broker.Margins{}, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	margins, err := client.GetMargins()
	if err != nil {
		uc.logger.Error("Failed to get margins", "email", query.Email, "error", err)
		return broker.Margins{}, fmt.Errorf("usecases: get margins: %w", err)
	}

	return margins, nil
}

// --- Trade queries ---

// GetTradesUseCase retrieves all executed trades for the current trading day.
type GetTradesUseCase struct {
	brokerResolver BrokerResolver
	logger         *slog.Logger
}

// NewGetTradesUseCase creates a GetTradesUseCase with all dependencies injected.
func NewGetTradesUseCase(resolver BrokerResolver, logger *slog.Logger) *GetTradesUseCase {
	return &GetTradesUseCase{
		brokerResolver: resolver,
		logger:         logger,
	}
}

// Execute retrieves the user's trades for the current trading day.
func (uc *GetTradesUseCase) Execute(ctx context.Context, query cqrs.GetTradesQuery) ([]broker.Trade, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(query.Email)
	if err != nil {
		return nil, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	trades, err := client.GetTrades()
	if err != nil {
		uc.logger.Error("Failed to get trades", "email", query.Email, "error", err)
		return nil, fmt.Errorf("usecases: get trades: %w", err)
	}

	return trades, nil
}

// --- Order history query ---

// GetOrderHistoryUseCase retrieves the state history of a specific order.
type GetOrderHistoryUseCase struct {
	brokerResolver BrokerResolver
	logger         *slog.Logger
}

// NewGetOrderHistoryUseCase creates a GetOrderHistoryUseCase with all dependencies injected.
func NewGetOrderHistoryUseCase(resolver BrokerResolver, logger *slog.Logger) *GetOrderHistoryUseCase {
	return &GetOrderHistoryUseCase{
		brokerResolver: resolver,
		logger:         logger,
	}
}

// Execute retrieves the state history for a specific order.
func (uc *GetOrderHistoryUseCase) Execute(ctx context.Context, query cqrs.GetOrderHistoryQuery) ([]broker.Order, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}
	if query.OrderID == "" {
		return nil, fmt.Errorf("usecases: order_id is required")
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(query.Email)
	if err != nil {
		return nil, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	history, err := client.GetOrderHistory(query.OrderID)
	if err != nil {
		uc.logger.Error("Failed to get order history", "email", query.Email, "order_id", query.OrderID, "error", err)
		return nil, fmt.Errorf("usecases: get order history: %w", err)
	}

	return history, nil
}

// --- Market data queries ---

// GetLTPUseCase retrieves the last traded price for instruments.
type GetLTPUseCase struct {
	brokerResolver BrokerResolver
	logger         *slog.Logger
}

// NewGetLTPUseCase creates a GetLTPUseCase with all dependencies injected.
func NewGetLTPUseCase(resolver BrokerResolver, logger *slog.Logger) *GetLTPUseCase {
	return &GetLTPUseCase{
		brokerResolver: resolver,
		logger:         logger,
	}
}

// Execute retrieves the last traded price for the given instruments.
func (uc *GetLTPUseCase) Execute(ctx context.Context, email string, query cqrs.GetLTPQuery) (map[string]broker.LTP, error) {
	if len(query.Instruments) == 0 {
		return nil, fmt.Errorf("usecases: at least one instrument is required")
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(email)
	if err != nil {
		return nil, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	ltp, err := client.GetLTP(query.Instruments...)
	if err != nil {
		uc.logger.Error("Failed to get LTP", "error", err)
		return nil, fmt.Errorf("usecases: get ltp: %w", err)
	}

	return ltp, nil
}

// GetOHLCUseCase retrieves OHLC data for instruments.
type GetOHLCUseCase struct {
	brokerResolver BrokerResolver
	logger         *slog.Logger
}

// NewGetOHLCUseCase creates a GetOHLCUseCase with all dependencies injected.
func NewGetOHLCUseCase(resolver BrokerResolver, logger *slog.Logger) *GetOHLCUseCase {
	return &GetOHLCUseCase{
		brokerResolver: resolver,
		logger:         logger,
	}
}

// Execute retrieves OHLC data for the given instruments.
func (uc *GetOHLCUseCase) Execute(ctx context.Context, email string, query cqrs.GetOHLCQuery) (map[string]broker.OHLC, error) {
	if len(query.Instruments) == 0 {
		return nil, fmt.Errorf("usecases: at least one instrument is required")
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(email)
	if err != nil {
		return nil, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	ohlc, err := client.GetOHLC(query.Instruments...)
	if err != nil {
		uc.logger.Error("Failed to get OHLC", "error", err)
		return nil, fmt.Errorf("usecases: get ohlc: %w", err)
	}

	return ohlc, nil
}

// --- Quote queries ---

// GetQuotesUseCase retrieves full market quotes for instruments.
type GetQuotesUseCase struct {
	brokerResolver BrokerResolver
	logger         *slog.Logger
}

// NewGetQuotesUseCase creates a GetQuotesUseCase with all dependencies injected.
func NewGetQuotesUseCase(resolver BrokerResolver, logger *slog.Logger) *GetQuotesUseCase {
	return &GetQuotesUseCase{
		brokerResolver: resolver,
		logger:         logger,
	}
}

// Execute retrieves full market quotes for the given instruments.
func (uc *GetQuotesUseCase) Execute(ctx context.Context, email string, query cqrs.GetQuotesQuery) (map[string]broker.Quote, error) {
	if len(query.Instruments) == 0 {
		return nil, fmt.Errorf("usecases: at least one instrument is required")
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(email)
	if err != nil {
		return nil, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	quotes, err := client.GetQuotes(query.Instruments...)
	if err != nil {
		uc.logger.Error("Failed to get quotes", "error", err)
		return nil, fmt.Errorf("usecases: get quotes: %w", err)
	}

	return quotes, nil
}

// --- Order trade queries ---

// GetOrderTradesUseCase retrieves executed trades for a specific order.
type GetOrderTradesUseCase struct {
	brokerResolver BrokerResolver
	logger         *slog.Logger
}

// NewGetOrderTradesUseCase creates a GetOrderTradesUseCase with all dependencies injected.
func NewGetOrderTradesUseCase(resolver BrokerResolver, logger *slog.Logger) *GetOrderTradesUseCase {
	return &GetOrderTradesUseCase{
		brokerResolver: resolver,
		logger:         logger,
	}
}

// Execute retrieves executed trades for a specific order.
func (uc *GetOrderTradesUseCase) Execute(ctx context.Context, query cqrs.GetOrderTradesQuery) ([]broker.Trade, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}
	if query.OrderID == "" {
		return nil, fmt.Errorf("usecases: order_id is required")
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(query.Email)
	if err != nil {
		return nil, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	trades, err := client.GetOrderTrades(query.OrderID)
	if err != nil {
		uc.logger.Error("Failed to get order trades", "email", query.Email, "order_id", query.OrderID, "error", err)
		return nil, fmt.Errorf("usecases: get order trades: %w", err)
	}

	return trades, nil
}

// GetHistoricalDataUseCase retrieves historical candle data for an instrument.
type GetHistoricalDataUseCase struct {
	brokerResolver BrokerResolver
	logger         *slog.Logger
}

// NewGetHistoricalDataUseCase creates a GetHistoricalDataUseCase with all dependencies injected.
func NewGetHistoricalDataUseCase(resolver BrokerResolver, logger *slog.Logger) *GetHistoricalDataUseCase {
	return &GetHistoricalDataUseCase{
		brokerResolver: resolver,
		logger:         logger,
	}
}

// Execute retrieves historical candle data for the given instrument.
func (uc *GetHistoricalDataUseCase) Execute(ctx context.Context, email string, query cqrs.GetHistoricalDataQuery) ([]broker.HistoricalCandle, error) {
	if query.InstrumentToken == 0 {
		return nil, fmt.Errorf("usecases: instrument_token is required")
	}
	if query.Interval == "" {
		return nil, fmt.Errorf("usecases: interval is required")
	}
	if query.From.IsZero() || query.To.IsZero() {
		return nil, fmt.Errorf("usecases: from and to dates are required")
	}
	if query.From.After(query.To) {
		return nil, fmt.Errorf("usecases: from must be before to")
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(email)
	if err != nil {
		return nil, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	candles, err := client.GetHistoricalData(query.InstrumentToken, query.Interval, query.From, query.To)
	if err != nil {
		uc.logger.Error("Failed to get historical data", "instrument_token", query.InstrumentToken, "error", err)
		return nil, fmt.Errorf("usecases: get historical data: %w", err)
	}

	return candles, nil
}
