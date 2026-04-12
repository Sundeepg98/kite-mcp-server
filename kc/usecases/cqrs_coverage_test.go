package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/watchlist"
)

// ===========================================================================
// Coverage push: tests for ALL remaining 0% use case functions.
// Only includes tests that don't already exist in other test files.
// ===========================================================================

// ---------------------------------------------------------------------------
// alert_usecases.go — ListAlerts, DeleteAlert
// ---------------------------------------------------------------------------

type mockAlertReader struct {
	alerts    []*alerts.Alert
	deleteErr error
}

func (m *mockAlertReader) List(email string) []*alerts.Alert { return m.alerts }
func (m *mockAlertReader) Delete(email, alertID string) error { return m.deleteErr }

func TestListAlerts_Success(t *testing.T) {
	t.Parallel()
	store := &mockAlertReader{alerts: []*alerts.Alert{{Email: "u@t.com"}}}
	uc := NewListAlertsUseCase(store, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.GetAlertsQuery{Email: "u@t.com"})
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestListAlerts_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewListAlertsUseCase(&mockAlertReader{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetAlertsQuery{})
	assert.ErrorContains(t, err, "email is required")
}

func TestDeleteAlert_Success(t *testing.T) {
	t.Parallel()
	uc := NewDeleteAlertUseCase(&mockAlertReader{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.DeleteAlertCommand{Email: "u@t.com", AlertID: "a1"})
	assert.NoError(t, err)
}

func TestDeleteAlert_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewDeleteAlertUseCase(&mockAlertReader{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.DeleteAlertCommand{AlertID: "a1"})
	assert.ErrorContains(t, err, "email is required")
}

func TestDeleteAlert_EmptyID(t *testing.T) {
	t.Parallel()
	uc := NewDeleteAlertUseCase(&mockAlertReader{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.DeleteAlertCommand{Email: "u@t.com"})
	assert.ErrorContains(t, err, "alert_id is required")
}

func TestDeleteAlert_StoreError(t *testing.T) {
	t.Parallel()
	store := &mockAlertReader{deleteErr: errors.New("db fail")}
	uc := NewDeleteAlertUseCase(store, testLogger())
	err := uc.Execute(context.Background(), cqrs.DeleteAlertCommand{Email: "u@t.com", AlertID: "a1"})
	assert.ErrorContains(t, err, "delete alert")
}

// ---------------------------------------------------------------------------
// native_alert_usecases.go — Place, List, Modify, Delete, History
// ---------------------------------------------------------------------------

type mockNativeAlertClient struct {
	createResult any
	createErr    error
	modifyResult any
	modifyErr    error
	deleteErr    error
	alerts       any
	alertsErr    error
	history      any
	historyErr   error
}

func (m *mockNativeAlertClient) CreateAlert(params any) (any, error) {
	return m.createResult, m.createErr
}
func (m *mockNativeAlertClient) ModifyAlert(uuid string, params any) (any, error) {
	return m.modifyResult, m.modifyErr
}
func (m *mockNativeAlertClient) DeleteAlerts(uuids ...string) error { return m.deleteErr }
func (m *mockNativeAlertClient) GetAlerts(filters map[string]string) (any, error) {
	return m.alerts, m.alertsErr
}
func (m *mockNativeAlertClient) GetAlertHistory(uuid string) (any, error) {
	return m.history, m.historyErr
}

func TestPlaceNativeAlert_Success(t *testing.T) {
	t.Parallel()
	client := &mockNativeAlertClient{createResult: "ok"}
	uc := NewPlaceNativeAlertUseCase(testLogger())
	result, err := uc.Execute(context.Background(), client, cqrs.PlaceNativeAlertCommand{
		Email: "u@t.com", Params: map[string]any{"name": "test"},
	})
	require.NoError(t, err)
	assert.Equal(t, "ok", result)
}

func TestPlaceNativeAlert_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewPlaceNativeAlertUseCase(testLogger())
	_, err := uc.Execute(context.Background(), &mockNativeAlertClient{}, cqrs.PlaceNativeAlertCommand{})
	assert.ErrorContains(t, err, "email is required")
}

func TestPlaceNativeAlert_Error(t *testing.T) {
	t.Parallel()
	client := &mockNativeAlertClient{createErr: errors.New("api fail")}
	uc := NewPlaceNativeAlertUseCase(testLogger())
	_, err := uc.Execute(context.Background(), client, cqrs.PlaceNativeAlertCommand{Email: "u@t.com"})
	assert.ErrorContains(t, err, "create native alert")
}

func TestListNativeAlerts_Success(t *testing.T) {
	t.Parallel()
	client := &mockNativeAlertClient{alerts: []string{"a1"}}
	uc := NewListNativeAlertsUseCase(testLogger())
	result, err := uc.Execute(context.Background(), client, cqrs.ListNativeAlertsQuery{Email: "u@t.com"})
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestListNativeAlerts_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewListNativeAlertsUseCase(testLogger())
	_, err := uc.Execute(context.Background(), &mockNativeAlertClient{}, cqrs.ListNativeAlertsQuery{})
	assert.ErrorContains(t, err, "email is required")
}

func TestListNativeAlerts_Error(t *testing.T) {
	t.Parallel()
	client := &mockNativeAlertClient{alertsErr: errors.New("api fail")}
	uc := NewListNativeAlertsUseCase(testLogger())
	_, err := uc.Execute(context.Background(), client, cqrs.ListNativeAlertsQuery{Email: "u@t.com"})
	assert.ErrorContains(t, err, "list native alerts")
}

func TestModifyNativeAlert_Success(t *testing.T) {
	t.Parallel()
	client := &mockNativeAlertClient{modifyResult: "updated"}
	uc := NewModifyNativeAlertUseCase(testLogger())
	result, err := uc.Execute(context.Background(), client, cqrs.ModifyNativeAlertCommand{
		Email: "u@t.com", UUID: "uuid-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "updated", result)
}

func TestModifyNativeAlert_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewModifyNativeAlertUseCase(testLogger())
	_, err := uc.Execute(context.Background(), &mockNativeAlertClient{}, cqrs.ModifyNativeAlertCommand{UUID: "u1"})
	assert.ErrorContains(t, err, "email is required")
}

func TestModifyNativeAlert_EmptyUUID(t *testing.T) {
	t.Parallel()
	uc := NewModifyNativeAlertUseCase(testLogger())
	_, err := uc.Execute(context.Background(), &mockNativeAlertClient{}, cqrs.ModifyNativeAlertCommand{Email: "u@t.com"})
	assert.ErrorContains(t, err, "uuid is required")
}

func TestModifyNativeAlert_Error(t *testing.T) {
	t.Parallel()
	client := &mockNativeAlertClient{modifyErr: errors.New("api fail")}
	uc := NewModifyNativeAlertUseCase(testLogger())
	_, err := uc.Execute(context.Background(), client, cqrs.ModifyNativeAlertCommand{Email: "u@t.com", UUID: "u1"})
	assert.ErrorContains(t, err, "modify native alert")
}

func TestDeleteNativeAlert_Success(t *testing.T) {
	t.Parallel()
	uc := NewDeleteNativeAlertUseCase(testLogger())
	err := uc.Execute(context.Background(), &mockNativeAlertClient{}, cqrs.DeleteNativeAlertCommand{
		Email: "u@t.com", UUIDs: []string{"u1", "u2"},
	})
	assert.NoError(t, err)
}

func TestDeleteNativeAlert_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewDeleteNativeAlertUseCase(testLogger())
	err := uc.Execute(context.Background(), &mockNativeAlertClient{}, cqrs.DeleteNativeAlertCommand{UUIDs: []string{"u1"}})
	assert.ErrorContains(t, err, "email is required")
}

func TestDeleteNativeAlert_NoUUIDs(t *testing.T) {
	t.Parallel()
	uc := NewDeleteNativeAlertUseCase(testLogger())
	err := uc.Execute(context.Background(), &mockNativeAlertClient{}, cqrs.DeleteNativeAlertCommand{Email: "u@t.com"})
	assert.ErrorContains(t, err, "at least one uuid")
}

func TestDeleteNativeAlert_Error(t *testing.T) {
	t.Parallel()
	client := &mockNativeAlertClient{deleteErr: errors.New("api fail")}
	uc := NewDeleteNativeAlertUseCase(testLogger())
	err := uc.Execute(context.Background(), client, cqrs.DeleteNativeAlertCommand{Email: "u@t.com", UUIDs: []string{"u1"}})
	assert.ErrorContains(t, err, "delete native alert")
}

func TestGetNativeAlertHistory_Success(t *testing.T) {
	t.Parallel()
	client := &mockNativeAlertClient{history: []string{"h1"}}
	uc := NewGetNativeAlertHistoryUseCase(testLogger())
	result, err := uc.Execute(context.Background(), client, cqrs.GetNativeAlertHistoryQuery{Email: "u@t.com", UUID: "u1"})
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestGetNativeAlertHistory_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewGetNativeAlertHistoryUseCase(testLogger())
	_, err := uc.Execute(context.Background(), &mockNativeAlertClient{}, cqrs.GetNativeAlertHistoryQuery{UUID: "u1"})
	assert.ErrorContains(t, err, "email is required")
}

func TestGetNativeAlertHistory_EmptyUUID(t *testing.T) {
	t.Parallel()
	uc := NewGetNativeAlertHistoryUseCase(testLogger())
	_, err := uc.Execute(context.Background(), &mockNativeAlertClient{}, cqrs.GetNativeAlertHistoryQuery{Email: "u@t.com"})
	assert.ErrorContains(t, err, "uuid is required")
}

func TestGetNativeAlertHistory_Error(t *testing.T) {
	t.Parallel()
	client := &mockNativeAlertClient{historyErr: errors.New("api fail")}
	uc := NewGetNativeAlertHistoryUseCase(testLogger())
	_, err := uc.Execute(context.Background(), client, cqrs.GetNativeAlertHistoryQuery{Email: "u@t.com", UUID: "u1"})
	assert.ErrorContains(t, err, "get native alert history")
}

// ---------------------------------------------------------------------------
// setup_usecases.go — Login, OpenDashboard, isAlphanumeric
// ---------------------------------------------------------------------------

func TestLoginUseCase_Valid(t *testing.T) {
	t.Parallel()
	uc := NewLoginUseCase(testLogger())
	err := uc.Validate(context.Background(), cqrs.LoginCommand{})
	assert.NoError(t, err)
}

func TestLoginUseCase_APIKeyOnly(t *testing.T) {
	t.Parallel()
	uc := NewLoginUseCase(testLogger())
	err := uc.Validate(context.Background(), cqrs.LoginCommand{APIKey: "abc123"})
	assert.ErrorContains(t, err, "both api_key and api_secret")
}

func TestLoginUseCase_APISecretOnly(t *testing.T) {
	t.Parallel()
	uc := NewLoginUseCase(testLogger())
	err := uc.Validate(context.Background(), cqrs.LoginCommand{APISecret: "abc123"})
	assert.ErrorContains(t, err, "both api_key and api_secret")
}

func TestLoginUseCase_InvalidAPIKey(t *testing.T) {
	t.Parallel()
	uc := NewLoginUseCase(testLogger())
	err := uc.Validate(context.Background(), cqrs.LoginCommand{APIKey: "abc!@#", APISecret: "abc123"})
	assert.ErrorContains(t, err, "invalid api_key")
}

func TestLoginUseCase_InvalidAPISecret(t *testing.T) {
	t.Parallel()
	uc := NewLoginUseCase(testLogger())
	err := uc.Validate(context.Background(), cqrs.LoginCommand{APIKey: "abc123", APISecret: "abc!@#"})
	assert.ErrorContains(t, err, "invalid api_secret")
}

func TestLoginUseCase_BothValid(t *testing.T) {
	t.Parallel()
	uc := NewLoginUseCase(testLogger())
	err := uc.Validate(context.Background(), cqrs.LoginCommand{APIKey: "abc123", APISecret: "def456"})
	assert.NoError(t, err)
}

func TestOpenDashboard_Valid(t *testing.T) {
	t.Parallel()
	uc := NewOpenDashboardUseCase(testLogger())
	err := uc.Validate(context.Background(), cqrs.OpenDashboardQuery{Page: "portfolio"})
	assert.NoError(t, err)
}

func TestOpenDashboard_EmptyPage(t *testing.T) {
	t.Parallel()
	uc := NewOpenDashboardUseCase(testLogger())
	err := uc.Validate(context.Background(), cqrs.OpenDashboardQuery{})
	assert.ErrorContains(t, err, "page is required")
}

// ---------------------------------------------------------------------------
// telegram_usecases.go — SetupTelegram
// ---------------------------------------------------------------------------

type mockTelegramStore struct {
	chatID int64
	email  string
}

func (m *mockTelegramStore) SetTelegramChatID(email string, chatID int64) {
	m.email = email
	m.chatID = chatID
}
func (m *mockTelegramStore) GetTelegramChatID(email string) (int64, bool) {
	if m.email == email {
		return m.chatID, true
	}
	return 0, false
}

func TestSetupTelegram_Success(t *testing.T) {
	t.Parallel()
	store := &mockTelegramStore{}
	uc := NewSetupTelegramUseCase(store, testLogger())
	err := uc.Execute(context.Background(), cqrs.SetupTelegramCommand{Email: "u@t.com", ChatID: 12345})
	require.NoError(t, err)
	assert.Equal(t, int64(12345), store.chatID)
}

func TestSetupTelegram_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewSetupTelegramUseCase(&mockTelegramStore{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.SetupTelegramCommand{ChatID: 12345})
	assert.ErrorContains(t, err, "email is required")
}

func TestSetupTelegram_ZeroChatID(t *testing.T) {
	t.Parallel()
	uc := NewSetupTelegramUseCase(&mockTelegramStore{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.SetupTelegramCommand{Email: "u@t.com"})
	assert.ErrorContains(t, err, "chat_id is required")
}

// ---------------------------------------------------------------------------
// account_usecases.go — UpdateMyCredentials
// ---------------------------------------------------------------------------

type mockCredUpdater struct{ deleted bool }

func (m *mockCredUpdater) Delete(email string) { m.deleted = true }

type mockTokenStr struct{ deleted bool }

func (m *mockTokenStr) Delete(email string) { m.deleted = true }

type mockAlertDel struct{ deleted bool }

func (m *mockAlertDel) DeleteByEmail(email string) { m.deleted = true }

func TestUpdateMyCredentials_Success(t *testing.T) {
	t.Parallel()
	uc := NewUpdateMyCredentialsUseCase(&mockCredUpdater{}, &mockTokenStr{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.UpdateMyCredentialsCommand{
		Email: "u@t.com", APIKey: "key", APISecret: "secret",
	})
	assert.NoError(t, err)
}

func TestUpdateMyCredentials_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewUpdateMyCredentialsUseCase(&mockCredUpdater{}, &mockTokenStr{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.UpdateMyCredentialsCommand{APIKey: "k", APISecret: "s"})
	assert.ErrorContains(t, err, "email is required")
}

func TestUpdateMyCredentials_MissingKeys(t *testing.T) {
	t.Parallel()
	uc := NewUpdateMyCredentialsUseCase(&mockCredUpdater{}, &mockTokenStr{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.UpdateMyCredentialsCommand{Email: "u@t.com"})
	assert.ErrorContains(t, err, "both api_key and api_secret")
}

// ---------------------------------------------------------------------------
// context_usecases.go — TradingContext
// ---------------------------------------------------------------------------

func TestTradingContext_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		margins:   broker.Margins{},
		positions: broker.Positions{},
		orders:    []broker.Order{{OrderID: "o1"}},
		holdings:  []broker.Holding{{Tradingsymbol: "INFY"}},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewTradingContextUseCase(resolver, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.TradingContextQuery{Email: "u@t.com"})
	require.NoError(t, err)
	assert.NotNil(t, result.Margins)
	assert.NotNil(t, result.Positions)
	assert.Len(t, result.Orders, 1)
	assert.Len(t, result.Holdings, 1)
	assert.Nil(t, result.Errors)
}

func TestTradingContext_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewTradingContextUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.TradingContextQuery{})
	assert.ErrorContains(t, err, "email is required")
}

func TestTradingContext_ResolveError(t *testing.T) {
	t.Parallel()
	resolver := &mockBrokerResolver{resolveErr: errors.New("no session")}
	uc := NewTradingContextUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.TradingContextQuery{Email: "u@t.com"})
	assert.ErrorContains(t, err, "resolve broker")
}

func TestTradingContext_PartialErrors(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		marginsErr:   errors.New("margin fail"),
		positionsErr: errors.New("pos fail"),
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewTradingContextUseCase(resolver, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.TradingContextQuery{Email: "u@t.com"})
	require.NoError(t, err)
	assert.NotNil(t, result.Errors)
	assert.Contains(t, result.Errors["margins"], "margin fail")
	assert.Contains(t, result.Errors["positions"], "pos fail")
}

// ---------------------------------------------------------------------------
// pretrade_usecases.go — PreTradeCheck
// ---------------------------------------------------------------------------

func TestPreTradeCheck_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		ltpMap: map[string]broker.LTP{"NSE:INFY": {LastPrice: 1500}},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewPreTradeCheckUseCase(resolver, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.PreTradeCheckQuery{
		Email: "u@t.com", Exchange: "NSE", Tradingsymbol: "INFY",
		TransactionType: "BUY", Product: "CNC", OrderType: "LIMIT",
		Quantity: 10, Price: 1500,
	})
	require.NoError(t, err)
	assert.NotNil(t, result.LTP)
	assert.Nil(t, result.Errors)
}

func TestPreTradeCheck_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewPreTradeCheckUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PreTradeCheckQuery{})
	assert.ErrorContains(t, err, "email is required")
}

func TestPreTradeCheck_ResolveError(t *testing.T) {
	t.Parallel()
	resolver := &mockBrokerResolver{resolveErr: errors.New("no session")}
	uc := NewPreTradeCheckUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PreTradeCheckQuery{Email: "u@t.com"})
	assert.ErrorContains(t, err, "resolve broker")
}

// ---------------------------------------------------------------------------
// gtt_usecases.go — new coverage: Error, EmptySymbol only
// ---------------------------------------------------------------------------

func TestGetGTTs_Error(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{gttsErr: errors.New("api fail")}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetGTTsUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetGTTsQuery{Email: "u@t.com"})
	assert.ErrorContains(t, err, "get gtts")
}

func TestPlaceGTT_EmptySymbol(t *testing.T) {
	t.Parallel()
	uc := NewPlaceGTTUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PlaceGTTCommand{Email: "u@t.com", Type: "single"})
	assert.ErrorContains(t, err, "tradingsymbol is required")
}

func TestPlaceGTT_CQRS_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{placeGTTResp: broker.GTTResponse{TriggerID: 42}}
	resolver := &mockBrokerResolver{client: client}
	uc := NewPlaceGTTUseCase(resolver, testLogger())
	resp, err := uc.Execute(context.Background(), cqrs.PlaceGTTCommand{
		Email: "u@t.com", Tradingsymbol: "INFY", Type: "single",
	})
	require.NoError(t, err)
	assert.Equal(t, 42, resp.TriggerID)
}

func TestModifyGTT_Error(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{modifyGTTErr: errors.New("api fail")}
	resolver := &mockBrokerResolver{client: client}
	uc := NewModifyGTTUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.ModifyGTTCommand{Email: "u@t.com", TriggerID: 1, Type: "two-leg"})
	assert.ErrorContains(t, err, "modify gtt")
}

func TestDeleteGTT_Error(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{deleteGTTErr: errors.New("api fail")}
	resolver := &mockBrokerResolver{client: client}
	uc := NewDeleteGTTUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.DeleteGTTCommand{Email: "u@t.com", TriggerID: 1})
	assert.ErrorContains(t, err, "delete gtt")
}

// ---------------------------------------------------------------------------
// cancel_order.go — new: EmptyEmail, EmptyOrderID
// ---------------------------------------------------------------------------

func TestCancelOrder_CQRS_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewCancelOrderUseCase(&mockBrokerResolver{}, nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.CancelOrderCommand{OrderID: "o1"})
	assert.ErrorContains(t, err, "email is required")
}

func TestCancelOrder_CQRS_EmptyOrderID(t *testing.T) {
	t.Parallel()
	uc := NewCancelOrderUseCase(&mockBrokerResolver{}, nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.CancelOrderCommand{Email: "u@t.com"})
	assert.ErrorContains(t, err, "order_id is required")
}

// ---------------------------------------------------------------------------
// modify_order.go — ModifyOrder
// ---------------------------------------------------------------------------

func TestModifyOrder_UC_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{modifyResp: broker.OrderResponse{OrderID: "o1"}}
	resolver := &mockBrokerResolver{client: client}
	uc := NewModifyOrderUseCase(resolver, nil, nil, testLogger())
	resp, err := uc.Execute(context.Background(), cqrs.ModifyOrderCommand{
		Email: "u@t.com", OrderID: "o1", Quantity: 5,
	})
	require.NoError(t, err)
	assert.Equal(t, "o1", resp.OrderID)
}

func TestModifyOrder_UC_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewModifyOrderUseCase(&mockBrokerResolver{}, nil, nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.ModifyOrderCommand{OrderID: "o1"})
	assert.ErrorContains(t, err, "email is required")
}

func TestModifyOrder_UC_EmptyOrderID(t *testing.T) {
	t.Parallel()
	uc := NewModifyOrderUseCase(&mockBrokerResolver{}, nil, nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.ModifyOrderCommand{Email: "u@t.com"})
	assert.ErrorContains(t, err, "order_id is required")
}

func TestModifyOrder_UC_BrokerError(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{modifyErr: errors.New("api fail")}
	resolver := &mockBrokerResolver{client: client}
	uc := NewModifyOrderUseCase(resolver, nil, nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.ModifyOrderCommand{Email: "u@t.com", OrderID: "o1"})
	assert.ErrorContains(t, err, "modify order")
}

// ---------------------------------------------------------------------------
// close_position.go — ClosePosition
// ---------------------------------------------------------------------------

func TestClosePosition_UC_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewClosePositionUseCase(&mockBrokerResolver{}, nil, nil, testLogger())
	_, err := uc.Execute(context.Background(), "", "NSE", "INFY", "")
	assert.ErrorContains(t, err, "email is required")
}

func TestClosePosition_UC_EmptyExchange(t *testing.T) {
	t.Parallel()
	uc := NewClosePositionUseCase(&mockBrokerResolver{}, nil, nil, testLogger())
	_, err := uc.Execute(context.Background(), "u@t.com", "", "INFY", "")
	assert.ErrorContains(t, err, "exchange and symbol")
}

func TestClosePosition_UC_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		positions: broker.Positions{Net: []broker.Position{
			{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 10, Product: "CNC", PnL: 100},
		}},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewClosePositionUseCase(resolver, nil, nil, testLogger())
	result, err := uc.Execute(context.Background(), "u@t.com", "NSE", "INFY", "")
	require.NoError(t, err)
	assert.Equal(t, "SELL", result.Direction)
	assert.Equal(t, 10, result.Quantity)
}

func TestClosePosition_UC_NoPosition(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{positions: broker.Positions{}}
	resolver := &mockBrokerResolver{client: client}
	uc := NewClosePositionUseCase(resolver, nil, nil, testLogger())
	_, err := uc.Execute(context.Background(), "u@t.com", "NSE", "UNKNOWN", "")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// close_all_positions.go — CloseAllPositions
// ---------------------------------------------------------------------------

func TestCloseAllPositions_UC_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewCloseAllPositionsUseCase(&mockBrokerResolver{}, nil, nil, testLogger())
	_, err := uc.Execute(context.Background(), "", "")
	assert.ErrorContains(t, err, "email is required")
}

func TestCloseAllPositions_UC_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		positions: broker.Positions{Net: []broker.Position{
			{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 10, Product: "MIS"},
			{Tradingsymbol: "SBIN", Exchange: "NSE", Quantity: -5, Product: "MIS"},
		}},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewCloseAllPositionsUseCase(resolver, nil, nil, testLogger())
	result, err := uc.Execute(context.Background(), "u@t.com", "")
	require.NoError(t, err)
	assert.Equal(t, 2, result.Total)
}

// ---------------------------------------------------------------------------
// queries.go — GetProfile error, GetMargins
// ---------------------------------------------------------------------------

func TestGetProfile_Error(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{profileErr: errors.New("fail")}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetProfileUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetProfileQuery{Email: "u@t.com"})
	assert.ErrorContains(t, err, "get profile")
}

func TestGetMargins_UC_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{margins: broker.Margins{}}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetMarginsUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetMarginsQuery{Email: "u@t.com"})
	assert.NoError(t, err)
}

func TestGetMargins_UC_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewGetMarginsUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetMarginsQuery{})
	assert.ErrorContains(t, err, "email is required")
}

// ---------------------------------------------------------------------------
// PlaceOrder additional paths (resolve error, broker error)
// ---------------------------------------------------------------------------

func TestPlaceOrder_CQRS_ResolveErr(t *testing.T) {
	t.Parallel()
	resolver := &mockBrokerResolver{resolveErr: errors.New("no session")}
	uc := NewPlaceOrderUseCase(resolver, nil, nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PlaceOrderCommand{
		Email: "u@t.com", Exchange: "NSE", Tradingsymbol: "INFY",
		TransactionType: "BUY", Quantity: 10,
	})
	assert.ErrorContains(t, err, "resolve broker")
}

func TestPlaceOrder_CQRS_BrokerErr(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{placeErr: errors.New("api fail")}
	resolver := &mockBrokerResolver{client: client}
	uc := NewPlaceOrderUseCase(resolver, nil, nil, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PlaceOrderCommand{
		Email: "u@t.com", Exchange: "NSE", Tradingsymbol: "INFY",
		TransactionType: "BUY", Quantity: 10,
	})
	assert.ErrorContains(t, err, "place order")
}

// ---------------------------------------------------------------------------
// watchlist_usecases.go — AddToWatchlist, GetWatchlist
// ---------------------------------------------------------------------------

func TestAddToWatchlist_Success(t *testing.T) {
	t.Parallel()
	store := &mockWatchlistStore{}
	uc := NewAddToWatchlistUseCase(store, testLogger())
	err := uc.Execute(context.Background(), cqrs.AddToWatchlistCommand{
		Email: "u@t.com", WatchlistID: "wl1",
		Exchange: "NSE", Tradingsymbol: "INFY",
	})
	assert.NoError(t, err)
}

func TestAddToWatchlist_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewAddToWatchlistUseCase(&mockWatchlistStore{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.AddToWatchlistCommand{WatchlistID: "wl1"})
	assert.ErrorContains(t, err, "email is required")
}

func TestAddToWatchlist_EmptyWatchlistID(t *testing.T) {
	t.Parallel()
	uc := NewAddToWatchlistUseCase(&mockWatchlistStore{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.AddToWatchlistCommand{Email: "u@t.com"})
	assert.ErrorContains(t, err, "watchlist_id is required")
}

func TestAddToWatchlist_StoreError(t *testing.T) {
	t.Parallel()
	store := &mockWatchlistStore{addItemErr: errors.New("full")}
	uc := NewAddToWatchlistUseCase(store, testLogger())
	err := uc.Execute(context.Background(), cqrs.AddToWatchlistCommand{
		Email: "u@t.com", WatchlistID: "wl1",
	})
	assert.ErrorContains(t, err, "add to watchlist")
}

func TestGetWatchlist_Success(t *testing.T) {
	t.Parallel()
	store := &mockWatchlistStore{
		items: []*watchlist.WatchlistItem{{Tradingsymbol: "INFY"}},
	}
	uc := NewGetWatchlistUseCase(store, testLogger())
	items, err := uc.Execute(context.Background(), cqrs.GetWatchlistQuery{
		Email: "u@t.com", WatchlistID: "wl1",
	})
	require.NoError(t, err)
	assert.Len(t, items, 1)
}

func TestGetWatchlist_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewGetWatchlistUseCase(&mockWatchlistStore{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetWatchlistQuery{WatchlistID: "wl1"})
	assert.ErrorContains(t, err, "email is required")
}

func TestGetWatchlist_EmptyID(t *testing.T) {
	t.Parallel()
	uc := NewGetWatchlistUseCase(&mockWatchlistStore{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetWatchlistQuery{Email: "u@t.com"})
	assert.ErrorContains(t, err, "watchlist_id is required")
}
