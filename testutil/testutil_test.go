package testutil

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// MockKiteServer tests
// ---------------------------------------------------------------------------

func TestNewMockKiteServer(t *testing.T) {
	t.Parallel()
	srv := NewMockKiteServer(t)
	assert.NotNil(t, srv)
	assert.NotEmpty(t, srv.URL())
}

func TestMockKiteServer_Client(t *testing.T) {
	t.Parallel()
	srv := NewMockKiteServer(t)
	kc := srv.Client("test_key", "test_token")
	assert.NotNil(t, kc)
}

func TestMockKiteServer_ProfileEndpoint(t *testing.T) {
	t.Parallel()
	srv := NewMockKiteServer(t)
	body := httpGet(t, srv.URL()+"/user/profile")

	var envelope map[string]any
	require.NoError(t, json.Unmarshal(body, &envelope))
	assert.Equal(t, "success", envelope["status"])

	data, ok := envelope["data"].(map[string]any)
	require.True(t, ok, "data should be an object")
	assert.Equal(t, "AB1234", data["user_id"])
	assert.Equal(t, "test@example.com", data["email"])
}

func TestMockKiteServer_HoldingsEndpoint(t *testing.T) {
	t.Parallel()
	srv := NewMockKiteServer(t)
	body := httpGet(t, srv.URL()+"/portfolio/holdings")

	var envelope map[string]any
	require.NoError(t, json.Unmarshal(body, &envelope))
	assert.Equal(t, "success", envelope["status"])

	data, ok := envelope["data"].([]any)
	require.True(t, ok, "holdings data should be an array")
	assert.Len(t, data, 1)
}

func TestMockKiteServer_PositionsEndpoint(t *testing.T) {
	t.Parallel()
	srv := NewMockKiteServer(t)
	body := httpGet(t, srv.URL()+"/portfolio/positions")

	var envelope map[string]any
	require.NoError(t, json.Unmarshal(body, &envelope))
	assert.Equal(t, "success", envelope["status"])

	data, ok := envelope["data"].(map[string]any)
	require.True(t, ok, "positions data should be an object")
	_, hasNet := data["net"]
	assert.True(t, hasNet, "positions should have 'net' field")
}

func TestMockKiteServer_OrdersEndpoint(t *testing.T) {
	t.Parallel()
	srv := NewMockKiteServer(t)
	body := httpGet(t, srv.URL()+"/orders")

	var envelope map[string]any
	require.NoError(t, json.Unmarshal(body, &envelope))
	assert.Equal(t, "success", envelope["status"])

	data, ok := envelope["data"].([]any)
	require.True(t, ok)
	assert.Len(t, data, 1)
}

func TestMockKiteServer_TradesEndpoint(t *testing.T) {
	t.Parallel()
	srv := NewMockKiteServer(t)
	body := httpGet(t, srv.URL()+"/trades")

	var envelope map[string]any
	require.NoError(t, json.Unmarshal(body, &envelope))
	assert.Equal(t, "success", envelope["status"])
}

func TestMockKiteServer_QuoteEndpoint(t *testing.T) {
	t.Parallel()
	srv := NewMockKiteServer(t)
	// The SDK routes GetLTP/GetOHLC/GetQuotes all through /quote.
	body := httpGet(t, srv.URL()+"/quote")

	var envelope map[string]any
	require.NoError(t, json.Unmarshal(body, &envelope))
	assert.Equal(t, "success", envelope["status"])

	data, ok := envelope["data"].(map[string]any)
	require.True(t, ok)
	_, hasINFY := data["NSE:INFY"]
	assert.True(t, hasINFY, "quotes should contain NSE:INFY")
	_, hasRELIANCE := data["NSE:RELIANCE"]
	assert.True(t, hasRELIANCE, "quotes should contain NSE:RELIANCE")
}

func TestMockKiteServer_QuoteLTPAlias(t *testing.T) {
	t.Parallel()
	srv := NewMockKiteServer(t)
	// /quote/ltp is an alias for /quote, for direct HTTP testing convenience.
	body := httpGet(t, srv.URL()+"/quote/ltp")

	var envelope map[string]any
	require.NoError(t, json.Unmarshal(body, &envelope))
	assert.Equal(t, "success", envelope["status"])
}

func TestMockKiteServer_QuoteOHLCAlias(t *testing.T) {
	t.Parallel()
	srv := NewMockKiteServer(t)
	body := httpGet(t, srv.URL()+"/quote/ohlc")

	var envelope map[string]any
	require.NoError(t, json.Unmarshal(body, &envelope))
	assert.Equal(t, "success", envelope["status"])
}

func TestMockKiteServer_TriggerRangeEndpoint(t *testing.T) {
	t.Parallel()
	srv := NewMockKiteServer(t)
	body := httpGet(t, srv.URL()+"/instruments/NSE/INFY/trigger_range")

	var envelope map[string]any
	require.NoError(t, json.Unmarshal(body, &envelope))
	assert.Equal(t, "success", envelope["status"])
}

func TestMockKiteServer_MFOrdersEndpoint(t *testing.T) {
	t.Parallel()
	srv := NewMockKiteServer(t)
	body := httpGet(t, srv.URL()+"/mf/orders")

	var envelope map[string]any
	require.NoError(t, json.Unmarshal(body, &envelope))
	assert.Equal(t, "success", envelope["status"])
}

func TestMockKiteServer_MFSIPsEndpoint(t *testing.T) {
	t.Parallel()
	srv := NewMockKiteServer(t)
	body := httpGet(t, srv.URL()+"/mf/sips")

	var envelope map[string]any
	require.NoError(t, json.Unmarshal(body, &envelope))
	assert.Equal(t, "success", envelope["status"])
}

func TestMockKiteServer_MFHoldingsEndpoint(t *testing.T) {
	t.Parallel()
	srv := NewMockKiteServer(t)
	body := httpGet(t, srv.URL()+"/mf/holdings")

	var envelope map[string]any
	require.NoError(t, json.Unmarshal(body, &envelope))
	assert.Equal(t, "success", envelope["status"])
}

func TestMockKiteServer_MarginsEndpoint(t *testing.T) {
	t.Parallel()
	srv := NewMockKiteServer(t)
	body := httpGet(t, srv.URL()+"/user/margins")

	var envelope map[string]any
	require.NoError(t, json.Unmarshal(body, &envelope))
	assert.Equal(t, "success", envelope["status"])

	data, ok := envelope["data"].(map[string]any)
	require.True(t, ok)
	_, hasEquity := data["equity"]
	assert.True(t, hasEquity, "margins should have 'equity' field")
}

func TestMockKiteServer_OrderMarginsEndpoint(t *testing.T) {
	t.Parallel()
	srv := NewMockKiteServer(t)
	body := httpGet(t, srv.URL()+"/margins/orders")

	var envelope map[string]any
	require.NoError(t, json.Unmarshal(body, &envelope))
	assert.Equal(t, "success", envelope["status"])
}

func TestMockKiteServer_BasketMarginsEndpoint(t *testing.T) {
	t.Parallel()
	srv := NewMockKiteServer(t)
	body := httpGet(t, srv.URL()+"/margins/basket")

	var envelope map[string]any
	require.NoError(t, json.Unmarshal(body, &envelope))
	assert.Equal(t, "success", envelope["status"])
}

func TestMockKiteServer_InstrumentsCSV(t *testing.T) {
	t.Parallel()
	srv := NewMockKiteServer(t)
	resp, err := http.Get(srv.URL() + "/instruments")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/csv", resp.Header.Get("Content-Type"))
}

func TestMockKiteServer_SetProfile(t *testing.T) {
	t.Parallel()
	srv := NewMockKiteServer(t)
	custom := map[string]any{"user_id": "XY9999", "email": "custom@test.com"}
	srv.SetProfile(custom)

	body := httpGet(t, srv.URL()+"/user/profile")
	var envelope map[string]any
	require.NoError(t, json.Unmarshal(body, &envelope))

	data, ok := envelope["data"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "XY9999", data["user_id"])
}

func TestMockKiteServer_SetHoldings(t *testing.T) {
	t.Parallel()
	srv := NewMockKiteServer(t)
	srv.SetHoldings([]map[string]any{})

	body := httpGet(t, srv.URL()+"/portfolio/holdings")
	var envelope map[string]any
	require.NoError(t, json.Unmarshal(body, &envelope))

	data, ok := envelope["data"].([]any)
	require.True(t, ok)
	assert.Empty(t, data)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func TestDiscardLogger(t *testing.T) {
	t.Parallel()
	logger := DiscardLogger()
	assert.NotNil(t, logger)
}

// ---------------------------------------------------------------------------
// NewSessionKiteServer tests
// ---------------------------------------------------------------------------

func TestNewSessionKiteServer_ProfileRoute(t *testing.T) {
	t.Parallel()
	srv := NewSessionKiteServer(t)
	body := httpGet(t, srv.URL+"/user/profile")

	var envelope map[string]any
	require.NoError(t, json.Unmarshal(body, &envelope))
	assert.Equal(t, "success", envelope["status"])
}

func TestNewSessionKiteServer_SessionTokenPOST(t *testing.T) {
	t.Parallel()
	srv := NewSessionKiteServer(t)
	resp, err := http.Post(srv.URL+"/session/token", "application/x-www-form-urlencoded", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var envelope map[string]any
	require.NoError(t, json.Unmarshal(body, &envelope))
	assert.Equal(t, "success", envelope["status"])

	data, ok := envelope["data"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "mock-access-token", data["access_token"])
}

func TestNewSessionKiteServer_SessionTokenDELETE(t *testing.T) {
	t.Parallel()
	srv := NewSessionKiteServer(t)
	req, err := http.NewRequest(http.MethodDelete, srv.URL+"/session/token", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// httpGet is a test helper that performs a GET and returns the body bytes.
func httpGet(t *testing.T, url string) []byte {
	t.Helper()
	resp, err := http.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return body
}
