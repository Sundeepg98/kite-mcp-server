package alerts

// briefing_injection_test.go — Coverage push via briefing injection points.
// Covers:
//   - defaultBrokerProvider success paths (GetHoldings/GetPositions/GetUserMargins/GetLTP)
//     by wiring a KiteClientFactory whose clients point at testutil.MockKiteServer.
//   - BriefingService.SetKiteClientFactory (was 0%)
//   - PnLSnapshotService.SetKiteClientFactory (was 0%)

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/testutil"
)

// testKiteFactory implements alerts.KiteClientFactory, producing clients that
// hit the mock Kite HTTP server instead of the real API.
type testKiteFactory struct {
	baseURL string
}

func (f *testKiteFactory) NewClientWithToken(apiKey, accessToken string) *kiteconnect.Client {
	c := kiteconnect.New(apiKey)
	c.SetAccessToken(accessToken)
	c.SetBaseURI(f.baseURL)
	return c
}

func TestDefaultBrokerProvider_GetHoldings_SuccessViaFactory(t *testing.T) {
	t.Parallel()
	mock := testutil.NewMockKiteServer(t)
	p := &defaultBrokerProvider{factory: &testKiteFactory{baseURL: mock.URL()}}

	holdings, err := p.GetHoldings("test_key", "test_token")
	require.NoError(t, err)
	require.Len(t, holdings, 1)
	assert.Equal(t, "INFY", holdings[0].Tradingsymbol)
}

func TestDefaultBrokerProvider_GetPositions_SuccessViaFactory(t *testing.T) {
	t.Parallel()
	mock := testutil.NewMockKiteServer(t)
	p := &defaultBrokerProvider{factory: &testKiteFactory{baseURL: mock.URL()}}

	pos, err := p.GetPositions("test_key", "test_token")
	require.NoError(t, err)
	require.Len(t, pos.Net, 1)
	assert.Equal(t, "SBIN", pos.Net[0].Tradingsymbol)
}

func TestDefaultBrokerProvider_GetUserMargins_SuccessViaFactory(t *testing.T) {
	t.Parallel()
	mock := testutil.NewMockKiteServer(t)
	p := &defaultBrokerProvider{factory: &testKiteFactory{baseURL: mock.URL()}}

	margins, err := p.GetUserMargins("test_key", "test_token")
	require.NoError(t, err)
	assert.True(t, margins.Equity.Enabled)
	assert.InDelta(t, 100000.0, margins.Equity.Net, 0.001)
}

func TestDefaultBrokerProvider_GetLTP_SuccessViaFactory(t *testing.T) {
	t.Parallel()
	mock := testutil.NewMockKiteServer(t)
	p := &defaultBrokerProvider{factory: &testKiteFactory{baseURL: mock.URL()}}

	ltp, err := p.GetLTP("test_key", "test_token", "NSE:INFY", "NSE:RELIANCE")
	require.NoError(t, err)
	assert.Contains(t, ltp, "NSE:INFY")
	assert.InDelta(t, 1550.0, ltp["NSE:INFY"].LastPrice, 0.001)
}

// TestBriefingService_SetKiteClientFactory covers the previously-0% setter and
// verifies the default broker() path uses the wired factory to produce results.
func TestBriefingService_SetKiteClientFactory(t *testing.T) {
	t.Parallel()
	mock := testutil.NewMockKiteServer(t)

	b := &BriefingService{}
	b.SetKiteClientFactory(&testKiteFactory{baseURL: mock.URL()})

	// broker() with no explicit provider should use the default+factory path.
	bp := b.broker()
	require.NotNil(t, bp)
	_, isDefault := bp.(*defaultBrokerProvider)
	require.True(t, isDefault)

	holdings, err := bp.GetHoldings("test_key", "test_token")
	require.NoError(t, err)
	require.Len(t, holdings, 1)
	assert.Equal(t, "INFY", holdings[0].Tradingsymbol)
}

// TestBriefingService_SetKiteClientFactory_NilSafe exercises the nil-receiver
// guard on SetKiteClientFactory (the other branch of the if check).
func TestBriefingService_SetKiteClientFactory_NilSafe(t *testing.T) {
	t.Parallel()
	var b *BriefingService
	b.SetKiteClientFactory(&testKiteFactory{baseURL: "http://unused"}) // must not panic
}

// TestPnLSnapshotService_SetKiteClientFactory covers the previously-0% setter
// and verifies the factory flows through to broker() for default provider.
func TestPnLSnapshotService_SetKiteClientFactory(t *testing.T) {
	t.Parallel()
	mock := testutil.NewMockKiteServer(t)

	s := &PnLSnapshotService{}
	s.SetKiteClientFactory(&testKiteFactory{baseURL: mock.URL()})

	bp := s.broker()
	require.NotNil(t, bp)
	_, isDefault := bp.(*defaultBrokerProvider)
	require.True(t, isDefault)

	pos, err := bp.GetPositions("test_key", "test_token")
	require.NoError(t, err)
	require.Len(t, pos.Net, 1)
}

// TestPnLSnapshotService_SetKiteClientFactory_NilSafe exercises the nil-receiver
// guard on SetKiteClientFactory.
func TestPnLSnapshotService_SetKiteClientFactory_NilSafe(t *testing.T) {
	t.Parallel()
	var s *PnLSnapshotService
	s.SetKiteClientFactory(&testKiteFactory{baseURL: "http://unused"}) // must not panic
}
