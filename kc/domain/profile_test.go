package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zerodha/kite-mcp-server/broker"
)

func TestNewProfileFromBroker_CopiesFields(t *testing.T) {
	t.Parallel()

	src := broker.Profile{
		UserID:    "KA1234",
		UserName:  "Test User",
		Email:     "u@example.com",
		Broker:    broker.Zerodha,
		Exchanges: []string{"NSE", "BSE", "NFO"},
		Products:  []string{"CNC", "MIS", "NRML"},
	}

	p := NewProfileFromBroker(src)
	assert.Equal(t, "KA1234", p.UserID)
	assert.Equal(t, "Test User", p.UserName)
	assert.Equal(t, "u@example.com", p.Email)
	assert.Equal(t, "zerodha", p.Broker)
	assert.Equal(t, []string{"NSE", "BSE", "NFO"}, p.Exchanges)
	assert.Equal(t, []string{"CNC", "MIS", "NRML"}, p.Products)

	// Mutating the source slices after conversion must not affect the
	// rich entity — proves we made a defensive copy.
	src.Exchanges[0] = "MUTATED"
	src.Products[0] = "MUTATED"
	assert.Equal(t, "NSE", p.Exchanges[0])
	assert.Equal(t, "CNC", p.Products[0])
}

func TestProfile_SupportsExchange(t *testing.T) {
	t.Parallel()

	p := Profile{Exchanges: []string{"NSE", "BSE"}}

	assert.True(t, p.SupportsExchange("NSE"))
	assert.True(t, p.SupportsExchange("nse"), "case-insensitive")
	assert.True(t, p.SupportsExchange("  BSE "), "trims whitespace")
	assert.False(t, p.SupportsExchange("NFO"))
	assert.False(t, p.SupportsExchange(""))
}

func TestProfile_SupportsProduct(t *testing.T) {
	t.Parallel()

	p := Profile{Products: []string{"CNC", "MIS"}}

	assert.True(t, p.SupportsProduct("CNC"))
	assert.True(t, p.SupportsProduct("mis"))
	assert.False(t, p.SupportsProduct("NRML"))
	assert.False(t, p.SupportsProduct(""))
}

func TestProfile_SegmentConvenience(t *testing.T) {
	t.Parallel()

	equityOnly := Profile{
		Exchanges: []string{"NSE", "BSE"},
		Products:  []string{"CNC"},
	}
	assert.True(t, equityOnly.HasEquityAccess())
	assert.False(t, equityOnly.HasDerivativesAccess())
	assert.False(t, equityOnly.HasCommodityAccess())
	assert.False(t, equityOnly.IsIntradayEligible())

	fullRetail := Profile{
		Exchanges: []string{"NSE", "BSE", "NFO", "BFO", "MCX"},
		Products:  []string{"CNC", "MIS", "NRML"},
	}
	assert.True(t, fullRetail.HasEquityAccess())
	assert.True(t, fullRetail.HasDerivativesAccess())
	assert.True(t, fullRetail.HasCommodityAccess())
	assert.True(t, fullRetail.IsIntradayEligible())
}

func TestProfile_IsZerodhaAccount(t *testing.T) {
	t.Parallel()

	assert.True(t, Profile{Broker: "zerodha"}.IsZerodhaAccount())
	assert.True(t, Profile{Broker: "Zerodha"}.IsZerodhaAccount())
	assert.False(t, Profile{Broker: "angelone"}.IsZerodhaAccount())
	assert.False(t, Profile{Broker: ""}.IsZerodhaAccount())
}
