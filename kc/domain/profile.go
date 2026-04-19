package domain

import (
	"strings"

	"github.com/zerodha/kite-mcp-server/broker"
)

// Profile is the domain-layer representation of a trading account's
// identity + capability surface. Matches the broker.Profile wire DTO
// field-for-field so NewProfileFromBroker is a pure refcopy, but adds
// business-meaning methods that live on the entity rather than being
// duplicated in every tool handler that needs them.
//
// Scope:
//   - Exchange/product capability checks — used by pretrade validation,
//     compliance reporting, and the admin user page to show "what can
//     this user actually trade?". Previously callers would string-search
//     profile.Exchanges[] inline (4 prod sites and counting) and do a
//     case-sensitive comparison, producing subtle bugs when Kite
//     returns "NSE" but config uses "nse".
//
// Explicitly NOT modeled here — and NOT a DDD gap:
//   - IsKycComplete / AccountTenure / IsCorporateAccount — the Kite
//     Profile response carries NONE of these fields (no kyc_status,
//     no account_created_at, no account_type). Modeling them today
//     would be speculative entities that hold no data. If Zerodha's
//     API ever exposes these, add them to broker.Profile first, then
//     the methods land here trivially.
type Profile struct {
	UserID    string
	UserName  string
	Email     string
	Broker    string
	Exchanges []string
	Products  []string
}

// NewProfileFromBroker converts a broker.Profile DTO into the rich
// domain entity. Zero-value input returns a zero-value Profile — not
// an error — because Profile is a read-side snapshot; the "invalid
// profile" condition is the absence of one, not a malformed one.
func NewProfileFromBroker(p broker.Profile) Profile {
	exchanges := make([]string, len(p.Exchanges))
	copy(exchanges, p.Exchanges)
	products := make([]string, len(p.Products))
	copy(products, p.Products)
	return Profile{
		UserID:    p.UserID,
		UserName:  p.UserName,
		Email:     p.Email,
		Broker:    string(p.Broker),
		Exchanges: exchanges,
		Products:  products,
	}
}

// SupportsExchange reports whether the account can trade on the given
// exchange (NSE, BSE, NFO, BFO, MCX, ...). Case-insensitive because
// Kite responses are upper-case but user input + configs are mixed.
func (p Profile) SupportsExchange(exchange string) bool {
	want := strings.ToUpper(strings.TrimSpace(exchange))
	if want == "" {
		return false
	}
	for _, ex := range p.Exchanges {
		if strings.EqualFold(ex, want) {
			return true
		}
	}
	return false
}

// SupportsProduct reports whether the account can place orders with
// the given product type (CNC, MIS, NRML, MTF, ...). Case-insensitive
// for the same reason as SupportsExchange.
func (p Profile) SupportsProduct(product string) bool {
	want := strings.ToUpper(strings.TrimSpace(product))
	if want == "" {
		return false
	}
	for _, pr := range p.Products {
		if strings.EqualFold(pr, want) {
			return true
		}
	}
	return false
}

// HasEquityAccess reports whether the profile can trade on any equity
// exchange (NSE or BSE). Convenience predicate used by the pretrade
// check to short-circuit stock orders for F&O-only accounts.
func (p Profile) HasEquityAccess() bool {
	return p.SupportsExchange("NSE") || p.SupportsExchange("BSE")
}

// HasDerivativesAccess reports whether the profile can trade F&O
// (NFO, BFO). Segment-enabled brokers have explicit NFO activation;
// default retail accounts don't.
func (p Profile) HasDerivativesAccess() bool {
	return p.SupportsExchange("NFO") || p.SupportsExchange("BFO")
}

// HasCommodityAccess reports whether the profile can trade commodity
// futures (MCX). Separate enablement from equity derivatives.
func (p Profile) HasCommodityAccess() bool {
	return p.SupportsExchange("MCX")
}

// IsIntradayEligible reports whether the account can place intraday
// orders. Accounts with MIS product access can trade intraday; pure
// delivery accounts cannot.
func (p Profile) IsIntradayEligible() bool {
	return p.SupportsProduct("MIS")
}

// IsZerodhaAccount returns true if the broker name identifies a
// Zerodha Kite account. Useful for segment-specific code paths that
// depend on Kite-only features like ATO alerts.
func (p Profile) IsZerodhaAccount() bool {
	return strings.EqualFold(p.Broker, "zerodha")
}
