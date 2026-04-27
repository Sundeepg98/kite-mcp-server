// Package domain contains DDD value objects and domain events for the trading platform.
// These are pure domain types with zero external dependencies — they model the
// ubiquitous language of Indian equity trading (Money in INR, Quantities,
// InstrumentKeys like "NSE:RELIANCE") and domain events that capture what
// happened in the system.
package domain

import (
	"github.com/zerodha/kite-mcp-server/kc/money"
)

// Money is the canonical monetary value object. As of Slice 6e it lives
// in the leaf package kc/money so the broker package can import it
// without inverting the existing kc/domain → broker import direction
// (kc/domain itself imports broker for its rich Holding / Position /
// Order wrappers; broker → kc/domain would be a cycle).
//
// This type alias preserves the established Slice 1-6d API surface
// — 65+ files, 372+ constructor sites — without churn. domain.Money
// is structurally identical to money.Money: fields (Amount, Currency),
// methods (Add, Sub, Multiply, GreaterThan, Float64, IsPositive,
// IsZero, IsNegative, String), and struct literals all keep working.
//
// New code may import kc/money directly OR keep using kc/domain for
// the existing convention; both compile to the same type at the call
// site.
type Money = money.Money

// NewINR re-exports money.NewINR so existing call sites
// `domain.NewINR(N)` continue to work unchanged. Package-level
// function value (`var`, not `func`) is the cheapest re-export — Go
// resolves the call exactly like the original.
var NewINR = money.NewINR

// NewMoney re-exports money.NewMoney for the validated-positive
// constructor. Same identity guarantee as NewINR.
var NewMoney = money.NewMoney
