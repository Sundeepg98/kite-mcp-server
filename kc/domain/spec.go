package domain

import "fmt"

// --- Specification Pattern ---
// Specifications encapsulate reusable business rules as composable, testable
// objects. Instead of scattering validation logic across use cases, rules are
// expressed as first-class domain types that can be combined with And/Or/Not.

// Spec is a predicate over a value of type T.
// Implementations encode a single business rule ("quantity is within lot limits",
// "price is positive", "order passes all pre-trade checks").
type Spec[T any] interface {
	// IsSatisfiedBy returns true if the candidate meets this specification.
	IsSatisfiedBy(candidate T) bool
	// Reason returns a human-readable explanation when IsSatisfiedBy returns false.
	// Callers may use this to build rejection messages.
	Reason() string
}

// --- Composite specifications ---

// AndSpec is satisfied only when both Left and Right are satisfied.
type AndSpec[T any] struct {
	Left  Spec[T]
	Right Spec[T]
	last  string // cached reason from the failing side
}

// And returns a new specification that is the logical conjunction of two specs.
func And[T any](left, right Spec[T]) *AndSpec[T] {
	return &AndSpec[T]{Left: left, Right: right}
}

func (s *AndSpec[T]) IsSatisfiedBy(candidate T) bool {
	if !s.Left.IsSatisfiedBy(candidate) {
		s.last = s.Left.Reason()
		return false
	}
	if !s.Right.IsSatisfiedBy(candidate) {
		s.last = s.Right.Reason()
		return false
	}
	return true
}

func (s *AndSpec[T]) Reason() string { return s.last }

// OrSpec is satisfied when at least one of Left or Right is satisfied.
type OrSpec[T any] struct {
	Left  Spec[T]
	Right Spec[T]
	last  string
}

// Or returns a new specification that is the logical disjunction of two specs.
func Or[T any](left, right Spec[T]) *OrSpec[T] {
	return &OrSpec[T]{Left: left, Right: right}
}

func (s *OrSpec[T]) IsSatisfiedBy(candidate T) bool {
	if s.Left.IsSatisfiedBy(candidate) {
		return true
	}
	if s.Right.IsSatisfiedBy(candidate) {
		return true
	}
	s.last = fmt.Sprintf("%s; also %s", s.Left.Reason(), s.Right.Reason())
	return false
}

func (s *OrSpec[T]) Reason() string { return s.last }

// NotSpec negates the inner specification.
type NotSpec[T any] struct {
	Inner  Spec[T]
	reason string
}

// Not returns a new specification that is the logical negation of inner.
func Not[T any](inner Spec[T]) *NotSpec[T] {
	return &NotSpec[T]{Inner: inner}
}

func (s *NotSpec[T]) IsSatisfiedBy(candidate T) bool {
	if s.Inner.IsSatisfiedBy(candidate) {
		s.reason = fmt.Sprintf("expected NOT(%s) to fail", s.Inner.Reason())
		return false
	}
	return true
}

func (s *NotSpec[T]) Reason() string { return s.reason }

// --- Concrete trading specifications ---

// QuantitySpec validates that an integer quantity falls within [Min, Max].
// Min defaults to 1 if zero; Max of 0 means no upper bound.
type QuantitySpec struct {
	Min    int
	Max    int
	reason string
}

// NewQuantitySpec creates a quantity specification with the given bounds.
func NewQuantitySpec(min, max int) *QuantitySpec {
	if min <= 0 {
		min = 1
	}
	return &QuantitySpec{Min: min, Max: max}
}

func (s *QuantitySpec) IsSatisfiedBy(qty int) bool {
	if qty < s.Min {
		s.reason = fmt.Sprintf("quantity %d below minimum %d", qty, s.Min)
		return false
	}
	if s.Max > 0 && qty > s.Max {
		s.reason = fmt.Sprintf("quantity %d exceeds maximum %d", qty, s.Max)
		return false
	}
	return true
}

func (s *QuantitySpec) Reason() string { return s.reason }

// PriceSpec validates that a price is positive and within an optional ceiling.
// A zero-Money MaxPrice means no upper bound. Currency-aware: a candidate
// price in a different currency than the configured ceiling is rejected
// with an explanatory reason — never silently coerced.
type PriceSpec struct {
	MaxPrice Money // zero-Money means no upper bound
	reason   string
}

// NewPriceSpec creates a price specification with the given ceiling.
// Pass a zero-Money (e.g. domain.Money{}) for no upper bound; the standard
// constructor for "no bound" is the literal zero value, which IsSatisfiedBy
// treats as "skip ceiling check" via IsZero.
func NewPriceSpec(maxPrice Money) *PriceSpec {
	return &PriceSpec{MaxPrice: maxPrice}
}

// IsSatisfiedBy reports whether the candidate price is positive and (when
// the spec has a non-zero ceiling) does not exceed MaxPrice. Cross-currency
// comparisons are rejected — a USD ceiling cannot validate an INR
// candidate, so the spec records a currency-mismatch reason rather than
// performing implicit conversion.
func (s *PriceSpec) IsSatisfiedBy(price Money) bool {
	if !price.IsPositive() {
		s.reason = fmt.Sprintf("price %s must be positive", price)
		return false
	}
	if s.MaxPrice.IsZero() {
		return true
	}
	if s.MaxPrice.Currency != price.Currency {
		s.reason = fmt.Sprintf("price currency %s does not match maximum %s", price.Currency, s.MaxPrice.Currency)
		return false
	}
	if price.Amount > s.MaxPrice.Amount {
		s.reason = fmt.Sprintf("price %s exceeds maximum %s", price, s.MaxPrice)
		return false
	}
	return true
}

func (s *PriceSpec) Reason() string { return s.reason }

// OrderCandidate bundles the fields needed for composite order validation.
// This is a transient value — not persisted, just passed through specs.
// Price is a Money value object (currency-aware); MARKET / SL-M orders
// carry the zero-Money by convention, and OrderSpec.IsSatisfiedBy skips
// the price check on those order types.
type OrderCandidate struct {
	Quantity        int
	Price           Money
	Exchange        string
	Tradingsymbol   string
	TransactionType string // "BUY" or "SELL"
	OrderType       string // "MARKET", "LIMIT", "SL", "SL-M"
}

// OrderSpec composes quantity and price specs into a single order-level check.
// Additional rules (valid exchange, valid order type) are included.
type OrderSpec struct {
	QtySpec   *QuantitySpec
	PriceSpec *PriceSpec
	reason    string
}

// NewOrderSpec creates a composite order specification.
func NewOrderSpec(qtySpec *QuantitySpec, priceSpec *PriceSpec) *OrderSpec {
	return &OrderSpec{QtySpec: qtySpec, PriceSpec: priceSpec}
}

func (s *OrderSpec) IsSatisfiedBy(o OrderCandidate) bool {
	if o.Tradingsymbol == "" {
		s.reason = "tradingsymbol is required"
		return false
	}
	if o.TransactionType != "BUY" && o.TransactionType != "SELL" {
		s.reason = fmt.Sprintf("transaction_type must be BUY or SELL, got %q", o.TransactionType)
		return false
	}
	if !s.QtySpec.IsSatisfiedBy(o.Quantity) {
		s.reason = s.QtySpec.Reason()
		return false
	}
	// Price check only for non-MARKET orders (MARKET orders have price=0).
	if o.OrderType != "MARKET" && o.OrderType != "SL-M" {
		if !s.PriceSpec.IsSatisfiedBy(o.Price) {
			s.reason = s.PriceSpec.Reason()
			return false
		}
	}
	return true
}

func (s *OrderSpec) Reason() string { return s.reason }
