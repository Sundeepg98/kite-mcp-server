package domain

import "fmt"

// Quantity is a value object representing an order quantity.
// It is always a positive integer — zero and negative quantities are invalid.
type Quantity struct {
	value int
}

// NewQuantity creates a validated Quantity. Returns an error if v <= 0.
func NewQuantity(v int) (Quantity, error) {
	if v <= 0 {
		return Quantity{}, fmt.Errorf("domain: quantity must be positive, got %d", v)
	}
	return Quantity{value: v}, nil
}

// Int returns the underlying integer value.
func (q Quantity) Int() int {
	return q.value
}

// IsValid returns true if the quantity has a positive value.
// A zero-value Quantity (e.g., from var q Quantity) is invalid.
func (q Quantity) IsValid() bool {
	return q.value > 0
}

// String returns the quantity as a string.
func (q Quantity) String() string {
	return fmt.Sprintf("%d", q.value)
}
