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

// String returns the quantity as a string.
func (q Quantity) String() string {
	return fmt.Sprintf("%d", q.value)
}
