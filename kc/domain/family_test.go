package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewFamily_RejectsEmptyEmail(t *testing.T) {
	t.Parallel()
	_, err := NewFamily("", 0, 5)
	assert.Error(t, err)
}

func TestNewFamily_RejectsWhitespaceEmail(t *testing.T) {
	t.Parallel()
	_, err := NewFamily("   ", 0, 5)
	assert.Error(t, err)
}

func TestNewFamily_NormalisesEmail(t *testing.T) {
	t.Parallel()
	f, err := NewFamily("Admin@Example.COM", 0, 5)
	assert.NoError(t, err)
	assert.Equal(t, "admin@example.com", f.AdminEmail())
}

func TestNewFamily_RejectsNegativeCurrentSize(t *testing.T) {
	t.Parallel()
	_, err := NewFamily("a@b.com", -1, 5)
	assert.Error(t, err)
}

func TestNewFamily_RejectsZeroMaxSize(t *testing.T) {
	t.Parallel()
	_, err := NewFamily("a@b.com", 0, 0)
	assert.Error(t, err)
}

func TestFamily_CanInvite_HasRoom(t *testing.T) {
	t.Parallel()
	f, _ := NewFamily("a@b.com", 2, 5)
	assert.True(t, f.CanInvite())
	assert.False(t, f.IsAtCapacity())
	assert.Equal(t, 3, f.AvailableSeats())
}

func TestFamily_CanInvite_AtCapacity(t *testing.T) {
	t.Parallel()
	f, _ := NewFamily("a@b.com", 5, 5)
	assert.False(t, f.CanInvite())
	assert.True(t, f.IsAtCapacity())
	assert.Equal(t, 0, f.AvailableSeats())
}

func TestFamily_CanInvite_OverCapacity(t *testing.T) {
	t.Parallel()
	// Defensive: shouldn't happen at runtime, but test the boundary.
	f, _ := NewFamily("a@b.com", 7, 5)
	assert.False(t, f.CanInvite())
	assert.Equal(t, 0, f.AvailableSeats(), "AvailableSeats clamps to 0 when over capacity")
}

func TestFamily_CanInvite_OneSeatPlan(t *testing.T) {
	t.Parallel()
	// Single-seat plan with 0 used: can invite once. Matches the
	// pre-refactor `current < max` semantic in FamilyService.CanInvite.
	f, _ := NewFamily("a@b.com", 0, 1)
	assert.True(t, f.CanInvite())
	assert.False(t, f.IsAtCapacity())
	assert.Equal(t, 1, f.AvailableSeats())
}

func TestFamily_CanInvite_OneSeatPlan_Full(t *testing.T) {
	t.Parallel()
	// Single-seat plan with 1 used: at capacity.
	f, _ := NewFamily("a@b.com", 1, 1)
	assert.False(t, f.CanInvite())
	assert.True(t, f.IsAtCapacity())
}
