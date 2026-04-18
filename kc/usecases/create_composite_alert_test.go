package usecases

// create_composite_alert_test.go — tests for CreateCompositeAlertUseCase.
// Mirrors the TDD patterns in usecases_test.go (validation table + happy
// path + store-error surface). The use case owns business-logic validation
// (min/max legs, operator compatibility, reference-price requirements);
// the store only enforces persistence invariants (quota, row writes).

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// mockCompositeAlertStore implements CompositeAlertStore for use-case tests.
// It records the last composite that was added so assertions can inspect it.
type mockCompositeAlertStore struct {
	lastEmail      string
	lastName       string
	lastLogic      domain.CompositeLogic
	lastConditions []domain.CompositeCondition
	returnID       string
	returnErr      error
}

func (m *mockCompositeAlertStore) AddComposite(email, name string, logic domain.CompositeLogic, conds []domain.CompositeCondition) (string, error) {
	if m.returnErr != nil {
		return "", m.returnErr
	}
	m.lastEmail = email
	m.lastName = name
	m.lastLogic = logic
	// Copy to avoid aliasing with caller's slice.
	m.lastConditions = append([]domain.CompositeCondition(nil), conds...)
	if m.returnID == "" {
		return "CMP-1", nil
	}
	return m.returnID, nil
}

// validComposite returns a cqrs command with two valid legs so individual
// tests only need to override the field under test.
func validComposite() cqrs.CreateCompositeAlertCommand {
	return cqrs.CreateCompositeAlertCommand{
		Email: "user@example.com",
		Name:  "nifty_vix",
		Logic: string(domain.CompositeLogicAnd),
		Conditions: []cqrs.CompositeConditionSpec{
			{Exchange: "NSE", Tradingsymbol: "NIFTY 50", Operator: "drop_pct", Value: 0.5, ReferencePrice: 22500.0},
			{Exchange: "NSE", Tradingsymbol: "INDIA VIX", Operator: "rise_pct", Value: 15.0, ReferencePrice: 14.2},
		},
	}
}

// TestCreateCompositeAlert_Success is the happy path: valid command, store
// succeeds, use case returns the ID and tokens resolve on every leg.
func TestCreateCompositeAlert_Success(t *testing.T) {
	store := &mockCompositeAlertStore{returnID: "CMP-42"}
	resolver := &mockInstrumentResolver{token: 256265}
	uc := NewCreateCompositeAlertUseCase(store, resolver, testLogger())

	id, err := uc.Execute(context.Background(), validComposite())
	require.NoError(t, err)
	assert.Equal(t, "CMP-42", id)
	assert.Equal(t, "user@example.com", store.lastEmail)
	assert.Equal(t, "nifty_vix", store.lastName)
	assert.Equal(t, domain.CompositeLogicAnd, store.lastLogic)
	require.Len(t, store.lastConditions, 2)
	// Instrument tokens should be resolved from the resolver.
	assert.Equal(t, uint32(256265), store.lastConditions[0].InstrumentToken)
	assert.Equal(t, uint32(256265), store.lastConditions[1].InstrumentToken)
}

// TestCreateCompositeAlert_ValidationFailures covers every rejection path
// so the use case's validation matrix is exercised. Cases are expressed
// as table-driven tests to match the patterns in usecases_test.go.
func TestCreateCompositeAlert_ValidationFailures(t *testing.T) {
	uc := NewCreateCompositeAlertUseCase(nil, nil, testLogger())

	tests := []struct {
		name string
		mut  func(c *cqrs.CreateCompositeAlertCommand)
		want string
	}{
		{
			name: "empty email",
			mut:  func(c *cqrs.CreateCompositeAlertCommand) { c.Email = "" },
			want: "email is required",
		},
		{
			name: "empty name",
			mut:  func(c *cqrs.CreateCompositeAlertCommand) { c.Name = "" },
			want: "name is required",
		},
		{
			name: "invalid logic",
			mut:  func(c *cqrs.CreateCompositeAlertCommand) { c.Logic = "XOR" },
			want: "logic",
		},
		{
			name: "too few conditions",
			mut: func(c *cqrs.CreateCompositeAlertCommand) {
				c.Conditions = c.Conditions[:1]
			},
			want: "at least",
		},
		{
			name: "too many conditions",
			mut: func(c *cqrs.CreateCompositeAlertCommand) {
				tmpl := c.Conditions[0]
				c.Conditions = nil
				for range 11 {
					c.Conditions = append(c.Conditions, tmpl)
				}
			},
			want: "at most",
		},
		{
			name: "invalid operator",
			mut: func(c *cqrs.CreateCompositeAlertCommand) {
				c.Conditions[0].Operator = "sideways"
			},
			want: "operator",
		},
		{
			name: "zero value",
			mut: func(c *cqrs.CreateCompositeAlertCommand) {
				c.Conditions[0].Value = 0
			},
			want: "value",
		},
		{
			name: "percentage missing reference",
			mut: func(c *cqrs.CreateCompositeAlertCommand) {
				c.Conditions[0].Operator = "drop_pct"
				c.Conditions[0].ReferencePrice = 0
			},
			want: "reference_price",
		},
		{
			name: "percentage > 100",
			mut: func(c *cqrs.CreateCompositeAlertCommand) {
				c.Conditions[0].Operator = "drop_pct"
				c.Conditions[0].Value = 150.0
				c.Conditions[0].ReferencePrice = 100.0
			},
			want: "percentage",
		},
		{
			name: "empty exchange",
			mut: func(c *cqrs.CreateCompositeAlertCommand) {
				c.Conditions[0].Exchange = ""
			},
			want: "exchange",
		},
		{
			name: "empty tradingsymbol",
			mut: func(c *cqrs.CreateCompositeAlertCommand) {
				c.Conditions[0].Tradingsymbol = ""
			},
			want: "tradingsymbol",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := validComposite()
			tt.mut(&cmd)
			_, err := uc.Execute(context.Background(), cmd)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

// TestCreateCompositeAlert_InstrumentResolveError surfaces per-leg
// instrument-lookup failures with the offending leg index so callers
// can pinpoint the bad input.
func TestCreateCompositeAlert_InstrumentResolveError(t *testing.T) {
	resolver := &mockInstrumentResolver{err: fmt.Errorf("not found")}
	uc := NewCreateCompositeAlertUseCase(nil, resolver, testLogger())

	_, err := uc.Execute(context.Background(), validComposite())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve instrument")
}

// TestCreateCompositeAlert_StoreError verifies that store failures are
// wrapped (not swallowed) and don't leak bare fmt.Errorf tokens.
func TestCreateCompositeAlert_StoreError(t *testing.T) {
	store := &mockCompositeAlertStore{returnErr: fmt.Errorf("db write failed")}
	resolver := &mockInstrumentResolver{token: 256265}
	uc := NewCreateCompositeAlertUseCase(store, resolver, testLogger())

	_, err := uc.Execute(context.Background(), validComposite())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create composite alert")
}

// TestCreateCompositeAlert_LogicNormalization ensures case-insensitive
// logic parsing ("and" -> AND) — the tool handler already uppercases,
// but the use case should not rely on the caller's casing.
func TestCreateCompositeAlert_LogicNormalization(t *testing.T) {
	store := &mockCompositeAlertStore{}
	resolver := &mockInstrumentResolver{token: 256265}
	uc := NewCreateCompositeAlertUseCase(store, resolver, testLogger())

	cmd := validComposite()
	cmd.Logic = "and"
	_, err := uc.Execute(context.Background(), cmd)
	require.NoError(t, err)
	assert.Equal(t, domain.CompositeLogicAnd, store.lastLogic)

	cmd.Logic = "Any"
	_, err = uc.Execute(context.Background(), cmd)
	require.NoError(t, err)
	assert.Equal(t, domain.CompositeLogicAny, store.lastLogic)
}

// TestCreateCompositeAlert_CompatibleWithAlertStore confirms the
// production-store method signature satisfies the use-case interface.
// This is a compile-time guard: if AddComposite's signature drifts, the
// build breaks here before downstream call sites notice.
func TestCreateCompositeAlert_CompatibleWithAlertStore(t *testing.T) {
	var _ CompositeAlertStore = (*alerts.Store)(nil)
}
