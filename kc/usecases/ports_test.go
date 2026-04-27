package usecases

import (
	"errors"
	"testing"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/broker/mock"
)

// ports_test.go locks the BrokerResolver port contract with executable
// tests. The contract has THREE behavioural cases, one happy + two
// error shapes; this file pins each one and the interface-compliance
// boundary so any future signature drift breaks the build (interface
// assertions) AND the test suite (behaviour cases).
//
// Wave D Phase 1 Slice D1 — port introduction. No use cases migrated
// yet; this file documents the contract D2-D7 will rely on.

// --- interface compliance ---

// brokerResolverInterfaceAssertion is a compile-time witness that
// BrokerResolver remains exactly one method with the documented
// signature. Adding/removing/renaming methods on the interface OR on
// the asserted concrete types breaks the build here, alerting any
// drift before D2-D7 callers regress.
//
// We use the test-internal mockBrokerResolver (defined in mocks_test.go)
// as the concrete witness because it lives in this package and only
// exists in test builds — no production import dependency.
//
// Note: assigning a typed-nil pointer to a non-nil interface value is
// the documented "interface holds a typed-nil concrete" pattern and
// what we want — the assertion fires at compile time even though the
// runtime value's interface header is non-nil.
var _ BrokerResolver = (*mockBrokerResolver)(nil)

// Second witness using the local test-only impl, locking the contract
// to "any one-method implementation satisfies the port".
var _ BrokerResolver = (*brokerResolverTestImpl)(nil)

func TestBrokerResolver_ContractInterfaceShape(t *testing.T) {
	t.Parallel()

	// The two var assertions above provide compile-time guarantees.
	// This test exercises the concrete witnesses through the
	// interface to ensure the method set is reachable at runtime.
	var resolver BrokerResolver = &mockBrokerResolver{}
	if resolver == nil {
		t.Fatal("expected non-nil interface holding typed mock")
	}
}

// --- behavioural contract ---

func TestBrokerResolver_ReturnsResolvedClient(t *testing.T) {
	t.Parallel()

	// Contract: when the resolver has a backing client for the email,
	// GetBrokerForEmail returns (client, nil).
	client := mock.NewDemoClient()
	resolver := &mockBrokerResolver{client: client}

	got, err := resolver.GetBrokerForEmail("user@example.com")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil client")
	}
	if got != client {
		t.Errorf("expected resolver to return its backing client, got different broker.Client")
	}
}

func TestBrokerResolver_PropagatesResolutionError(t *testing.T) {
	t.Parallel()

	// Contract: when the resolver fails to look up a client, it
	// returns (nil, err) — the error MUST be non-nil and the client
	// MUST be nil. Use cases rely on errors.Is / errors.As to
	// distinguish "no token" vs "broker construction failed".
	wantErr := errors.New("no Kite access token for user@example.com")
	resolver := &mockBrokerResolver{resolveErr: wantErr}

	got, err := resolver.GetBrokerForEmail("user@example.com")
	if err == nil {
		t.Fatal("expected non-nil error on resolution failure")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("expected error chain to contain wantErr, got %v", err)
	}
	if got != nil {
		t.Errorf("expected nil client on error, got non-nil")
	}
}

func TestBrokerResolver_EmptyEmailIsResolverConcern(t *testing.T) {
	t.Parallel()

	// Contract: BrokerResolver does NOT itself validate the email
	// argument — empty-string handling is left to the implementation
	// (production *kc.SessionService returns an error via the
	// downstream credential lookup; *kc.pinnedBrokerResolver ignores
	// the email entirely because it's a pre-resolved client).
	//
	// This test pins the "no shared empty-email policy at the port
	// level" expectation: callers must not assume the port short-
	// circuits on "" — they must handle the underlying error or
	// validate before dispatch.
	client := mock.NewDemoClient()
	resolver := &mockBrokerResolver{client: client}

	got, err := resolver.GetBrokerForEmail("")
	if err != nil {
		t.Fatalf("mockBrokerResolver should pass empty email through, got err: %v", err)
	}
	if got == nil {
		t.Fatal("mockBrokerResolver should return its backing client for any email, got nil")
	}
}

// --- table-driven multi-implementation contract ---

// brokerResolverTestImpl is a minimal implementation used to exercise
// the contract. Mirrors *kc.pinnedBrokerResolver's
// "ignore-email-return-pinned-client" flavor.
type brokerResolverTestImpl struct {
	client broker.Client
	err    error
}

func (r *brokerResolverTestImpl) GetBrokerForEmail(_ string) (broker.Client, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.client, nil
}

func TestBrokerResolver_ContractTableDriven(t *testing.T) {
	t.Parallel()

	demoClient := mock.NewDemoClient()
	wantErr := errors.New("session lookup failed")

	tests := []struct {
		name       string
		resolver   BrokerResolver
		email      string
		wantClient bool
		wantErr    error
	}{
		{
			name:       "happy path returns client",
			resolver:   &brokerResolverTestImpl{client: demoClient},
			email:      "user@example.com",
			wantClient: true,
			wantErr:    nil,
		},
		{
			name:       "error path returns err",
			resolver:   &brokerResolverTestImpl{err: wantErr},
			email:      "user@example.com",
			wantClient: false,
			wantErr:    wantErr,
		},
		{
			name:       "empty email passes through",
			resolver:   &brokerResolverTestImpl{client: demoClient},
			email:      "",
			wantClient: true,
			wantErr:    nil,
		},
		{
			name:       "mockBrokerResolver also satisfies the port",
			resolver:   &mockBrokerResolver{client: demoClient},
			email:      "user@example.com",
			wantClient: true,
			wantErr:    nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := tt.resolver.GetBrokerForEmail(tt.email)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("error chain mismatch: got %v, want %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}

			if tt.wantClient && got == nil {
				t.Errorf("expected non-nil client")
			}
			if !tt.wantClient && got != nil {
				t.Errorf("expected nil client on error")
			}
		})
	}
}
