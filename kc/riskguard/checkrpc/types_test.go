// Package checkrpc smoke tests for the wire-types contract.
//
// These tests pin the public IPC contract that cross-language plugins
// rely on. The wire types (OrderCheckRequestWire, CheckResultWire) are
// gob-serialised at the host ↔ subprocess boundary; any field rename,
// type change, or struct-tag mutation is a wire-format break that
// would silently corrupt every existing plugin binary.
//
// Test discipline:
//
//   - Round-trip via encoding/gob (the transport hashicorp/go-plugin
//     uses for net/rpc). If gob can't reconstruct the value bit-for-bit
//     after a Marshal/Unmarshal cycle, the contract is broken.
//   - Forward-compat: an OLD wire payload (a struct with a SUBSET of
//     today's fields) MUST decode without error. This is the property
//     that lets plugin binaries built against version N keep talking
//     to a host running version N+1 with new optional fields.
//   - Backward-compat: a NEW wire payload (a struct with a SUPERSET of
//     today's fields) MUST decode without error against the current
//     types. This is the property that lets a host running version N
//     keep talking to a plugin built against version N+1.
//   - Handshake stability: the protocol version + magic cookie must
//     not silently drift; bumping ProtocolVersion is a breaking change.
//
// These tests are smoke-level by design. The deeper subprocess
// integration tests (panic isolation, concurrent eval safety, stale
// binary fallback) live in kc/riskguard/subprocess_check_test.go and
// exercise the host adapter end-to-end.
package checkrpc

import (
	"bytes"
	"encoding/gob"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOrderCheckRequestWire_GobRoundTrip pins the canonical encode →
// decode cycle for the request side of the wire. A representative
// payload (every field non-zero) must come back bit-identical.
func TestOrderCheckRequestWire_GobRoundTrip(t *testing.T) {
	t.Parallel()

	want := OrderCheckRequestWire{
		Email:           "trader@example.com",
		ToolName:        "place_order",
		Exchange:        "NSE",
		Tradingsymbol:   "RELIANCE",
		TransactionType: "BUY",
		Quantity:        10,
		Price:           2500.50,
		OrderType:       "LIMIT",
		Confirmed:       true,
		ClientOrderID:   "idem-abc-123",
	}

	var buf bytes.Buffer
	require.NoError(t, gob.NewEncoder(&buf).Encode(want))

	var got OrderCheckRequestWire
	require.NoError(t, gob.NewDecoder(&buf).Decode(&got))

	assert.Equal(t, want, got, "gob must round-trip every exported field")
}

// TestCheckResultWire_GobRoundTrip pins the response side. Both the
// allow case (Allowed=true, Reason="", Message="") and the reject
// case (Allowed=false, Reason+Message populated) must round-trip.
func TestCheckResultWire_GobRoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   CheckResultWire
	}{
		{
			name: "allow result",
			in:   CheckResultWire{Allowed: true},
		},
		{
			name: "reject result with reason and message",
			in: CheckResultWire{
				Allowed: false,
				Reason:  "blocked_prefix",
				Message: "symbol BLOCKED_X matched a BLOCKED_ prefix",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			require.NoError(t, gob.NewEncoder(&buf).Encode(tc.in))

			var got CheckResultWire
			require.NoError(t, gob.NewDecoder(&buf).Decode(&got))

			assert.Equal(t, tc.in, got)
		})
	}
}

// TestOrderCheckRequestWire_ForwardCompat verifies that a payload
// emitted by an OLDER plugin (lacking the most recently-added field
// ClientOrderID) decodes cleanly against the current type with the
// missing field defaulting to its zero value. This is the property
// that lets plugin authors build against vN-1 and ship without
// breaking when the host upgrades to vN.
func TestOrderCheckRequestWire_ForwardCompat(t *testing.T) {
	t.Parallel()

	// Mirror the wire shape from BEFORE ClientOrderID was added.
	// Same field ordering, same types, same names — just truncated.
	type orderCheckRequestWireOld struct {
		Email           string
		ToolName        string
		Exchange        string
		Tradingsymbol   string
		TransactionType string
		Quantity        int
		Price           float64
		OrderType       string
		Confirmed       bool
	}

	old := orderCheckRequestWireOld{
		Email:           "old@example.com",
		ToolName:        "place_order",
		Exchange:        "NSE",
		Tradingsymbol:   "TCS",
		TransactionType: "SELL",
		Quantity:        5,
		Price:           4100.0,
		OrderType:       "MARKET",
		Confirmed:       false,
	}

	var buf bytes.Buffer
	require.NoError(t, gob.NewEncoder(&buf).Encode(old))

	// Decode INTO the current (richer) type.
	var got OrderCheckRequestWire
	require.NoError(t, gob.NewDecoder(&buf).Decode(&got),
		"old plugin payload must decode against current type")

	assert.Equal(t, old.Email, got.Email)
	assert.Equal(t, old.Tradingsymbol, got.Tradingsymbol)
	assert.Equal(t, old.Quantity, got.Quantity)
	assert.Equal(t, old.Price, got.Price)
	// New field absent from the old payload defaults to zero.
	assert.Equal(t, "", got.ClientOrderID,
		"new field absent from old payload must default to zero value")
}

// TestOrderCheckRequestWire_BackwardCompat verifies the symmetric
// property: a payload emitted by a NEWER plugin (with extra fields
// the host doesn't yet know about) decodes cleanly against the
// current type, dropping the unknown fields. This is the property
// that lets a host running vN keep dispatching to a plugin built
// against vN+1.
//
// gob's contract: unknown fields on the wire are silently ignored.
// We pin that behaviour so a future Go version that tightens the
// rule (or a transport swap to a stricter codec) surfaces here.
func TestOrderCheckRequestWire_BackwardCompat(t *testing.T) {
	t.Parallel()

	// Mirror the wire shape from AFTER a hypothetical future field
	// addition — say a "Reason" hint passed from a smarter host.
	type orderCheckRequestWireNew struct {
		Email           string
		ToolName        string
		Exchange        string
		Tradingsymbol   string
		TransactionType string
		Quantity        int
		Price           float64
		OrderType       string
		Confirmed       bool
		ClientOrderID   string
		FutureHint      string // hypothetical new field
	}

	newer := orderCheckRequestWireNew{
		Email:           "future@example.com",
		ToolName:        "place_order",
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		TransactionType: "BUY",
		Quantity:        20,
		Price:           1900.0,
		OrderType:       "LIMIT",
		Confirmed:       true,
		ClientOrderID:   "idem-xyz",
		FutureHint:      "the host wants you to know this",
	}

	var buf bytes.Buffer
	require.NoError(t, gob.NewEncoder(&buf).Encode(newer))

	// Decode INTO the current (smaller) type. gob drops the unknown
	// FutureHint field silently.
	var got OrderCheckRequestWire
	require.NoError(t, gob.NewDecoder(&buf).Decode(&got),
		"future plugin payload must decode against current type, dropping unknowns")

	assert.Equal(t, newer.Email, got.Email)
	assert.Equal(t, newer.ClientOrderID, got.ClientOrderID)
	assert.Equal(t, newer.Tradingsymbol, got.Tradingsymbol)
}

// TestHandshake_StableProtocol pins the handshake constants so a
// drift in ProtocolVersion or magic cookie surfaces as a test
// failure rather than a silent runtime "not our plugin" rejection
// at customer sites.
//
// To intentionally bump the protocol: change the expected values
// here AND update every plugin binary in the wild AND document the
// break in CHANGELOG. This test exists to make that ceremony
// visible, not to forbid it.
func TestHandshake_StableProtocol(t *testing.T) {
	t.Parallel()

	assert.Equal(t, uint(1), Handshake.ProtocolVersion,
		"ProtocolVersion bump is a breaking change for every existing plugin binary")
	assert.Equal(t, "KITE_RISKGUARD_CHECK_PLUGIN", Handshake.MagicCookieKey)
	assert.Equal(t, "riskguard-check-v1", Handshake.MagicCookieValue)
}

// TestPluginMap_DispenseKeyContract pins that the canonical
// dispense-key constant matches the one in the plugin map. A typo
// would manifest as "no plugin found for key" at runtime; this test
// surfaces it at build time.
func TestPluginMap_DispenseKeyContract(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "check", DispenseKey)
	_, ok := PluginMap[DispenseKey]
	assert.True(t, ok, "DispenseKey must resolve in PluginMap")
}
