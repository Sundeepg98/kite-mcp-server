// Package checkrpc carries the wire types and HashiCorp go-plugin
// handshake for subprocess-based riskguard Check plugins.
//
// It is a SEPARATE package from riskguard (not a sub-type file)
// because:
//   1. Plugin executables import this package to serve a Check without
//      pulling in the full riskguard package (which would drag in
//      alerts.DB, broker, audit, slog, and the entire guard.go tree).
//      A plugin binary should be small and self-contained.
//   2. Tests for the serialisation boundary (gob round-tripping,
//      field-addition compatibility) are easier to write on a
//      package-boundary type set than on the live riskguard.Check
//      that also carries methods.
//
// Wire discipline:
//   - OrderCheckRequestWire and CheckResultWire MUST remain a strict
//     subset of riskguard.OrderCheckRequest / riskguard.CheckResult.
//     Adding a new field to the live struct without updating the
//     wire mirror silently drops data at the subprocess boundary.
//   - Gob tolerates field additions but panics on type renames or
//     tag changes — treat this file like a protobuf schema.
//   - Reason is a string, not a riskguard.RejectionReason, so plugin
//     authors can emit arbitrary reason codes without importing the
//     constants file.
package checkrpc

import (
	"net/rpc"

	"github.com/hashicorp/go-plugin"
)

// OrderCheckRequestWire is the gob-serialised form of
// riskguard.OrderCheckRequest. All exported fields must be copied
// verbatim at the host -> subprocess boundary.
type OrderCheckRequestWire struct {
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
}

// CheckResultWire is the gob-serialised form of riskguard.CheckResult.
// Reason is a plain string (not a typed constant) so plugin authors
// can emit custom reason codes without importing riskguard.
type CheckResultWire struct {
	Allowed bool
	Reason  string
	Message string
}

// CheckRPC is the server interface the plugin binary implements. The
// host side calls Evaluate via netRPC; the plugin side does the
// actual rule logic. Name/Order/RecordOnRejection are static metadata
// captured once and cached — they don't need to be called on every
// Evaluate.
type CheckRPC interface {
	Name() (string, error)
	Order() (int, error)
	RecordOnRejection() (bool, error)
	Evaluate(req OrderCheckRequestWire) (CheckResultWire, error)
}

// --- net/rpc wire plumbing ---
//
// go-plugin's netRPC transport uses Go's net/rpc, which requires the
// server handler to have signature `Method(args, reply) error`. We
// bridge that to the CheckRPC interface below.

// CheckRPCServer is the server-side adapter. It embeds a concrete
// CheckRPC implementation (supplied by the plugin binary) and exposes
// the net/rpc method signatures.
type CheckRPCServer struct {
	Impl CheckRPC
}

// Name handler — no args, returns the plugin's name.
func (s *CheckRPCServer) Name(_ any, resp *string) error {
	name, err := s.Impl.Name()
	if err != nil {
		return err
	}
	*resp = name
	return nil
}

// Order handler — no args, returns the plugin's Order value.
func (s *CheckRPCServer) Order(_ any, resp *int) error {
	order, err := s.Impl.Order()
	if err != nil {
		return err
	}
	*resp = order
	return nil
}

// RecordOnRejection handler — no args, returns a bool.
func (s *CheckRPCServer) RecordOnRejection(_ any, resp *bool) error {
	b, err := s.Impl.RecordOnRejection()
	if err != nil {
		return err
	}
	*resp = b
	return nil
}

// Evaluate handler — the hot path. Takes a wire-form request,
// returns a wire-form result.
func (s *CheckRPCServer) Evaluate(req OrderCheckRequestWire, resp *CheckResultWire) error {
	result, err := s.Impl.Evaluate(req)
	if err != nil {
		return err
	}
	*resp = result
	return nil
}

// CheckRPCClient is the host-side proxy. It implements the CheckRPC
// interface by dispatching each method over the net/rpc client.
type CheckRPCClient struct {
	Client *rpc.Client
}

// Name dispatches to the plugin over RPC.
func (c *CheckRPCClient) Name() (string, error) {
	var resp string
	err := c.Client.Call("Plugin.Name", new(any), &resp)
	return resp, err
}

// Order dispatches to the plugin over RPC.
func (c *CheckRPCClient) Order() (int, error) {
	var resp int
	err := c.Client.Call("Plugin.Order", new(any), &resp)
	return resp, err
}

// RecordOnRejection dispatches to the plugin over RPC.
func (c *CheckRPCClient) RecordOnRejection() (bool, error) {
	var resp bool
	err := c.Client.Call("Plugin.RecordOnRejection", new(any), &resp)
	return resp, err
}

// Evaluate dispatches to the plugin over RPC. This is the hot path;
// one rpc.Call per order-placement event. Latency is ~1-2ms on
// localhost stdio — acceptable for the pre-trade path.
func (c *CheckRPCClient) Evaluate(req OrderCheckRequestWire) (CheckResultWire, error) {
	var resp CheckResultWire
	err := c.Client.Call("Plugin.Evaluate", req, &resp)
	return resp, err
}

// --- plugin.Plugin adapter ---
//
// HashiCorp go-plugin requires each exported plugin interface to have
// a plugin.Plugin wrapper that tells the library how to serve it
// (Server side) and how to consume it (Client side). CheckPlugin is
// that wrapper.

// CheckPlugin is the plugin.Plugin adapter for the Check type. It
// lives in checkrpc so BOTH the host (riskguard package) and the
// plugin binary (examples/riskguard-check-plugin) import it from
// the same place — preventing subtle drift between what the host
// serves and what the plugin expects.
type CheckPlugin struct {
	// Impl is set on the PLUGIN side (the binary being served).
	// On the HOST side it is nil — the library uses CheckPlugin
	// only to know HOW to dial the already-running subprocess.
	Impl CheckRPC
}

// Server is called by go-plugin on the plugin side to wrap the
// concrete Impl in a net/rpc-compatible server.
func (p *CheckPlugin) Server(_ *plugin.MuxBroker) (any, error) {
	return &CheckRPCServer{Impl: p.Impl}, nil
}

// Client is called by go-plugin on the host side to produce the
// CheckRPC proxy that host code will call.
func (*CheckPlugin) Client(_ *plugin.MuxBroker, c *rpc.Client) (any, error) {
	return &CheckRPCClient{Client: c}, nil
}

// Handshake is the shared magic-cookie handshake. BOTH host and
// plugin must declare the EXACT same ProtocolVersion + MagicCookie
// pair — mismatch means "not our plugin" and the library refuses
// to connect. Bump ProtocolVersion on any incompatible wire change.
//
// MagicCookieKey / MagicCookieValue are the sanity-check env vars
// the plugin binary checks on startup: if the parent process didn't
// set them, the plugin bails out, preventing double-click execution
// as a standalone program.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "KITE_RISKGUARD_CHECK_PLUGIN",
	MagicCookieValue: "riskguard-check-v1",
}

// PluginMap is the name -> plugin.Plugin map shared by the host and
// the plugin binary. The string key "check" is the dispense() argument
// both sides use to identify the riskguard.Check type.
var PluginMap = map[string]plugin.Plugin{
	"check": &CheckPlugin{},
}

// DispenseKey is the single name both sides use when dispensing /
// serving the check interface. Exposed as a const so callers don't
// typo the key string.
const DispenseKey = "check"
