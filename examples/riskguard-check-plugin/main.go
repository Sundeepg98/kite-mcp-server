// riskguard-check-plugin is the reference implementation of a
// subprocess riskguard Check. It is intentionally small — less than
// 100 lines of meaningful logic — so you can read it in one sitting
// and fork it as the starting point for your own plugin.
//
// Wire model:
//
//   1. The host (kite-mcp-server) calls NewSubprocessCheck + registers
//      this binary's path via Guard.RegisterSubprocessCheck.
//   2. On the first Evaluate call, the host launches this binary as a
//      child process. hashicorp/go-plugin manages the stdio-based
//      netRPC transport. A magic-cookie handshake (defined in
//      checkrpc.Handshake) prevents double-clicking the plugin from
//      running it as a standalone program.
//   3. The host dispenses a proxy via the shared plugin.Plugin
//      adapter (checkrpc.PluginMap["check"]).
//   4. Each Evaluate round-trips over the RPC — typical latency
//      ~1-2ms on localhost.
//   5. If this binary panics, go-plugin surfaces the broken pipe as
//      an RPC error; the host marks the subprocess as dead, tears it
//      down, and relaunches on the NEXT call. The host never crashes.
//
// Rebuilding:
//
//   go build -o riskguard-check-plugin ./examples/riskguard-check-plugin
//
// Then on the host:
//
//   g.RegisterSubprocessCheck("example", "/abs/path/to/riskguard-check-plugin", 2500)
//
// Host-side Order=2500 puts this check AFTER every built-in check
// (built-ins occupy 100..1200), so it only runs when no built-in
// has already rejected the order. Pick any unused slot you like.
//
// The example logic:
//
//   - Any symbol prefixed with "BLOCKED_" is rejected with
//     Reason="blocked_prefix".
//   - The magic symbol "PANIC_ME" deliberately panics, exercising
//     the host's crash-isolation guarantee.
//   - Everything else is allowed.
//
// Fork this file, swap in your own Evaluate body, and ship.
package main

import (
	"strings"

	hplugin "github.com/hashicorp/go-plugin"
	"github.com/zerodha/kite-mcp-server/kc/riskguard/checkrpc"
)

// exampleCheck implements checkrpc.CheckRPC. It's pure data + a
// single Evaluate method; no broker connection, no shared state, no
// file handles. A plugin that needs per-evaluation context (a DB
// lookup, a market data fetch) can do the I/O inside Evaluate.
type exampleCheck struct{}

// Name — the plugin identifier the host uses in logs and metrics.
// Host-side RegisterSubprocessCheck takes its own name argument,
// but this value is what appears if the host calls proxy.Name()
// for metadata purposes.
func (exampleCheck) Name() (string, error) {
	return "example_check", nil
}

// Order — the default evaluation position. The host overrides this
// via the Order argument to RegisterSubprocessCheck; returning a
// value here is informational.
func (exampleCheck) Order() (int, error) {
	return 5000, nil
}

// RecordOnRejection — plugin rejections do NOT feed the auto-freeze
// circuit breaker for this example. Set to true only when your
// plugin mirrors the "limit violation" semantics of order_value /
// quantity / daily_value (rejection suggests the user should be
// slowed down, not merely informed).
func (exampleCheck) RecordOnRejection() (bool, error) {
	return false, nil
}

// Evaluate is the hot path. The wire types (OrderCheckRequestWire,
// CheckResultWire) are gob-serialised at the host-subprocess
// boundary; keep field additions conservative (see the wire
// discipline notes in checkrpc/types.go).
func (exampleCheck) Evaluate(req checkrpc.OrderCheckRequestWire) (checkrpc.CheckResultWire, error) {
	// Magic panic-me symbol — exercises host-side crash isolation.
	// Remove this in your own fork; it exists only so the host's
	// TestSubprocessCheck_PanicInPluginFailsClosed test has
	// something deterministic to trigger.
	if req.Tradingsymbol == "PANIC_ME" {
		panic("deliberate plugin panic — host must recover")
	}

	// Simple domain rule: block any symbol prefixed with BLOCKED_.
	if strings.HasPrefix(req.Tradingsymbol, "BLOCKED_") {
		return checkrpc.CheckResultWire{
			Allowed: false,
			Reason:  "blocked_prefix",
			Message: "symbol " + req.Tradingsymbol + " matched a BLOCKED_ prefix; orders on these symbols are rejected",
		}, nil
	}

	return checkrpc.CheckResultWire{Allowed: true}, nil
}

// main is the plugin entry point. hashicorp/go-plugin.Serve takes
// over stdio after the handshake is accepted and never returns
// under normal operation — it blocks serving RPC until the host
// closes the connection.
func main() {
	hplugin.Serve(&hplugin.ServeConfig{
		HandshakeConfig: checkrpc.Handshake,
		Plugins: map[string]hplugin.Plugin{
			checkrpc.DispenseKey: &checkrpc.CheckPlugin{
				Impl: exampleCheck{},
			},
		},
		// NetRPC only — no protoc dependency, pure Go.
		GRPCServer: nil,
	})
}
