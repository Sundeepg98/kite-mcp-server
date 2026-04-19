# riskguard-check-plugin

Reference implementation of a subprocess riskguard `Check` plugin for
kite-mcp-server.

## What it does

- Blocks any order whose `Tradingsymbol` starts with `BLOCKED_`
- The magic symbol `PANIC_ME` deliberately panics (used by
  `TestSubprocessCheck_PanicInPluginFailsClosed` on the host side)
- Allows everything else

## Build

```bash
go build -o riskguard-check-plugin .
# Windows:
go build -o riskguard-check-plugin.exe .
```

No CGO required. Cross-compile with `GOOS=linux GOARCH=amd64 go build` etc.

## Register on the host

```go
import "github.com/zerodha/kite-mcp-server/kc/riskguard"

g := riskguard.NewGuard(logger)
err := g.RegisterSubprocessCheck(
    "example",
    "/abs/path/to/riskguard-check-plugin",
    2500, // Order slot — 2000+ recommended so it runs after built-ins
)
```

## Fork it

1. Copy this entire directory.
2. Rewrite the `exampleCheck.Evaluate` body with your own rule.
3. `go build`.
4. Re-register on the host with your new binary path.

## Crash isolation guarantee

A panic or segfault inside this plugin CANNOT crash the host server.
hashicorp/go-plugin routes every RPC call over a stdio transport; if
the subprocess dies, the next Evaluate on the host:

1. returns a fail-closed `CheckResult{Allowed: false, Reason:
   "subprocess_unavailable"}` for that one evaluation,
2. tears down the dead subprocess handle,
3. relaunches the binary on the NEXT Evaluate.

You can iterate on this plugin without restarting the host — rebuild,
wait for one fail-closed evaluation, subsequent calls pick up the new
binary.

## Wire protocol

- Transport: netRPC over stdio (no protoc dependency)
- Handshake: `KITE_RISKGUARD_CHECK_PLUGIN=riskguard-check-v1`
- Dispense key: `"check"`
- Types: `checkrpc.OrderCheckRequestWire` / `checkrpc.CheckResultWire`

See `kc/riskguard/checkrpc/types.go` for the full contract.
