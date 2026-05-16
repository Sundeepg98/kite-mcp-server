# Extension Points

This server is built to be extended without forking. Three orthogonal
extension surfaces exist today; this doc maps each to its wire-up point,
reference implementation, and "when you'd reach for it" rationale.

Per `dead-code-utilization-analysis-2026-05-11.md` §3 #8: these
extension points exist in code but were under-documented; new operators
can't discover them. This doc closes that gap.

---

## 1. Subprocess RiskGuard plugins (`RISKGUARD_PLUGIN_DIR`)

**When to reach for it**: a regulator-mandated check, a broker-specific
veto, or an operator-private compliance rule needs to ship as a
**separate binary** — independently signed, independently versioned,
hot-pluggable without restarting the main server.

### 1.1 Activation

Set the env var **before server startup**:

```bash
export RISKGUARD_PLUGIN_DIR=/srv/kite-mcp/plugins
flyctl secrets set RISKGUARD_PLUGIN_DIR=/srv/kite-mcp/plugins -a kite-mcp-server
```

Empty / unset → no discovery (default). The directory must contain one
or more pre-built plugin binaries (see § 1.3 for the build recipe) plus
a per-binary `manifest.json` describing each plugin's name + check
order.

### 1.2 Loader chain (verified empirically 2026-05-11)

```
app/config.go::ConfigFromEnv
  → reads "RISKGUARD_PLUGIN_DIR" env at startup (line 66)
  → threads into Config.RiskguardPluginDir (line 105)
app/providers/riskguard.go
  → ProvideRiskGuardConfig sees PluginDir non-empty (line 67)
  → riskguard.DiscoverPlugins reads manifest.json files
  → for each: guard.RegisterSubprocessCheck(name, path, order) (line 196)
```

If `PluginDir` is empty, the loader exits cleanly — compile-time
overhead of the subprocess-check infrastructure is zero, runtime
overhead is zero. No "lazy load on first use" — discovery happens
once, at server boot.

### 1.3 Plugin protocol

The wire protocol is **`hashicorp/go-plugin` over stdio + netRPC**.
The shared interface lives at `github.com/algo2go/kite-mcp-riskguard/checkrpc`:

- **Handshake**: `checkrpc.Handshake` — magic-cookie prevents
  double-clicking the binary from running it as a standalone program.
- **Plugin map**: `checkrpc.PluginMap` — single entry `"check"`.
- **`Check` interface**: `Evaluate(ctx, OrderCheckRequest) (Decision, error)`.
- **`Decision`**: `Allow` / `Reject(reason string)`.

### 1.4 Reference implementation

`examples/riskguard-check-plugin/main.go` — under 100 lines of
meaningful logic. Fork this as the starting point for any new plugin.

**Build + register**:

```bash
go build -o /srv/kite-mcp/plugins/my-check ./examples/riskguard-check-plugin
# manifest.json next to it:
cat > /srv/kite-mcp/plugins/manifest.json <<EOF
{
  "plugins": [
    { "name": "my-check", "path": "/srv/kite-mcp/plugins/my-check", "order": 2500 }
  ]
}
EOF
```

The example's `Evaluate` rejects any symbol prefixed `BLOCKED_` and
panics on the magic symbol `PANIC_ME` (deliberately — exercises the
host's crash-isolation guarantee: a panicking plugin marks the
subprocess dead and relaunches on the NEXT call without crashing the
host).

### 1.5 Order numbering

Built-in checks occupy slots 100-1200. Pick **2000+** for your plugin's
`order` so it runs AFTER every built-in. This gives the built-ins
first-pass veto (cheap rejections like daily-count limit, rate limit)
before paying the ~1-2ms IPC cost of your subprocess. Picking 50 (run
first) is valid for plugins that gate everything else — e.g., a kill
switch.

### 1.6 Crash isolation

`go-plugin` runs each subprocess as a real OS process. A panic surfaces
as an RPC error; the host marks the plugin dead, tears down the
subprocess, and relaunches on the NEXT Evaluate call. The main server
never crashes.

Latency: ~1-2ms localhost round-trip per Evaluate. Place compute-heavy
checks late in the order so cheap built-ins veto first.

---

## 2. Inline MCP tool plugins (`plugins/example` pattern)

**When to reach for it**: you want to add a brand-new MCP tool to the
server (e.g., a custom analytics tool, a new dashboard widget) **as
part of your own fork**. Compiled into the binary at build time.

### 2.1 Reference template

`plugins/example/plugin.go` (in `algo2go/kite-mcp-bootstrap` post
2026-05-16, or older `kite-mcp-server/plugins/example/` pre-extraction):

```go
package example

import (
  "github.com/mark3labs/mcp-go/mcp"
  kitemcp "github.com/algo2go/kite-mcp-bootstrap/mcp"
)

func init() {
  kitemcp.RegisterPlugin(&ServerTimeTool{})
}

type ServerTimeTool struct{}

func (*ServerTimeTool) Tool() mcp.Tool {
  return mcp.NewTool("server_time",
    mcp.WithDescription("Returns current server time and timezone. Example plugin tool."),
  )
}

// ...handler implementation
```

### 2.2 Wire-up (per-fork)

In your fork's `main.go`, add a blank-import alongside the production
import:

```go
import (
  _ "github.com/myorg/my-mcp-fork/plugins/mytool"  // init() registers tool
)
```

The `init()` registers via `kitemcp.RegisterPlugin(&Tool{})`. No
config changes needed — the tool appears in `tools/list` after rebuild.

### 2.3 Existing in-tree plugins

`plugins/rolegate` and `plugins/telegramnotify` are production-active
plugins compiled into the standard build. Both follow the same pattern
as `plugins/example` — read them for production-shape examples (with
real dependencies and lifecycle hooks).

---

## 3. Around-hooks (`OnBeforeToolExecution` / `OnAfterToolExecution`)

**When to reach for it**: cross-cutting middleware (audit annotations,
distributed-trace span injection, per-tool circuit breakers, dynamic
rate-limiting) that doesn't belong to any single tool.

### 3.1 Pattern

Register at init time or App-scoped construction time:

```go
import kitemcp "github.com/algo2go/kite-mcp-bootstrap/mcp"

func init() {
  kitemcp.OnBeforeToolExecution(func(ctx context.Context, name string, args map[string]any) error {
    // your before-logic; return non-nil to abort the tool call
    return nil
  })
}
```

For App-scoped isolation (multi-tenant or test parallelism), use the
`*Registry` returned by `app.Registry()` instead of the default
registry. See `algo2go/kite-mcp-bootstrap/mcp/plugin/plugin_middleware.go`
for the App-scoped variants.

### 3.2 Audit + RiskGuard chain

The production audit + riskguard middleware is wired this way:
`app/providers/mcpserver.go:126` calls
`server.WithToolHandlerMiddleware(auditMw)` against the mcp-go server.
This is the same hook surface available to operator-authored
middleware — just attached at a different layer (Fx provider vs
init-time global).

---

## Cross-reference

| Need | Use |
|---|---|
| Custom compliance/veto check that ships independently | § 1 Subprocess plugin |
| Brand-new tool in tools/list | § 2 Inline plugin |
| Cross-tool middleware (logging, tracing, rate limit) | § 3 Around-hook |
| Modify response post-execution | § 3 OnAfterToolExecution |
| Reject before tool runs | § 3 OnBeforeToolExecution (return error) |
| Hot-reload without restart | § 1 Subprocess plugin (file-watcher loader) |

For the loader's full plugin lifecycle (manifest validation, SBOM
publishing, signature verification — present in
`mcp/plugin/plugin_sbom.go`), see the in-tree code; not all of it is
yet documented here.
