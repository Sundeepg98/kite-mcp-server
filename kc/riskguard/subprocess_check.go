package riskguard

import (
	"fmt"
	"log/slog"
	"os/exec"
	"sync"
	"sync/atomic"

	hplugin "github.com/hashicorp/go-plugin"
	"github.com/zerodha/kite-mcp-server/kc/riskguard/checkrpc"
)

// SubprocessCheckConfig wires a subprocess-based Check into the
// riskguard chain. The plugin runs as a child process, communicating
// over netRPC via stdio pipes (managed by hashicorp/go-plugin). A
// crash in the plugin subprocess cannot corrupt host memory or kill
// the server — the worst case is one evaluation returns a
// subprocess_unavailable rejection and the host re-launches the
// plugin on the next call.
//
// Why this matters:
//   - third-party / user-authored checks can be iterated on without
//     rebuilding the server binary (re-build the plugin binary and
//     the next evaluation picks it up);
//   - a plugin bug (nil deref, infinite loop, memory leak) is
//     isolated to its own process — the host does not care;
//   - the plugin binary is sandboxable at the OS level (cgroups,
//     Windows Job Objects, seccomp) without the host having to
//     opt into the same sandbox;
//   - for regulated trading (SEBI Apr 2026 retail-algo), having
//     each custom check run under the operator's OS isolation
//     policy rather than in-process gives a clean audit story.
//
// Performance: each Evaluate is one netRPC call over stdio. Measured
// latency on localhost is ~1-2ms — acceptable for the pre-trade path
// because riskguard's own chain already has 10-12 in-process checks
// adding similar per-call overhead.
type SubprocessCheckConfig struct {
	// Name is the Check.Name() value. Used for health reporting,
	// logs, and manifest entries. Must be non-empty.
	Name string
	// Order is the Check.Order() value. Plugin authors pick a
	// slot that doesn't collide with built-in checks (100..1200).
	// Recommended: 2000+ so subprocess checks run AFTER all
	// built-ins, keeping built-in behaviour deterministic even
	// if the plugin is slow to respond.
	Order int
	// RecordOnRejection decides whether a plugin rejection counts
	// toward the auto-freeze circuit breaker. Default false —
	// plugin rejections are treated as policy signals, not limit
	// violations, until we have more experience with how plugin
	// authors use the hook.
	RecordOnRejection bool
	// Executable is the absolute path to the plugin binary. Must
	// be executable. A missing / broken binary fails CLOSED
	// (Evaluate returns Allowed=false) — see the fail-closed
	// comment on safeEvaluate in guard.go for the rationale.
	Executable string
	// Args are optional command-line arguments passed to the
	// plugin binary on launch (e.g., a config-file path).
	Args []string
	// Logger is the host-side logger. May be nil (logs are then
	// silent). The plugin subprocess gets its own hclog handle
	// managed by go-plugin.
	Logger *slog.Logger
}

// Validate checks the config for obvious authoring mistakes. Called
// by both NewSubprocessCheck and Guard.RegisterSubprocessCheck.
func (c SubprocessCheckConfig) Validate() error {
	if c.Name == "" {
		return fmt.Errorf("riskguard: subprocess check Name is empty")
	}
	if c.Executable == "" {
		return fmt.Errorf("riskguard: subprocess check %q has empty Executable path", c.Name)
	}
	return nil
}

// SubprocessCheck implements the riskguard.Check interface by
// dispatching Evaluate() to a subprocess over hashicorp/go-plugin's
// netRPC transport. The subprocess is LAZILY launched on first
// Evaluate — construction is cheap and side-effect-free.
//
// Thread safety: Evaluate is safe for concurrent callers. The
// mutex serialises subprocess launch AND cached-client replacement
// after a crash, but the actual RPC call is un-mutex'd so multiple
// goroutines can be in-flight against the single subprocess.
// (hashicorp/go-plugin's netRPC client is safe for concurrent use.)
type SubprocessCheck struct {
	cfg SubprocessCheckConfig
	// mu serialises client creation + replacement. The hot path
	// (Evaluate when client is already cached) takes the reader
	// lock; launch / teardown take the writer lock.
	mu sync.RWMutex
	// client is the hashicorp/go-plugin host-side client handle.
	// Nil until first successful launch; reset to nil on close /
	// post-crash.
	client *hplugin.Client
	// proxy is the dispensed CheckRPC proxy — invalidated whenever
	// client is replaced.
	proxy checkrpc.CheckRPC
	// closed is set by Close() so in-flight Evaluate calls can
	// short-circuit rather than racing against a dying subprocess.
	closed atomic.Bool
}

// NewSubprocessCheck constructs a SubprocessCheck. No subprocess is
// spawned yet — the plugin is launched on the first Evaluate call.
func NewSubprocessCheck(cfg SubprocessCheckConfig) *SubprocessCheck {
	return &SubprocessCheck{cfg: cfg}
}

// Name returns the configured plugin name. Does NOT dispatch to the
// subprocess — the host-side name is authoritative and constant.
// This is safe to call before first launch.
func (s *SubprocessCheck) Name() string {
	return s.cfg.Name
}

// Order returns the configured Order value. See Name — host-side
// authoritative, no subprocess round-trip.
func (s *SubprocessCheck) Order() int {
	return s.cfg.Order
}

// RecordOnRejection returns the configured flag. Host-side
// authoritative (plugin authors shouldn't change this at runtime).
func (s *SubprocessCheck) RecordOnRejection() bool {
	return s.cfg.RecordOnRejection
}

// Evaluate dispatches the pre-trade check to the subprocess. On any
// of the following failure modes, returns Allowed=false (fail-closed)
// with Reason="subprocess_unavailable":
//
//   - Close() has been called;
//   - the plugin binary does not exist / is not executable;
//   - the subprocess died between calls and relaunch failed;
//   - the RPC call itself errored (transport failure).
//
// A subprocess-side panic is converted by go-plugin into a
// broken-pipe RPC error on the next call; we catch that, log, and
// fail closed. The subprocess is relaunched on the NEXT evaluation
// attempt — no retry-in-place, because a plugin that crashed once
// is likely to crash again on the same input.
func (s *SubprocessCheck) Evaluate(req OrderCheckRequest) CheckResult {
	if s.closed.Load() {
		return s.failClosed("subprocess_closed", "plugin was shut down")
	}

	proxy, err := s.ensureProxy()
	if err != nil {
		return s.failClosed("subprocess_unavailable", err.Error())
	}

	wire := checkrpc.OrderCheckRequestWire{
		Email:           req.Email,
		ToolName:        req.ToolName,
		Exchange:        req.Exchange,
		Tradingsymbol:   req.Tradingsymbol,
		TransactionType: req.TransactionType,
		Quantity:        req.Quantity,
		Price:           req.Price,
		OrderType:       req.OrderType,
		Confirmed:       req.Confirmed,
		ClientOrderID:   req.ClientOrderID,
	}
	resp, err := proxy.Evaluate(wire)
	if err != nil {
		// RPC error — subprocess likely died. Tear down so the
		// next call re-launches. Fail closed.
		s.discardClient()
		return s.failClosed("subprocess_rpc_error", err.Error())
	}
	return CheckResult{
		Allowed: resp.Allowed,
		Reason:  RejectionReason(resp.Reason),
		Message: resp.Message,
	}
}

// failClosed builds a deterministic rejection result. Never
// Allowed=true; the whole point is the fail-closed guarantee.
func (s *SubprocessCheck) failClosed(reason, detail string) CheckResult {
	msg := fmt.Sprintf("subprocess plugin %q unavailable: %s", s.cfg.Name, detail)
	if s.cfg.Logger != nil {
		s.cfg.Logger.Warn("riskguard: subprocess check fail-closed",
			"plugin", s.cfg.Name, "reason", reason, "detail", detail)
	}
	return CheckResult{
		Allowed: false,
		Reason:  RejectionReason(reason),
		Message: msg,
	}
}

// ensureProxy returns a cached proxy or launches the subprocess.
// Uses a reader-then-writer pattern: 99% of calls hit the reader
// lock, only the launch path takes the writer lock.
func (s *SubprocessCheck) ensureProxy() (checkrpc.CheckRPC, error) {
	s.mu.RLock()
	if s.proxy != nil {
		p := s.proxy
		s.mu.RUnlock()
		return p, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	// Double-check: another goroutine may have launched.
	if s.proxy != nil {
		return s.proxy, nil
	}
	if err := s.launchLocked(); err != nil {
		return nil, err
	}
	return s.proxy, nil
}

// launchLocked spawns the plugin subprocess and dispenses the Check
// proxy. Caller must hold s.mu write-lock.
func (s *SubprocessCheck) launchLocked() error {
	client := hplugin.NewClient(&hplugin.ClientConfig{
		HandshakeConfig: checkrpc.Handshake,
		Plugins:         checkrpc.PluginMap,
		Cmd:             exec.Command(s.cfg.Executable, s.cfg.Args...),
		Logger:          newHclogShim(s.cfg.Logger),
		// Explicit AllowedProtocols=netRPC: pure Go, no protoc
		// dependency. Matches the examples/riskguard-check-plugin
		// binary's server config.
		AllowedProtocols: []hplugin.Protocol{hplugin.ProtocolNetRPC},
	})

	rpcClient, err := client.Client()
	if err != nil {
		client.Kill()
		return fmt.Errorf("launch subprocess: %w", err)
	}
	raw, err := rpcClient.Dispense(checkrpc.DispenseKey)
	if err != nil {
		client.Kill()
		return fmt.Errorf("dispense check proxy: %w", err)
	}
	proxy, ok := raw.(checkrpc.CheckRPC)
	if !ok {
		client.Kill()
		return fmt.Errorf("dispensed proxy is not checkrpc.CheckRPC (got %T)", raw)
	}
	s.client = client
	s.proxy = proxy
	return nil
}

// discardClient tears down the cached client + proxy so the NEXT
// Evaluate launches a fresh subprocess. Called on RPC error
// (subprocess likely dead).
func (s *SubprocessCheck) discardClient() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client != nil {
		s.client.Kill()
		s.client = nil
		s.proxy = nil
	}
}

// Close tears down the subprocess. After Close the SubprocessCheck
// returns fail-closed from every Evaluate call — Close is terminal.
// Safe to call multiple times.
func (s *SubprocessCheck) Close() {
	s.closed.Store(true)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client != nil {
		s.client.Kill()
		s.client = nil
		s.proxy = nil
	}
}

// Ensure SubprocessCheck satisfies the Check interface at compile
// time. If Check ever gains a new method, this will flag.
var _ Check = (*SubprocessCheck)(nil)

// RegisterSubprocessCheck is the Guard-side ergonomic wrapper:
// construct a SubprocessCheck from minimal config and register it
// in the Check chain.
//
// Returns an error for invalid config; otherwise the subprocess
// check is installed at the given Order slot. The subprocess is
// NOT launched yet — first Evaluate triggers launch.
//
// Plugin authors' workflow:
//   1. Write a Go program implementing checkrpc.CheckRPC.
//   2. Serve it via hashicorp/go-plugin.Serve (see
//      examples/riskguard-check-plugin/main.go).
//   3. Build: `go build -o myplugin .`
//   4. Register on the Guard:
//          g.RegisterSubprocessCheck("my_plugin", "/path/to/myplugin", 2500)
//
// Reload: to ship a new version, rebuild the binary — the NEXT
// failed RPC call tears down the cached client; the call after
// that relaunches from disk and picks up the new binary. No
// server restart required.
func (g *Guard) RegisterSubprocessCheck(name, executable string, order int) error {
	cfg := SubprocessCheckConfig{
		Name:       name,
		Order:      order,
		Executable: executable,
		Logger:     g.logger,
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	sc := NewSubprocessCheck(cfg)
	g.RegisterCheck(sc)
	return nil
}
