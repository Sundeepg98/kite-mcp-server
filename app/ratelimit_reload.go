package app

import (
	"encoding/json"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/zerodha/kite-mcp-server/mcp"
)

// ratelimit_reload.go — SIGHUP-driven hot reload for per-tool rate limits.
//
// Problem
// -------
// Per-tool rate limits are built into the server at startup in app/wire.go
// (place_order=10, modify_order=10, cancel_order=20, ...). An operator who
// needs to tighten a cap during an ongoing abuse incident, or loosen a cap
// after a load-test finding, previously had to redeploy — a 30-60 second
// outage for a cap change that takes milliseconds in memory.
//
// Design
// ------
// startRateLimitReloadLoop subscribes to SIGHUP and, on each signal, reads
// the KITE_RATELIMIT env var (a comma-separated `tool=N` list), parses
// it, and hands the resulting map to ToolRateLimiter.SetLimits. The
// limiter's in-flight counters are preserved — only the caps change.
//
// Env format (single string, so a systemd ExecReload / Fly.io secret can
// ship one value):
//
//	KITE_RATELIMIT="place_order=5,modify_order=10,cancel_order=25"
//
// Any tool not listed in the updated env keeps its startup cap UNTIL the
// next reload, at which point the updated env is the sole source of truth
// (full replacement, not merge — matches SetLimits semantics).
//
// Why SIGHUP and not a /admin HTTP endpoint?
// ------------------------------------------
// SIGHUP is the POSIX convention for config reload and needs no auth
// wiring — the signal can only be sent by the process owner or root, so
// it inherits OS-level access control. An HTTP endpoint would need a
// fresh auth path (admin JWT? shared secret? mTLS?) for a feature that
// already has a battle-tested answer. On Windows, SIGHUP is unavailable
// but the signal.Notify call silently no-ops there — local dev on
// Windows keeps the startup caps, which is fine because Windows is a
// dev-only target for this server.

// startRateLimitReloadLoop launches a goroutine that re-parses
// KITE_RATELIMIT on every SIGHUP and updates the limiter atomically.
// The goroutine exits when stopCh closes — wire into the server's
// shutdown sequence to avoid leaking on process teardown.
//
// Returns the signal channel (for unit tests that send SIGHUP directly)
// AND a doneCh that closes when the goroutine exits. Callers wiring this
// into graceful shutdown should <-doneCh after closing stopCh to
// demonstrate the goroutine has actually terminated — otherwise
// goleak-style sentinels race the exit.
//
// Production wrapper around startRateLimitReloadLoopWithGetenv: the latter
// accepts a getenv injection so tests can drive the SIGHUP-handler logic
// with a literal env source — no t.Setenv, parallel-safe.
func startRateLimitReloadLoop(rl *mcp.ToolRateLimiter, logger *slog.Logger, stopCh <-chan struct{}) (chan os.Signal, <-chan struct{}) {
	return startRateLimitReloadLoopWithGetenv(rl, logger, stopCh, os.Getenv)
}

// startRateLimitReloadLoopWithGetenv is the parameterised variant. The
// getenv callback is invoked once per SIGHUP — production code wires this
// to os.Getenv; tests pass a closure backed by a map literal so the test
// can both express "what env should the SIGHUP handler see" and run with
// t.Parallel().
func startRateLimitReloadLoopWithGetenv(rl *mcp.ToolRateLimiter, logger *slog.Logger, stopCh <-chan struct{}, getenv func(string) string) (chan os.Signal, <-chan struct{}) {
	sigCh := make(chan os.Signal, 1)
	doneCh := make(chan struct{})
	// Notify for SIGHUP. On platforms without SIGHUP (Windows),
	// signal.Notify is a no-op for that signal — the channel simply
	// never fires and the goroutine blocks forever on <-sigCh.
	signal.Notify(sigCh, syscall.SIGHUP)

	go func() {
		defer close(doneCh)
		for {
			select {
			case <-sigCh:
				raw := getenv("KITE_RATELIMIT")
				limits, err := parseRateLimitEnv(raw)
				if err != nil {
					logger.Error("SIGHUP rate-limit reload: parse failed",
						"error", err, "raw", raw)
					continue
				}
				if len(limits) == 0 {
					logger.Warn("SIGHUP rate-limit reload: KITE_RATELIMIT is empty; skipping swap")
					continue
				}
				rl.SetLimits(limits)
				// Small structured snapshot so ops can confirm the
				// intended caps landed.
				asJSON, _ := json.Marshal(limits)
				logger.Info("SIGHUP rate-limit reload: limits swapped", "limits", string(asJSON))
			case <-stopCh:
				signal.Stop(sigCh)
				return
			}
		}
	}()
	return sigCh, doneCh
}

// parseRateLimitEnv decodes a comma-separated `tool=N` string into a
// rate-limit map. Empty input returns (nil, nil) so callers can treat
// "env unset" as "don't touch anything". A malformed pair returns an
// error and the whole parse is rejected — partial application of a bad
// config is worse than ignoring it.
func parseRateLimitEnv(s string) (map[string]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	out := make(map[string]int)
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			return nil, &rateLimitParseErr{pair: pair, reason: "missing '='"}
		}
		tool := strings.TrimSpace(kv[0])
		if tool == "" {
			return nil, &rateLimitParseErr{pair: pair, reason: "empty tool name"}
		}
		limit, err := strconv.Atoi(strings.TrimSpace(kv[1]))
		if err != nil {
			return nil, &rateLimitParseErr{pair: pair, reason: "non-integer limit"}
		}
		if limit < 0 {
			return nil, &rateLimitParseErr{pair: pair, reason: "negative limit"}
		}
		out[tool] = limit
	}
	return out, nil
}

type rateLimitParseErr struct {
	pair   string
	reason string
}

func (e *rateLimitParseErr) Error() string {
	return "invalid KITE_RATELIMIT pair " + strconv.Quote(e.pair) + ": " + e.reason
}
