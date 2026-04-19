package riskguard

import (
	"io"
	"log"
	"log/slog"
	"os"

	"github.com/hashicorp/go-hclog"
)

// newHclogShim returns a minimal hclog.Logger that routes messages
// into the supplied *slog.Logger when one is configured. hclog is
// hashicorp/go-plugin's native logging interface; we adapt rather
// than adopt it because the rest of this codebase already uses slog.
//
// When logger is nil we return a discarding hclog — the subprocess
// lifecycle messages (plugin starting, plugin exited) are useful in
// production but noise-level in tests, and tests commonly pass a
// discard-logger via slog.
//
// Level mapping: hclog.Trace/Debug -> slog.Debug, hclog.Info ->
// slog.Info, hclog.Warn -> slog.Warn, hclog.Error -> slog.Error.
// Above Error (hclog.Off) are dropped.
func newHclogShim(logger *slog.Logger) hclog.Logger {
	if logger == nil {
		return hclog.New(&hclog.LoggerOptions{
			Name:   "riskguard.subprocess",
			Output: io.Discard,
			Level:  hclog.Off,
		})
	}
	return &slogHclogAdapter{slog: logger}
}

// slogHclogAdapter implements hclog.Logger by forwarding to slog.
// Only the methods hashicorp/go-plugin actually calls are
// implemented as non-trivial forwarders; the rest are defensive
// no-ops (go-plugin uses Info/Warn/Error/Debug; the plumbing
// methods like With/Named/ResetNamed are stub-implemented for
// interface satisfaction).
type slogHclogAdapter struct {
	slog *slog.Logger
	name string
}

// Log is the interface-level shared entry point. hclog's Log(level, ...)
// routes based on level.
func (a *slogHclogAdapter) Log(level hclog.Level, msg string, args ...any) {
	switch level {
	case hclog.Trace, hclog.Debug:
		a.slog.Debug(msg, args...)
	case hclog.Info:
		a.slog.Info(msg, args...)
	case hclog.Warn:
		a.slog.Warn(msg, args...)
	case hclog.Error:
		a.slog.Error(msg, args...)
	}
}

func (a *slogHclogAdapter) Trace(msg string, args ...any) { a.slog.Debug(msg, args...) }
func (a *slogHclogAdapter) Debug(msg string, args ...any) { a.slog.Debug(msg, args...) }
func (a *slogHclogAdapter) Info(msg string, args ...any)  { a.slog.Info(msg, args...) }
func (a *slogHclogAdapter) Warn(msg string, args ...any)  { a.slog.Warn(msg, args...) }
func (a *slogHclogAdapter) Error(msg string, args ...any) { a.slog.Error(msg, args...) }

func (a *slogHclogAdapter) IsTrace() bool { return true }
func (a *slogHclogAdapter) IsDebug() bool { return true }
func (a *slogHclogAdapter) IsInfo() bool  { return true }
func (a *slogHclogAdapter) IsWarn() bool  { return true }
func (a *slogHclogAdapter) IsError() bool { return true }

// ImpliedArgs / With / Name / Named / ResetNamed are plumbing
// methods hclog exposes; go-plugin uses them sparingly. Returning
// self (or a shallow clone) suffices.
func (a *slogHclogAdapter) ImpliedArgs() []any            { return nil }
func (a *slogHclogAdapter) With(args ...any) hclog.Logger { return a }
func (a *slogHclogAdapter) Name() string                  { return a.name }
func (a *slogHclogAdapter) Named(name string) hclog.Logger {
	return &slogHclogAdapter{slog: a.slog, name: name}
}
func (a *slogHclogAdapter) ResetNamed(name string) hclog.Logger {
	return &slogHclogAdapter{slog: a.slog, name: name}
}
func (a *slogHclogAdapter) SetLevel(_ hclog.Level) {}

// GetLevel returns Trace so nothing gets filtered at the hclog layer;
// the slog side applies its own filtering.
func (a *slogHclogAdapter) GetLevel() hclog.Level { return hclog.Trace }

// StandardLogger returns a *log.Logger that routes into the slog
// adapter's Info level. go-plugin occasionally calls this for
// hooking third-party logging libraries.
func (a *slogHclogAdapter) StandardLogger(_ *hclog.StandardLoggerOptions) *log.Logger {
	return log.New(a.StandardWriter(nil), "", 0)
}

// StandardWriter returns an io.Writer that parses newline-delimited
// messages into slog.Info calls. Minimal — we use os.Stderr for
// safety when slog is mis-configured.
func (a *slogHclogAdapter) StandardWriter(_ *hclog.StandardLoggerOptions) io.Writer {
	if a.slog == nil {
		return os.Stderr
	}
	return &slogWriter{slog: a.slog}
}

// slogWriter is the minimum-viable io.Writer -> slog.Info bridge.
// hashicorp/go-plugin rarely writes through it — only for legacy
// log-package adapters on the plugin side.
type slogWriter struct {
	slog *slog.Logger
}

func (w *slogWriter) Write(b []byte) (int, error) {
	w.slog.Info(string(b))
	return len(b), nil
}
