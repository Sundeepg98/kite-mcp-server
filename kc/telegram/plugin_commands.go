package telegram

import (
	"fmt"
	"strings"
	"sync"
	"unicode"
)

// PluginCommandContext is what a plugin-registered command handler
// receives when a user sends its command. It is intentionally narrow:
// chat ID, caller email, and the raw argument string (everything after
// the command token). Plugins that need to send rich responses can use
// the BotHandler reference on the caller side — PluginCommandContext
// only carries inputs.
type PluginCommandContext struct {
	// ChatID is the Telegram chat the command came from. Private chats
	// only; group/channel messages are filtered upstream by ServeHTTP.
	ChatID int64
	// Email is the registered user's email, resolved via TelegramLookup.
	// Guaranteed non-empty by the time the plugin handler runs.
	Email string
	// Args is the raw argument text after the command token, stripped
	// of surrounding whitespace. Empty when the user types just the
	// command (e.g. "/echo" with no args).
	Args string
}

// PluginCommandHandler is the function signature a plugin implements to
// handle a /command. It returns the reply text (HTML-formatted; the bot
// will send it via sendHTML). An empty return string means "nothing to
// say" — useful when the plugin sends its own response out-of-band.
//
// Safety contract: the bot's ServeHTTP recovers panics in plugin
// handlers and converts them into an error message to the user. Plugins
// SHOULD return errors via a formatted string rather than panicking,
// but the recovery net keeps one buggy plugin from crashing the bot
// for every other user.
type PluginCommandHandler func(ctx PluginCommandContext) string

// reservedCommands is the set of built-in command names that plugins
// are forbidden to override. Kept in sync with the switch statement in
// bot.go ServeHTTP — if a new built-in is added there, append it here
// too. Duplicated deliberately (rather than derived) so the forbidden
// list is auditable and test-asserted: the TestRegisterCommand_
// DoesNotOverrideBuiltin test enumerates this list explicitly.
var reservedCommands = map[string]bool{
	"/price":       true,
	"/portfolio":   true,
	"/positions":   true,
	"/orders":      true,
	"/pnl":         true,
	"/alerts":      true,
	"/prices":      true,
	"/mywatchlist": true,
	"/watchlist":   true,
	"/status":      true,
	"/help":        true,
	"/start":       true,
	"/disclaimer":  true,
	"/buy":         true,
	"/sell":        true,
	"/quick":       true,
	"/setalert":    true,
}

// pluginCommandRegistry is the per-BotHandler map of plugin commands.
// Embedded in BotHandler via the pluginCmds field (see bot.go). Guarded
// by its own mutex so RegisterCommand (typically called during app
// wiring) does not contend on the BotHandler's hot-path rate-limit
// mutex.
type pluginCommandRegistry struct {
	mu       sync.RWMutex
	handlers map[string]PluginCommandHandler
}

func newPluginCommandRegistry() *pluginCommandRegistry {
	return &pluginCommandRegistry{
		handlers: make(map[string]PluginCommandHandler),
	}
}

// RegisterCommand installs a plugin handler for the given /command.
// Returns an error when:
//   - name is empty or doesn't start with "/";
//   - name contains whitespace (commands are single tokens);
//   - name collides with a built-in (reservedCommands).
//
// Registering the same name twice is allowed — last-wins semantics —
// which matches a plugin's likely lifecycle (re-registration on a
// scheduler restart or a config-reload).
//
// Rationale for "built-in wins" precedence:
//   - Built-in commands carry rate-limiting, tier gating, and
//     confirmation flows that plugins can't replicate correctly.
//     Letting a plugin shadow /buy would bypass riskguard. Hard no.
//   - Plugins that want to CO-OPERATE with a built-in (e.g. "run a
//     metric after /buy") use OnAfterToolExecution-equivalent hooks
//     at the MCP layer, not the Telegram bot layer.
func (h *BotHandler) RegisterCommand(name string, fn PluginCommandHandler) error {
	if err := validateCommandName(name); err != nil {
		return err
	}
	if reservedCommands[name] {
		return fmt.Errorf("telegram: cannot register %q — reserved for built-in handler", name)
	}
	if fn == nil {
		return fmt.Errorf("telegram: handler for %q is nil", name)
	}

	h.ensurePluginRegistry()
	h.pluginCmds.mu.Lock()
	defer h.pluginCmds.mu.Unlock()
	h.pluginCmds.handlers[name] = fn
	return nil
}

// validateCommandName enforces the shape Telegram users actually type:
//
//	/lowercase-ish-token
//
// with no embedded whitespace or control characters. The parseCommand
// helper in bot.go lowercases and trims, so registered names must be
// lowercase too (otherwise a user's "/Echo" would never match
// "/Echo" stored in the map).
func validateCommandName(name string) error {
	if name == "" {
		return fmt.Errorf("telegram: command name is empty")
	}
	if !strings.HasPrefix(name, "/") {
		return fmt.Errorf("telegram: command %q must start with '/'", name)
	}
	if len(name) < 2 {
		return fmt.Errorf("telegram: command %q has no token after '/'", name)
	}
	for _, r := range name {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("telegram: command %q contains whitespace/control characters", name)
		}
	}
	return nil
}

// ensurePluginRegistry lazily initialises pluginCmds on first
// registration. Keeps BotHandler zero-value valid for the common case
// of no plugin commands without paying construction cost every time.
func (h *BotHandler) ensurePluginRegistry() {
	h.pluginRegistryOnce.Do(func() {
		h.pluginCmds = newPluginCommandRegistry()
	})
}

// lookupPluginCommand returns the handler for cmd, if any. Second
// return value is false when no plugin has registered the name — the
// caller (ServeHTTP's default branch) then falls back to the existing
// "Unknown command" banner.
func (h *BotHandler) lookupPluginCommand(cmd string) (PluginCommandHandler, bool) {
	if h.pluginCmds == nil {
		return nil, false
	}
	h.pluginCmds.mu.RLock()
	defer h.pluginCmds.mu.RUnlock()
	fn, ok := h.pluginCmds.handlers[cmd]
	return fn, ok
}

// dispatchPluginCommand invokes a registered handler with panic
// recovery. Returns the reply text. On panic, returns a user-facing
// error notice so the bot still replies to the user (matches the
// built-in "Unknown command" fallback ethos: never ghost the caller).
//
// The logger hook writes a structured log line so operators notice
// misbehaving plugins. The original panic value is captured; we do NOT
// re-panic — that would crash the goroutine mcp-go / httptest expects
// to return cleanly.
func (h *BotHandler) dispatchPluginCommand(fn PluginCommandHandler, pctx PluginCommandContext) (reply string) {
	defer func() {
		if r := recover(); r != nil {
			if h.logger != nil {
				h.logger.Error("telegram: plugin command panicked",
					"chat_id", pctx.ChatID,
					"email", pctx.Email,
					"panic", r,
				)
			}
			reply = "\u26A0\uFE0F Plugin command failed. The server administrator has been notified."
		}
	}()
	return fn(pctx)
}
