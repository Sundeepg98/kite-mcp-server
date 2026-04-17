package telegram

import (
	"strings"
	"testing"
)

// These fuzz harnesses exercise the /buy, /sell, /quick, /setalert command
// parsers that live in trading_commands.go. The inputs come from Telegram
// message text, which is entirely user-controlled — so the parser must:
//
//  1. Never panic on any input.
//  2. Never hang or consume unbounded memory (no regex DoS, no unchecked
//     loop with attacker-controlled bound).
//  3. Always send *some* response to the chat (usage message on bad input,
//     confirmation on good input, error on invalid field).
//
// We can't verify the full order-placement path without a live broker, so
// these harnesses focus on the parsing layer before any HTTP calls happen.
//
// Run:
//   go test ./kc/telegram/ -run=^$ -fuzz=FuzzHandleBuy   -fuzztime=30s
//   go test ./kc/telegram/ -run=^$ -fuzz=FuzzHandleQuick -fuzztime=30s

// FuzzHandleBuy fuzzes /buy SYMBOL QTY [PRICE] with adversarial inputs.
func FuzzHandleBuy(f *testing.F) {
	// Realistic seeds.
	f.Add("RELIANCE 10")
	f.Add("INFY 5 1500")
	f.Add("SBIN 100 650.25")
	f.Add("")
	f.Add("  ")

	// Adversarial seeds.
	f.Add("INFY -5")                                       // negative qty
	f.Add("INFY abc")                                      // non-numeric qty
	f.Add("INFY 10 notanumber")                            // non-numeric price
	f.Add("INFY 10 1500 extra arg")                        // too many args
	f.Add(strings.Repeat("A", 10_000) + " 10")             // long symbol
	f.Add("'; DROP TABLE orders; --")                      // SQL-ish
	f.Add("<script>alert(1)</script> 10")                  // XSS primitive in symbol
	f.Add("INFY \u0000 \u2028")                            // NUL + line separator
	f.Add("INFY 99999999999999999999999")                  // int overflow
	f.Add("INFY 10 -1.5")                                  // negative price
	f.Add("INFY 10 1.7e308")                               // huge float
	f.Add("\t\t\t")                                        // whitespace only
	f.Add("INFY\n10\n1500")                                // newline separators
	f.Add("INFY 10 1500\x00injected")                      // embedded NUL after valid parse
	f.Add("\xff\xfe INFY 10")                              // invalid UTF-8 prefix

	f.Fuzz(func(t *testing.T, input string) {
		mgr := newMockKiteManager()
		h, mock := newTestBotHandler(mgr)
		defer h.Shutdown()

		// Must not panic regardless of input.
		h.handleBuy(42, "user@test.com", input)

		// Must always send *some* reply — a usage message, validation error,
		// or confirmation. Never silent.
		if mock.bodyCount() == 0 {
			t.Fatalf("no reply sent for input %q", input)
		}
	})
}

// FuzzHandleSell fuzzes /sell with the same adversarial inputs.
func FuzzHandleSell(f *testing.F) {
	f.Add("INFY 5")
	f.Add("INFY 5 1500")
	f.Add("")
	f.Add("INFY abc")
	f.Add(strings.Repeat("\x00", 100))
	f.Add("INFY 2147483648") // int32 overflow
	f.Add("INFY 10 \u2028")
	f.Add("INFY 10 ; rm -rf /")
	f.Add("   ")

	f.Fuzz(func(t *testing.T, input string) {
		mgr := newMockKiteManager()
		h, mock := newTestBotHandler(mgr)
		defer h.Shutdown()

		h.handleSell(42, "user@test.com", input)

		if mock.bodyCount() == 0 {
			t.Fatalf("no reply sent for input %q", input)
		}
	})
}

// FuzzHandleQuick fuzzes /quick SYMBOL QTY SIDE TYPE [PRICE].
// Extra argument surface vs /buy — 4-5 fields, two constrained enums.
func FuzzHandleQuick(f *testing.F) {
	f.Add("RELIANCE 10 BUY MARKET")
	f.Add("INFY 5 SELL LIMIT 1500")
	f.Add("INFY 10 BUY MARKET extra")
	f.Add("INFY 10 HOLD MARKET")  // invalid side
	f.Add("INFY 10 BUY SL")       // invalid type
	f.Add("INFY 10 BUY LIMIT")    // missing price
	f.Add("INFY 10 BUY LIMIT abc") // bad price
	f.Add("")
	f.Add("INFY")
	f.Add("INFY 10 BUY\u2028MARKET")
	f.Add("\x00 \x00 \x00 \x00")
	f.Add(strings.Repeat("X", 10_000) + " 10 BUY MARKET")
	f.Add("INFY -1 BUY MARKET")
	f.Add("INFY 0 BUY MARKET")
	f.Add("INFY 10 buy market") // lowercase — handler upper-cases

	f.Fuzz(func(t *testing.T, input string) {
		mgr := newMockKiteManager()
		h, mock := newTestBotHandler(mgr)
		defer h.Shutdown()

		h.handleQuick(42, "user@test.com", input)

		if mock.bodyCount() == 0 {
			t.Fatalf("no reply sent for input %q", input)
		}
	})
}

// FuzzHandleSetAlert fuzzes /setalert SYMBOL DIRECTION PRICE.
// Unlike buy/sell/quick, handleSetAlert returns a string (not sent via bot),
// so we assert the returned string is non-empty and not indicative of panic.
func FuzzHandleSetAlert(f *testing.F) {
	f.Add("RELIANCE above 2700")
	f.Add("NIFTY below 22000")
	f.Add("INFY drop_pct 5")
	f.Add("INFY rise_pct 2.5")
	f.Add("")
	f.Add("INFY")
	f.Add("INFY above")
	f.Add("INFY sideways 100")        // invalid direction
	f.Add("INFY above -1")             // negative price
	f.Add("INFY above abc")            // non-numeric
	f.Add("INFY drop_pct 150")         // pct > 100
	f.Add("INFY above 2700 extra")     // too many parts
	f.Add("\u0000 \u0000 \u0000")      // NULs
	f.Add(strings.Repeat("A", 5_000) + " above 100")
	f.Add("INFY above 1.7e308")        // huge float
	f.Add("INFY\nabove\n100")

	f.Fuzz(func(t *testing.T, input string) {
		mgr := newMockKiteManager()
		h, _ := newTestBotHandler(mgr)
		defer h.Shutdown()

		// Must never panic; must always return *some* string (usage, error,
		// or success). Empty return is a parser bug.
		reply := h.handleSetAlert(42, "user@test.com", input)
		if reply == "" {
			t.Fatalf("empty reply for input %q", input)
		}
	})
}

// FuzzTradingCommandFields fuzzes the `strings.Fields` pre-parse layer on a
// broader surface — any characters between commands. The goal is to catch
// edge cases where Fields() produces zero or unexpected counts that the
// handlers branch on (len(parts) < 2, > 3, == 3, etc).
func FuzzTradingCommandFields(f *testing.F) {
	f.Add("a b c")
	f.Add("a  b\tc\n")
	f.Add("")
	f.Add("\u00A0\u2028\u2029") // exotic whitespace
	f.Add("\x00\x01\x02")
	f.Add(strings.Repeat(" ", 10_000) + "RELIANCE 10")

	f.Fuzz(func(t *testing.T, input string) {
		// Sanity: Fields must never panic or produce nil.
		parts := strings.Fields(input)
		if parts == nil && input != "" {
			// Even on weird input, a non-empty input that contains at least
			// one non-whitespace rune should yield a non-nil slice.
			hasNonWS := false
			for _, r := range input {
				if !isFieldsWhitespace(r) {
					hasNonWS = true
					break
				}
			}
			if hasNonWS {
				t.Fatalf("Fields returned nil for non-whitespace input %q", input)
			}
		}
	})
}

// isFieldsWhitespace mirrors the subset of unicode.IsSpace that strings.Fields
// considers a separator. We only use this in the assertion above.
func isFieldsWhitespace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0x85, 0xA0:
		return true
	}
	// Everything else we treat as non-whitespace for the assertion.
	return false
}
