package mcp

import (
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/algo2go/kite-mcp-ticker"
	"github.com/zerodha/kite-mcp-server/mcp/misc"
)

// Anchor 1 PR 1.10: thin wrappers preserving the legacy lowercase
// `resolveInstrumentTokens` and `resolveTickerMode` symbols so the
// pre-extraction tests in mcp/tools_pure_format_test.go continue to
// compile against package mcp without rewriting every call site.
//
// The canonical implementations live in mcp/misc; new code should call
// misc.ResolveInstrumentTokens / misc.ResolveTickerMode directly.

func resolveInstrumentTokens(instr kc.InstrumentManagerInterface, ids []string) ([]uint32, []string) {
	return misc.ResolveInstrumentTokens(instr, ids)
}

func resolveTickerMode(mode string) ticker.Mode {
	return misc.ResolveTickerMode(mode)
}
