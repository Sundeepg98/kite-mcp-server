# Kite MCP Plugin for Claude

Installs an MCP server + 8 Skills for power-user trading on Zerodha Kite.

## Install via Claude Code

```
/plugin install kite@github.com/Sundeepg98/kite-mcp-server
```

## Manual install

Clone this repo, point `~/.claude/plugins/` to the `.claude-plugin/` folder.

## What you get

- MCP connection to `kite-mcp-server.fly.dev/mcp` (per-user OAuth to Zerodha Kite)
- 8 Skills: /kite:morning, /kite:trade, /kite:eod, /kite:options-sanity-check, /kite:sector-rotation, /kite:alert-playbook, /kite:tax-harvest, /kite:backtest-interpretation
- Ships with the repo's MCP server for self-hosting if needed

## Caveats

- Hosted endpoint is read-only (order placement gated off for compliance)
- For order placement: self-host with `ENABLE_TRADING=true`
- Not investment advice. Not SEBI-registered.
