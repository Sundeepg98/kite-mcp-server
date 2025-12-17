---
title: FAQ
description: Frequently asked questions about Kite MCP
---

# Frequently Asked Questions

## General

### What is Kite MCP?

Kite MCP is a Model Context Protocol server that connects AI assistants (like Claude, Cursor, VS Code Copilot) to your Zerodha trading account via the Kite Connect API.

### Is this official from Zerodha?

Yes, Kite MCP is developed and maintained by Zerodha.

### Which AI assistants are supported?

Any MCP-compatible client works, including:
- Claude Desktop
- Cursor IDE
- VS Code with GitHub Copilot
- Claude Code CLI
- Custom MCP clients via `mcp-remote`

### Is it free to use?

Yes, Kite MCP is free. You just need a Zerodha account with Kite.

---

## Security

### Is my data safe?

Yes. Kite MCP uses industry-standard OAuth 2.1 with PKCE:
- Your Zerodha credentials are never stored on our servers
- Authentication happens directly with Zerodha
- We only receive a temporary session token
- All data is transmitted over HTTPS

### Can Claude see my password?

No. Your password is entered directly on Zerodha's login page. Claude only receives a temporary access token after you authorize.

### How do I revoke access?

1. Go to [kite.zerodha.com](https://kite.zerodha.com)
2. Navigate to Settings → Apps
3. Find "kitemcp" and click Revoke

### Can Claude place orders without my permission?

Order placement tools require explicit confirmation. You control what actions are taken.

---

## Troubleshooting

### "Server disconnected" error

This usually means the connection timed out. Try:
1. Restart your AI client
2. Ask to login again

### "Invalid session" error

Your session has expired (sessions last ~6 hours). Simply login again.

### Tools not appearing in Claude

1. Verify Node.js is installed: `node --version`
2. Check your config is valid JSON
3. Restart Claude Desktop completely

### Login link not working

1. Make sure you're clicking the full URL
2. Check if pop-ups are blocked
3. Try copying the URL manually

### "Rate limit exceeded"

Wait a few minutes and try again. Rate limits prevent abuse.

---

## Data & Features

### What data can I access?

- Portfolio holdings and positions
- Real-time quotes and market data
- Order history and GTT orders
- Account margins and funds
- Historical OHLC data
- Alerts and watchlists

### Can I place orders?

Yes, Kite MCP supports:
- Market and limit orders
- GTT (Good Till Triggered) orders
- Order modification and cancellation

### What about mutual funds?

Currently, Kite MCP focuses on equity and F&O. Coin (mutual fund) integration is planned.

### Is historical data available?

Yes, you can access historical OHLC data for charting and analysis.

---

## Technical

### Can I self-host?

Yes, the [source code](https://github.com/zerodha/kite-mcp-server) is available. You'll need your own Kite Connect API credentials.

### What's the difference between SSE and HTTP mode?

- **HTTP mode** (default): Uses streamable HTTP transport, compatible with `mcp-remote`
- **SSE mode**: Server-Sent Events transport for real-time streaming
- **Hybrid mode**: Supports both

### How long do sessions last?

Sessions match Kite Connect's session duration, approximately 6 hours.

---

## Getting Help

- **GitHub Issues**: [Report bugs or request features](https://github.com/zerodha/kite-mcp-server/issues)
- **Zerodha Support**: [Contact support](https://support.zerodha.com/)
- **Kite Connect Docs**: [API documentation](https://kite.trade/docs/connect/v3/)
