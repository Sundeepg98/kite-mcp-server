---
title: Cursor Setup
description: Connect Kite MCP to Cursor IDE
---

# Cursor Setup

Use Kite MCP with Cursor for AI-assisted coding with market data access.

## Prerequisites

- [Cursor](https://cursor.sh/) installed
- [Node.js](https://nodejs.org/) installed

## Configuration

1. Open Cursor settings (`Cmd+,` / `Ctrl+,`)
2. Search for "MCP" in settings
3. Add the Kite MCP server configuration:

```json
{
    "mcpServers": {
        "kite": {
            "command": "npx",
            "args": ["mcp-remote", "https://mcp.kite.trade/mcp"]
        }
    }
}
```

4. Restart Cursor

## Verify Connection

1. Open a new Cursor chat
2. Look for Kite tools in the available tools list
3. Ask "Login to Kite" to initiate authentication
4. Complete the OAuth flow in your browser
5. Return to Cursor - you're connected!

## Usage Tips

In Cursor, you can:

- Ask about your portfolio while coding trading algorithms
- Get real-time price data for stocks you're analyzing
- Check your positions without leaving the editor
- Execute trades directly from the chat

## Troubleshooting

### Tools not appearing

1. Ensure Node.js is installed: `node --version`
2. Check your MCP configuration syntax
3. Restart Cursor completely (quit and reopen)

### Connection timeouts

If connections timeout:
1. Check your internet connection
2. Try restarting Cursor
3. Re-authenticate if your session expired
