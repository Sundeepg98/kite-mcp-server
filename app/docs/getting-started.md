---
title: Quick Start
description: Get started with Kite MCP in 2 minutes
---

# Quick Start

Get Kite MCP working with your AI assistant in just a few steps.

## Prerequisites

- A Zerodha account with Kite
- Node.js installed (for `npx mcp-remote`)
- An MCP-compatible AI client (Claude Desktop, Cursor, VS Code, etc.)

## Setup

### Claude Desktop

1. Open Claude Desktop settings
2. Navigate to the MCP section
3. Add this configuration:

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

4. Restart Claude Desktop
5. Start a new conversation and ask: "Log me into Kite"

### Cursor

1. Open Cursor settings (`Cmd/Ctrl + ,`)
2. Search for "MCP"
3. Add the Kite MCP server configuration
4. Restart Cursor

### VS Code (with GitHub Copilot)

Add to your `settings.json`:

```json
{
  "mcp": {
    "servers": {
      "kite": {
        "command": "npx",
        "args": ["mcp-remote", "https://mcp.kite.trade/mcp"]
      }
    }
  }
}
```

## First Login

When you first interact with Kite MCP, you'll need to authenticate:

1. Ask your AI to "login to Kite" or perform any Kite action
2. Click the login link provided
3. Authorize the app on Zerodha's login page
4. Return to your AI client - you're now connected!

## Try These Commands

Once logged in, try asking:

- "Show me my portfolio"
- "What are my holdings?"
- "Get the current price of RELIANCE"
- "Show my open orders"
- "What's my account margin?"

## Troubleshooting

### "Server disconnected" error

This usually means the connection timed out. Try:
1. Restart your AI client
2. Ask to login again

### "Invalid session" error

Your session has expired (sessions last ~6 hours). Simply login again.

### Tools not appearing

Make sure:
1. Node.js is installed (`node --version`)
2. Your config is valid JSON
3. You've restarted the client after adding config

## Next Steps

- [Understand the OAuth flow](/docs/oauth-flow)
- [Explore all available tools](/docs/tools/)
- [Read the FAQ](/docs/faq)
