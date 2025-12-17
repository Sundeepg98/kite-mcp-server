---
title: Introduction
description: Kite MCP Server connects AI assistants to your Zerodha trading account via the Model Context Protocol.
---

# Introduction

Kite MCP Server is a [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server that connects AI assistants like Claude, Cursor, and others to your Zerodha trading account via the Kite Connect API.

## What is MCP?

The Model Context Protocol is an open standard that allows AI assistants to securely connect to external data sources and tools. Instead of copying and pasting data, MCP lets AI assistants directly access your portfolio, market data, and trading functions.

## What Can You Do?

With Kite MCP, you can ask your AI assistant to:

- **View your portfolio**: "Show me my current holdings and their P&L"
- **Analyze positions**: "Which of my stocks are down more than 5% today?"
- **Get market data**: "What's the current price of RELIANCE?"
- **Place orders**: "Buy 10 shares of INFY at market price"
- **Manage GTT orders**: "Set a stop loss at 1500 for my TCS position"
- **Track alerts**: "Show me my active price alerts"

## Security

- **OAuth 2.1 with PKCE**: Industry-standard secure authentication
- **No stored credentials**: Your Kite credentials are never stored on our servers
- **Session-based access**: Each session requires fresh authorization
- **Read-only by default**: Order placement requires explicit confirmation

## Getting Started

1. [Quick Start Guide](/docs/getting-started) - Set up in 2 minutes
2. [OAuth Flow](/docs/oauth-flow) - Understand how authentication works
3. [Tools Reference](/docs/tools/) - See all available MCP tools

## Hosted vs Self-Hosted

### Hosted (Recommended)

Use our hosted server at `mcp.kite.trade` - no setup required:

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

### Self-Hosted

Run your own instance for development or custom deployments. See the [GitHub repository](https://github.com/zerodha/kite-mcp-server) for instructions.
