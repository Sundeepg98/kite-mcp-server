---
title: Quick Start
description: Get started with Kite MCP
---

# Quick Start

## Prerequisites

* A Zerodha account with Kite
* [Node.js](https://nodejs.org/) installed
* An MCP-compatible AI client

## Choose Your Client

Select your AI assistant and follow the setup guide:

* [Claude Desktop](/docs/clients/claude-desktop) - Anthropic's desktop app
* [VS Code](/docs/clients/vscode) - With GitHub Copilot
* [Cursor](/docs/clients/cursor) - AI-first code editor

## Basic Configuration

All clients use the same server URL:

```
https://mcp.kite.trade/mcp
```

For Claude Desktop and Cursor (using mcp-remote):

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

For VS Code (native HTTP MCP support):

```json
{
    "servers": {
        "kite": {
            "url": "https://mcp.kite.trade/mcp",
            "type": "http"
        }
    },
    "inputs": []
}
```

## First Login

When you first interact with Kite MCP:

1. Ask your AI to perform any Kite action (e.g., "Show my portfolio")
2. Click the login link provided
3. Authorise the app on Zerodha's login page
4. Return to your AI client - you're now connected

Sessions last approximately 6 hours. Simply login again when your session expires.
