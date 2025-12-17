---
title: Cursor
description: Setting up Kite MCP with Cursor IDE
---

# Cursor Setup

## Prerequisites

* [Cursor](https://cursor.sh/) installed
* [Node.js](https://nodejs.org/) installed

## Configuration

* Open Cursor settings (`Cmd+,` / `Ctrl+,`)
* Search for "MCP" in settings
* Add the Kite MCP server configuration:

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

* Restart Cursor

## Verify Connection

* Open a new Cursor chat
* Look for Kite tools in the available tools list
* Ask "Login to Kite" to initiate authentication
* Complete the OAuth flow in your browser
* Return to Cursor - you're connected
