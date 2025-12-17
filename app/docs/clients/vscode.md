---
title: VS Code Setup
description: Connect Kite MCP to VS Code with GitHub Copilot
---

# VS Code Setup

Use Kite MCP with GitHub Copilot in Visual Studio Code.

## Prerequisites

- [Visual Studio Code](https://code.visualstudio.com/download) installed
- [Node.js](https://nodejs.org/) installed
- GitHub Copilot extension (or another AI extension supporting MCP)

## Configuration (VS Code 1.102.0+)

For VS Code versions 1.102.0 or newer:

1. Open Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`)
2. Type `MCP: Open User Configuration` and press Enter
3. Replace the contents with:

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

4. Save the file and restart VS Code
5. Open the Copilot Chat panel, select **Agent** mode
6. When prompted, authorize your Zerodha account

## Configuration (VS Code < 1.102.0)

For older VS Code versions:

1. Open VS Code settings (`File > Preferences > Settings` or `Ctrl+,`)
2. Search for "copilot chat mcp"
3. Click **Edit in settings.json**
4. Add the following configuration:

```json
{
    "mcp": {
        "inputs": [],
        "servers": {
            "kite": {
                "url": "https://mcp.kite.trade/mcp"
            }
        }
    }
}
```

5. Save and restart VS Code
6. Open Copilot Chat and use `/mcp` to verify Kite is available

## Verify Connection

1. Open the Copilot Chat panel
2. Verify Kite MCP tools are listed
3. Ask a test question like "Show my portfolio"
4. Authorize when prompted

## More Information

For detailed information on MCP in VS Code, see the [official documentation](https://code.visualstudio.com/docs/copilot/customization/mcp-servers).
