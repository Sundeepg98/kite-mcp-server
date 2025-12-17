---
title: VS Code
description: Setting up Kite MCP with VS Code and GitHub Copilot
---

# VS Code Setup

## Prerequisites

* [Visual Studio Code](https://code.visualstudio.com/download) installed
* [Node.js](https://nodejs.org/en) installed
* VS Code GitHub Copilot extension or another AI extension that supports MCP


## Configuration (version 1.102.0 or newer)

For VS Code versions 1.102.0 or newer, please follow the configuration steps outlined below.

* Open Command Palette (`Ctrl+Shift+P`)
* Type `MCP: Open User Configuration` and press `Enter`
* Delete/Remove existing configuration details
* Add the following configuration:

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

* Save the file and restart VS Code
* Open the Copilot Chat panel, select `Agent` mode and ask your queries
* When prompted, authorise your Zerodha account to connect with VS Code


## Configuration (version below 1.102.0)

* Open VS Code settings (File > Preferences > Settings, or press `Ctrl+,`)
* Search for "copilot chat mcp" or navigate to the GitHub Copilot Chat configuration
* Click on Edit in settings.json
* Add the following configuration to your settings.json file:


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

* Save the settings file and restart VS Code
* Open the Copilot Chat panel and use the `/mcp` command to verify that Kite is listed as an available MCP server
* When prompted, authorise your Zerodha account to connect with VS Code


For more detailed information on setting up MCP servers in VS Code, refer to the [official documentation](https://code.visualstudio.com/docs/copilot/customization/mcp-servers).
