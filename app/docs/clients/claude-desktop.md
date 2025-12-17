---
title: Claude Desktop
description: Setting up Kite MCP with Claude Desktop
---

# Setting up Kite MCP using Claude

## Install Node.js

* Download and install Node.js from [nodejs.org](https://nodejs.org/en)
* Verify installation by opening Command Prompt and typing `node --version`


## Configure Claude Desktop

* Open [Claude Desktop](https://claude.ai/download) application
* Go to Settings (gear icon)
* Click on Developer in the left sidebar
* Click Edit Config
* Add the following configuration:


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

* Save and restart Claude Desktop

For a visual walkthrough of the setup process, check out this [step-by-step video](https://www.youtube.com/watch?v=tD1z8lR0CDE) guide on configuring MCP for Claude Desktop.



## Verify Connection

* In Claude Desktop, look for the `Search and tools` icon in the chat interface
* Click it to verify Kite MCP tools are available
* Follow the authorisation prompts to connect to your Zerodha account


## Linux Installation

There are two unofficial builds for Claude Desktop on Linux:

### Using aaddrick's Debian/Ubuntu build

[GitHub Repository](https://github.com/aaddrick/claude-desktop-debian)

```bash
git clone https://github.com/aaddrick/claude-desktop-debian.git
cd claude-desktop-debian
chmod +x build.sh
./build.sh
sudo dpkg -i ./claude-desktop_*.deb
```

### Using k3d3's Nix Flake method

[GitHub Repository](https://github.com/k3d3/claude-desktop-linux-flake)

```bash
NIXPKGS_ALLOW_UNFREE=1 nix run github:k3d3/claude-desktop-linux-flake --impure
```

After installing with either method, configure MCP:

```bash
mkdir -p ~/.config/Claude
nano ~/.config/Claude/claude_desktop_config.json
```

Add the same JSON configuration as above.

### Claude Code (official Linux support)

```bash
npm install -g @anthropic-ai/claude-code
claude
/mcp add
```

When prompted, set up the Kite MCP server with the remote URL.
