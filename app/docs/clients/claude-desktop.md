---
title: Claude Desktop Setup
description: Connect Kite MCP to Claude Desktop on macOS, Windows, or Linux
---

# Claude Desktop Setup

Connect your Zerodha account to Claude Desktop for natural conversations about your portfolio.

## Prerequisites

- [Node.js](https://nodejs.org/) installed
- [Claude Desktop](https://claude.ai/download) application

## Configuration Steps

1. Open Claude Desktop application
2. Go to **Settings** (gear icon)
3. Click **Developer** in the left sidebar
4. Click **Edit Config**
5. Add the following configuration:

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

6. Save and restart Claude Desktop

## Verify Connection

1. In Claude Desktop, look for the **Search and tools** icon in the chat interface
2. Click it to verify Kite MCP tools are available
3. Follow the authorization prompts to connect to your Zerodha account

## Video Guide

For a visual walkthrough, check out this [step-by-step video guide](https://www.youtube.com/watch?v=tD1z8lR0CDE) on configuring MCP for Claude Desktop.

## Linux Installation

Claude Desktop doesn't have an official Linux build, but there are community options:

### Option 1: Debian/Ubuntu Build

```bash
git clone https://github.com/aaddrick/claude-desktop-debian.git
cd claude-desktop-debian
chmod +x build.sh
./build.sh
sudo dpkg -i ./claude-desktop_*.deb
```

### Option 2: Nix Flake

```bash
NIXPKGS_ALLOW_UNFREE=1 nix run github:k3d3/claude-desktop-linux-flake --impure
```

After installation, configure MCP:

```bash
mkdir -p ~/.config/Claude
nano ~/.config/Claude/claude_desktop_config.json
```

Add the same JSON configuration as above.

### Option 3: Claude Code CLI

Claude Code has official Linux support:

```bash
npm install -g @anthropic-ai/claude-code
claude
/mcp add
```

When prompted, set up the Kite MCP server with the remote URL.
