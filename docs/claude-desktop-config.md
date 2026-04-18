# Claude Desktop config (copy-paste)

Connect Claude Desktop to kite-mcp-server in 60 seconds. All snippets assume you already have Claude Desktop installed.

## Option A: Hosted (read-only, fastest to try)

Connect to `https://kite-mcp-server.fly.dev/mcp`. Read-only — order placement is gated off on the hosted endpoint (Path 2 compliance). Research tools, portfolio, quotes all work.

### Mac

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "kite": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://kite-mcp-server.fly.dev/mcp"]
    }
  }
}
```

Restart Claude Desktop: `Cmd+Q` then reopen.

### Windows

Edit `%APPDATA%\Claude\claude_desktop_config.json` (or `C:\Users\<you>\AppData\Roaming\Claude\claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "kite": {
      "command": "cmd",
      "args": ["/c", "npx", "-y", "mcp-remote", "https://kite-mcp-server.fly.dev/mcp"]
    }
  }
}
```

Note the `cmd /c` wrapper — Windows-specific quirk.

Restart Claude Desktop from the tray (right-click → Quit, then reopen).

### Linux

Edit `~/.config/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "kite": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://kite-mcp-server.fly.dev/mcp"]
    }
  }
}
```

## Option B: Local (full trading, requires self-host)

Run your local kite-mcp server first (see [self-host.md](./self-host.md)), then add:

### Mac / Linux

```json
{
  "mcpServers": {
    "kite-local": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://127.0.0.1:8080/mcp"]
    }
  }
}
```

### Windows

```json
{
  "mcpServers": {
    "kite-local": {
      "command": "cmd",
      "args": ["/c", "npx", "-y", "mcp-remote", "http://127.0.0.1:8080/mcp"]
    }
  }
}
```

## Both at once

You can connect both hosted (read) and local (trading) simultaneously. Claude will see both under different names:

```json
{
  "mcpServers": {
    "kite": { "command": "npx", "args": ["-y", "mcp-remote", "https://kite-mcp-server.fly.dev/mcp"] },
    "kite-local": { "command": "npx", "args": ["-y", "mcp-remote", "http://127.0.0.1:8080/mcp"] }
  }
}
```

## Verify the connection

In Claude Desktop, open a new chat and ask:

> Call `server_version` from kite

You should see a JSON blob with git SHA + uptime + region. That proves the MCP bridge is working.

## Troubleshooting

### "Claude can't find command npx"

Install Node.js (https://nodejs.org). Claude Desktop expects `npx` in PATH.

### "mcp-remote keeps asking me to log in"

Kite access tokens expire daily at ~6 AM IST. Click through the login when prompted. See [kite-token-refresh.md](./kite-token-refresh.md).

### Windows: "The system cannot find the path specified"

Ensure `cmd /c` prefix (Windows only). Without it, Node can't resolve `npx.cmd` from Claude Desktop's process.

### OAuth keeps failing

1. Confirm your Kite Connect app's Redirect URI is exactly `http://127.0.0.1:8080/callback` (local) or your hosted URL + `/callback`
2. Clear mcp-remote cache: delete `~/.mcp-auth/` folder
3. Restart Claude Desktop

## Related
- [README](../README.md) — project overview
- [self-host.md](./self-host.md) — run your own local server
- [Kite token refresh](./kite-token-refresh.md) — daily re-auth
- [ChatGPT Connectors docs](https://platform.openai.com/docs/guides/connectors) — different client, similar idea
