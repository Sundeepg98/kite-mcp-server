# BYO (Bring Your Own) Anthropic API Key

## Why

Claude.ai Pro tier caps tool use at ~20-25 calls per turn and 40-80 Sonnet hours/week. Heavy kite-mcp-server users — active traders analyzing multi-quarter concalls, running backtests, chaining options-Greeks queries — hit that wall quickly. Raw Anthropic API access bypasses those caps entirely.

## Realistic cost (Sonnet 4.6)

- Active retail trader: 20 tool calls/day × ~2,500 tokens avg × 30 days = ~$18/month
- With prompt caching (90% hit): ~$5-8/month
- Power user (100 tool calls/day): ~$40-60/month

All below a Claude Max subscription ($100-200/mo), with no quota ceiling.

## Options

### Option 1 — Claude Agent SDK (programmatic)

Use https://github.com/anthropic-ai/claude-agent-sdk-python or the Node equivalent. MCP servers can be added to an agent instance. The SDK uses your `ANTHROPIC_API_KEY` env var for direct API billing.

Example skeleton (Python):

```python
import os
from claude_agent_sdk import ClaudeAgentOptions, query

# ANTHROPIC_API_KEY must be set in the environment.
options = ClaudeAgentOptions(
    model="claude-sonnet-4-6",
    mcp_servers={
        "kite": {
            "type": "http",
            "url": "https://kite-mcp-server.fly.dev/mcp",
        },
    },
    allowed_tools=["mcp__kite__*"],
)

async for message in query(
    prompt="Show my portfolio concentration by sector.",
    options=options,
):
    print(message)
```

On first run, the SDK's OAuth helper opens a browser for the Kite login handshake; the MCP bearer JWT and Kite access token are then cached for the 24-hour JWT window.

### Option 2 — mcp-remote (Claude Desktop / Claude Code)

If using Claude Desktop's "Custom connectors" feature, you're already going through Claude.ai's quota. To use API billing:

- Use Claude Code's API-billing mode (see https://docs.claude.com/en/docs/claude-code/pricing)
- Or switch to an MCP host that supports direct API auth (Cursor, VS Code Copilot, Goose)

Claude Code with `ANTHROPIC_API_KEY` set bills the same direct API backend; the `mcp-remote` bridge to `https://kite-mcp-server.fly.dev/mcp` is identical either way.

### Option 3 — Custom client

Any client speaking MCP over HTTP streamable transport can connect to `https://kite-mcp-server.fly.dev/mcp`. Use https://github.com/modelcontextprotocol/create-python-server or equivalent to bootstrap a client that drives the Anthropic SDK directly and treats this server as a tool provider.

## Setup steps

1. Get an Anthropic API key at https://console.anthropic.com/settings/keys
2. Install Claude Agent SDK: `pip install claude-agent-sdk`
3. Configure the SDK to talk to `https://kite-mcp-server.fly.dev/mcp` with your Kite Connect developer key (registered via the `login` tool on first call)
4. Run queries — token usage shows in the Anthropic console, not the Claude.ai quota dashboard

Whitelisting reminder: the static egress IP `209.71.68.157` must be in your Kite developer console regardless of which client surface you use (SEBI April 2026 mandate).

## When BYO-key is overkill

Casual users (<20 tool calls/day) stay within Claude.ai Pro comfortably. BYO-key is the power-user path — worth it if you hit the weekly Sonnet ceiling, run agentic backtests, or drive the server from your own scripts.

## Links

- [Anthropic API pricing](https://www.anthropic.com/pricing)
- [Claude Agent SDK](https://docs.claude.com/en/docs/claude-code/sdk/sdk-overview)
- [MCP Inspector / client guide](https://modelcontextprotocol.io/docs/tools/inspector)
- [Client Examples](./client-examples.md) — quota-bound setup for each client surface
</content>
</invoke>