# Kite MCP Skills

A pack of [Claude Skills](https://docs.claude.com/en/docs/agents-and-tools/agent-skills/overview) tuned
for Indian retail traders who use [kite-mcp-server](../README.md) (a self-hosted MCP bridge to
Zerodha Kite Connect). Claude Skills are static `SKILL.md` files with YAML frontmatter — they don't
execute code. They teach Claude **how** to reason about a domain (here: Indian markets, Kite tool
names, SEBI constraints, NSE session timing) so that when you ask for a "morning brief" or a
"pre-trade check", Claude calls the right MCP tools in the right order and presents the output in a
disciplined, repeatable format.

Skills are the reasoning layer; the [kite-mcp-server](../README.md) is the execution layer. Install
both for the full workflow: Skills give you better prompting, the MCP server actually talks to Kite.

## What you get

8 focused workflows, each a single `SKILL.md` file:

| Skill | What it does |
|---|---|
| `morning-brief` | Pre-market briefing: portfolio state, indices, alerts, margin, warnings |
| `trade-check` | Pre-flight check before an order: margin, concentration, stop-loss suggestion |
| `eod-review` | End-of-day review: P&L, positions, orders, MIS square-off warnings |
| `options-sanity-check` | Pre-entry sanity pass for options: IV, Greeks, margin, liquidity |
| `sector-rotation` | Sector exposure review using `sector_exposure` + FII/DII flow |
| `alert-playbook` | Disciplined alert-setting: price, percentage, volume, GTT, native |
| `tax-harvest` | LTCG/STCG-aware tax-loss harvesting walkthrough |
| `backtest-interpretation` | How to read `historical_price_analyzer` output without over-fitting |

## Install

### Option 1: Drop into `~/.claude/skills/`

Clone or copy the `skills/` subfolders into your user skills directory. On Windows:

```bash
cp -r skills/* ~/.claude/skills/
```

Claude Code and Claude Desktop auto-discover skills from this directory on startup. The
frontmatter `description` field is what Claude uses to decide when to load each skill, so phrases
like "morning brief", "pre-trade check", or "tax harvest" in your prompt will light up the right
one automatically.

### Option 2: Plugin marketplace (future)

We plan to publish these as a plugin at `Sundeepg98/kite-mcp-skills` for `/plugin install`. For now,
Option 1 is the supported path.

## Requires

For the skills to be useful you also need the MCP server connected so Claude can actually call
tools like `get_holdings`, `place_order`, `sector_exposure`, etc. See the
[main README](../README.md) for connecting:

- **Hosted**: `https://kite-mcp-server.fly.dev/mcp` (OAuth, bring your own Kite developer app)
- **Self-hosted**: `go build && ./kite-mcp-server` with your own `OAUTH_JWT_SECRET`

Without the MCP server the skills still teach Claude the right vocabulary and workflow shape, but
no tool calls will succeed — you'll get advice-shaped responses instead of execution.

## Constraints baked into every skill

- Never claim "this stock will go up / will rise" or recommend specific buys/sells as predictions
- Always cite the exact MCP tool being called (e.g., `get_holdings`, not "fetch portfolio")
- Factual framing over predictive framing
- One workflow per skill — compose by chaining, not by stuffing

## License

MIT, matching the [parent repository](../LICENSE).
