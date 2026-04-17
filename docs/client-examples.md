# Client Examples

Copy-paste-ready interactions for each MCP client surface. The [Cookbook](cookbook.md) shows five end-to-end workflows in natural language; this doc shows **how each workflow actually runs** in claude.ai web, Claude Desktop, Claude Code, and ChatGPT — prompts, expected output, widget rendering, and client-specific quirks.

All four surfaces point at the same endpoint: `https://kite-mcp-server.fly.dev/mcp`. The registry listing lives in [`server.json`](../server.json); version history is in [`CHANGELOG.md`](../CHANGELOG.md).

---

## 1. claude.ai Web

### Setup (4 steps)

1. Open [claude.ai](https://claude.ai) → **Settings** → **Connectors**.
2. Click **Add custom connector**.
3. Paste the URL: `https://kite-mcp-server.fly.dev/mcp`.
4. Click **Connect**, then authenticate with Kite when the OAuth popup appears. If you already have a dashboard cookie from `https://kite-mcp-server.fly.dev/dashboard`, the second Kite login is skipped (dashboard SSO short-circuit, see `OAuth /oauth/authorize` in the changelog).

One-time after connect: run `test_ip_whitelist` in chat — this confirms `209.71.68.157` is whitelisted in your Kite developer console (SEBI April 2026 mandate).

### Example conversations

**Example 1 — Morning scan with portfolio widget**

> **You:** Morning scan. Show my positions, today's P&L, and any concentration risk.

> **Claude:** *(calls `trading_context`, then `portfolio_analysis` with `sector_exposure=true`)*
>
> Here's your snapshot. [Portfolio Widget appears inline — holdings table, P&L line, sector donut, concentration flags.]
>
> - Unrealised P&L: +₹12,430 (+1.2%)
> - 3 sector over-exposures flagged: IT (38%), Banking (27%), FMCG (22%)
> - No open positions breaching the ₹5L order cap.
>
> Want me to suggest a rebalance?

**[Screenshot: portfolio widget in claude.ai]** — inline widget with sortable holdings table, sector pie, and "Rebalance" CTA linking to `/dashboard`.

Click the **Rebalance** button inside the widget to drill into `portfolio_analysis` output; click any holding row to open that symbol's Kite chart in a new tab.

**Example 2 — Backtest an RSI-reversal idea**

> **You:** Backtest RSI-reversal on RELIANCE for the last 180 days. Default parameters.

> **Claude:** *(calls `historical_price_analyzer` with `strategy="rsi_reversal"`, `tradingsymbol="RELIANCE"`, `days=180`)*
>
> [Technical-analysis widget renders the equity curve, drawdown chart, and trade log.]
>
> - Total return: +8.3% vs buy-and-hold +6.1%
> - Max drawdown: −4.2%
> - Sharpe: 1.14, Win rate: 56% (14/25 trades)
>
> The strategy slightly outperformed buy-and-hold with lower volatility. Want me to try `breakout` on the same symbol?

**[Screenshot: backtest widget with equity curve]**

**Example 3 — Set a percentage alert**

> **You:** Alert me if NIFTY drops 0.5% from current levels. Send it to Telegram.

> **Claude:** *(calls `set_alert` with `direction="drop_pct"`, `price=0.5`; then `list_alerts` to confirm)*
>
> Alert created: NIFTY 50 `drop_pct 0.5%` from ₹22,460.30. You'll get a Telegram DM when the price hits ₹22,348.00. [Alerts widget appears inline showing all active alerts with pause/delete controls.]

Click any row in the alerts widget to edit threshold; elicitation dialog fires for destructive ops.

---

## 2. Claude Desktop

### Setup

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "kite": {
      "type": "http",
      "url": "https://kite-mcp-server.fly.dev/mcp"
    }
  }
}
```

**Config file locations:**

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

Restart Claude Desktop. On first tool call, a browser window opens for the Kite OAuth handshake.

### Widget rendering

Claude Desktop renders MCP Apps widgets identically to claude.ai web — the same `ui://kite-mcp/*` resources are inlined (SEP-1865 / MCP Apps). Portfolio widget, options chain, order form, alerts — all work.

### Example conversations

**Example 1 — Paper trade a signal**

> **You:** Enable paper trading with ₹10 lakh virtual cash, then paper-buy 50 RELIANCE at market.

> **Claude:** *(calls `paper_trading_toggle` with `enable=true, initial_cash=1000000`; then `order_risk_report`; elicitation dialog opens)*
>
> Paper mode: ON. Pre-trade check:
> - LTP: ₹2,842.50 | Charges: ₹14.21 | Margin: ₹28,425
> - Order value: ₹1,42,125 (well under ₹5L cap)
>
> *(Elicitation: "Confirm paper buy 50 RELIANCE @ MARKET?" — you click Confirm)*
>
> *(calls `place_order`; Paper Trading middleware intercepts, fills at LTP)*
>
> Filled. New paper position: 50 RELIANCE @ ₹2,842.50. [Paper trading widget shows virtual book.]

**Example 2 — Options payoff on a spread**

> **You:** Build me a NIFTY iron condor: sell 22400 CE and 22600 PE, buy 22700 CE and 22300 PE, April expiry.

> **Claude:** *(calls `options_payoff_builder` with 4 legs)*
>
> [Options payoff widget: payoff curve, breakevens, max profit/loss, Greeks aggregate.]
>
> - Max profit: ₹4,250 between 22400–22600
> - Max loss: ₹5,750 outside 22300 or 22700
> - Net Delta: −0.04, Net Vega: −18.2
> - Breakevens: 22383 / 22617

**Example 3 — Tax loss harvesting**

> **You:** Any tax-loss harvesting opportunities in my holdings before March 31?

> **Claude:** *(calls `tax_loss_analysis`)*
>
> 3 candidates with unrealised losses:
> - INFY: −₹8,200 (long-term, 14 months)
> - HDFCBANK: −₹3,450 (short-term, 4 months)
> - WIPRO: −₹1,200 (short-term, 2 months)
>
> Harvesting HDFCBANK + WIPRO would offset ₹4,650 of short-term gains. INFY is long-term so it offsets LTCG specifically. Not investment advice.

---

## 3. Claude Code (CLI)

### Setup

One-liner:

```bash
claude mcp add --transport http kite-fly https://kite-mcp-server.fly.dev/mcp
```

Then start a Claude Code session and ask Claude to log in with your Kite API key and secret — this triggers the OAuth flow via `mcp-remote`, which opens a browser for Kite's login page and caches the token locally (`~/.mcp-auth/mcp-remote-{version}/`).

### Widget rendering

**Claude Code does NOT render widgets.** The transport is text/JSON-only — `ui://kite-mcp/*` resources are ignored. Every response is the plain text + `structuredContent` JSON that the tool returns. This is a Claude Code limitation, not a server limitation — the same tools on the same endpoint render widgets when called from claude.ai web or Desktop.

### Example conversations

**Example 1 — Portfolio summary (no widget)**

> **You:** What's my current portfolio concentration by sector?

> **Claude:** *(calls `portfolio_analysis` with `sector_exposure=true`)*
>
> Here's your sector breakdown:
>
> | Sector | Value | % |
> |---|---|---|
> | IT Services | ₹3,80,420 | 38.0% |
> | Banking | ₹2,70,100 | 27.0% |
> | FMCG | ₹2,20,500 | 22.0% |
> | Pharma | ₹85,300 | 8.5% |
> | Other | ₹43,680 | 4.5% |
>
> HHI: 0.27 (moderate concentration). IT sector is above the 30% concentration guideline.

Compare this to the same call on claude.ai web — there, you get the sortable/clickable **Portfolio Widget** with a donut chart inline. In Claude Code you get the markdown table only; the underlying tool JSON is identical.

**Example 2 — Volume spike scan**

> **You:** Anything in my watchlist trading at 3x average volume today?

> **Claude:** *(calls `volume_spike_detector` with `multiplier=3.0`)*
>
> 2 spikes detected:
>
> - **TATAMOTORS**: 4.1x avg volume (18.2M vs 4.5M avg), price +2.3%
> - **BAJFINANCE**: 3.2x avg volume (2.8M vs 870K avg), price −1.1%
>
> TATAMOTORS has both volume and price confirmation — likely institutional accumulation. BAJFINANCE is distribution. Want quotes?

**Example 3 — Composite alert (elicitation still works)**

> **You:** Alert me when RELIANCE breaks above 2900 AND volume is above 2x average.

> **Claude:** *(calls `composite_alert` with two conditions)*
>
> *(Elicitation dialog in Claude Code: "Create composite alert on RELIANCE? conditions: price>2900 AND volume>2x avg. [y/N]" — you type `y`)*
>
> Alert created. ID: `alert_7f3c1a`. Both conditions must be true at evaluation time. You'll get a Telegram DM on fire.

Elicitation **does** work in Claude Code — it falls back to a text prompt instead of a rich dialog. Widgets don't, but the interactive order-confirmation flow is intact.

---

## 4. ChatGPT

### Setup

Settings → **Tools & Integrations** → **MCP Servers** → **Add** → paste URL `https://kite-mcp-server.fly.dev/mcp`. Complete OAuth when prompted.

### Caveats (read first)

- ChatGPT's MCP support is **less complete** than Claude's. Tool calls work; the newer spec extensions are hit-or-miss.
- **Elicitation**: uncertain / client-dependent. Order-confirmation dialogs may be skipped — `place_order` is fail-open so it will still execute. If you're placing real orders, prefer Claude.
- **Widgets**: partial. Simple text-based responses render; `ui://kite-mcp/*` MCP Apps resources may not render inline. The server still returns `structuredContent` alongside text, so ChatGPT shows the JSON.

### Example conversations

**Example 1 — Activity audit trail**

> **You:** What did I do on Kite last week through this server? Highlight any errors.

> **ChatGPT:** *(calls `open_dashboard` with `page="activity", days=7, errors=true`)*
>
> Here's your activity link: [Activity Timeline](https://kite-mcp-server.fly.dev/dashboard/activity?days=7&errors=true)
>
> Summary from the last 7 days: 23 orders placed, 2 rejected (insufficient margin on BAJFINANCE x2), 4 alerts fired, 0 tool errors at the transport level.

The dashboard link renders as a plain hyperlink in ChatGPT; in Claude it embeds as the Activity Widget inline.

**Example 2 — Basic quote + risk check**

> **You:** What's RELIANCE trading at, and what would a 100-share buy cost me including charges?

> **ChatGPT:** *(calls `get_quotes` then `order_risk_report`)*
>
> RELIANCE LTP: ₹2,842.50. For a 100-share buy:
> - Order value: ₹2,84,250
> - Estimated charges: ₹28.43 (brokerage, STT, exchange, GST, SEBI, stamp)
> - Required margin (MIS): ₹56,850
> - Total out-of-pocket: ₹56,878.43

---

## Which should I use?

| Surface | Setup friction | Widget support | Elicitation | Mobile |
|---|---|---|---|---|
| claude.ai web | Low | Yes | Yes | Yes (remote MCP) |
| Claude Desktop | Low | Yes | Yes | No |
| Claude Code | Very low | No (text only) | Yes | No |
| ChatGPT | Medium | Partial | Uncertain | Yes |

**Rules of thumb:**

- **Building / scripting / agentic workflows** → Claude Code. The CLI is fast and composable; loss of widgets doesn't matter when you're consuming JSON.
- **Daily trading / monitoring / mobile access** → claude.ai web. Widgets shine here; mobile access via the claude.ai mobile app gives you remote-MCP on the go.
- **Desktop power user** → Claude Desktop. Same widget experience as web, with filesystem / local tools alongside.
- **Already living in ChatGPT** → ChatGPT works for basic queries; switch to Claude for order placement and multi-leg workflows where elicitation matters.

## Shared auth flow

All four surfaces authenticate via the **same OAuth 2.1 + PKCE flow** backed by `kite-mcp-server`:

1. Client sends initial MCP request.
2. Server returns `401` with `WWW-Authenticate: Bearer resource_metadata="..."`.
3. Client (or `mcp-remote`) discovers OAuth metadata, performs dynamic client registration (RFC 7591), and redirects the user to Kite login.
4. Kite redirects back to `https://kite-mcp-server.fly.dev/callback` with an authorization code.
5. Server exchanges code for a Kite access token and issues its own MCP bearer JWT (24h expiry).
6. Subsequent MCP calls include the bearer JWT; the server looks up the per-user Kite token from the encrypted token store.

The **dashboard cookie short-circuit** only applies to web contexts — if you have a 7-day dashboard session cookie at `https://kite-mcp-server.fly.dev/dashboard`, `/oauth/authorize` skips the second Kite login. Claude Desktop / Claude Code / ChatGPT don't share cookies with the dashboard, so they always complete the full flow on first connect (and a daily Kite token refresh at ~6 AM IST).

For deeper protocol detail see [`docs/callback-deep-dive-13-levels.md`](callback-deep-dive-13-levels.md).
