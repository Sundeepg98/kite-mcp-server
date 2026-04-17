// SEBI classification-drift protection (April 2026).
//
// Telegram is a 1:1 private-chat surface and the user initiates every
// interaction — we do not broadcast, push unsolicited tips, or make
// recommendations. Per Agent 58's classification audit the surface is
// low risk under the SEBI Investment Adviser / Research Analyst regs,
// but we apply belt-and-braces protection: every outbound *financial*
// message (prices, P&L, alerts, order confirmations, errors) carries
// an explicit "Not investment advice" prefix, and the user can run
// /disclaimer at any time for the full classification statement.
//
// Help/start/disclaimer meta-commands themselves are NOT prefixed —
// prefixing a help screen with "not investment advice" adds noise
// without legal value.

package telegram

// DisclaimerPrefix is the short banner prepended to every financial
// outbound Telegram message. Keep it short (one visible line) so it
// doesn't dominate the chat surface, but unambiguous.
const DisclaimerPrefix = "\u26A0\uFE0F <i>Not investment advice. Kite MCP is a tool, not an advisor.</i>\n\n"

// DisclaimerFullText is returned by the /disclaimer command. Mirrors
// the classification-statement excerpt from TERMS.md §3 so users
// always see the same wording whether they read the website or the
// bot.
const DisclaimerFullText = `<b>Kite MCP — Classification Statement</b>

Kite MCP is a software tool. It is <b>not</b>:
  \u2022 A SEBI-registered Investment Adviser
  \u2022 A SEBI-registered Research Analyst
  \u2022 A stock broker

We provide <b>no advice, recommendations, or performance claims</b>.
All trades are user-initiated through your own Zerodha account via
the Kite Connect API. The user retains full control and full
responsibility for every order placed.

Market data, P&amp;L figures, and alert notifications are informational
outputs of the software — they are not a solicitation to trade.

See the full Terms of Service at
<a href="https://kite-mcp-server.fly.dev/terms">kite-mcp-server.fly.dev/terms</a>.`

// withDisclaimer prepends the short disclaimer banner to a message
// body. Use this helper wherever a financial message is built; the
// returned string is safe to pass to sendHTML / sendHTMLWithKeyboard
// without further escaping (the banner is a constant, not derived
// from user input).
func withDisclaimer(body string) string {
	return DisclaimerPrefix + body
}
