# Kite Access Token Refresh (Daily, ~6 AM IST)

Zerodha Kite Connect issues access tokens that expire every day around
06:00 IST. This is a fundamental constraint of the API — any tool built
on Kite Connect must handle it. Our server turns this into a ~10-second
one-click re-auth the first time you use it each trading day.

For operator day-2 steps see
[operator-playbook.md § 3](operator-playbook.md). For the wider incident
path see [incident-response.md](incident-response.md).

## What happens

1. At ~06:00 IST, all `access_token` values issued by Zerodha become
   invalid. Zerodha treats this as a daily session cut-off, not a
   refreshable token.
2. The next call to a Kite API endpoint returns `403 Forbidden` with
   `token_expired` (Kite Connect v3 semantics).
3. The user must re-authenticate via the Kite OAuth flow to mint a
   fresh token. There is no refresh-token path exposed to third-party
   apps.

The refresh window our landing page advertises is `~7:35 AM IST` —
the point by which most users have finished the morning login. The
invalidation happens earlier at 06:00 IST; users just don't notice
until they touch a Kite tool.

## Our server's handling (auto re-auth)

- **Middleware:** `RequireAuth` detects the 401/403 from Kite on the
  next authenticated call and returns 401 to mcp-remote. Gated behind
  the check in `kc/expiry.go` so we don't re-auth prematurely.
- **Client:** mcp-remote sees 401, automatically triggers its OAuth
  re-auth flow.
- **User:** sees a "please log in to Kite" browser tab
  (`kite.zerodha.com`) and clicks through. No fresh developer-app
  registration needed — their API key/secret are still cached
  server-side.
- **Result:** fresh `access_token`, persisted per-user
  (AES-256-GCM encrypted in `KiteTokenStore`).

Users don't need to do anything proactive — they just hit a brief
"log in again" the first time they use the server after ~06:00 IST.

## Smart expiry detection

The `kc/kiteconnect/` and `kc/expiry.go` layer checks the current time
against the Indian Market Calendar:

- If now is between 06:00–06:30 IST → token is almost certainly
  invalid; the middleware challenges re-auth eagerly rather than
  letting a user waste a tool call to discover the error.
- If now is between 09:15–15:30 IST → market open, fast-path auth
  check on every call (no extra expiry heuristics).
- Outside market hours → rely on the cached token until Kite itself
  rejects it.

This avoids both extremes: blasting Kite with known-dead tokens, and
forcing a re-auth on a user who's just checking holdings after hours
on a still-valid token.

## What breaks if re-auth fails

| Failure | User-visible symptom |
|---|---|
| User dismisses the OAuth tab | Kite tools return `authentication_required` error; dashboard shows session-expired banner |
| Network blocks `kite.zerodha.com` | All Kite calls fail; local-only tools (paper trading, backtests, alert store reads) still work |
| User's Kite Connect app deleted | `api_key` invalid; user must re-register their developer app and run `login` again |
| Zerodha incident | Global outage; no recovery path — wait for Zerodha |

## Operator response

### Multiple users reporting re-auth failures simultaneously

1. Check the Kite status page (`https://kite.zerodha.com/status` or
   `https://status.zerodha.com/`).
2. Check Twitter `@zerodhaonline` for outage announcements.
3. Check our Fly.io egress (`209.71.68.157`) isn't banned — the static
   egress IP is whitelisted per-user in Kite developer console; a
   Zerodha-side block there would manifest as a simultaneous outage
   for every user on our instance.
4. Hit `/healthz?format=json` and read `components.kite_connectivity`
   (see `operator-playbook.md § 1`).

### Single user reports

1. Confirm they're running a current mcp-remote version. Older
   versions (pre-0.1.x) don't handle 401 challenge-response cleanly —
   they fail the call instead of re-auth.
2. Ask them to clear their mcp-remote cache
   (`~/.mcp-auth/mcp-remote-*/`) and re-auth fresh.
3. Verify their Kite Connect app still has a valid `api_key` in the
   kite.trade console — they may have deleted or regenerated it.
4. As a last resort: ask them to call `login` again from their MCP
   client to re-register their API credentials.

## User-facing FAQ

**Q: Why do I have to log in every morning?**
A: Zerodha's API design. Access tokens expire at 06:00 IST daily. All
Kite tools — including the official `mcp.kite.trade` endpoint and
every third-party dashboard — behave the same way.

**Q: Can I automate this?**
A: No. Zerodha requires interactive OAuth consent each time; no
refresh tokens are exposed to third parties. You must click through
the Kite login once per trading day.

**Q: What if I forget to re-auth?**
A: Nothing breaks silently. The next Kite API call returns an error
asking you to re-authenticate. Morning Telegram briefings still send
status/alerts from cached data, but order-sensitive content is
skipped until you log in.

**Q: Do I need to do anything special at 6 AM?**
A: No. Just log in normally the first time you use the server after
06:00 IST. If you never use it before 09:00 IST, the morning briefing
still sends from last-known state, just without fresh quotes.

**Q: Does paper trading need re-auth?**
A: Paper trading reads live quotes for fills, so yes — the broker
layer still needs a valid Kite token. But paper-trading state itself
survives the refresh; your virtual portfolio is untouched.

## Related

- [Operator playbook § 3](operator-playbook.md) — daily ops checklist
- [Incident response](operator-playbook.md#6-incident-response) —
  if token expiry ever becomes a regulatory issue (hash-chain audit
  trail survives re-auth)
- [env-vars.md](env-vars.md) — `KITE_ACCESS_TOKEN` env var (local-dev
  bypass only; production always uses per-user OAuth)
- Zerodha forum: `https://kite.trade/forum/` (community discussion
  of token-expiry patterns)
