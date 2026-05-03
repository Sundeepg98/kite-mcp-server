# Uninstall + Data Deletion Runbook

This page covers two scenarios:

1. **Stop using kite-mcp-server but keep your data** — for testing or
   temporary disconnect.
2. **Permanently delete all your data** — for full DPDP-compliant removal
   of every byte we hold for your email.

If you're self-hosting (running your own copy locally), you control the
filesystem and database directly; the deletion endpoint below is for the
hosted instance at `https://kite-mcp-server.fly.dev/`. Self-host users
who want to wipe local state can simply delete the SQLite database file
named in `ALERT_DB_PATH` (default `/data/alerts.db`).

---

## Scenario 1 — Stop using the server (keep your data)

If you just want to disconnect kite-mcp-server from your AI client without
deleting any stored data:

### Claude Desktop

1. Open `~/Library/Application Support/Claude/claude_desktop_config.json`
   (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
2. Find the entry for `kite-mcp-server` (or whatever name you configured)
   inside `mcpServers`.
3. Remove the entry.
4. Restart Claude Desktop.

### Claude Code (CLI)

```bash
claude mcp remove kite
```

### Any MCP client

Remove the `https://kite-mcp-server.fly.dev/mcp` URL from the client's
MCP server list.

After this step, the AI client no longer talks to the server, but your
stored data (cached credentials, alerts, watchlists, audit logs) remains
on the server until you complete Scenario 2.

---

## Scenario 2 — Permanently delete all your data (DPDP-compliant)

Every byte we hold keyed to your OAuth-verified email gets purged. This
is a one-shot, irreversible action.

### What gets deleted

The `DELETE /dashboard/api/account/delete` endpoint dispatches a
`DeleteMyAccountCommand` through the CQRS bus, which:

| Surface | Action |
|---------|--------|
| **Kite credentials** (encrypted API key + secret) | Hard delete from `kite_credentials` table; in-memory cache cleared. |
| **Kite tokens** (encrypted access tokens) | Hard delete from `kite_tokens` table; in-memory cache cleared. |
| **Active alerts** | All your alerts removed from `alerts` table; ticker subscriptions unwound. |
| **Watchlists** | All your watchlists removed from `watchlists` table. |
| **Trailing stops** | All your trailing stops cancelled and removed. |
| **Paper-trading state** | Reset to defaults; mode disabled. Virtual portfolio + virtual orders purged. |
| **MCP sessions** | All active sessions for your email terminated; `sessions` table rows removed. |
| **OAuth client registrations** | Removed from `oauth_clients` table — your client_id / client_secret combos go away. |
| **User row** | `users.status` set to `offboarded`; row retained as a tombstone for the audit trail (see *Audit retention* below). |
| **Active dashboard JWT cookie** | Cleared by the response (`Set-Cookie: kite_jwt=; Max-Age=-1`). |

### Audit retention

The `tool_calls` audit log (every MCP tool invocation, with PII-redacted
arguments) is **retained for 90 days** for incident response and
regulatory compliance, then auto-purged by the retention worker. After
account deletion, your row in `users` carries `status = 'offboarded'`
solely so that audit-log entries reference a known prior identity rather
than dangling. No live data, no credentials.

If you need pre-90-day audit purge for a specific compliance reason
(e.g. court order), contact `sundeepg8@gmail.com` and we'll process the
request manually.

### How to call it

**Via the dashboard UI:** sign in to `https://kite-mcp-server.fly.dev/dashboard`,
navigate to the account section, click **Delete Account**, and confirm.

**Via curl** (you must already be authenticated; the endpoint reads your
session cookie):

```bash
curl -X POST https://kite-mcp-server.fly.dev/dashboard/api/account/delete \
  -H "Content-Type: application/json" \
  -H "Cookie: kite_jwt=<your-dashboard-cookie>" \
  -d '{"confirm": true}'
```

Without `{"confirm": true}` in the body, the server returns 400
`confirmation_required` so you can't accidentally trigger deletion via a
bare POST.

Successful response:

```json
{"status": "ok", "message": "Account deleted. All data has been removed."}
```

The response also clears your `kite_jwt` cookie, so the next dashboard
visit will be unauthenticated.

### Verifying the deletion

After the DELETE call returns 200:

1. Visit `/dashboard` — you should be redirected to the login page.
2. Try a tools/list MCP call from your AI client — it should fail with
   `not_authenticated` because the session is gone.
3. If you re-authenticate later, you'll start fresh: no stored
   credentials, no alerts, no watchlists. Even your OAuth client
   registration is gone, so the next sign-in will dynamically register
   a new one.

---

## After deletion: revoke Kite developer-app access

The kite-mcp-server's deletion only purges OUR copy of your credentials
(API key + secret) and access tokens. Your **Kite developer app itself**
still exists in your Zerodha developer console — that app's API key is
public information; revoking access on our side does not invalidate it
upstream.

To fully sever the link:

1. Visit https://developers.kite.trade/apps
2. Find the app you registered for kite-mcp-server.
3. Either:
   - **Regenerate the API secret** — invalidates any cached tokens
     anywhere (a partial replay-defense).
   - **Delete the app** — fully removes it.

This step is optional but recommended if the reason for deletion is a
suspected credential compromise.

---

## Self-host: full local wipe

If you self-host (running your own kite-mcp-server with `ENABLE_TRADING=
true`), data deletion is local filesystem cleanup:

```bash
# Stop the server first.
# Then delete the alert/credential/audit DB:
rm $ALERT_DB_PATH                # default: /data/alerts.db
rm $ALERT_DB_PATH-wal            # SQLite WAL
rm $ALERT_DB_PATH-shm            # SQLite shared-memory
# If using Litestream replication, also delete the R2 bucket contents:
litestream destroy <replica-url> # see etc/litestream.yml
```

The next server start will recreate empty schemas. No further action
required.

---

## Re-onboarding after deletion

If you delete and then want to use the server again later:

1. Sign in to `/dashboard` again — OAuth flow registers a new client.
2. In the dashboard, paste your Kite developer app's API key + secret
   into the credentials form.
3. Talk to your AI: `Log me in to Kite` — the LLM uses the `login`
   MCP tool to drive the Kite OAuth dance, and you're back online.

There is no "restore" — deleted data is gone. Re-onboarding starts you
from a clean slate.

---

## Questions?

- **Privacy policy:** `/privacy` on the deployed server, or
  [`docs/PRIVACY.md`](PRIVACY.md) in the repo.
- **Issue tracker:** https://github.com/Sundeepg98/kite-mcp-server/issues
- **Email:** `sundeepg8@gmail.com`
