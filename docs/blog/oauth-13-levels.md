# How Kite Connect OAuth actually works (13 layers deep)

I built an MCP server for Zerodha Kite. OAuth seemed simple — user clicks "login", browser redirects, we get a token. Then I tried to make it work with Claude Code over `mcp-remote`, with per-user developer credentials, with tokens that expire at 6 AM IST every day, with a server that restarts on every deploy. It took 13 levels of investigation to understand why a callback URL is either perfect or a disaster. What follows is the condensed version of a 237KB internal deep-dive, cut down to the parts that generalise.

The server is open source at [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server). All code references below point into the real tree.

---

## The 13 levels

### Level 1 — HTTP layer: GET is not an opinion

The OAuth authorization response comes back as a browser-driven `GET` with a query string. This matters for two reasons. First, the authorization `code` ends up in browser history, server access logs, and any upstream proxy. Second, you cannot put the client secret here — `GET` bodies are not a thing, and a secret in a query string is a logged secret. The token endpoint, by contrast, is a `POST` with `application/x-www-form-urlencoded`. Treat the two endpoints as semantically different: the `/authorize` endpoint is a trust handshake visible to everyone in the redirect chain; the `/token` endpoint is a back-channel conversation.

### Level 2 — State parameter: CSRF defence, but also session glue

Textbooks treat `state` as a CSRF nonce. In practice it is also the only piece of context you can carry through the user's browser and back to yourself. In our server, the `/authorize` handler packs `{client_id, redirect_uri, code_challenge, state}` into a short JSON blob, base64url-encodes it, HMAC-SHA256 signs it with `OAUTH_JWT_SECRET`, and smuggles it through Kite's `redirect_params` query parameter. Kite has no concept of OAuth; `redirect_params` is a pass-through mechanism that the server co-opts to reconstruct OAuth state after the Kite login page strips everything else. Signed state is both CSRF defence and the substrate on which the whole flow depends.

### Level 3 — PKCE: why the code verifier exists

PKCE (RFC 7636) solves one specific problem: what if someone intercepts the authorization `code` between the browser and the OAuth client? Public clients — CLI tools, native apps, anything that cannot safely hold a `client_secret` — need a bearer-style proof that the entity redeeming the code is the same entity that started the flow. The client generates a 43-character random `code_verifier`, sends `SHA-256(verifier)` as the `code_challenge`, and reveals the `verifier` only at the token exchange. The server stores the challenge, verifies `SHA-256(submitted_verifier) == stored_challenge`, and rejects mismatches. S256 only — `plain` is a trap. Without PKCE, a malicious process on the same loopback interface can steal the code and redeem it.

### Level 4 — Client authentication: shared secret vs dynamic registration

There are three ways a client proves it is the same entity that registered:

1. **Shared secret** — you gave them a `client_secret` out of band; they send it at token exchange.
2. **PKCE only** — public client, no secret, rely on `code_verifier`.
3. **Dynamic Client Registration (RFC 7591)** — the client POSTs to `/register` and gets a fresh `client_id` and `client_secret` minted on the fly.

Our server supports all three. Dynamic registration matters for MCP because `mcp-remote` cannot ship a pre-shared secret — every user gets their own. The catch: dynamically-registered clients are stored in memory on our server, so a deploy wipes them and `mcp-remote` must re-register. This is normal and the client handles it, but it is the source of the `invalid_client` error during the 60-second window while the new instance boots. Plan for this.

### Level 5 — Scope and consent: what the user actually agreed to

Kite does not expose granular scopes the way Google or GitHub do — a Kite session is an all-or-nothing grant that lets your app place orders, read holdings, and cancel GTTs on the user's behalf. This pushes the scope problem up a layer into your own server. On `kite-mcp-server` we encode scope in the issued JWT's `aud` claim (the Kite API key the client was authorized against) and enforce it per-tool via middleware. If a user authorized client A, client B cannot reuse their Kite session through a different JWT. Absence of broker-side scopes means you, the MCP author, are the enforcement boundary.

### Level 6 — Redirect URI registration and validation

The redirect URI is registered twice and validated three times. Kite's developer portal holds the permanent server-side URI (`https://kite-mcp-server.fly.dev/callback`). The `mcp-remote` client registers its own loopback URI (`http://localhost:<port>/callback`) at runtime. On each authorize request the server validates three things: the scheme is `http` or `https` (blocks `javascript:`, `data:`, `ftp:`), the URI parses as a valid URL, and — most importantly — the exact-match string reappears unchanged at token exchange. The redirect URI that enters the flow must equal the redirect URI that leaves. This is where open-redirect vulnerabilities live; substring matching or wildcard subdomains have been CVE-generators for a decade.

### Level 7 — Token exchange: what happens in the 200ms after callback

When the browser hits `/callback?request_token=xxx&data=<signed_blob>`, this sequence runs:

```go
// handlers.go — condensed
1. hmac.Equal(computed, submitted) || reject    // tamper check
2. timestamp < now - 35min       || reject      // replay window
3. json.Unmarshal(blob, &oauthState)            // unpack {c, r, k, s}
4. code := randomHex(32)                         // 256-bit auth code
5. codeStore.Put(code, {challenge, requestToken, redirectURI})
6. http.Redirect(w, r, redirectURI + "?code=..." + "&state=...")
```

The server does NOT exchange the Kite `request_token` for an access token here. That happens at `/oauth/token`, after PKCE verification. We call this the "deferred exchange" pattern — it lets the server look up the per-user Kite API secret from the encrypted credential store at token time, when the client is POSTing back with its identity proven.

### Level 8 — Encryption at rest for access_token

Once a Kite access token and API secret land in our database, they are encrypted with AES-256-GCM. The key is derived via HKDF-SHA256 from `OAUTH_JWT_SECRET` with a domain-separation label:

```go
// crypto.go
hkdfReader := hkdf.New(sha256.New, []byte(secret), nil,
    []byte("kite-mcp-credential-encryption-v1"))
key := make([]byte, 32)
io.ReadFull(hkdfReader, key)
```

The label matters. The same `OAUTH_JWT_SECRET` signs JWTs, signs the HMAC-packed `redirect_params` state, and — via HKDF — derives this encryption key. HKDF's `info` parameter gives each use a cryptographically-independent key, so a break in one subsystem does not propagate. Nonces are 12 random bytes per record; at our realistic scale (< 300 encryptions per key lifetime) the birthday-bound collision probability is around 10^-25.

### Level 9 — Token expiry and refresh

Three independent clocks govern session life:

- **Kite access token**: expires daily at 6 AM IST. No refresh token. The user must log in again.
- **MCP bearer JWT**: 24 hours, signed by `OAUTH_JWT_SECRET`.
- **Dashboard JWT cookie**: 7 days (because browser UX punishes short sessions).

The first constraint is brutal: Kite invalidates every access token at 6 AM IST regardless of issue time, and there is no refresh endpoint. Our middleware detects this by wallclock check plus broker-call probe, returns 401 to trigger `mcp-remote`'s re-auth flow, and the user goes through Kite login again. We initially tried to hide this with opportunistic re-auth; in practice surfacing the 401 is more honest and the `mcp-remote` retry loop handles it cleanly.

### Level 10 — Per-user OAuth vs shared OAuth

The aggregator model says: "I hold one OAuth app, users authenticate me, I call Kite on their behalf." It is easier to build. It also puts you in the regulatory blast radius: SEBI's April 2026 static-IP mandate, per-user rate limits, KYC questions, whether you are a trading-advisor under a different rule. We chose BYO (bring-your-own) Kite developer app instead. Users register their own Kite app, supply their own `API_KEY` / `API_SECRET`, and our server merely orchestrates the OAuth dance. The `client_id` in the OAuth flow IS the user's Kite API key. The economic model collapses (we sell the software, not the brokerage integration), the compliance surface shrinks, and bugs become tenants-of-one.

### Level 11 — MCP-specific OAuth: mcp-remote's dynamic client registration

`mcp-remote` is the shim that turns any MCP server into something Claude Code, Desktop, and Cowork can talk to over HTTP with OAuth. It implements RFC 7591 dynamic registration: on first connect it discovers `/.well-known/oauth-authorization-server`, POSTs to `/register`, caches the returned `client_info.json` in `~/.mcp-auth/mcp-remote-<version>/<url-hash>/`, and computes a deterministic callback port from the server URL hash. When our server restarts, the cached `client_id` is no longer valid; `mcp-remote` catches the 401, re-registers, and retries. For our self-hosted server we use `--static-oauth-client-info` pointing at a JSON file, because dynamic registration + Windows `cmd /c` JSON escaping is a footgun: `\"` silently disappears inside `cmd /c` invocations, so we write the client info to disk and reference it by path.

### Level 12 — Failure modes: what happens when each level fails

Across 5 hops we mapped 27 distinct failure points. The ones that bit us hardest:

- **C3 — HMAC signature invalid**: happens if the server restarts and `OAUTH_JWT_SECRET` is not persistent. Every in-flight login breaks.
- **C4 — HMAC timestamp expired**: 30min + 5min skew. Users fumbling an OTP for 35 minutes land here. Recovery is "restart the flow" and we say so on the error page.
- **D2 — localhost port conflict**: the browser redirects to `localhost:3334/callback` and another process picks it up. The auth code leaks. PKCE protects against redemption, but the code is still visible to a hostile process on the same machine.
- **E4 — Client not found**: server restarted between `/authorize` and `/token`. In-memory client store lost. We persist clients to SQLite now; this turned a 3%-per-deploy failure into zero.

Every level has a failure mode. Plan for each one explicitly and write the error text so a human can recover without reading logs.

### Level 13 — The confused deputy problem

The "confused deputy" is the classic OAuth pitfall: the OAuth server happily redirects the user's authorization to wherever the client asked, and a malicious client tricks the server into sending the credentials somewhere the user did not intend. Three defences stack to prevent it in our flow:

1. **Exact-match redirect URI validation** at both `/authorize` and `/token`. Pre-registered or RFC 7591-registered, but never fuzzy.
2. **PKCE binding**: even if a code leaks, the verifier is held only by the legitimate client.
3. **Signed-state round-trip**: the `client_id` and `redirect_uri` are signed by our server at `/authorize` and verified at `/callback`. A client cannot swap them out mid-flow without invalidating the HMAC.

Remove any one of these and you have a redirect-stealing bug. All three are small code; all three are load-bearing.

---

## What this means for `kite-mcp-server`

**Architecture: per-user BYO Kite app.** Each user registers their own Kite developer app and brings their own `oauth_client_id` (API key) and `oauth_client_secret` (API secret). We never hold credentials that let us trade on the user's behalf without their developer app; the user revokes the app and we're out of the loop entirely. Global `KITE_API_KEY`/`KITE_API_SECRET` environment variables are optional; on the Fly.io deployment they are unset, so the server is purely a per-user OAuth broker.

**Encryption at rest.** AES-256-GCM for the `kite_credentials`, `kite_tokens`, and `clients` tables (the `client_secret` column). Key is derived per-purpose via HKDF-SHA256 from `OAUTH_JWT_SECRET`, so a leak of one ciphertext class does not compromise another. Plaintext fallback on decrypt is explicit: if a stored value is not valid hex, it is treated as pre-encryption legacy data (migration-safe); if it is hex but fails the GCM tag check, we return an empty string rather than leak ciphertext.

**HKDF domain separation.** The same `OAUTH_JWT_SECRET` feeds JWT signing, HMAC on `redirect_params` state, and the HKDF-derived AES key for credentials at rest. The `info` label (`"kite-mcp-credential-encryption-v1"`) enforces cryptographic independence. A break in one subsystem does not cascade. The JWT and HMAC paths do not go through HKDF today — they rely on message-format incompatibility for separation, which works but is load-bearing accidental; a v2 would route both through HKDF too.

**Audit trail.** Every MCP tool call is logged to SQLite with per-user scoping, PII redaction, and 90-day retention. The audit middleware sits between rate limiting and tool execution. A user can export their own activity as CSV or JSON from the dashboard. We log the decision, not the full payload — enough to investigate, not enough to leak PAN numbers.

**Why we chose this over the aggregator model.** In the aggregator pattern (our server holds one Kite app; users authenticate us), we inherit Kite's per-app rate limits across all users, the SEBI April 2026 static-IP mandate falls on our single egress IP (209.71.68.157 on Fly.io), and we become a custodian of trading access. In the per-user model we are a software author, not a broker intermediary. Users pay Kite ₹500/month per app; we get none of that; we charge (or don't) for the software itself. Regulatory risk shifts to where it already lives — between the user and Zerodha — and we stay a tool.

**One real-world trade-off**: the BYO model costs users ~15 minutes of setup (register Kite app, whitelist the Fly.io static IP, copy API key and secret into the OAuth flow). Aggregators can onboard in 30 seconds. We decided the long-term story — users own their credentials, revocable in one click at developers.kite.trade, no lock-in — was worth the friction.

---

## Takeaways for other MCP developers

**Don't skip PKCE.** `code_challenge_method=S256` adds four lines of client code and closes the single biggest class of OAuth bugs for public clients. `mcp-remote` does this by default; if you are writing a custom MCP client, add it.

**Validate redirect URI strictly.** Exact string match at both `/authorize` and `/token`. No wildcards. No substring. No "starts with." Every time someone has relaxed this, they shipped a CVE. Block `javascript:`, `data:`, `ftp:` schemes explicitly — a permissive scheme check plus open redirect gives you XSS on your own origin.

**Use short-lived JWT for the MCP session, long-lived encrypted access_token for the broker.** The MCP JWT is the thing every tool call validates; making it 24h keeps the hot path cheap (no DB hit on every request). The broker access_token is the thing you actually protect — encrypt it at rest with a key you never log. Never conflate the two; never put the broker token in the JWT payload.

**Store state in a signed blob, not in a server-side session.** Carrying the OAuth state through the user's browser via signed `redirect_params` means a deploy or a pod restart does not invalidate in-flight logins. The HMAC is the integrity boundary. Server-side state is attractive until you run more than one replica; then the signed-blob approach wins on every axis.

**Test the failure path.** Not just "wrong password." Test: server restarts between `/authorize` and `/token`, HMAC secret rotation, 35-minute login, `localhost` port collision, expired `request_token`, Kite API returning 503, `mcp-remote` cache corruption. We have 27 distinct failure modes catalogued; every one of them shipped as a real user bug report before it got a test.

---

## Call to action

The server is open source and free:

- Code: [`github.com/Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
- Fork, break, submit issues. The per-user OAuth layer is the most reviewed part of the code (181 findings in the February 2026 security audit, all resolved); fresh eyes are welcome.
- Specifications referenced: [OAuth 2.1 draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/), [RFC 7636 (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636), [RFC 7591 (Dynamic Client Registration)](https://datatracker.ietf.org/doc/html/rfc7591), [MCP specification](https://modelcontextprotocol.io/specification).

If you are building an MCP server that talks to a third-party OAuth provider, the architectural choices above generalise. If you just want to trade through Claude, point `mcp-remote` at `https://kite-mcp-server.fly.dev/mcp` and go.

Follow [@Sundeepg98](https://github.com/Sundeepg98) for more technical deep-dives on the boring, load-bearing parts of real systems.
