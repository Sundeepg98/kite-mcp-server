---
title: OAuth Flow
description: How Kite MCP authentication works
---

# OAuth Flow

Kite MCP uses OAuth 2.1 with PKCE to securely connect to your Zerodha account without ever storing your credentials.

## How It Works

```
┌─────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  MCP Client │────▶│ Kite MCP Server │────▶│ KiteConnect     │
│  (Claude,   │     │                 │     │ OAuth           │
│   Cursor)   │◀────│  Issues JWT     │◀────│                 │
└─────────────┘     │  Access Token   │     └─────────────────┘
                    └─────────────────┘
```

### Step-by-Step

1. **You ask your AI to access Kite data**
   - e.g., "Show me my portfolio"

2. **MCP client requests authorization**
   - Kite MCP server generates a login URL with PKCE challenge

3. **You click the login link**
   - Browser opens Zerodha's login page
   - You enter your Kite credentials (on Zerodha's site, not ours)

4. **Zerodha redirects back**
   - After successful login, Zerodha sends an authorization code

5. **Kite MCP exchanges the code**
   - Server exchanges code for Kite access token
   - Issues its own JWT token to the MCP client

6. **You're connected!**
   - All subsequent requests use the JWT token
   - Session lasts approximately 6 hours

## Security Features

### PKCE (Proof Key for Code Exchange)

PKCE prevents authorization code interception attacks:
- Client generates a random `code_verifier`
- Server validates the verifier during token exchange
- Even if someone intercepts the auth code, they can't use it

### JWT Tokens

- Short-lived (6 hours, matching Kite session)
- Contains only session ID (no credentials)
- Validated on every request

### No Credential Storage

- Your Kite username/password are never sent to Kite MCP
- We only receive a temporary access token from Zerodha
- Token is tied to your session, not stored permanently

## Dynamic Client Registration (RFC 7591)

For tools like `mcp-remote` that need to register dynamically:

```
POST /register
Content-Type: application/json

{
  "client_name": "my-mcp-client",
  "redirect_uris": ["http://localhost:3000/callback"]
}
```

Response:
```json
{
  "client_id": "auto-generated-id",
  "client_name": "my-mcp-client",
  "redirect_uris": ["http://localhost:3000/callback"]
}
```

## OAuth Endpoints

| Endpoint | Description |
|----------|-------------|
| `/.well-known/oauth-authorization-server` | OAuth server metadata (RFC 8414) |
| `/.well-known/oauth-protected-resource` | Protected resource metadata |
| `/authorize` | Start OAuth flow |
| `/token` | Exchange code for token |
| `/callback` | Receive Kite authorization code |
| `/register` | Dynamic client registration |

## Revoking Access

To revoke Kite MCP's access to your account:

1. Go to [kite.zerodha.com](https://kite.zerodha.com)
2. Navigate to Settings → Apps
3. Find "kitemcp" and revoke access

Your session will immediately become invalid.
