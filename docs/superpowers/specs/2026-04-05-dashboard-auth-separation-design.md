# Dashboard Auth Separation — Google SSO for All Users

## Goal
Separate dashboard authentication from MCP trading authentication. Users sign in with Google SSO to access the dashboard (monitoring). Kite OAuth is only needed when they want live portfolio data or MCP trading.

## Architecture

Three separate auth flows with three JWT audiences:

| Flow | Who | How | JWT Audience | Session Lifetime |
|------|-----|-----|-------------|-----------------|
| Dashboard (monitoring) | All users | Google SSO | `dashboard` | 7 days |
| MCP (trading) | Traders with Kite | Kite OAuth | `mcp` | 4 hours (6 AM expiry) |
| Admin (operations) | Admins only | Google SSO + password | `admin` | 8 hours |

## User Journey

### First Visit
1. User visits `/dashboard` → redirected to `/auth/login`
2. Login page shows "Sign in with Google" (primary) + "Sign in with Kite" (secondary)
3. Google SSO → auto-creates user record (role=trader) → 7-day JWT cookie → `/dashboard`
4. Dashboard loads with local data: Activity, Alerts, Paper Trading, Safety
5. Portfolio page shows "Connect your Kite account" card with button

### Connecting Kite (optional)
6. User clicks "Connect Kite" → Kite OAuth flow via `/auth/browser-login`
7. On success, Kite credentials stored in CredentialStore keyed by email
8. Portfolio page shows live holdings, market indices, sector exposure

### Next Day (after 6 AM IST)
- Dashboard still works (7-day JWT, reads local SQLite)
- Portfolio live data shows "Kite session expired — Refresh" button
- MCP tools auto-trigger Kite re-auth via mcp-remote (unchanged)

## Changes

### 1. Google SSO — Open to All Users
File: `oauth/google_sso.go`

Current: `HandleGoogleCallback` checks `role == admin`, rejects non-admins.
New: Accept all authenticated Google users. Call `EnsureUser(email, "trader")` if no existing record.

Redirect after login:
- role=admin → `/admin/ops`
- role=trader/viewer → `/dashboard`

### 2. Login Page Redesign
File: `kc/templates/login_choice.html`

New layout:
- "Sign in with Google" — primary, large button (always shown)
- "Sign in with Kite" — secondary, smaller link (always shown)
- NO admin password option (admin login is at `/auth/admin-login`)
- NO Google SSO conditional on `?admin=1` (Google SSO is now for everyone)

### 3. Dashboard JWT Lifetime
File: `oauth/middleware.go` or `oauth/handlers.go` (wherever cookie MaxAge is set)

Change dashboard JWT cookie from 4 hours (`MaxAge: 14400`) to 7 days (`MaxAge: 604800`).
MCP JWT stays at 4 hours.

### 4. RequireAuthBrowser Redirect
File: `oauth/middleware.go`

Already fixed: redirects to `/auth/browser-login`. Change to redirect to `/auth/login` (the new Google-primary page) instead, since Google SSO is now the primary login.

### 5. Portfolio "Connect Kite" Pattern
File: `kc/templates/dashboard.html`

Three states for Portfolio:
- **No Kite credentials**: Show card "Connect your Kite account to see live holdings" with "Connect Kite" button linking to `/auth/browser-login?redirect=/dashboard`
- **Credentials exist, token expired**: Show banner "Kite session expired" with "Refresh" button
- **Valid token**: Show live holdings, positions, market indices (current behavior)

The auth banner already handles expired tokens. Extend it to handle "no credentials" state.

### 6. User Store Changes
File: `kc/users/store.go`

`EnsureUser(email, role)` already exists. Google SSO callback calls it with role=trader. No schema change needed — the users table already supports trader/viewer/admin roles.

### 7. Admin Flow — Unchanged
- `/admin/ops` → `adminAuth` middleware → `/auth/admin-login`
- Admin login page: password + Google SSO (admin-only check remains here)
- Admin Google SSO: still checks role=admin in a SEPARATE handler path

Implementation note: The Google SSO callback needs to differentiate between admin and user login. Use a `?flow=admin` or `?flow=dashboard` parameter on the Google login URL to determine which check to apply.

## Security Model

| Data | Auth Required | Risk Level |
|------|--------------|------------|
| Activity trail | Dashboard JWT (Google SSO) | Low — read-only, own data |
| Alerts list | Dashboard JWT | Low — read-only |
| Paper trading | Dashboard JWT | Low — virtual money |
| Safety/RiskGuard status | Dashboard JWT | Low — read-only |
| Billing status | Dashboard JWT | Low — read-only |
| Live holdings/positions | Dashboard JWT + valid Kite token | Medium — real portfolio |
| Place/modify/cancel orders | MCP JWT + valid Kite token | High — real money |
| Delete account | Dashboard JWT + step-up re-auth | High — destructive |
| Manage credentials | Dashboard JWT + step-up re-auth | High — credential access |

Step-up authentication: For destructive actions (delete account, credential management), require the user to re-authenticate even if their JWT is valid. This is a future enhancement — for now, the existing auth is sufficient since these are self-service operations on the user's own account.

## What Does NOT Change
- MCP endpoint auth (`/mcp`) — Kite OAuth, 4-hour JWT
- All 80 MCP tools — unchanged
- Admin console auth (`/admin/ops`) — Google SSO + password, admin-only
- All dashboard API endpoints — same data, same email scoping
- All stores, interfaces, services, htmx templates, SSE streams
- MCP Apps widgets — unchanged

## Files Changed

| File | Change | Complexity |
|------|--------|-----------|
| `oauth/google_sso.go` | Remove admin-only check, auto-create user, flow-based redirect | Medium |
| `oauth/handlers.go` | HandleLoginChoice: Google SSO primary for all users | Low |
| `oauth/middleware.go` | RequireAuthBrowser redirect → `/auth/login`, JWT MaxAge 7 days | Low |
| `kc/templates/login_choice.html` | Redesign: Google primary, Kite secondary, no admin options | Low |
| `kc/templates/browser_login.html` | Add `?redirect=` passthrough for "Connect Kite" flow | Low |
| `kc/templates/dashboard.html` | "Connect Kite" card when no credentials stored | Low |
| `kc/ops/dashboard_templates.go` | Pass `HasKiteCredentials` flag to portfolio page data | Low |

## Success Criteria
1. User can sign in with Google and see dashboard without Kite credentials
2. Dashboard session lasts 7 days without re-auth
3. Portfolio page shows "Connect Kite" when no credentials
4. After connecting Kite, live data flows
5. MCP trading still requires Kite OAuth (unchanged)
6. Admin login unchanged
7. All existing tests pass
