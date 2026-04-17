# User Count — Template

**Do NOT pre-fill this file.** At incident time, run the queries below against the live SQLite DB and paste the exact numbers. Stale numbers are worse than no numbers.

---

## As-of timestamp

`[FILL: YYYY-MM-DD HH:MM IST — exact moment of snapshot]`

## Headline figures

- **Total registered users (OAuth client_store entries):** `[FILL]`
- **Users with stored Kite credentials (credential_store entries):** `[FILL]`
- **Monthly Active Users (distinct user emails with audit tool_calls in last 30d):** `[FILL]`
- **Weekly Active Users (distinct emails last 7d):** `[FILL]`
- **Daily Active Users (distinct emails last 24h):** `[FILL]`
- **Paying users:** `0 (not monetized as of 2026-04-17 — see revenue.md)`

## Geographic distribution

- **India-based users (%):** `[FILL — infer from audit IP + Kite account; Kite itself is India-only, so this will be ~100%]`
- **Other countries:** `[FILL or N/A]`

## Exposure

- **Total portfolio value under audit (sum of holdings queries in last 7d):** `[FILL — expected to be large because it aggregates across all users]`
- **Total trade value executed through server (sum of successful place_order last 30d):** `[FILL]`
- **Largest single trade executed (last 30d):** `[FILL]`
- **Total unique instruments traded (last 30d):** `[FILL]`

## Order composition (for proportionality argument)

- **Orders placed via our server (last 30d):** `[FILL]`
- **Compare to Zerodha's public daily order volume:** `[FILL — expected to be a rounding error; include this for scale context]`

---

## Queries to run at incident time

```sql
-- Total registered users
SELECT COUNT(DISTINCT email) FROM client_store;

-- Users with stored Kite creds (i.e., actually completed setup)
SELECT COUNT(*) FROM kite_credentials;

-- MAU / WAU / DAU (replace interval as needed)
SELECT COUNT(DISTINCT email)
FROM tool_calls
WHERE created_at > datetime('now', '-30 days');

-- Trade volume last 30d
SELECT COUNT(*), SUM(CAST(json_extract(args, '$.quantity') AS REAL) *
                     CAST(json_extract(args, '$.price') AS REAL))
FROM tool_calls
WHERE tool_name = 'place_order'
  AND status = 'success'
  AND created_at > datetime('now', '-30 days');
```

Adjust table/column names based on current schema. Cross-check against `audit/store.go` before citing numbers.

## Caveats for the fill-in

- State the DB snapshot time in IST explicitly
- If Fly.io volume is being used for DB, note the volume region (bom)
- Distinguish "registered" (OAuth completed) from "active" (actually placed orders / made tool calls)
- If trade value is huge, add the Zerodha-comparison footnote so the number is not misread as scale of business — it is scale of instrument activity, not revenue
