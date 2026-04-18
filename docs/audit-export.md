# Audit trail export

Export the audit log for a specific user, date range, or both.

## Use cases

- User files DPDP Access Request — export their data for disclosure
- Incident response — compile evidence for regulator
- Compliance review — last 30 days of order-tool activity

## Basic usage

```sh
./scripts/export-audit.sh --email user@example.com --from 2026-03-01 --to 2026-04-17 --output user-audit.csv
```

Defaults:
- `--from`: 90 days ago
- `--to`: today
- `--email`: all users
- `--output`: stdout

## Executable bit on Windows

Git on Windows does not always preserve the `+x` bit. If the script won't run directly:

```sh
chmod +x scripts/export-audit.sh           # POSIX
sh scripts/export-audit.sh --help          # or invoke via sh explicitly
git update-index --chmod=+x scripts/export-audit.sh   # persist +x in git index
```

## PII / Redaction

The audit store already redacts sensitive args (see `sanitizeForLog` in `kc/audit/store.go`). `args_hash` lets you verify identity without revealing content. Never include raw args in compliance disclosure.

## Location of SQLite DB

Override via `ALERT_DB_PATH` env. Default: `./data/alerts.db`. On Fly.io production: persisted volume, check `flyctl ssh console` to SCP.

## Related

- [Incident response](./incident-response.md) § Scenario 3 (security breach) uses this for user notification
- [Monitoring](./monitoring.md) § Audit trail explains the data model
