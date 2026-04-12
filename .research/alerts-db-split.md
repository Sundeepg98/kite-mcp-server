# Task 11 — kc/alerts/db.go Split

## Goal
Split the 1033-line `kc/alerts/db.go` monolith into focused files:
persistence (DDL/connection), crypto (HMAC/AES), queries (Load/Save/Delete).

## BEFORE

| File                 | LOC  | Methods                                            |
|----------------------|------|----------------------------------------------------|
| kc/alerts/db.go      | 1033 | 40 DB methods (all CRUD + DDL + migrations + raw)  |
| kc/alerts/crypto.go  | 239  | AES/HKDF primitives (encrypt/decrypt/key derive)   |

## AFTER

| File                         | LOC | Role                                                       |
|------------------------------|-----|------------------------------------------------------------|
| kc/alerts/db.go              | 291 | DB struct, OpenDB, schema DDL, raw helpers, Config, Close  |
| kc/alerts/db_migrations.go   | 87  | migrateAlerts, migrateRegistryCheckConstraint              |
| kc/alerts/db_queries.go      | 323 | 9 Load\* methods (one per domain)                          |
| kc/alerts/db_commands.go     | 328 | Save/Delete/Update methods for all domains (~22 methods)   |
| kc/alerts/crypto.go          | 252 | AES-GCM, HKDF, salt management, HMAC-SHA256 hashSessionID  |

Total LOC: 1281 across 5 files (vs 1033+239=1272 before — minor overhead from file boilerplate).

## Method distribution

- **db.go** (10 methods): SetEncryptionKey, ExecDDL, ExecInsert, ExecResult,
  QueryRow, RawQuery, Close, GetConfig, SetConfig + OpenDB (constructor).
- **db_queries.go** (9 methods): LoadAlerts, LoadTelegramChatIDs, LoadTokens,
  LoadCredentials, LoadClients, LoadSessions, LoadTrailingStops, LoadDailyPnL,
  LoadRegistryEntries.
- **db_commands.go** (22 methods): SaveAlert, DeleteAlert, DeleteAlertsByEmail,
  UpdateAlertNotification, UpdateTriggered, SaveTelegramChatID,
  DeleteTelegramChatID, SaveToken, DeleteToken, SaveCredential,
  DeleteCredential, SaveClient, DeleteClient, SaveSession, DeleteSession,
  SaveTrailingStop, DeactivateTrailingStop, UpdateTrailingStop, SaveDailyPnL,
  SaveRegistryEntry, DeleteRegistryEntry.
- **crypto.go** (added hashSessionID — was in db.go before): HMAC-SHA256 is
  a crypto primitive and belongs next to the AES/HKDF code it pairs with
  (the encrypted session_id_enc column round-trips through both).
- **db_migrations.go** (2 migration funcs): schema-upgrade helpers.

## Verification

```
$ go build ./kc/alerts/
(clean)

$ grep -c "^func (d \*DB)" kc/alerts/db.go
10   # was 40

$ wc -l kc/alerts/db.go
291  # was 1033
```

Full module build has unrelated failures in `kc/ops/` (task #12 in progress)
and `testutil/` (task #2/#3 in progress). alerts package itself is clean.

## Notes

Part of the split was already in flight by another teammate when this task
was claimed: `db_queries.go`, `db_commands.go`, and `db_migrations.go` already
existed. Remaining work completed here:
1. Moved `hashSessionID` from db.go to crypto.go (crypto primitive colocated).
2. Removed the now-unused `crypto/hmac`, `crypto/sha256`, `encoding/hex`
   imports from db.go.
3. Verified the split compiles cleanly.

The types (TokenEntry, CredentialEntry, ClientDBEntry, SessionDBEntry,
DailyPnLEntry, RegistryDBEntry) remain in db.go because they are shared
by both db_queries.go and db_commands.go and are conceptually schema-level
data shapes. Moving them into either queries or commands file would make
the other file depend on the "wrong" side of the split.
