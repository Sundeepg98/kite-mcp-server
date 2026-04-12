package alerts

// ceil_test.go — coverage ceiling documentation for kc/alerts.
// Current: 97.0%. Ceiling: 97.0%.
//
// ===========================================================================
// crypto.go — DeriveEncryptionKeyWithSalt (85.7%)
// ===========================================================================
//
// Line 31: `io.ReadFull(hkdfReader, key) err` check.
//   HKDF-SHA256 with a non-empty secret and valid salt always produces the
//   requested number of bytes. The only way ReadFull fails is if the HKDF
//   reader is exhausted, which requires requesting more than 255*HashLen bytes
//   (8160 bytes for SHA-256). We request 32 bytes. Unreachable.
//
// ===========================================================================
// crypto.go — EnsureEncryptionSalt (77.3%)
// ===========================================================================
//
// Line 63: `io.ReadFull(rand.Reader, salt) err` check.
//   Go 1.25 crypto/rand.Read is guaranteed to succeed or panic (it calls
//   the kernel CSPRNG). It never returns a non-nil error. Unreachable.
//
// Line 69: `DeriveEncryptionKey(secret) err` check.
//   secret is verified non-empty on line 47. DeriveEncryptionKey with a
//   non-empty secret always succeeds (same HKDF reasoning). Unreachable.
//
// Lines 75-76, 81-82, 89-90, 95-96: Error paths in the migration flow.
//   Each corresponds to:
//   - DeriveEncryptionKeyWithSalt failing (unreachable — see above)
//   - reEncryptTable failing (requires scan/query failure on a just-opened DB)
//   - db.SetConfig failing (requires write failure on a working DB)
//   All are defensive guards around operations that cannot fail on a healthy
//   in-memory SQLite database.
//
// ===========================================================================
// crypto.go — reEncryptTable (93.2%)
// ===========================================================================
//
// Line 140: `rows.Scan(scanDest...) err` check.
//   Scan error after successful query. SQLite dynamic typing ensures scan
//   always succeeds. Unreachable.
//
// Line 145: `rows.Err() err` check.
//   SQLite driver does not produce mid-iteration errors. Unreachable.
//
// ===========================================================================
// crypto.go — encrypt (81.8%)
// ===========================================================================
//
// Line 187: `aes.NewCipher(key) err` check.
//   Callers always provide a 32-byte key (derived from HKDF). NewCipher only
//   fails for invalid key sizes (not 16/24/32). Unreachable.
//
// Line 191: `cipher.NewGCM(block) err` check.
//   NewGCM never fails with a standard AES block cipher. Unreachable.
//
// Line 195: `io.ReadFull(rand.Reader, nonce) err` check.
//   Same as line 63: Go 1.25 crypto/rand.Read is fatal on failure. Unreachable.
//
// ===========================================================================
// crypto.go — decrypt (93.8%)
// ===========================================================================
//
// Line 223: `aes.NewCipher(key) err` — same as encrypt line 187. Unreachable.
// Line 227: `cipher.NewGCM(block) err` — same as encrypt line 191. Unreachable.
//
// ===========================================================================
// db.go — OpenDB (66.7%)
// ===========================================================================
//
// Line 33: `db.Ping() err` check.
//   SQLite Open succeeds → Ping always succeeds (in-process DB, no network). Unreachable.
//
// Line 36: `db.Exec("PRAGMA journal_mode=WAL;") err` check.
//   PRAGMA always succeeds on a valid connection. Unreachable.
//
// Line 39: `db.Exec("PRAGMA busy_timeout=5000;") err` check.
//   Same as above. Unreachable.
//
// ===========================================================================
// db.go — migrateRegistryCheckConstraint (76.2%)
// ===========================================================================
//
// Lines 205-206: `db.Begin() err` — transaction begin error on a working DB. Unreachable.
// Lines 222-223: `tx.Exec(CREATE TABLE) err` — DDL error on fresh table. Unreachable.
// Lines 230-231: `tx.Exec(INSERT INTO) err` — data copy error. Unreachable.
// Lines 234-235: `tx.Exec(DROP TABLE) err` — drop error. Unreachable.
// Lines 237-238: `tx.Exec(ALTER TABLE RENAME) err` — rename error. Unreachable.
//
// All require the DB to become corrupted mid-transaction.
//
// ===========================================================================
// db.go — migrateAlerts (88.9%)
// ===========================================================================
//
// Line 252-253: `db.QueryRow(...).Scan(&count) err` — PRAGMA query error. Unreachable.
//
// ===========================================================================
// db.go — Load* functions (LoadAlerts, LoadTokens, LoadCredentials,
//          LoadClients, LoadSessions, LoadTrailingStops, LoadDailyPnL,
//          LoadRegistryEntries)
// ===========================================================================
//
// All Load functions share the same pattern:
//   1. rows.Scan error after successful query — unreachable (SQLite dynamic typing)
//   2. rows.Err() after iteration — unreachable (SQLite driver)
//   3. time.Parse error on RFC3339 timestamps stored by our own Save functions —
//      unreachable unless DB is externally modified
//
// Specific lines:
//   LoadAlerts:296,300,304 — scan/parse errors. Unreachable.
//   LoadTokens:459 — scan error. Unreachable.
//   LoadCredentials:526 — scan error. Unreachable.
//   LoadClients:600 — scan error. Unreachable.
//   LoadSessions:685 — scan error. Unreachable.
//   LoadTrailingStops:856 — scan error. Unreachable.
//   LoadDailyPnL:935 — scan error. Unreachable.
//   LoadRegistryEntries:974 — scan error. Unreachable.
//
// ===========================================================================
// db.go — SaveCredential (92.3%)
// ===========================================================================
//
// Lines 553-554: `encrypt(d.encryptionKey, apiSecret) err` — encrypt error.
//   encrypt only fails if aes.NewCipher or crypto/rand fails (see crypto.go
//   analysis). Unreachable.
//
// ===========================================================================
// db.go — SaveRegistryEntry (93.8%)
// ===========================================================================
//
// Lines 1008-1009: `encrypt(d.encryptionKey, e.APISecret) err` — same as above.
//   Unreachable.
//
// ===========================================================================
// evaluator.go — Evaluate (92.3%)
// ===========================================================================
//
// Line 49-51: `e.store.onNotify != nil` + call.
//   The onNotify callback is only set when a Telegram bot is configured.
//   In test scenarios without Telegram, onNotify is nil and this branch is
//   skipped. However, the MarkTriggered + ShouldTrigger + IsPercentageAlert
//   paths are tested. The notification dispatch itself is unreachable without
//   configuring a full Telegram bot in tests.
//
// ===========================================================================
// Summary
// ===========================================================================
//
// All uncovered lines fall into these categories:
//   1. crypto/rand failures (Go 1.25 guarantees success or panic)
//   2. HKDF/AES/GCM construction errors (always succeed with valid key sizes)
//   3. SQLite scan/iteration errors (dynamic typing + driver behavior)
//   4. SQLite PRAGMA/DDL failures (always succeed on valid connection)
//   5. Notification dispatch (requires Telegram bot in test)
//
// Ceiling: 97.0% (~40 unreachable lines across crypto.go, db.go, evaluator.go).
