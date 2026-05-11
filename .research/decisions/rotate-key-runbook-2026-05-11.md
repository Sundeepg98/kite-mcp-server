# `cmd/rotate-key/` Empirical Runbook + OAUTH_JWT_SECRET Option B Procedure

**Date**: 2026-05-11 IST.
**Master HEAD audited**: `c7d2eec`.
**Mode**: research-only; no source mutations.
**Predecessor**: `.research/research-batch-2026-05-11.md` §N (Option A: in-process two-secret graceful rotation via `OAUTH_JWT_SECRET_PREVIOUS`). This doc extends with the **Option B** procedure (re-encrypt-during-grace) now that `cmd/rotate-key/` exists empirically.

---

## §0 — TL;DR

`cmd/rotate-key/` is a **standalone Go CLI** that re-encrypts all 4 sensitive SQLite columns (`kite_tokens.access_token`, `kite_credentials.api_key` + `api_secret`, `oauth_clients.client_secret`, `mcp_sessions.session_id_enc`) from an old `OAUTH_JWT_SECRET` to a new one. It uses HKDF salt from `config.hkdf_salt` for key derivation; if absent, falls back to nil salt (legacy mode).

Combined with `app/app.go:666-674`'s `OAUTH_JWT_SECRET_PREVIOUS` two-secret graceful-rotation pattern (which keeps JWT verification working through the grace window), `cmd/rotate-key/` enables **Option B: re-encrypt-during-grace** — old JWTs continue verifying via PREVIOUS while encrypted columns are migrated to the new key offline, then PREVIOUS is unset.

**Empirical state of the tool itself**:
- 168 LOC main.go + 878 LOC main_test.go = test:source ratio 5.2:1 (excellent)
- Tests cover: empty-table, single-row, multiple-rows, multiple-columns, OAuth-clients, MCP-sessions, salted, end-to-end-all-tables, same-key (no-op), plaintext-fallback, on-disk vs in-memory, run() entrypoint, error paths (bad salt hex, empty secrets, closed DB, encrypt failure, update failure, scan errors)
- Uses `alerts.DeriveEncryptionKeyWithSalt(secret, salt)`, `alerts.Encrypt(key, plaintext)`, `alerts.Decrypt(key, hexCiphertext)` from `github.com/algo2go/kite-mcp-alerts` (the algo2go module that owns the encryption primitives)

---

## §1 — What it does (empirical, line-by-line)

### §1.1 Flag surface (lines 16-29)

```bash
./rotate-key -db <path> -old-secret <current OAUTH_JWT_SECRET> -new-secret <new OAUTH_JWT_SECRET>
```

All 3 flags required; missing any prints usage + exits 1. No defaults; no env var fallback (must be flags). Output goes to stdout.

### §1.2 Run flow (lines 33-89 — `run()` function)

1. **Open DB** via `database/sql` + `modernc.org/sqlite` (pure-Go SQLite driver, no CGO).
2. **Load HKDF salt** from `config.hkdf_salt` row:
   - If present + valid hex: decode and use as 32-byte salt → "Using HKDF salt from database (N bytes)"
   - If absent or empty: fall back to nil salt → "No HKDF salt found in database, using nil salt (legacy)"
   - If present but invalid hex: returns error immediately. **This is the only error path that aborts early.**
3. **Derive two AES-256 keys** via `alerts.DeriveEncryptionKeyWithSalt(secret, salt)`:
   - `oldKey` from `-old-secret` + salt
   - `newKey` from `-new-secret` + salt
   - Empty secrets return derive errors (verified in `TestRun_EmptyOldSecret` / `TestRun_EmptyNewSecret`)
4. **Rotate 4 tables** (lines 67-76 define the static `tables` list):
   ```go
   {"kite_tokens",      "email",     []string{"access_token"}},
   {"kite_credentials", "email",     []string{"api_key", "api_secret"}},
   {"oauth_clients",    "client_id", []string{"client_secret"}},
   {"mcp_sessions",     "session_id",[]string{"session_id_enc"}},
   ```
5. **Per-table failures are logged but not fatal**: line 81 `log.Printf("ERROR rotating %s: %v", ...)` then continues to next table. So if `oauth_clients` table has a constraint violation mid-flight, the tool will report it but continue rotating subsequent tables. **NOT a transactional rotation.**
6. **Final message**: "Key rotation complete. Update OAUTH_JWT_SECRET on the server."

### §1.3 Per-table rotation (`rotateTable`, lines 94-168)

For each table:
1. `SELECT <pkCol>, <col1>, <col2>, ... FROM <table>` — fetches all rows into memory at once. No streaming.
2. Per row:
   - For each encrypted column: `alerts.Decrypt(oldKey, encVal)` → plaintext
   - **Plaintext fallback**: if `Decrypt` fails (AES-GCM auth tag mismatch OR not hex-encoded), it returns the input as-is. Test `TestRotateTable_PlaintextFallback` confirms: plaintext rows ARE re-encrypted with the new key. (So pre-encryption legacy rows are silently upgraded; this is "lazy migration".)
   - `alerts.Encrypt(newKey, plaintext)` → new ciphertext
3. `UPDATE <table> SET <col1>=?, <col2>=?, ... WHERE <pkCol>=?` — per-row UPDATE; no batching, no transaction.
4. Returns count of rows rotated.

---

## §2 — Empirical answers to the dispatch questions

### Q1: What does it rotate?

**4 encrypted columns across 4 tables** (full list in §1.2). These match the AES-256-GCM-encrypted columns documented in `MEMORY.md` "Full 4-layer persistence" section.

### Q2: Which secret does it rotate?

**`OAUTH_JWT_SECRET`** — the one secret. The HKDF-derived AES-256 key is its only dependent. There is no separate per-column AES key; every encrypted column uses keys derived from the same `OAUTH_JWT_SECRET + hkdf_salt` via HKDF.

The JWT-signing aspect of `OAUTH_JWT_SECRET` is separate — `cmd/rotate-key` does NOT touch JWT signing. It only re-encrypts the at-rest ciphertexts. JWT verification continues to work because:
- The server reads `OAUTH_JWT_SECRET` for both JWT signing AND HKDF key derivation
- The two uses are independent: JWT signing uses HMAC over the JWT payload; HKDF derives the AES-256 key for column encryption
- After running `cmd/rotate-key` + setting the new `OAUTH_JWT_SECRET` on the server: new JWTs verify; old JWTs FAIL unless `OAUTH_JWT_SECRET_PREVIOUS` is set (see §3)

### Q3: Does it support OAUTH_JWT_SECRET_PREVIOUS graceful rotation grace-period?

**Yes — but indirectly.** `cmd/rotate-key` doesn't read or care about `OAUTH_JWT_SECRET_PREVIOUS`. It just re-encrypts. The "graceful rotation" comes from how the SERVER handles `OAUTH_JWT_SECRET_PREVIOUS` per `app/app.go:666-674` (per research-batch §N):
- The server's JWT verifier reads `OAUTH_JWT_SECRET` (current, signs new tokens) AND `OAUTH_JWT_SECRET_PREVIOUS` (verify-only, for old tokens during grace window)
- After running `cmd/rotate-key` + setting `OAUTH_JWT_SECRET=new` + `OAUTH_JWT_SECRET_PREVIOUS=old`:
  - Old JWTs continue verifying via PREVIOUS (grace window: 24h MCP / 7d dashboard per the default expiry)
  - Encrypted columns are now decryptable only with the new key
  - After grace window: unset `OAUTH_JWT_SECRET_PREVIOUS` → old JWTs reject with 401 → seamless re-auth via `RequireAuth` middleware (forces mcp-remote to re-auth without user friction per MEMORY.md "Auto re-auth v43")

### Q4: Does it touch `kite_credentials` / `kite_tokens` / `oauth_clients.client_secret`?

**Yes — all three plus `mcp_sessions.session_id_enc`**. See §1.2 step 4 for the exact 4-table × 4-column matrix.

### Q5: Runbook for Option B (re-encrypt-during-grace)

See §4 below.

---

## §3 — Why Option B matters: the encryption-vs-signing decoupling

Per research-batch §N:
- `OAUTH_JWT_SECRET_PREVIOUS` lets old JWTs verify during a grace window (Option A)
- BUT encrypted columns can only be decrypted with ONE key at a time (whichever was last used to encrypt them)
- If you ONLY do Option A (set PREVIOUS without re-encrypting columns), the old JWT verifies → server hits the credential store → tries to decrypt with the CURRENT key → fails with AES-GCM auth-tag mismatch (per `alerts.Decrypt` returning empty string per its line 223 implementation, which the consuming code treats as "credential not found")
- **Therefore**: rotating `OAUTH_JWT_SECRET` without also re-encrypting columns BREAKS every cached Kite token + credential + OAuth client_secret on the first request after the env-var change

**Option B closes this gap**: re-encrypt columns to the new key FIRST (offline, via `cmd/rotate-key`), then flip the env vars. This way:
- After flip: new JWTs verify with current; old JWTs verify with PREVIOUS
- All encrypted columns decrypt with the current key (which is what the server uses)
- No user-visible re-auth or data loss

---

## §4 — Option B operational runbook

**Preconditions**:
- Fly.io app running stable; `/healthz` returning 200
- Current `OAUTH_JWT_SECRET` value known (from secret manager / `flyctl secrets list` shows digest only — need the actual value from your secret store)
- `cmd/rotate-key` binary built or buildable on operator machine
- `/data/alerts.db` accessible (via `flyctl ssh` or local replica restored from Litestream → R2)

**Operator steps**:

1. **Snapshot current state** (for rollback):
   ```bash
   flyctl ssh console -a kite-mcp-server -C "cp /data/alerts.db /data/alerts.db.pre-rotation-$(date -u +%Y%m%dT%H%M%SZ)"
   ```
   Verify the copy exists:
   ```bash
   flyctl ssh console -a kite-mcp-server -C "ls -la /data/alerts.db.pre-rotation-*"
   ```

2. **Generate the new secret**:
   ```bash
   NEW_SECRET=$(openssl rand -hex 32)
   ```
   (≥32 chars required by envcheck per `app/envcheck.go`.)

3. **Build the rotate-key binary** locally (WSL2 per `feedback_wsl_for_go_test.md`):
   ```bash
   cd /mnt/d/Sundeep/projects/kite-mcp-server
   /usr/local/go/bin/go build -o /tmp/rotate-key ./cmd/rotate-key
   ```

4. **Restore a working DB from Litestream → R2** (do NOT run rotation against `/data/alerts.db` directly; use a local replica to keep production untouched until the rotation is verified):
   ```bash
   # On the production VM (one-shot offline restore — the alternative is to
   # SFTP-pull the DB to local and run rotate-key there). Production VM has
   # litestream CLI installed:
   flyctl ssh console -a kite-mcp-server -C "litestream restore -if-replica-exists -config /etc/litestream.yml -o /tmp/alerts-rotation-work.db /data/alerts.db"

   # SFTP-pull to local WSL2:
   echo "get /tmp/alerts-rotation-work.db /tmp/alerts-rotation-work.db" | flyctl ssh sftp shell -a kite-mcp-server
   ```

5. **Run `cmd/rotate-key` against the local replica**:
   ```bash
   /tmp/rotate-key -db /tmp/alerts-rotation-work.db -old-secret "$CURRENT_SECRET" -new-secret "$NEW_SECRET"
   ```
   Expected output:
   ```
   Using HKDF salt from database (32 bytes)
   Rotated N rows in kite_tokens
   Rotated M rows in kite_credentials
   Rotated K rows in oauth_clients
   Rotated J rows in mcp_sessions
   Key rotation complete. Update OAUTH_JWT_SECRET on the server.
   ```
   If any "ERROR rotating <table>" appears: stop. Do not flip env vars. Investigate.

6. **Verify the rotation worked** by decrypting one canary row with the NEW key (similar to `scripts/dr-drill-prod-keys.sh`'s phase 4 if `cmd/dr-decrypt-probe` exists, OR via a one-off Go check):
   ```bash
   # The simplest verification: re-run rotate-key against the rotated DB with
   # new -> NEW_NEXT. It should succeed (rows decrypt with new key, re-encrypt
   # with next key). If it fails, the first rotation didn't actually work.
   # Throw away the temp file after.
   ```
   Manual SQL check: confirm `SELECT count(*) FROM kite_tokens` is unchanged from pre-rotation snapshot.

7. **Upload the rotated DB back to production** AND flip env vars in the SAME deploy (atomic-ish — Fly machine is single-instance, so no two-machine race):
   ```bash
   # Push rotated DB back to production VM:
   echo "put /tmp/alerts-rotation-work.db /data/alerts.db.new" | flyctl ssh sftp shell -a kite-mcp-server

   # Stop the server briefly, swap DB, set env vars:
   flyctl ssh console -a kite-mcp-server -C "mv /data/alerts.db /data/alerts.db.pre-rotation-final && mv /data/alerts.db.new /data/alerts.db"

   # Set both env vars atomically (Fly redeploys after secrets change):
   flyctl secrets set \
       OAUTH_JWT_SECRET="$NEW_SECRET" \
       OAUTH_JWT_SECRET_PREVIOUS="$CURRENT_SECRET" \
       -a kite-mcp-server
   ```
   Fly secrets set triggers a redeploy. The new binary reads BOTH secrets; new JWTs use NEW; old JWTs verify against PREVIOUS during their TTL.

8. **Verify post-deploy**:
   ```bash
   curl https://kite-mcp-server.fly.dev/healthz
   # Should return: {"status":"ok","tools":111,"version":"v1.3.0","uptime":"<seconds>"}
   ```
   Run dr-drill (per `.research/dr-drill-results-2026-05-11.md` § §4) to confirm restore + decrypt with the new key works.

9. **Grace window** (default 24h MCP / 7d dashboard cookie):
   - Monitor `/admin/ops` for 401 spikes (would indicate old JWTs failing to verify) — should NOT spike, because both keys are accepted
   - All cached Kite tokens auto-refresh at ~6 AM IST anyway, so by next morning everyone has new tokens encrypted under the new key

10. **Close grace window** (after ≥24h, or after observed traffic shows zero old-JWT verification needs):
    ```bash
    flyctl secrets unset OAUTH_JWT_SECRET_PREVIOUS -a kite-mcp-server
    ```
    This triggers another redeploy. After: old JWTs that haven't rotated yet (unlikely after 24h+) will 401 → re-auth seamlessly via `RequireAuth` middleware.

11. **Clean up snapshots** (after ≥7 days of confirmed stability):
    ```bash
    flyctl ssh console -a kite-mcp-server -C "rm /data/alerts.db.pre-rotation-*"
    ```

**Rollback plan** (if any step 4-7 fails):
- Restore `/data/alerts.db.pre-rotation-<timestamp>` over `/data/alerts.db`
- Do NOT flip env vars
- Server keeps running with the original `OAUTH_JWT_SECRET`

---

## §5 — Risk profile

| Risk | Severity | Mitigation |
|---|---|---|
| Per-table failure leaves DB partially rotated | MEDIUM | `cmd/rotate-key` logs but continues; partial state means SOME columns are new-key, SOME are old-key. **Mitigation**: snapshot before rotation (step 1); rollback restores atomic pre-rotation state. |
| No transaction wraps the rotation | MEDIUM | Per-row UPDATE without `BEGIN/COMMIT`. **Mitigation**: run against an OFFLINE replica (step 4), not against `/data/alerts.db` directly. The atomic-flip is in step 7 (swap files + flip env vars). |
| `OAUTH_JWT_SECRET_PREVIOUS` not unset → indefinite grace | LOW | Per research-batch §N: leaving PREVIOUS set forever doesn't break anything operationally; it just means old JWTs verify forever. **Mitigation**: include the unset step in operator runbook (step 10). |
| `cmd/rotate-key` run against `/data/alerts.db` directly (race) | HIGH | If you run rotate-key while the server is actively writing to `/data/alerts.db`, modernc.org/sqlite + WAL may not see the changes consistently. **Mitigation**: ALWAYS run against an offline replica. Don't shortcut step 4. |
| HKDF salt missing → silent "nil salt legacy" mode | LOW | The tool prints "No HKDF salt found in database, using nil salt (legacy)" — operator should NOT proceed if production has an `hkdf_salt` row. **Mitigation**: verify the replica was restored cleanly (Litestream restore preserves the salt; chain agent's dr-drill confirms it survived). |
| Bad salt hex → tool aborts | LOW | The tool returns an error immediately if the salt is unparseable. Operator gets a clear "decode stored salt" error. Mitigation: don't manually edit the config table. |
| Plaintext fallback silently upgrades | LOW | If a row was somehow stored as plaintext (pre-encryption migration era), `cmd/rotate-key` encrypts it with the new key — a one-way lazy migration. This is intentional; not a bug. |

---

## §6 — Open questions / gaps

1. **Verification step**: the runbook step 6 currently relies on running rotate-key a second time to verify. A dedicated `cmd/dr-decrypt-probe` binary (per `.research/dr-drill-results-2026-05-11.md` finding §3) would be cleaner. **The chain agent is implementing dr-decrypt-probe per the parallel dispatch**; once shipped, swap step 6 to use it.
2. **`mcp_sessions.session_id_enc`**: the tool rotates this column but its production use is documented as "lazy Kite client creation per SessionRegistry" — the impact of rotating in-flight session IDs is not empirically verified here.
3. **Litestream replication freshness**: step 4 restores from Litestream → R2 with ~10s lag. If a write happens to `/data/alerts.db` in the 10s window before the offline DB is replaced (step 7), it could be lost. **Mitigation**: schedule the rotation during low-traffic hours OR briefly stop the server before step 7.
4. **No production test of Option B**: this runbook is empirically grounded in `cmd/rotate-key`'s 22 unit tests + main_test.go end-to-end coverage, but Option B has NEVER been executed against a real Fly.io production deployment. First execution should be on a non-critical staging app or with the user explicitly co-piloting.

---

## §7 — Cross-references

- `.research/research-batch-2026-05-11.md` §N — original Option A runbook (PREVIOUS env-var graceful rotation; no column re-encryption)
- `.research/dr-drill-results-2026-05-11.md` — backup chain health + cmd/dr-decrypt-probe gap that this runbook step 6 references
- `D:/Sundeep/projects/kite-mcp-server/cmd/rotate-key/main.go` — source-of-truth implementation
- `D:/Sundeep/projects/kite-mcp-server/cmd/rotate-key/main_test.go` — 22 test cases covering happy path + error paths
- `D:/Sundeep/projects/algo2go/kite-mcp-alerts/crypto.go:31-46` — `DeriveEncryptionKey` + `DeriveEncryptionKeyWithSalt` HKDF source
- `D:/Sundeep/projects/algo2go/kite-mcp-alerts/crypto.go:217-235` — `Encrypt`/`Decrypt` AES-256-GCM source
- `app/app.go:666-674` — `OAUTH_JWT_SECRET_PREVIOUS` verify-only fallback (server-side; not in this tool)
- `MEMORY.md` "Full 4-layer persistence" — schema reference for the 4 encrypted columns

---

## §8 — Time used

~1 hour: 30 min reading main.go + main_test.go + crypto.go signatures; 30 min writing this runbook. Inside the ~1h TASK 3 budget.
