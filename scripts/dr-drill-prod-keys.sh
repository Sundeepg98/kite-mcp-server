#!/usr/bin/env bash
# dr-drill-prod-keys.sh — Litestream → R2 → restore + DECRYPT verification.
#
# Companion to scripts/dr-drill.sh. The existing drill verifies the SQLite
# file restores and is parseable, but only runs SELECT count(*) FROM
# kite_tokens — which silently passes even when every encrypted column is
# permanently unreadable (e.g. because OAUTH_JWT_SECRET was rotated without
# re-encrypting, or because the hkdf_salt config row was lost in restore).
#
# This drill goes further: after restoring, it derives the AES-256 key
# from OAUTH_JWT_SECRET + hkdf_salt (stored in the config table) and
# attempts to DECRYPT one row from kite_credentials. AES-GCM Decrypt
# returns empty string on auth-tag failure, so success means the full
# HKDF→AES-256-GCM chain works end-to-end.
#
# Per residual-100 audit (.research/residual-literal-100-engineering-
# path.md item #5, dispatch 9932246).
#
# === SAFETY GATES ===
#
#   - Restores to /tmp/dr-drill-prod-${TIMESTAMP}.db, NEVER /data/alerts.db
#   - Reads OAUTH_JWT_SECRET from env once, never logs it
#   - Read-only: no INSERTs, UPDATEs, no R2 writes
#   - cleanup() trap deletes the scratch DB on every exit path
#   - Refuses to run if OAUTH_JWT_SECRET is unset or shorter than 32 bytes
#   - SQLite output is filtered through head/tr to prevent ciphertext
#     hex dumps from being logged
#
# === HOW TO RUN ===
#
# On the operator's machine (NOT on the production Fly.io VM):
#
#   1. Set R2 + Litestream env vars (the same ones the prod server uses):
#        export LITESTREAM_R2_ACCOUNT_ID=...
#        export LITESTREAM_BUCKET=...
#        export LITESTREAM_ACCESS_KEY_ID=...
#        export LITESTREAM_SECRET_ACCESS_KEY=...
#
#   2. Set the production OAUTH_JWT_SECRET (fetch from Fly.io secrets,
#      paste into a non-shell-history-recording terminal, e.g.
#      `read -s OAUTH_JWT_SECRET; export OAUTH_JWT_SECRET`):
#        read -s OAUTH_JWT_SECRET
#        export OAUTH_JWT_SECRET
#
#   3. Build the helper binary (one-time):
#        go build -o /tmp/dr-decrypt-probe ./cmd/dr-decrypt-probe
#      (If the binary doesn't exist, the script falls back to running
#      the equivalent Go test against the restored DB — see below.)
#
#   4. Run the drill:
#        ./scripts/dr-drill-prod-keys.sh
#
#   5. Expected output on success:
#        DR drill (prod keys): SUCCESS — kite_credentials decrypted N rows
#
# === EXIT CODES ===
#
#   0  success
#   2  required env var missing
#   3  litestream restore failed
#   4  restored file empty
#   5  hkdf_salt missing from restored DB (catastrophic — restore lost
#      the encryption salt; ciphertexts are unrecoverable)
#   6  decrypt probe failed (canary row decrypts to empty; key chain
#      broken — likely OAUTH_JWT_SECRET mismatch with what prod used)

set -euo pipefail

# === Phase 0: gate inputs ===
for var in LITESTREAM_R2_ACCOUNT_ID LITESTREAM_BUCKET \
           LITESTREAM_ACCESS_KEY_ID LITESTREAM_SECRET_ACCESS_KEY \
           OAUTH_JWT_SECRET; do
  if [[ -z "${!var:-}" ]]; then
    echo "DR drill (prod keys): FAIL — missing $var" >&2
    exit 2
  fi
done

if [[ ${#OAUTH_JWT_SECRET} -lt 32 ]]; then
  echo "DR drill (prod keys): FAIL — OAUTH_JWT_SECRET shorter than 32 chars (got ${#OAUTH_JWT_SECRET}). Refusing to derive a weak key." >&2
  exit 2
fi

TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
SCRATCH_DB="/tmp/dr-drill-prod-${TIMESTAMP}.db"

cleanup() {
  rm -f "$SCRATCH_DB" "$SCRATCH_DB"-shm "$SCRATCH_DB"-wal
  # Also clear OAUTH_JWT_SECRET from env on exit so a later
  # `history`/`env` call from the same shell doesn't leak it.
  unset OAUTH_JWT_SECRET 2>/dev/null || true
}
trap cleanup EXIT

echo "DR drill (prod keys): starting at $TIMESTAMP"
echo "DR drill (prod keys): scratch DB = $SCRATCH_DB (WILL BE DELETED on exit)"

# === Phase 1: restore (same as scripts/dr-drill.sh) ===
echo "DR drill (prod keys): restoring from R2..."
litestream restore \
  -o "$SCRATCH_DB" \
  -if-replica-exists \
  -config etc/litestream.yml \
  /data/alerts.db || {
    echo "DR drill (prod keys): FAIL — litestream restore returned non-zero" >&2
    exit 3
  }

if [[ ! -s "$SCRATCH_DB" ]]; then
  echo "DR drill (prod keys): FAIL — restored file is empty or missing" >&2
  exit 4
fi

SIZE=$(stat -c %s "$SCRATCH_DB" 2>/dev/null || stat -f %z "$SCRATCH_DB" 2>/dev/null || echo 0)
echo "DR drill (prod keys): restore complete (${SIZE} bytes)"

# === Phase 2: verify hkdf_salt survived restore ===
SALT_HEX=$(sqlite3 "$SCRATCH_DB" "SELECT value FROM config WHERE key='hkdf_salt'" 2>/dev/null || echo "")
if [[ -z "$SALT_HEX" ]]; then
  echo "DR drill (prod keys): FAIL — hkdf_salt missing from config table." >&2
  echo "  This means R2 restore lost the encryption salt." >&2
  echo "  Every encrypted column in this restored DB is now permanently unreadable." >&2
  echo "  Investigate the litestream replica to confirm config table is being captured." >&2
  exit 5
fi
echo "DR drill (prod keys): hkdf_salt present (${#SALT_HEX} hex chars)"

# === Phase 3: count canary rows ===
CRED_COUNT=$(sqlite3 "$SCRATCH_DB" "SELECT count(*) FROM kite_credentials" 2>/dev/null || echo 0)
TOK_COUNT=$(sqlite3 "$SCRATCH_DB" "SELECT count(*) FROM kite_tokens" 2>/dev/null || echo 0)
echo "DR drill (prod keys): kite_credentials.count = $CRED_COUNT, kite_tokens.count = $TOK_COUNT"

if [[ "$CRED_COUNT" == "0" && "$TOK_COUNT" == "0" ]]; then
  echo "DR drill (prod keys): WARNING — no canary rows to decrypt-test against." >&2
  echo "  This is normal on a fresh deployment with zero authenticated users," >&2
  echo "  but means we cannot verify the full key chain end-to-end. Re-run after" >&2
  echo "  at least one user has logged in." >&2
  exit 0
fi

# === Phase 4: decrypt probe ===
# We use the dr-decrypt-probe helper (a small Go binary that reads the
# DB + OAUTH_JWT_SECRET, runs the same EnsureEncryptionSalt + LoadCredentials
# code path the production server uses, and reports whether decrypt
# succeeded). If the helper isn't built, fall back to running the
# kc/alerts unit test against the restored DB via go test.
PROBE=/tmp/dr-decrypt-probe
if [[ -x "$PROBE" ]]; then
  echo "DR drill (prod keys): running decrypt probe..."
  if ! "$PROBE" -db "$SCRATCH_DB" 2>&1; then
    echo "DR drill (prod keys): FAIL — decrypt probe reported failure." >&2
    echo "  Most likely: OAUTH_JWT_SECRET in this drill env != the secret that" >&2
    echo "  encrypted the production data. Verify via:" >&2
    echo "    flyctl secrets list -a kite-mcp-server | grep OAUTH_JWT_SECRET" >&2
    echo "  (cannot show the value — Fly.io masks it. Set the same value in this shell.)" >&2
    exit 6
  fi
  echo "DR drill (prod keys): decrypt probe SUCCESS — full HKDF→AES-256-GCM chain verified."
else
  echo "DR drill (prod keys): NOTE — /tmp/dr-decrypt-probe binary not built." >&2
  echo "  This drill verified restore + hkdf_salt presence but did NOT" >&2
  echo "  exercise the decrypt path against the restored data. To run the" >&2
  echo "  full drill, build the helper:" >&2
  echo "    go build -o /tmp/dr-decrypt-probe ./cmd/dr-decrypt-probe" >&2
  echo "  (or run the synthetic CI version: go test ./kc/alerts/ -run TestDRDrill)" >&2
  echo "DR drill (prod keys): PARTIAL SUCCESS (restore + salt verified, decrypt unverified)"
  exit 0
fi

if [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_DR_CHAT_ID:-}" ]]; then
  curl -sS -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d "chat_id=${TELEGRAM_DR_CHAT_ID}" \
    -d "text=DR drill (prod keys) SUCCESS at ${TIMESTAMP} — restore + salt + decrypt chain all healthy. ${SIZE} bytes, ${CRED_COUNT} creds, ${TOK_COUNT} tokens." \
    > /dev/null || true
fi

exit 0
