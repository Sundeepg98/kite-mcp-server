#!/usr/bin/env bash
# dr-drill.sh — Litestream → R2 → restore + integrity check.
# Per .research/path-to-100-per-class-deep-dive.md Class 3.
# Wire via cron / systemd timer / Fly.io scheduled job. Weekly cadence
# satisfies dim-12 (NIST CSF 2.0 "Recover") audit; daily for paranoia.
# Required env: LITESTREAM_R2_ACCOUNT_ID, LITESTREAM_BUCKET,
# LITESTREAM_ACCESS_KEY_ID, LITESTREAM_SECRET_ACCESS_KEY.
# Optional: TELEGRAM_BOT_TOKEN + TELEGRAM_DR_CHAT_ID for success ping.
# Exit codes: 0 success, 2 missing env, 3 restore fail, 4 empty file,
# 5 sanity query fail.

set -euo pipefail

for var in LITESTREAM_R2_ACCOUNT_ID LITESTREAM_BUCKET \
           LITESTREAM_ACCESS_KEY_ID LITESTREAM_SECRET_ACCESS_KEY; do
  if [[ -z "${!var:-}" ]]; then
    echo "DR drill: FAIL — missing $var" >&2
    exit 2
  fi
done

TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
SCRATCH_DB="/tmp/dr-drill-${TIMESTAMP}.db"

cleanup() { rm -f "$SCRATCH_DB" "$SCRATCH_DB"-shm "$SCRATCH_DB"-wal; }
trap cleanup EXIT

echo "DR drill: starting at $TIMESTAMP"
echo "DR drill: restoring to $SCRATCH_DB ..."

# -if-replica-exists tolerates fresh deployment with no snapshot yet.
litestream restore \
  -o "$SCRATCH_DB" \
  -if-replica-exists \
  -config etc/litestream.yml \
  /data/alerts.db || {
    echo "DR drill: FAIL — litestream restore returned non-zero" >&2
    exit 3
  }

if [[ ! -s "$SCRATCH_DB" ]]; then
  echo "DR drill: FAIL — restored file is empty or missing" >&2
  exit 4
fi

SIZE=$(stat -c %s "$SCRATCH_DB" 2>/dev/null || stat -f %z "$SCRATCH_DB" 2>/dev/null || echo 0)
echo "DR drill: restore complete (${SIZE} bytes)"

# kite_tokens always non-empty in production (every authenticated user
# has a row); alerts can legitimately be empty on fresh deployment.
ROW_COUNT=$(sqlite3 "$SCRATCH_DB" "SELECT count(*) FROM kite_tokens" 2>/dev/null || echo "ERR")
if [[ "$ROW_COUNT" == "ERR" ]]; then
  echo "DR drill: FAIL — sqlite3 query failed" >&2
  exit 5
fi

echo "DR drill: kite_tokens.count = $ROW_COUNT"
echo "DR drill: SUCCESS"

if [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_DR_CHAT_ID:-}" ]]; then
  curl -sS -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d "chat_id=${TELEGRAM_DR_CHAT_ID}" \
    -d "text=DR drill SUCCESS at ${TIMESTAMP} (kite_tokens=${ROW_COUNT}, ${SIZE} bytes)" \
    > /dev/null || true
fi

exit 0
