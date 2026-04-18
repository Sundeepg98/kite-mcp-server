#!/bin/sh
# Export audit trail to CSV for a specific user or date range.
# Usage:
#   ./scripts/export-audit.sh [--email x@y.com] [--from YYYY-MM-DD] [--to YYYY-MM-DD] [--output file.csv]
# Default: all audit calls from the last 90 days to stdout

set -e

DB_PATH="${ALERT_DB_PATH:-./data/alerts.db}"
EMAIL=""
FROM=$(date -u -d '90 days ago' '+%Y-%m-%d' 2>/dev/null || date -u -v-90d '+%Y-%m-%d')
TO=$(date -u '+%Y-%m-%d')
OUTPUT="-"  # stdout

while [ $# -gt 0 ]; do
  case "$1" in
    --email) EMAIL="$2"; shift 2 ;;
    --from) FROM="$2"; shift 2 ;;
    --to) TO="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    --help)
      echo "Usage: $0 [--email x@y.com] [--from YYYY-MM-DD] [--to YYYY-MM-DD] [--output file.csv]"
      exit 0
      ;;
    *) echo "unknown: $1"; exit 1 ;;
  esac
done

WHERE="WHERE timestamp >= '$FROM' AND timestamp <= '$TO 23:59:59'"
if [ -n "$EMAIL" ]; then
  WHERE="$WHERE AND email = '$EMAIL'"
fi

QUERY=".headers on
.mode csv
SELECT id, timestamp, email, tool_name, args_hash, duration_ms, result_summary
FROM tool_calls
$WHERE
ORDER BY timestamp ASC;"

if [ "$OUTPUT" = "-" ]; then
  echo "$QUERY" | sqlite3 "$DB_PATH"
else
  echo "$QUERY" | sqlite3 "$DB_PATH" > "$OUTPUT"
  echo "Exported to $OUTPUT ($(wc -l < "$OUTPUT") lines including header)"
fi
