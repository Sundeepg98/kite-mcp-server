#!/bin/bash
set -e

DB_PATH="/data/alerts.db"

# Restore the database if it does not already exist.
if [ -f "$DB_PATH" ]; then
    echo "Database already exists, skipping restore"
else
    echo "No database found, attempting restore from replica..."
    litestream restore -v -if-replica-exists -o "$DB_PATH" -config /etc/litestream.yml "$DB_PATH"
fi

# Run litestream as PID 1 with the app as a subprocess.
exec litestream replicate -exec "kite-mcp-server" -config /etc/litestream.yml
