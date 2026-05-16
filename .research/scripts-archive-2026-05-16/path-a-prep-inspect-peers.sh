#!/usr/bin/env bash
# Inspect stale broker references in peer go.mod files post-rewrite.
set -uo pipefail
cd /tmp/algo2go-consumer-cutover-dryrun/kite-mcp-server
for f in oauth/go.mod app/providers/go.mod testutil/go.mod plugins/go.mod \
         kc/telegram/go.mod kc/domain/go.mod kc/usecases/go.mod kc/audit/go.mod \
         kc/alerts/go.mod kc/ticker/go.mod kc/eventsourcing/go.mod \
         kc/papertrading/go.mod kc/cqrs/go.mod kc/registry/go.mod \
         kc/users/go.mod kc/billing/go.mod kc/riskguard/go.mod; do
	echo "--- $f ---"
	grep -nE 'zerodha/kite-mcp-server/broker' "$f" || echo "  (no match — already clean)"
done
