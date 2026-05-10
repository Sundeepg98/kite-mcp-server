#!/usr/bin/env bash
set -euo pipefail
SCRATCH=/tmp/algo2go-eventsourcing-extract-dryrun/kite-mcp-eventsourcing-extract
[ -d "$SCRATCH" ] || { echo "ERROR: run prep first"; exit 1; }
cd "$SCRATCH"

find . -name '*.go' -type f -exec sed -i 's#github.com/zerodha/kite-mcp-server/kc/eventsourcing#github.com/algo2go/kite-mcp-eventsourcing#g' {} \;
sed -i 's#^module github.com/zerodha/kite-mcp-server/kc/eventsourcing$#module github.com/algo2go/kite-mcp-eventsourcing#' go.mod

# Drop stale 'replace zerodha/kite-mcp-server => ../..' workspace artifact
sed -i '/github\.com\/zerodha\/kite-mcp-server v0\.0\.0-/d' go.mod
sed -i '/github\.com\/zerodha\/kite-mcp-server => /d' go.mod
# Drop now-empty replace () block
sed -i '/^replace ($/{N;s/^replace (\n)$//}' go.mod
# Also drop stale prose-narration comment line referring to the source repo
sed -i '/it lives in github\.com\/zerodha\/kite-mcp-server/d' go.mod

cat go.mod
echo ""
stale=$(grep -rE 'github.com/zerodha/kite-mcp-server' --include='*.go' --include='go.mod' -l 2>/dev/null || true)
stale_count=$(echo -n "$stale" | grep -c . || true)
echo "Stale refs: $stale_count (target 0)"
[ -n "$stale" ] && echo "$stale"

GO=/usr/local/go/bin/go
$GO mod tidy 2>&1 | tail -3
$GO build ./... 2>&1 | tail -3
echo "build exit: $?"
$GO test -count=1 -timeout 60s ./... 2>&1 | tail -3
