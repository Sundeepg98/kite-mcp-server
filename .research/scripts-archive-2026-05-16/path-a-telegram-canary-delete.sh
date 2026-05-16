#!/usr/bin/env bash
set -uo pipefail
ROOT=/mnt/d/Sundeep/projects/kite-mcp-server
cd "$ROOT"
[ "$(git rev-parse --abbrev-ref HEAD)" != "master" ] && { echo "ERROR: not on master"; exit 1; }

sed -i '/github\.com\/algo2go\/kite-mcp-telegram => \.\/kc\/telegram/d' go.mod

find . -path ./kc/telegram -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	if grep -qE 'github\.com/algo2go/kite-mcp-telegram => ' "$mod" 2>/dev/null; then
		sed -i '/github\.com\/algo2go\/kite-mcp-telegram => /d' "$mod"
		echo "  patched: $mod"
	fi
done

sed -i '/^[[:space:]]\+\.\/kc\/telegram\b/d' go.work
echo "go.work members: $(grep -cE '^[[:space:]]+\./' go.work)"

sed -i '/^COPY kc\/telegram\/go\.mod kc\/telegram\/go\.sum/d' Dockerfile

git rm -rq kc/telegram/

find . -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	if grep -qE 'github\.com/algo2go/kite-mcp-telegram v0\.0\.0-00010101000000-000000000000' "$mod" 2>/dev/null; then
		sed -i 's#github\.com/algo2go/kite-mcp-telegram v0\.0\.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-telegram v0.1.0#g' "$mod"
		echo "  pinned: $mod"
	fi
done

GO=/usr/local/go/bin/go
$GO mod tidy 2>&1 | tail -3
$GO build ./... 2>&1 | tail -3
GOWORK=off $GO build ./... 2>&1 | tail -3
$GO test -run "^TestHTTPRoundtrip_InitToolsList$" -count=1 -timeout 60s ./mcp/ 2>&1 | tail -3
$GO test -timeout 240s -count=1 ./mcp/ ./app/ 2>&1 | tail -5

echo "Files changed: $(git status --short | grep -vE '^\?\?' | wc -l)"
