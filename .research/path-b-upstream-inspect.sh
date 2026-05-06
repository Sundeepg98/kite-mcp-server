#!/usr/bin/env bash
# Inspect upstream algo2go/kite-mcp-broker@v0.1.0 source extraction.
set -uo pipefail

cd /tmp/phase-b-deepcheck

cat > go.mod <<EOF
module check

go 1.25.0

require github.com/algo2go/kite-mcp-broker v0.1.0
EOF

GO=/usr/local/go/bin/go
GOFLAGS='-mod=mod' "$GO" mod download github.com/algo2go/kite-mcp-broker 2>&1 | head

EXTRACTED=$(ls -d ~/go/pkg/mod/github.com/algo2go/kite-mcp-broker@v0.1.0 2>/dev/null)
echo "extracted dir: $EXTRACTED"

if [ -n "$EXTRACTED" ]; then
	echo ""
	echo "=== Files in upstream broker module ==="
	find "$EXTRACTED" -name '*.go' -o -name '*.mod' -o -name '*.sum' 2>/dev/null | head -30
	echo ""
	echo "=== kc/money references in upstream broker source ==="
	grep -rE 'github\.com/(algo2go/kite-mcp-money|zerodha/kite-mcp-server/kc/money)' "$EXTRACTED" --include='*.go' --include='*.mod' 2>/dev/null
	echo ""
	echo "=== upstream go.mod ==="
	cat "$EXTRACTED/go.mod"
fi
