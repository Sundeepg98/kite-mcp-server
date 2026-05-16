#!/usr/bin/env bash
# Phase B dependency-graph blocker workaround test.
#
# Hypothesis: consumer-side `replace github.com/algo2go/kite-mcp-money => ./kc/money`
# satisfies the upstream broker module's require directive, even though
# kc/money isn't published yet.
#
# Validates this in a scratch tree without mutating master.

set -euo pipefail

SCRATCH=/tmp/phase-b-money-shim-test
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"

echo "=== Phase 1: Fresh clone of master ==="
git clone -q "$SOURCE" "$SCRATCH/kite-mcp-server"
cd "$SCRATCH/kite-mcp-server"
echo "HEAD: $(git rev-parse HEAD)"
echo ""

echo "=== Phase 2: Apply Phase B mutations ==="
echo ""
echo "Step 2a: Drop replace directive for algo2go/kite-mcp-broker in root go.mod"
sed -i '/github\.com\/algo2go\/kite-mcp-broker => \.\/broker/d' go.mod
grep -nE 'algo2go/kite-mcp-broker' go.mod || echo "ERROR: replace not found"

echo ""
echo "Step 2b: Add shim replace for kc/money (workaround for upstream's silent-dropped replace)"
# Add kc/money replace pointing at consumer's ./kc/money
sed -i '/^replace (/a\	github.com/algo2go/kite-mcp-money => ./kc/money' go.mod
grep -nE 'algo2go/kite-mcp-money' go.mod

echo ""
echo "Step 2c: Drop ./broker from go.work use block"
sed -i '/^	\.\/broker$/d' go.work
grep -nE '\./broker' go.work || echo "  ./broker removed from go.work"

echo ""
echo "Step 2d: Rename in-tree ./broker out of the way (test only — DO NOT DELETE master's broker dir!)"
mv broker broker.MOVED-FOR-PHASE-B-TEST

echo ""
echo "=== Phase 3: Sweep peer go.mod files (drop broker replace) ==="
find . -path ./broker.MOVED-FOR-PHASE-B-TEST -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	if grep -q 'github\.com/algo2go/kite-mcp-broker => ' "$mod" 2>/dev/null; then
		# Drop the replace line
		sed -i '/github\.com\/algo2go\/kite-mcp-broker => /d' "$mod"
		# Pin require to v0.1.0
		sed -i 's#github\.com/algo2go/kite-mcp-broker v0\.0\.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-broker v0.1.0#g' "$mod"
		echo "  patched: $mod"
	fi
done

echo ""
echo "=== Phase 4: Build attempt (workspace mode) ==="
GO=/usr/local/go/bin/go
$GO version
echo ""
echo "--- go build ./... ---"
if $GO build ./... 2>&1 | tee /tmp/_phase-b-build.txt | tail -30; then
	echo "BUILD: PASS (workspace mode, no in-tree broker)"
	BUILD_OK=1
else
	echo "BUILD: FAIL"
	BUILD_OK=0
fi

echo ""
echo "=== Phase 5: GOWORK=off build ==="
if GOWORK=off $GO build ./... 2>&1 | tee /tmp/_phase-b-build-off.txt | tail -30; then
	echo "BUILD: PASS (GOWORK=off)"
else
	echo "BUILD: FAIL (GOWORK=off)"
fi

echo ""
echo "=== Phase 6: Tools=111 invariant test ==="
if [ "$BUILD_OK" = "1" ]; then
	$GO test -run "^TestHTTPRoundtrip_InitToolsList$" -count=1 -timeout 60s ./mcp/ 2>&1 | tail -10
fi

echo ""
echo "=== Test complete. Scratch: $SCRATCH ==="
