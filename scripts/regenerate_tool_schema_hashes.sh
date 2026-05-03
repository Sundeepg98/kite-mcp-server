#!/usr/bin/env bash
# regenerate_tool_schema_hashes.sh — refresh the per-tool schema lock.
#
# When you intentionally change a tool's name, description, input
# schema, output schema, or annotations, TestToolSchemaLock_PerTool
# in mcp/tool_schema_lock_test.go will fail. Run this script to
# refresh the golden table:
#
#   ./scripts/regenerate_tool_schema_hashes.sh
#
# It runs the failing test, extracts the actual rollup hash and the
# per-tool name:hash pairs, and prints the Go literals you can paste
# back into mcp/tool_schema_lock_test.go.
#
# Reviewers must treat the resulting diff as a wire-protocol change —
# external clients (Claude Desktop, Cursor, etc.) cache tool schemas
# by name and will need to re-fetch.
#
# Per residual-100 audit (.research/residual-literal-100-engineering-
# path.md) item #4, dispatch 9932246.

set -euo pipefail

cd "$(dirname "$0")/.."

echo "Running TestToolSchemaLock_PerTool to capture current schema state..." >&2

# We expect the test to fail when schema has drifted; the failure log
# carries the data we need. Capture it; don't fail the script if the
# test reports non-zero.
RAW=$(go test ./mcp/ -run TestToolSchemaLock_PerTool -count=1 2>&1 || true)

# Extract the actual rollup hash from the failure message. Use || true
# at the end of each pipeline so a no-match grep (the test passed; no
# drift) doesn't kill the script under set -eo pipefail.
ROLLUP=$(printf '%s\n' "$RAW" | { grep -oE 'actual rollup:[[:space:]]+[a-f0-9]{64}' || true; } \
  | sed -E 's/^.*[[:space:]]+([a-f0-9]{64}).*$/\1/' | head -1)

if [[ -z "$ROLLUP" ]]; then
  # No drift — the test passed. Nothing to regenerate.
  echo "TestToolSchemaLock_PerTool passed; no drift to capture." >&2
  exit 0
fi

# Extract per-tool name:hash pairs. The drift report tags each current
# pair on its own line as "GOLDEN<toolname:sha256hex>GOLDEN" for stable
# parsing — see the goldenLines block in the test's t.Errorf call.
# pipefail-guard tolerates the test passing (no GOLDEN markers).
PAIRS=$(printf '%s\n' "$RAW" \
  | { grep -oE 'GOLDEN<[A-Za-z0-9_.-]+:[a-f0-9]{64}>GOLDEN' || true; } \
  | sed -E 's/^GOLDEN<//; s/>GOLDEN$//' \
  | sort -u)

if [[ -z "$PAIRS" ]]; then
  echo "Could not extract per-tool pairs from test output. Run manually:" >&2
  echo "  go test ./mcp/ -run TestToolSchemaLock_PerTool -count=1 -v" >&2
  exit 1
fi

echo "" >&2
echo "Paste the following into mcp/tool_schema_lock_test.go:" >&2
echo "" >&2

printf 'const expectedToolSchemaHash = "%s"\n\n' "$ROLLUP"
echo 'var lockedToolSchemaHashes = []string{'
printf '%s\n' "$PAIRS" | awk '{printf "\t\"%s\",\n", $0}'
echo '}'

echo "" >&2
echo "Done. Verify by running: go test ./mcp/ -run TestToolSchemaLock_PerTool" >&2
