#!/bin/bash
# Tier 6 plugins extraction — inspect peer-module diffs
cd /mnt/d/Sundeep/projects/kite-mcp-server
echo "=== kc/audit/go.mod ==="
git diff kc/audit/go.mod | head -20
echo
echo "=== kc/billing/go.mod ==="
git diff kc/billing/go.mod | head -20
echo
echo "=== kc/cqrs/go.mod ==="
git diff kc/cqrs/go.mod | head -20
echo
echo "=== kc/eventsourcing/go.mod ==="
git diff kc/eventsourcing/go.mod | head -20
echo
echo "=== kc/registry/go.mod ==="
git diff kc/registry/go.mod | head -20
echo
echo "=== kc/users/go.mod ==="
git diff kc/users/go.mod | head -20
echo
echo "=== root go.mod (just Plugins-related lines) ==="
git diff go.mod | head -30
