#!/bin/bash
# Tier 6 plugins extraction — revert peer-module changes from go work sync
# Per Anchor 2 lesson: go work sync opportunistically rewrites peer go.mod
# files. Revert any modification not directly tied to plugins extraction.
set -e
cd /mnt/d/Sundeep/projects/kite-mcp-server

echo "--- Reverting peer-module go.mod / go.sum changes ---"
git checkout HEAD -- kc/audit/go.mod
git checkout HEAD -- kc/billing/go.mod
git checkout HEAD -- kc/cqrs/go.mod
git checkout HEAD -- kc/cqrs/go.sum
git checkout HEAD -- kc/eventsourcing/go.mod
git checkout HEAD -- kc/eventsourcing/go.sum
git checkout HEAD -- kc/registry/go.mod
git checkout HEAD -- kc/registry/go.sum
git checkout HEAD -- kc/users/go.mod
git checkout HEAD -- kc/users/go.sum

echo "--- After-revert git status (modified only) ---"
git status --porcelain | grep -v '^??'
