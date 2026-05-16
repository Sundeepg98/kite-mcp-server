#!/bin/bash
# Tier 6 plugins extraction — commit using -o (only-files-listed)
# per the team-commit-protocol rule. NO `git add -A`. NO rebase. NO stash.
set -e
cd /mnt/d/Sundeep/projects/kite-mcp-server

# First, stage the new plugins/go.mod and plugins/go.sum (untracked)
git add plugins/go.mod plugins/go.sum

# Commit only the listed paths via -o (other working-tree changes won't be touched)
git commit -o \
  Dockerfile \
  Dockerfile.selfhost \
  go.mod \
  go.work \
  plugins/go.mod \
  plugins/go.sum \
  -F .research/anchor_tier6_commit_msg.txt

echo ""
echo "--- git log -1 ---"
git log --oneline -1

echo ""
echo "--- git status --porcelain | grep -v '^??' ---"
git status --porcelain | grep -v '^??' || echo '(no modified files)'
