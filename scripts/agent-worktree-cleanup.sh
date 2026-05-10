#!/usr/bin/env bash
# scripts/agent-worktree-cleanup.sh — tear down a per-agent worktree
#
# Companion to agent-worktree-init.sh. Removes the worktree and (optionally)
# the branch.
#
# Usage:
#   ./scripts/agent-worktree-cleanup.sh <agent-role> <short-task-name> [--keep-branch]
#
# Default: removes worktree + deletes the branch (if merged into master).
# With --keep-branch: removes worktree but preserves the branch.
#
# Refuses to delete:
#   - branches with unmerged commits (use --force if you really want to)
#   - worktrees with uncommitted changes (commit or discard first)

set -euo pipefail

usage() {
  cat <<EOF >&2
Usage: $0 <agent-role> <short-task-name> [--keep-branch] [--force]

Examples:
  $0 chain v229-deploy
  $0 path-a-owner kc-i18n-promotion --keep-branch
  $0 audit scanner-phase-4 --force
EOF
  exit 64
}

if [ "$#" -lt 2 ] || [ "$#" -gt 4 ]; then
  usage
fi

AGENT_ROLE="$1"
TASK_NAME="$2"
shift 2

KEEP_BRANCH=false
FORCE=false
for arg in "$@"; do
  case "$arg" in
    --keep-branch) KEEP_BRANCH=true ;;
    --force) FORCE=true ;;
    *) echo "ERROR: unknown flag '$arg'" >&2; usage ;;
  esac
done

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

WORKTREE_DIR="$REPO_ROOT/.claude/worktrees/$AGENT_ROLE/$TASK_NAME"
BRANCH_NAME="agent/$AGENT_ROLE/$TASK_NAME"

if [ ! -d "$WORKTREE_DIR" ]; then
  echo "WARN: worktree dir not found at $WORKTREE_DIR — nothing to clean" >&2
fi

# Check for uncommitted changes in the worktree
if [ -d "$WORKTREE_DIR" ] && [ "$FORCE" != "true" ]; then
  if ! (cd "$WORKTREE_DIR" && git diff-index --quiet HEAD -- 2>/dev/null); then
    echo "ERROR: worktree at $WORKTREE_DIR has uncommitted changes" >&2
    echo "       Commit/push them, or pass --force to discard." >&2
    exit 65
  fi
fi

# Remove the worktree
if [ -d "$WORKTREE_DIR" ]; then
  echo "Removing worktree: $WORKTREE_DIR"
  if [ "$FORCE" = "true" ]; then
    git worktree remove --force "$WORKTREE_DIR"
  else
    git worktree remove "$WORKTREE_DIR"
  fi
fi

# Prune any stale worktree refs
git worktree prune

# Optionally delete the branch
if [ "$KEEP_BRANCH" = "true" ]; then
  echo "Keeping branch $BRANCH_NAME (per --keep-branch flag)"
else
  if git show-ref --verify --quiet "refs/heads/$BRANCH_NAME"; then
    if [ "$FORCE" = "true" ]; then
      echo "Force-deleting branch $BRANCH_NAME"
      git branch -D "$BRANCH_NAME"
    else
      # `-d` refuses to delete unmerged branches; that's the safety we want
      if git branch -d "$BRANCH_NAME" 2>/dev/null; then
        echo "Deleted branch $BRANCH_NAME"
      else
        echo "WARN: branch $BRANCH_NAME has unmerged commits; preserving it." >&2
        echo "      Use --force to delete anyway, or merge it first." >&2
      fi
    fi
  else
    echo "Branch $BRANCH_NAME not found locally (already deleted?)"
  fi
fi

# Clean up empty parent directory
rmdir "$REPO_ROOT/.claude/worktrees/$AGENT_ROLE" 2>/dev/null || true

echo "Cleanup complete."
