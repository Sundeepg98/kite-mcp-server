#!/usr/bin/env bash
# scripts/agent-worktree-init.sh — per-agent git worktree initialization
#
# Purpose: create an isolated working tree for one named agent role + task,
# avoiding the concurrent-edit friction observed when multiple Claude
# Code agents share a single working directory.
#
# Why: per .claude/team/config.yaml and user_team_commit_protocol.md, the
# fallback to scoped commits (`git commit -o -- <paths>`) is brittle when
# 3+ agents land changes in the same minute. Worktrees give each agent a
# dedicated checkout + dedicated branch + dedicated build cache.
#
# Why NOT git stash: per feedback_no_stash_anywhere.md, `git stash` is
# forbidden everywhere. Worktrees are the canonical isolation primitive.
#
# Usage:
#   ./scripts/agent-worktree-init.sh <agent-role> <short-task-name>
#
# Examples:
#   ./scripts/agent-worktree-init.sh chain v229-deploy
#   ./scripts/agent-worktree-init.sh path-a-owner kc-i18n-promotion
#   ./scripts/agent-worktree-init.sh audit scanner-phase-4
#   ./scripts/agent-worktree-init.sh capacity-architect 100k-blockers
#
# Output:
#   Creates: .claude/worktrees/<agent-role>/<short-task-name>/
#   Branch:  agent/<agent-role>/<short-task-name> (off master)
#   Working tree pre-checked-out, ready for the agent to cd in and work.
#
# Idempotency:
#   - If branch exists locally: re-uses it (DOES NOT reset).
#   - If worktree dir exists: errors out (use cleanup script first).
#
# After completion:
#   1. cd into the printed path
#   2. Make changes, run tests in WSL2
#   3. git commit -o -- <paths>
#   4. git push origin <branch>     (or merge into master per protocol)
#   5. ./scripts/agent-worktree-cleanup.sh <agent-role> <short-task-name>

set -euo pipefail

usage() {
  cat <<EOF >&2
Usage: $0 <agent-role> <short-task-name>

Agent roles (per .claude/team/config.yaml):
  chain               - Deploy/release pipeline
  audit               - Feature TDD work
  path-a-owner        - Module promotion to algo2go org
  playwright          - Visual verification / UI tests
  capacity-architect  - Research docs (.research/ only)

Short task name should be kebab-case, e.g.:
  v229-deploy
  kc-i18n-promotion
  scanner-phase-4
EOF
  exit 64  # EX_USAGE
}

if [ "$#" -ne 2 ]; then
  usage
fi

AGENT_ROLE="$1"
TASK_NAME="$2"

# Validate agent role against config (best-effort; warn if unknown)
case "$AGENT_ROLE" in
  chain|audit|path-a-owner|playwright|capacity-architect)
    ;;
  *)
    echo "WARN: agent role '$AGENT_ROLE' not in canonical list (chain|audit|path-a-owner|playwright|capacity-architect)" >&2
    echo "      Update .claude/team/config.yaml if adding a new role." >&2
    ;;
esac

# Validate task name (kebab-case, no shell metacharacters)
if ! [[ "$TASK_NAME" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
  echo "ERROR: task name must be kebab-case (lowercase, digits, hyphens; cannot start with hyphen)" >&2
  echo "       got: '$TASK_NAME'" >&2
  exit 64
fi

# Locate repo root (script is meant to run from anywhere inside the repo)
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

WORKTREE_BASE="$REPO_ROOT/.claude/worktrees"
WORKTREE_DIR="$WORKTREE_BASE/$AGENT_ROLE/$TASK_NAME"
BRANCH_NAME="agent/$AGENT_ROLE/$TASK_NAME"

# Refuse to clobber existing worktree
if [ -d "$WORKTREE_DIR" ]; then
  echo "ERROR: worktree already exists at $WORKTREE_DIR" >&2
  echo "       Run: ./scripts/agent-worktree-cleanup.sh $AGENT_ROLE $TASK_NAME" >&2
  echo "       Or:  cd $WORKTREE_DIR  (re-use the existing worktree)" >&2
  exit 65  # EX_DATAERR
fi

# Ensure base directory exists
mkdir -p "$WORKTREE_BASE/$AGENT_ROLE"

# Verify master is clean enough to branch from (warn but don't block; some
# agents may want to start from an in-progress local state)
if ! git diff-index --quiet HEAD -- 2>/dev/null; then
  echo "WARN: working tree has uncommitted changes; new worktree branches from current HEAD." >&2
  echo "      If you want a clean branch from origin/master, commit/discard local changes first." >&2
fi

# Create the worktree + branch
echo "Creating worktree: $WORKTREE_DIR"
echo "On branch:        $BRANCH_NAME"
echo "Off:              $(git rev-parse --short HEAD) ($(git rev-parse --abbrev-ref HEAD))"

# `git worktree add -b <branch> <path>` creates branch + checkout in one shot.
# If branch already exists, drop -b and re-use it.
if git show-ref --verify --quiet "refs/heads/$BRANCH_NAME"; then
  echo "Branch $BRANCH_NAME already exists; re-using it."
  git worktree add "$WORKTREE_DIR" "$BRANCH_NAME"
else
  git worktree add -b "$BRANCH_NAME" "$WORKTREE_DIR"
fi

# Print next-step instructions
cat <<EOF

Worktree ready.

Next steps for the $AGENT_ROLE agent:
  cd $WORKTREE_DIR
  # ... make changes ...
  # WSL2 verification (per feedback_wsl_for_go_test.md):
  wsl -d Ubuntu-24.04 -- bash -c 'cd /mnt/d/Sundeep/projects/kite-mcp-server/.claude/worktrees/$AGENT_ROLE/$TASK_NAME && go build ./... && go test ./... -count=1 -timeout 5m'
  # ... commit (per user_team_commit_protocol.md): ...
  git commit -o -- <paths> -m "<msg>"
  git push origin $BRANCH_NAME

When done:
  # Either merge into master from this worktree:
  git checkout master && git merge --ff-only $BRANCH_NAME && git push origin master
  # Or open PR for review and let reviewer merge.
  # Then clean up:
  cd $REPO_ROOT
  ./scripts/agent-worktree-cleanup.sh $AGENT_ROLE $TASK_NAME

EOF
