#!/bin/sh
# Install git hooks for kite-mcp-server contributors
set -e

HOOK_DIR=".githooks"
if [ ! -d "$HOOK_DIR" ]; then
  echo "error: run from repo root"
  exit 1
fi

# Modern approach: set core.hooksPath (versioned hooks, no copy needed)
git config core.hooksPath "$HOOK_DIR"
chmod +x "$HOOK_DIR/pre-commit"

echo "Installed: .githooks/pre-commit (via core.hooksPath)"
echo "Uninstall: git config --unset core.hooksPath"
