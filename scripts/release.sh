#!/bin/sh
# One-command release flow: tag + push + create GitHub Release + attach SBOM
#
# Usage: ./scripts/release.sh v1.1.0 [--dry-run]
# Assumes: current branch is master, working tree clean, gh CLI authenticated

set -e

if [ -z "$1" ]; then
  echo "Usage: $0 <tag> [--dry-run]"
  echo "Example: $0 v1.1.0"
  exit 1
fi

TAG="$1"
DRY=""
if [ "$2" = "--dry-run" ]; then
  DRY="echo [DRY] "
fi

# Validate tag format
echo "$TAG" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$' || {
  echo "error: tag must be vMAJOR.MINOR.PATCH (e.g. v1.1.0)"
  exit 1
}

# Pre-flight checks
BRANCH=$(git rev-parse --abbrev-ref HEAD)
[ "$BRANCH" = "master" ] || { echo "error: must be on master, currently on $BRANCH"; exit 1; }

CLEAN=$(git status --porcelain | grep -v '^??' || true)
[ -z "$CLEAN" ] || { echo "error: working tree has uncommitted changes"; exit 1; }

UP_TO_DATE=$(git fetch origin master 2>&1 && git rev-list HEAD..origin/master --count)
[ "$UP_TO_DATE" = "0" ] || { echo "error: local master is behind origin by $UP_TO_DATE commits"; exit 1; }

# Locate release notes
NOTES_FILE="docs/release-notes-${TAG}.md"
[ -f "$NOTES_FILE" ] || {
  echo "error: $NOTES_FILE not found — create it first"
  exit 1
}

echo "Preparing release $TAG"
echo "  branch: $BRANCH (clean, up to date with origin)"
echo "  notes:  $NOTES_FILE"
echo ""

# Build SBOM locally (mirrors CI)
if command -v cyclonedx-gomod >/dev/null 2>&1; then
  $DRY cyclonedx-gomod mod -licenses -json -output-file "kite-mcp-sbom-${TAG}.cdx.json"
  $DRY cyclonedx-gomod mod -licenses -output-file "kite-mcp-sbom-${TAG}.cdx.xml"
  echo "SBOM generated (JSON + XML)"
else
  echo "warning: cyclonedx-gomod not installed; skipping SBOM generation"
  echo "         install: go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest"
fi

# Tag
$DRY git tag -a "$TAG" -m "Release $TAG"

# Push tag
$DRY git push origin "$TAG"

# Create GitHub Release
SBOM_ARGS=""
[ -f "kite-mcp-sbom-${TAG}.cdx.json" ] && SBOM_ARGS="$SBOM_ARGS kite-mcp-sbom-${TAG}.cdx.json"
[ -f "kite-mcp-sbom-${TAG}.cdx.xml" ] && SBOM_ARGS="$SBOM_ARGS kite-mcp-sbom-${TAG}.cdx.xml"

$DRY gh release create "$TAG" --title "Release $TAG" --notes-file "$NOTES_FILE" $SBOM_ARGS

echo ""
echo "Release $TAG created: https://github.com/Sundeepg98/kite-mcp-server/releases/tag/$TAG"
echo "Next: flyctl deploy -a kite-mcp-server"
