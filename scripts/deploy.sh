#!/usr/bin/env bash
# deploy.sh - Push, deploy to Fly.io, wait for machine, then smoke-test.
#
# Usage:
#   ./scripts/deploy.sh                             # deploy to default app (kite-mcp-server)
#   ./scripts/deploy.sh --skip-push                 # skip git push (use if already pushed)
#   ./scripts/deploy.sh --app other-app             # deploy to a different Fly app
#
# Does NOT auto-rollback on smoke-test failure - prints the rollback command
# and lets the human decide.

set -u

APP="kite-mcp-server"
SKIP_PUSH=0
SMOKE_URL=""

while [ $# -gt 0 ]; do
  case "$1" in
    --skip-push) SKIP_PUSH=1; shift ;;
    --app) APP="$2"; shift 2 ;;
    --url) SMOKE_URL="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# ---------- colors ----------
if command -v tput >/dev/null 2>&1 && [ -t 1 ] && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
  C_GREEN="$(tput setaf 2)"; C_RED="$(tput setaf 1)"
  C_YELLOW="$(tput setaf 3)"; C_CYAN="$(tput setaf 6)"
  C_BOLD="$(tput bold 2>/dev/null || echo)"; C_RESET="$(tput sgr0)"
else
  C_GREEN=""; C_RED=""; C_YELLOW=""; C_CYAN=""; C_BOLD=""; C_RESET=""
fi

step() { printf "\n%s==>%s %s%s%s\n" "$C_BOLD$C_CYAN" "$C_RESET" "$C_BOLD" "$1" "$C_RESET"; }
die()  { printf "%s[error]%s %s\n" "$C_RED$C_BOLD" "$C_RESET" "$1" >&2; exit 1; }
note() { printf "%s[info]%s %s\n" "$C_YELLOW" "$C_RESET" "$1"; }

# ---------- locate flyctl ----------
FLYCTL=""
if command -v flyctl >/dev/null 2>&1; then
  FLYCTL="flyctl"
elif command -v flyctl.exe >/dev/null 2>&1; then
  FLYCTL="flyctl.exe"
elif [ -x "$HOME/.fly/bin/flyctl" ]; then
  FLYCTL="$HOME/.fly/bin/flyctl"
elif [ -x "$HOME/.fly/bin/flyctl.exe" ]; then
  FLYCTL="$HOME/.fly/bin/flyctl.exe"
elif [ -x "/c/Users/$USER/.fly/bin/flyctl.exe" ]; then
  FLYCTL="/c/Users/$USER/.fly/bin/flyctl.exe"
else
  die "flyctl not found in PATH or ~/.fly/bin. Install from https://fly.io/docs/flyctl/install/"
fi
note "using flyctl: $FLYCTL"

# ---------- script dir (so smoke-test.sh works regardless of CWD) ----------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SMOKE_TEST="$SCRIPT_DIR/smoke-test.sh"
if [ ! -x "$SMOKE_TEST" ]; then
  if [ -f "$SMOKE_TEST" ]; then
    note "making smoke-test.sh executable"
    chmod +x "$SMOKE_TEST" 2>/dev/null || true
  else
    die "smoke-test.sh not found at $SMOKE_TEST"
  fi
fi

# ---------- 1. git push ----------
if [ "$SKIP_PUSH" -eq 0 ]; then
  step "git push"
  if ! git rev-parse --git-dir >/dev/null 2>&1; then
    die "not inside a git repo"
  fi
  current_branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo HEAD)"
  note "branch: $current_branch"
  if ! git push; then
    die "git push failed - fix before deploying"
  fi
else
  note "skipping git push (--skip-push)"
fi

# ---------- 2. capture pre-deploy release version (for rollback hint) ----------
PREV_VERSION=""
if PREV_VERSION="$("$FLYCTL" releases -a "$APP" --json 2>/dev/null | head -c 8192)"; then
  if command -v jq >/dev/null 2>&1; then
    PREV_VERSION="$(printf "%s" "$PREV_VERSION" | jq -r '.[0].Version // .[0].version // empty' 2>/dev/null || echo "")"
  else
    # crude grep fallback: first "Version":N
    PREV_VERSION="$(printf "%s" "$PREV_VERSION" | grep -oE '"[Vv]ersion":[0-9]+' | head -1 | grep -oE '[0-9]+' || echo "")"
  fi
fi
note "current release version: ${PREV_VERSION:-unknown}"

# ---------- 3. flyctl deploy ----------
step "flyctl deploy -a $APP"
DEPLOY_START=$(date +%s)
if ! "$FLYCTL" deploy -a "$APP"; then
  die "flyctl deploy failed - check output above. Nothing to roll back (deploy aborted)."
fi
DEPLOY_ELAPSED=$(( $(date +%s) - DEPLOY_START ))
note "deploy command completed in ${DEPLOY_ELAPSED}s"

# ---------- 4. wait for machine state=started ----------
step "waiting for machine to be started"
waited=0
max_wait=180
started=0
while [ "$waited" -lt "$max_wait" ]; do
  # "flyctl status" exits 0 and prints state table; grep for 'started'
  status_out="$("$FLYCTL" status -a "$APP" 2>/dev/null || true)"
  if printf "%s" "$status_out" | grep -qiE '(\bstarted\b|state[[:space:]]*=[[:space:]]*started)'; then
    started=1
    break
  fi
  sleep 3
  waited=$((waited+3))
  printf "."
done
echo
if [ "$started" -ne 1 ]; then
  die "machine did not reach 'started' state within ${max_wait}s - check 'flyctl status -a $APP' and 'flyctl logs -a $APP'"
fi
note "machine is started (took ${waited}s)"

# Give the app a couple seconds after 'started' for Litestream restore + HTTP bind
sleep 3

# ---------- 5. smoke test ----------
step "running smoke-test.sh"
URL="$SMOKE_URL"
if [ -z "$URL" ]; then
  URL="https://${APP}.fly.dev"
fi

if bash "$SMOKE_TEST" "$URL"; then
  printf "\n%s==>%s %sDeploy successful and smoke test passed%s\n" \
    "$C_BOLD$C_GREEN" "$C_RESET" "$C_GREEN$C_BOLD" "$C_RESET"
  exit 0
else
  printf "\n%s==>%s %sSMOKE TEST FAILED%s\n" "$C_BOLD$C_RED" "$C_RESET" "$C_RED$C_BOLD" "$C_RESET"
  printf "%sDeploy went out but health checks did not all pass.%s\n" "$C_YELLOW" "$C_RESET"
  echo
  echo "Options:"
  echo "  1. Investigate logs:"
  echo "       $FLYCTL logs -a $APP"
  echo "  2. Check status:"
  echo "       $FLYCTL status -a $APP"
  if [ -n "$PREV_VERSION" ]; then
    echo "  3. Rollback to previous release (v${PREV_VERSION}):"
    echo "       $FLYCTL releases rollback ${PREV_VERSION} -a $APP"
  else
    echo "  3. Rollback: list releases then pick one:"
    echo "       $FLYCTL releases -a $APP"
    echo "       $FLYCTL releases rollback <VERSION> -a $APP"
  fi
  echo "  4. Re-run smoke test only:"
  echo "       bash $SMOKE_TEST $URL"
  exit 1
fi
