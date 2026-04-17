#!/usr/bin/env bash
# smoke-test.sh - End-to-end smoke test for a deployed Kite MCP Server.
#
# Usage:
#   ./scripts/smoke-test.sh                                # defaults to https://kite-mcp-server.fly.dev
#   ./scripts/smoke-test.sh https://other-host.example     # test a custom URL
#
# Exits 0 if all checks pass, 1 if any fail. Runs 9 checks in ~5-15s total.
# POSIX-ish; works under Git Bash on Windows. Requires curl. Uses jq if present,
# falls back to grep otherwise.

set -u

BASE_URL="${1:-https://kite-mcp-server.fly.dev}"
BASE_URL="${BASE_URL%/}"   # strip any trailing slash

# Kite API key used as OAuth client_id by the server (Fly.io deployment).
# Public information - NOT a secret. See: oauth/handlers.go.
TEST_CLIENT_ID="mmo8qxk1ccrcplad"
# RFC 7636 test vector PKCE challenge (S256 of a fixed verifier).
TEST_CODE_CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

# --------- Colors (only if terminal supports them) ----------
if command -v tput >/dev/null 2>&1 && [ -t 1 ] && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
  C_GREEN="$(tput setaf 2)"
  C_RED="$(tput setaf 1)"
  C_YELLOW="$(tput setaf 3)"
  C_DIM="$(tput dim 2>/dev/null || echo)"
  C_BOLD="$(tput bold 2>/dev/null || echo)"
  C_RESET="$(tput sgr0)"
else
  C_GREEN=""; C_RED=""; C_YELLOW=""; C_DIM=""; C_BOLD=""; C_RESET=""
fi

HAVE_JQ=0
if command -v jq >/dev/null 2>&1; then HAVE_JQ=1; fi

PASS=0
FAIL=0
TOTAL=0
FAILED_CHECKS=""
START_EPOCH="$(date +%s)"

# ---------- tiny helpers ----------
ok()   { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); printf "  %s\xE2\x9C\x93%s %s %s%s%s\n" "$C_GREEN" "$C_RESET" "$1" "$C_DIM" "$2" "$C_RESET"; }
bad()  { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); FAILED_CHECKS="${FAILED_CHECKS}  - $1\n"; printf "  %s\xE2\x9C\x97%s %s %s%s%s\n" "$C_RED" "$C_RESET" "$1" "$C_YELLOW" "$2" "$C_RESET"; }
warn() { printf "  %s!%s %s %s%s%s\n" "$C_YELLOW" "$C_RESET" "$1" "$C_DIM" "$2" "$C_RESET"; }

# curl with a sane default timeout; prints status code
status_of() {
  # $1 = url, $2... = extra curl args
  local url="$1"; shift
  curl -sS --max-time 5 -o /dev/null -w "%{http_code}" "$@" "$url" 2>/dev/null || echo "000"
}

# fetch body + status into temp files; echoes status, writes body to $2
fetch() {
  local url="$1"; local body_file="$2"; shift 2
  curl -sS --max-time 5 -o "$body_file" -w "%{http_code}" "$@" "$url" 2>/dev/null || echo "000"
}

# extract a JSON scalar by key. Uses jq if available, otherwise greedy grep -o.
json_get() {
  local key="$1"; local file="$2"
  if [ "$HAVE_JQ" -eq 1 ]; then
    jq -r ".$key // empty" <"$file" 2>/dev/null
  else
    # fallback: match "key": "value" or "key": literal (non-nested values only)
    grep -oE "\"$key\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$file" 2>/dev/null \
      | head -1 | sed -E "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"([^\"]*)\"/\1/"
  fi
}

json_has_key() {
  local key="$1"; local file="$2"
  if [ "$HAVE_JQ" -eq 1 ]; then
    jq -e "has(\"$key\")" <"$file" >/dev/null 2>&1
  else
    grep -qE "\"$key\"[[:space:]]*:" "$file"
  fi
}

# ---------- intro ----------
printf "%s==>%s Smoke-testing %s%s%s\n" "$C_BOLD" "$C_RESET" "$C_BOLD" "$BASE_URL" "$C_RESET"
if [ "$HAVE_JQ" -eq 0 ]; then
  warn "jq not found" "(using grep fallback - install jq for stricter JSON checks)"
fi
echo

TMPDIR="${TMPDIR:-/tmp}"
TS="$$-$(date +%s)"
HEALTH_BODY="$TMPDIR/smoke-health-$TS.txt"
HEALTH_JSON="$TMPDIR/smoke-healthjson-$TS.json"
OAUTH_AS="$TMPDIR/smoke-oauth-as-$TS.json"
OAUTH_PR="$TMPDIR/smoke-oauth-pr-$TS.json"
LANDING_HTML="$TMPDIR/smoke-landing-$TS.html"
trap 'rm -f "$HEALTH_BODY" "$HEALTH_JSON" "$OAUTH_AS" "$OAUTH_PR" "$LANDING_HTML"' EXIT

# ---------- 1. /healthz returns 200 within 5s ----------
code="$(fetch "$BASE_URL/healthz" "$HEALTH_BODY")"
if [ "$code" = "200" ] && [ -s "$HEALTH_BODY" ]; then
  # server returns JSON by default; that's fine - just verify non-empty 200 response
  size="$(wc -c <"$HEALTH_BODY" | tr -d ' ')"
  ok "GET /healthz returns 200" "(${size} bytes)"
else
  bad "GET /healthz returned $code" "(expected 200; body $(wc -c <"$HEALTH_BODY" 2>/dev/null || echo 0) bytes)"
fi

# ---------- 2. /healthz?format=json is valid JSON with status ok/degraded ----------
code="$(fetch "$BASE_URL/healthz?format=json" "$HEALTH_JSON")"
if [ "$code" != "200" ]; then
  bad "GET /healthz?format=json returned $code" "(expected 200)"
else
  status_val="$(json_get status "$HEALTH_JSON")"
  case "$status_val" in
    ok)
      tools="$(json_get tools "$HEALTH_JSON")"
      version="$(json_get version "$HEALTH_JSON")"
      ok "/healthz?format=json -> status=ok" "(version=${version:-?} tools=${tools:-?})"
      ;;
    degraded)
      # surface which component is flagged, if server exposes it
      if [ "$HAVE_JQ" -eq 1 ]; then
        flagged="$(jq -r '[.checks // {} | to_entries[] | select(.value != "ok" and .value != true) | .key] | join(",")' <"$HEALTH_JSON" 2>/dev/null)"
      else
        flagged="(see response)"
      fi
      warn "/healthz?format=json -> status=degraded" "(${flagged:-no detail})"
      PASS=$((PASS+1)); TOTAL=$((TOTAL+1))   # degraded is not a hard failure
      ;;
    "")
      bad "/healthz?format=json missing 'status' field" "(not valid JSON or wrong schema)"
      ;;
    *)
      bad "/healthz?format=json returned status=$status_val" "(expected 'ok' or 'degraded')"
      ;;
  esac
fi

# ---------- 3. /.well-known/oauth-authorization-server ----------
code="$(fetch "$BASE_URL/.well-known/oauth-authorization-server" "$OAUTH_AS")"
if [ "$code" != "200" ]; then
  bad "/.well-known/oauth-authorization-server returned $code" "(expected 200)"
elif ! json_has_key authorization_endpoint "$OAUTH_AS"; then
  bad "/.well-known/oauth-authorization-server missing authorization_endpoint" ""
elif ! json_has_key token_endpoint "$OAUTH_AS"; then
  bad "/.well-known/oauth-authorization-server missing token_endpoint" ""
else
  auth_ep="$(json_get authorization_endpoint "$OAUTH_AS")"
  ok "OAuth AS metadata present" "(authorization_endpoint=${auth_ep})"
fi

# ---------- 4. /.well-known/oauth-protected-resource ----------
code="$(fetch "$BASE_URL/.well-known/oauth-protected-resource" "$OAUTH_PR")"
if [ "$code" != "200" ]; then
  bad "/.well-known/oauth-protected-resource returned $code" "(expected 200)"
elif ! json_has_key resource "$OAUTH_PR"; then
  bad "/.well-known/oauth-protected-resource missing 'resource' key" ""
else
  res="$(json_get resource "$OAUTH_PR")"
  ok "OAuth protected-resource metadata present" "(resource=${res})"
fi

# ---------- 5. / landing page with IP whitelist warning ----------
code="$(fetch "$BASE_URL/" "$LANDING_HTML")"
if [ "$code" != "200" ]; then
  bad "GET / returned $code" "(expected 200 HTML)"
elif ! grep -q "209\.71\.68\.157" "$LANDING_HTML"; then
  bad "Landing page missing IP '209.71.68.157'" "(new landing template may not be deployed yet)"
else
  ok "Landing page contains static egress IP" "(209.71.68.157 present)"
fi

# ---------- 6. /mcp returns 401 or 405 (NOT 500) without auth ----------
code="$(status_of "$BASE_URL/mcp")"
case "$code" in
  401|405) ok "GET /mcp rejects unauthenticated request" "(HTTP $code)" ;;
  500|502|503|504) bad "GET /mcp returned $code" "(server error - middleware may be broken)" ;;
  000) bad "GET /mcp not reachable" "(network/timeout)" ;;
  *) bad "GET /mcp returned $code" "(expected 401 or 405)" ;;
esac

# ---------- 7. /oauth/authorize without params returns 400 ----------
code="$(status_of "$BASE_URL/oauth/authorize")"
case "$code" in
  400) ok "/oauth/authorize (no params) returns 400" "(handler is live)" ;;
  000) bad "/oauth/authorize not reachable" "(network/timeout)" ;;
  *)   bad "/oauth/authorize (no params) returned $code" "(expected 400)" ;;
esac

# ---------- 8. /oauth/authorize with valid params 302s to kite.zerodha.com ----------
auth_url="$BASE_URL/oauth/authorize?response_type=code&client_id=$TEST_CLIENT_ID&redirect_uri=http%3A%2F%2Flocalhost%3A8765%2Fcallback&state=smoketest&code_challenge=$TEST_CODE_CHALLENGE&code_challenge_method=S256"
code="$(curl -sS --max-time 5 -o /dev/null -w "%{http_code}" "$auth_url" 2>/dev/null || echo "000")"
redirect="$(curl -sS --max-time 5 -o /dev/null -w "%{redirect_url}" "$auth_url" 2>/dev/null || echo "")"
if [ "$code" != "302" ]; then
  bad "/oauth/authorize with valid params returned $code" "(expected 302)"
elif ! printf "%s" "$redirect" | grep -q "kite\.zerodha\.com"; then
  bad "/oauth/authorize 302 target is not kite.zerodha.com" "(redirect=${redirect:-empty})"
else
  ok "/oauth/authorize falls through to Kite login" "(302 -> kite.zerodha.com)"
fi

# ---------- 9. /healthz warm response-time sanity ----------
# The first 1-2 requests include TLS handshake + TCP warm-up, which regularly
# exceed 500ms even on a perfectly healthy server. Warm with 2 throwaway
# requests, then measure 5. This check catches real app-layer regressions.
curl -sS --max-time 5 -o /dev/null "$BASE_URL/healthz" 2>/dev/null || true
curl -sS --max-time 5 -o /dev/null "$BASE_URL/healthz" 2>/dev/null || true
max_ms=0
samples=""
i=1
while [ "$i" -le 5 ]; do
  t="$(curl -sS --max-time 5 -o /dev/null -w "%{time_total}" "$BASE_URL/healthz" 2>/dev/null || echo "9.999")"
  # convert seconds float to integer milliseconds (POSIX awk)
  ms="$(awk -v t="$t" 'BEGIN { printf "%d", t * 1000 }' 2>/dev/null || echo 9999)"
  if [ "$ms" -gt "$max_ms" ]; then
    max_ms=$ms
  fi
  samples="$samples ${ms}ms"
  i=$((i+1))
done
if [ "$max_ms" -lt 500 ]; then
  ok "/healthz warm response under 500ms" "(max=${max_ms}ms across 5)"
else
  bad "/healthz warm response over 500ms" "(max=${max_ms}ms; samples:${samples})"
fi

# ---------- summary ----------
echo
END_EPOCH="$(date +%s)"
ELAPSED=$((END_EPOCH - START_EPOCH))
if [ "$FAIL" -eq 0 ]; then
  printf "%s==>%s %s%d/%d checks passed%s in %ds\n" "$C_BOLD" "$C_RESET" "$C_GREEN" "$PASS" "$TOTAL" "$C_RESET" "$ELAPSED"
  exit 0
else
  printf "%s==>%s %s%d/%d checks passed%s in %ds\n" "$C_BOLD" "$C_RESET" "$C_RED" "$PASS" "$TOTAL" "$C_RESET" "$ELAPSED"
  printf "%sFailed:%s\n" "$C_RED" "$C_RESET"
  printf "%b" "$FAILED_CHECKS"
  exit 1
fi
