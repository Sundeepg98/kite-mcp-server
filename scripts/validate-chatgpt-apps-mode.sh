#!/usr/bin/env bash
# validate-chatgpt-apps-mode.sh
# Pre-flight checks for connecting kite-mcp-server to ChatGPT Apps SDK (Developer Mode).
# Exits 0 on all-green, 1 on any red.

set -u
set -o pipefail

BASE_URL="${KITE_MCP_BASE_URL:-https://kite-mcp-server.fly.dev}"

# -------- ANSI colors (TTY-aware) --------
if [ -t 1 ]; then
  GREEN="$(printf '\033[0;32m')"
  RED="$(printf '\033[0;31m')"
  YELLOW="$(printf '\033[0;33m')"
  RESET="$(printf '\033[0m')"
else
  GREEN=""
  RED=""
  YELLOW=""
  RESET=""
fi

PASS_COUNT=0
FAIL_COUNT=0
NOTE_COUNT=0

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf "%sPASS%s  %s\n" "$GREEN" "$RESET" "$1"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  printf "%sFAIL%s  %s\n" "$RED" "$RESET" "$1"
}

note() {
  NOTE_COUNT=$((NOTE_COUNT + 1))
  printf "%sNOTE%s  %s\n" "$YELLOW" "$RESET" "$1"
}

# -------- jq-optional --------
HAVE_JQ=0
if command -v jq >/dev/null 2>&1; then
  HAVE_JQ=1
fi

TMPDIR_BASE="${TMPDIR:-/tmp}"
TMP_ROOT="$(mktemp -d "$TMPDIR_BASE/kite-mcp-validate.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT

printf "ChatGPT Apps SDK pre-flight — target: %s\n" "$BASE_URL"
printf "jq available: %s\n" "$([ "$HAVE_JQ" -eq 1 ] && echo yes || echo no)"
printf "%s\n" "------------------------------------------------------------"

# -------- Check 1: /healthz returns 200 --------
HEALTH_BODY="$TMP_ROOT/health.txt"
HEALTH_CODE="$(curl -sS -o "$HEALTH_BODY" -w "%{http_code}" "${BASE_URL}/healthz" || echo "000")"
if [ "$HEALTH_CODE" = "200" ]; then
  pass "GET /healthz -> 200"
else
  fail "GET /healthz -> ${HEALTH_CODE} (expected 200)"
fi

# -------- Check 2: /.well-known/mcp/server-card.json --------
CARD_BODY="$TMP_ROOT/card.json"
CARD_CODE="$(curl -sS -o "$CARD_BODY" -w "%{http_code}" "${BASE_URL}/.well-known/mcp/server-card.json" || echo "000")"
if [ "$CARD_CODE" = "200" ]; then
  if [ "$HAVE_JQ" -eq 1 ]; then
    HAS_SERVER_INFO="$(jq -r 'has("serverInfo")' <"$CARD_BODY" 2>/dev/null || echo "false")"
    HAS_TRANSPORT="$(jq -r 'has("transport") or has("transports")' <"$CARD_BODY" 2>/dev/null || echo "false")"
  else
    if grep -q '"serverInfo"' "$CARD_BODY"; then
      HAS_SERVER_INFO="true"
    else
      HAS_SERVER_INFO="false"
    fi
    if grep -q -E '"transport"|"transports"' "$CARD_BODY"; then
      HAS_TRANSPORT="true"
    else
      HAS_TRANSPORT="false"
    fi
  fi
  if [ "$HAS_SERVER_INFO" = "true" ] && [ "$HAS_TRANSPORT" = "true" ]; then
    pass "GET /.well-known/mcp/server-card.json -> 200 (serverInfo + transport present)"
  else
    fail "GET /.well-known/mcp/server-card.json -> 200 but missing serverInfo or transport (serverInfo=${HAS_SERVER_INFO} transport=${HAS_TRANSPORT})"
  fi
else
  fail "GET /.well-known/mcp/server-card.json -> ${CARD_CODE} (expected 200)"
fi

# -------- Check 3: /.well-known/oauth-authorization-server --------
AUTH_BODY="$TMP_ROOT/auth.json"
AUTH_CODE="$(curl -sS -o "$AUTH_BODY" -w "%{http_code}" "${BASE_URL}/.well-known/oauth-authorization-server" || echo "000")"
REG_ENDPOINT=""
if [ "$AUTH_CODE" = "200" ]; then
  if [ "$HAVE_JQ" -eq 1 ]; then
    REG_ENDPOINT="$(jq -r '.registration_endpoint // empty' <"$AUTH_BODY" 2>/dev/null || true)"
  else
    REG_ENDPOINT="$(sed -n 's/.*"registration_endpoint"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$AUTH_BODY" | head -n1)"
  fi
  if [ -n "$REG_ENDPOINT" ]; then
    pass "GET /.well-known/oauth-authorization-server -> 200 (registration_endpoint=${REG_ENDPOINT})"
  else
    fail "GET /.well-known/oauth-authorization-server -> 200 but registration_endpoint missing"
  fi
else
  fail "GET /.well-known/oauth-authorization-server -> ${AUTH_CODE} (expected 200)"
fi

# -------- Check 4: /.well-known/oauth-protected-resource --------
PR_BODY="$TMP_ROOT/pr.json"
PR_CODE="$(curl -sS -o "$PR_BODY" -w "%{http_code}" "${BASE_URL}/.well-known/oauth-protected-resource" || echo "000")"
if [ "$PR_CODE" = "200" ]; then
  pass "GET /.well-known/oauth-protected-resource -> 200"
else
  fail "GET /.well-known/oauth-protected-resource -> ${PR_CODE} (expected 200)"
fi

# -------- Check 5: Dynamic client registration --------
if [ -n "$REG_ENDPOINT" ]; then
  REG_REQ="$TMP_ROOT/reg-req.json"
  REG_RESP="$TMP_ROOT/reg-resp.json"
  cat >"$REG_REQ" <<'EOF'
{
  "client_name": "ChatGPT Apps validation pre-flight",
  "redirect_uris": ["https://chatgpt.com/connector/oauth/validate-preflight"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "client_secret_basic"
}
EOF
  REG_CODE="$(curl -sS -o "$REG_RESP" -w "%{http_code}" \
    -X POST "$REG_ENDPOINT" \
    -H "Content-Type: application/json" \
    --data-binary "@$REG_REQ" || echo "000")"
  if [ "$REG_CODE" = "201" ]; then
    if [ "$HAVE_JQ" -eq 1 ]; then
      HAS_CLIENT_ID="$(jq -r 'has("client_id")' <"$REG_RESP" 2>/dev/null || echo "false")"
      HAS_CLIENT_SECRET="$(jq -r 'has("client_secret")' <"$REG_RESP" 2>/dev/null || echo "false")"
    else
      if grep -q '"client_id"' "$REG_RESP"; then
        HAS_CLIENT_ID="true"
      else
        HAS_CLIENT_ID="false"
      fi
      if grep -q '"client_secret"' "$REG_RESP"; then
        HAS_CLIENT_SECRET="true"
      else
        HAS_CLIENT_SECRET="false"
      fi
    fi
    if [ "$HAS_CLIENT_ID" = "true" ] && [ "$HAS_CLIENT_SECRET" = "true" ]; then
      pass "POST ${REG_ENDPOINT} -> 201 (client_id + client_secret returned)"
    else
      fail "POST ${REG_ENDPOINT} -> 201 but missing client_id/client_secret (client_id=${HAS_CLIENT_ID} client_secret=${HAS_CLIENT_SECRET})"
    fi
  else
    fail "POST ${REG_ENDPOINT} -> ${REG_CODE} (expected 201)"
  fi
else
  fail "Skipped client registration — no registration_endpoint from Check 3"
fi

# -------- Check 6: POST /mcp without bearer MUST return 401 --------
MCP_BODY="$TMP_ROOT/mcp.txt"
MCP_HEADERS="$TMP_ROOT/mcp-headers.txt"
MCP_CODE="$(curl -sS -o "$MCP_BODY" -D "$MCP_HEADERS" -w "%{http_code}" \
  -X POST "${BASE_URL}/mcp" \
  -H "Content-Type: application/json" \
  --data-binary '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' || echo "000")"
if [ "$MCP_CODE" = "401" ]; then
  pass "POST /mcp (no bearer) -> 401 (auth enforced)"
else
  fail "POST /mcp (no bearer) -> ${MCP_CODE} (expected 401)"
fi

# -------- Check 7: WWW-Authenticate header on /mcp 401 (informational) --------
if [ "$MCP_CODE" = "401" ]; then
  if grep -qi '^WWW-Authenticate:' "$MCP_HEADERS"; then
    WWW_AUTH_VALUE="$(grep -i '^WWW-Authenticate:' "$MCP_HEADERS" | head -n1 | sed 's/\r$//')"
    pass "WWW-Authenticate header present on /mcp 401 (${WWW_AUTH_VALUE})"
  else
    note "WWW-Authenticate header missing on /mcp 401 — informational, not fatal"
  fi
else
  note "Skipped WWW-Authenticate check — /mcp did not return 401"
fi

# -------- Summary --------
printf "%s\n" "------------------------------------------------------------"
printf "Summary: %sPASS=%d%s  %sFAIL=%d%s  %sNOTE=%d%s\n" \
  "$GREEN" "$PASS_COUNT" "$RESET" \
  "$RED" "$FAIL_COUNT" "$RESET" \
  "$YELLOW" "$NOTE_COUNT" "$RESET"

if [ "$FAIL_COUNT" -eq 0 ]; then
  printf "%sAll checks green.%s Proceed with docs/chatgpt-apps-validation.md Step 2.\n" "$GREEN" "$RESET"
  exit 0
else
  printf "%sOne or more checks failed.%s Fix before attempting ChatGPT connector setup.\n" "$RED" "$RESET"
  exit 1
fi
