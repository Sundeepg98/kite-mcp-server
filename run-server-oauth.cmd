@echo off
:: ============================================================================
:: Local dev launcher (OAuth mode) for kite-mcp-server (Windows CMD)
:: ============================================================================
:: SECURITY 2026-05-11: literal credentials were redacted after public-repo leak
:: discovered in showhn-redteam audit. ALL FOUR secret-pattern values below
:: MUST be set via env (Windows User Environment Variables) or via a gitignored
:: local copy of this file (run-server-oauth.local.cmd).
::
:: Rotate the Kite local-dev app at kite.trade -> My Apps BEFORE first use.
:: Generate a fresh OAUTH_JWT_SECRET (64+ random bytes, base64).
:: ============================================================================

:: Kite developer app credentials -- rotate before each use (see SECURITY note).
if "%KITE_API_KEY%"=="" echo [warn] KITE_API_KEY not set -- server starts in per-user OAuth-only mode
if "%KITE_API_SECRET%"=="" echo [warn] KITE_API_SECRET not set -- server starts in per-user OAuth-only mode

:: Optional: short-lived dev access token (skips browser login). Daily expiry.
:: To use: set KITE_ACCESS_TOKEN in your Windows env vars before running.

:: REQUIRED for OAuth mode: 64+ byte base64 secret used to sign MCP bearer JWTs
:: and to derive the AES-256-GCM key for credential/token-at-rest encryption.
:: NEVER commit a literal value. Generate locally with:
::   powershell -Command "[Convert]::ToBase64String((1..64 | %% { Get-Random -Min 0 -Max 256 }))"
if "%OAUTH_JWT_SECRET%"=="" (
  echo [error] OAUTH_JWT_SECRET must be set for OAuth mode; aborting.
  exit /b 1
)

set LOG_LEVEL=debug
set APP_MODE=http
set APP_PORT=8080
set EXTERNAL_URL=http://localhost:8080
D:\Sundeep\projects\kite-mcp-server\kite-mcp-server.exe 2>> D:\Sundeep\projects\kite-mcp-server\server.log
