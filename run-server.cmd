@echo off
:: ============================================================================
:: Local dev launcher for kite-mcp-server (Windows CMD)
:: ============================================================================
:: SECURITY 2026-05-11: literal credentials were redacted after public-repo leak
:: discovered in showhn-redteam audit. ALL three values below MUST be rotated
:: in the Kite developer console (kite.trade -> My Apps) BEFORE running this.
::
:: To use this launcher, EITHER:
::   (a) Set the three KITE_* variables in your Windows User Environment
::       (System Properties -> Environment Variables); this script picks them up.
::   (b) Copy this file to run-server.local.cmd (gitignored), populate the
::       three `set` lines below with the freshly-rotated values, and run that.
::
:: NEVER commit a copy with literal values. Pre-commit secret-scan hook will
:: block such a write. See .env.example for the canonical list of env vars.
:: ============================================================================

:: Required: Kite developer app credentials (rotate before each use).
:: If unset, the server still starts in OAuth-only mode (per-user creds via MCP).
if "%KITE_API_KEY%"=="" echo [warn] KITE_API_KEY not set -- server starts in per-user OAuth-only mode
if "%KITE_API_SECRET%"=="" echo [warn] KITE_API_SECRET not set -- server starts in per-user OAuth-only mode

:: Optional: short-lived dev access token (skips browser login).
:: Expires ~6 AM IST daily; NEVER commit a value here.
:: To use: set KITE_ACCESS_TOKEN in your Windows env vars before running.

set LOG_LEVEL=debug
set APP_MODE=http
set APP_PORT=8080
D:\Sundeep\projects\kite-mcp-server\kite-mcp-server.exe 2>> D:\Sundeep\projects\kite-mcp-server\server.log
