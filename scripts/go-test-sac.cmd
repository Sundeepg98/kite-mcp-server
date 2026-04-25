@echo off
REM Go test -exec wrapper that signs the test binary before launching it,
REM so Windows Smart App Control (SAC) does not block freshly-built test
REM binaries that have no cloud/ISG reputation.
REM
REM Usage:
REM   go test -exec=scripts\go-test-sac.cmd ./kc/riskguard/...
REM
REM Why this exists:
REM   SAC blocks any unsigned exe without ISG reputation. Go test binaries
REM   are recompiled with random content hashes per run, so they will never
REM   develop ISG reputation. We sign them on-the-fly using the existing
REM   "GoTools Local Dev" cert (thumbprint 4ABCEECC23F524EB460409F66B5306C2E1787272)
REM   that was set up for gopls.exe.
REM
REM Calling convention:
REM   go test -exec invokes us as:  go-test-sac.cmd <binary.exe> [test args...]
REM   We sign %1, then run "%1" with %2..%N forwarded.
REM
REM Errors are non-fatal (best-effort sign + always exec). If signing fails
REM the binary may be SAC-blocked but we still attempt to run it so the
REM error surfaces clearly.

setlocal

if "%~1"=="" (
  echo go-test-sac.cmd: missing test-binary path 1>&2
  exit /b 2
)

set "BIN=%~1"
shift

REM Sign the binary in place. Suppress only stdout chatter; keep errors visible.
powershell -NoProfile -ExecutionPolicy Bypass -File "%USERPROFILE%\go\bin\sign-bin.ps1" -Path "%BIN%" >nul

REM Reconstruct remaining args (go test passes test flags after the binary).
set "ARGS="
:argloop
if "%~1"=="" goto runit
set "ARGS=%ARGS% %1"
shift
goto argloop

:runit
"%BIN%" %ARGS%
exit /b %ERRORLEVEL%
