#!/usr/bin/env bash
# Helper to run go test on WSL2 with explicit PATH stripped of Windows entries.
# Two modes:
#   1. mfa-wsl-test.sh totp        — run the TOTP-only test set (this slice).
#   2. mfa-wsl-test.sh users-all   — run every test in kc/users (slice A regression).
#   3. mfa-wsl-test.sh oauth-all   — slice B regression target (oauth admin handlers).
#   4. mfa-wsl-test.sh app-all     — slice B regression target (app middleware).
# Default (no arg or unknown arg): forward all args to "go test".
set -euo pipefail
export PATH=/usr/local/go/bin:/usr/bin:/bin
cd /mnt/d/Sundeep/projects/kite-mcp-server
case "${1:-}" in
  totp)
    exec go test ./kc/users/ -run 'TestGenerateTOTPSecret|TestGenerateTOTPCode|TestVerifyTOTPCode|TestProvisioningURI|TestDecodeTOTPSecret' -count=1
    ;;
  mfa)
    exec go test ./kc/users/ -run 'TOTP|MFA' -count=1
    ;;
  users-all)
    exec go test ./kc/users/ -count=1
    ;;
  oauth-all)
    exec go test ./oauth/ -count=1
    ;;
  app-all)
    exec go test ./app/ -count=1
    ;;
  vet)
    exec go vet ./...
    ;;
  build)
    exec go build ./...
    ;;
  *)
    exec go test "$@"
    ;;
esac
