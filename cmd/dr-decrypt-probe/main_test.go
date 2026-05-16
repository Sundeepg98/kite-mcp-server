// Package main_test verifies the dr-decrypt-probe binary against
// synthetic state mirroring scripts/dr-drill-prod-keys.sh.
//
// The probe binary is exec'd via `go test` running it as a subprocess.
// This pattern lets us validate exit codes + stderr without coupling
// to algo2go/kite-mcp-alerts internals beyond what the binary itself
// uses.
package main

import (
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	alerts "github.com/algo2go/kite-mcp-alerts"
)

// buildProbe compiles the probe binary into a tempdir and returns its
// path. Tests share one build per package-test invocation by relying on
// t.TempDir's lifecycle and Go's per-package test process.
//
// Cross-platform: appends `.exe` on Windows so `exec.Command` can locate
// the binary. Without the extension, Windows' CreateProcess returns
// "executable file not found in %PATH%" even when the file exists at the
// exact path passed -- the OS resolver requires the extension when no
// PATHEXT lookup is desired. Verified 2026-05-16 against go1.25.6 on
// windows/amd64.
func buildProbe(t *testing.T) string {
	t.Helper()
	binName := "dr-decrypt-probe"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	bin := filepath.Join(t.TempDir(), binName)
	if os.Getenv("PROBE_BUILD_SKIP") != "" {
		// Allows CI to pre-build once and reuse.
		if pre := os.Getenv("PROBE_BIN"); pre != "" {
			return pre
		}
	}
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build dr-decrypt-probe: %v", err)
	}
	return bin
}

// writeProductionState seeds a synthetic SQLite DB with one
// kite_credentials row + one kite_tokens row, both encrypted under
// the key HKDF-derived from the supplied secret. Returns the DB path
// and the canary plaintexts the probe must successfully decrypt.
func writeProductionState(t *testing.T, secret string) (dbPath string, canaryAPIKey, canaryAccessToken string) {
	t.Helper()
	dbPath = filepath.Join(t.TempDir(), "production-state.db")
	db, err := alerts.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("alerts.OpenDB: %v", err)
	}
	defer db.Close()

	key, err := alerts.EnsureEncryptionSalt(db, secret)
	if err != nil {
		t.Fatalf("EnsureEncryptionSalt: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("derived key length = %d, want 32", len(key))
	}
	db.SetEncryptionKey(key)

	const (
		userEmail            = "drill-user@example.com"
		expectedAPIKey       = "drill-api-key-canary-BBB"
		expectedAPISecret    = "drill-api-secret-canary-CCC"
		expectedAccessToken  = "drill-access-token-canary-AAA"
		expectedUserID       = "uid-1"
		expectedUsername     = "uname-1"
	)
	now := time.Now().Truncate(time.Second)
	if err := db.SaveCredential(userEmail, expectedAPIKey, expectedAPISecret, "app1", now); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}
	if err := db.SaveToken(userEmail, expectedAccessToken, expectedUserID, expectedUsername, now); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
	return dbPath, expectedAPIKey, expectedAccessToken
}

// TestProbe_HappyPath_DecryptsAllCanaries is the positive control:
// the probe should exit 0 and print SUCCESS when given the correct
// secret + DB.
func TestProbe_HappyPath_DecryptsAllCanaries(t *testing.T) {
	t.Parallel()
	const secret = "synthetic-OAUTH_JWT_SECRET-32-bytes-test-only"
	dbPath, _, _ := writeProductionState(t, secret)

	bin := buildProbe(t)
	cmd := exec.Command(bin, "-db", dbPath)
	cmd.Env = append(os.Environ(), "OAUTH_JWT_SECRET="+secret)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("probe exited non-zero: %v\nOutput:\n%s", err, out)
	}
	got := string(out)
	if !strings.Contains(got, "SUCCESS") {
		t.Errorf("expected SUCCESS in output, got:\n%s", got)
	}
	if !strings.Contains(got, "1 credentials") || !strings.Contains(got, "1 tokens") {
		t.Errorf("expected '1 credentials' and '1 tokens' in output, got:\n%s", got)
	}
}

// TestProbe_WrongSecret_Exit6 is the negative control: a wrong secret
// produces AES-GCM auth-tag failures, decrypted strings come back
// empty, and the probe must exit 6 (not 0, not panic).
func TestProbe_WrongSecret_Exit6(t *testing.T) {
	t.Parallel()
	const correctSecret = "synthetic-OAUTH_JWT_SECRET-32-bytes-test-only"
	const wrongSecret = "WRONG-secret-also-32-bytes-test-only-XXX"
	dbPath, _, _ := writeProductionState(t, correctSecret)

	bin := buildProbe(t)
	cmd := exec.Command(bin, "-db", dbPath)
	cmd.Env = append(os.Environ(), "OAUTH_JWT_SECRET="+wrongSecret)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("probe should have failed but exited 0\nOutput:\n%s", out)
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("probe error was not *exec.ExitError: %v", err)
	}
	if exitErr.ExitCode() != 6 {
		t.Errorf("expected exit code 6 (decrypt fail), got %d\nOutput:\n%s", exitErr.ExitCode(), out)
	}
}

// TestProbe_MissingDBFlag_Exit1 validates input gating for the -db
// flag.
func TestProbe_MissingDBFlag_Exit1(t *testing.T) {
	t.Parallel()
	bin := buildProbe(t)
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), "OAUTH_JWT_SECRET=synthetic-OAUTH_JWT_SECRET-32-bytes-test-only")
	err := cmd.Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("probe with missing -db should fail; got err=%v", err)
	}
	if exitErr.ExitCode() != 1 {
		t.Errorf("expected exit code 1 (missing -db), got %d", exitErr.ExitCode())
	}
}

// TestProbe_ShortSecret_Exit2 validates the ≥32-byte secret requirement.
func TestProbe_ShortSecret_Exit2(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "irrelevant.db")
	// Create a placeholder; the probe must fail before opening it.
	if err := os.WriteFile(dbPath, []byte{0}, 0600); err != nil {
		t.Fatal(err)
	}

	bin := buildProbe(t)
	cmd := exec.Command(bin, "-db", dbPath)
	cmd.Env = append(os.Environ(), "OAUTH_JWT_SECRET=too-short")
	err := cmd.Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("probe with short secret should fail; got err=%v", err)
	}
	if exitErr.ExitCode() != 2 {
		t.Errorf("expected exit code 2 (env gate), got %d", exitErr.ExitCode())
	}
}

// TestProbe_MissingSalt_Exit5 validates the catastrophic-restore-loss
// path: an SQLite DB with the schema initialised but no hkdf_salt row
// in the config table.
func TestProbe_MissingSalt_Exit5(t *testing.T) {
	t.Parallel()
	const secret = "synthetic-OAUTH_JWT_SECRET-32-bytes-test-only"

	// Create a DB with schema but NO salt — simulates a Litestream
	// restore that lost the config row.
	dbPath := filepath.Join(t.TempDir(), "no-salt.db")
	db, err := alerts.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	// Do NOT call EnsureEncryptionSalt — leaves config table empty.
	db.Close()

	bin := buildProbe(t)
	cmd := exec.Command(bin, "-db", dbPath)
	cmd.Env = append(os.Environ(), "OAUTH_JWT_SECRET="+secret)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("probe should have failed (no salt); exited 0\nOutput:\n%s", out)
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("probe error was not *exec.ExitError: %v", err)
	}
	if exitErr.ExitCode() != 5 {
		t.Errorf("expected exit code 5 (salt missing), got %d\nOutput:\n%s", exitErr.ExitCode(), out)
	}
}

// TestProbe_EmptyDB_NoCanaries_Exit0_WithWarning validates the "fresh
// deployment, no users yet" path: salt is present but no encrypted
// rows. Probe should exit 0 with a WARNING printed.
func TestProbe_EmptyDB_NoCanaries_Exit0_WithWarning(t *testing.T) {
	t.Parallel()
	const secret = "synthetic-OAUTH_JWT_SECRET-32-bytes-test-only"

	dbPath := filepath.Join(t.TempDir(), "empty.db")
	db, err := alerts.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	// Initialize salt (so exit-5 doesn't fire) but write NO canary rows.
	if _, err := alerts.EnsureEncryptionSalt(db, secret); err != nil {
		t.Fatalf("EnsureEncryptionSalt: %v", err)
	}
	db.Close()

	bin := buildProbe(t)
	cmd := exec.Command(bin, "-db", dbPath)
	cmd.Env = append(os.Environ(), "OAUTH_JWT_SECRET="+secret)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("probe should exit 0 with no canaries; got err=%v\nOutput:\n%s", err, out)
	}
	got := string(out)
	if !strings.Contains(got, "WARNING") && !strings.Contains(got, "no canary") {
		t.Errorf("expected WARNING about no canaries, got:\n%s", got)
	}
}

// Sanity assertion against the alerts package — keep the test honest
// that our test fixture mirrors the production schema. If alerts
// changes the salt encoding, this surfaces immediately.
func TestFixture_Sanity_HexSaltIs32Bytes(t *testing.T) {
	t.Parallel()
	const secret = "synthetic-OAUTH_JWT_SECRET-32-bytes-test-only"
	dbPath, _, _ := writeProductionState(t, secret)

	db, err := alerts.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()
	saltHex, err := db.GetConfig("hkdf_salt")
	if err != nil {
		t.Fatalf("GetConfig(hkdf_salt): %v", err)
	}
	saltBytes, err := hex.DecodeString(saltHex)
	if err != nil {
		t.Fatalf("salt hex-decode: %v", err)
	}
	if len(saltBytes) != 32 {
		t.Errorf("salt is %d bytes, want 32", len(saltBytes))
	}
}
