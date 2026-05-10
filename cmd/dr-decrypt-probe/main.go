// dr-decrypt-probe is a one-shot CLI that verifies a Litestream-restored
// SQLite DB can be fully decrypted with the production OAUTH_JWT_SECRET.
//
// It closes the gap that scripts/dr-drill-prod-keys.sh documented at
// line 147-166: the script needs a helper binary that actually exercises
// the HKDF→AES-256-GCM key chain end-to-end, otherwise the drill silently
// passes through "restore succeeded but every encrypted column is empty"
// failures.
//
// The probe is invoked by scripts/dr-drill-prod-keys.sh; the script
// supplies the -db flag pointing at the restored scratch SQLite + the
// OAUTH_JWT_SECRET env var. Exit codes mirror the script's documented
// codes (see scripts/dr-drill-prod-keys.sh:56-65 and the §C spec in
// .research/research-batch-2026-05-11.md).
//
// Exit codes:
//
//	0  success: salt present + every probed encrypted row decrypted
//	   AES-GCM (auth-tag verified)
//	1  generic: bad -db path, file open failure, etc.
//	2  required env missing OR OAUTH_JWT_SECRET shorter than 32 bytes
//	5  hkdf_salt missing from config table — catastrophic; restore
//	   lost the salt and ciphertexts are permanently unreadable
//	6  decrypt fail: AES-GCM auth-tag failed (wrong secret OR salt
//	   corrupted between encrypt and probe runs)
//
// On success it prints a single line:
//
//	DR drill probe: SUCCESS — N credentials decrypted, M tokens decrypted, hkdf_salt OK
//
// On failure it prints the failure reason to stderr and exits with the
// matching non-zero code. The hint about OAUTH_JWT_SECRET mismatch is
// intentionally surfaced (not buried) because that's by far the most
// common cause of exit-6 in practice — an operator pasting an old or
// rotated secret value while drilling.
//
// IMPORTANT: this binary is NOT production-server code. It is operator-
// only tooling. It does NOT write to the DB, NOT write to R2, and NOT
// log the OAUTH_JWT_SECRET. The companion script (dr-drill-prod-keys.sh)
// handles cleanup of the scratch DB via a trap.
package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"

	alerts "github.com/algo2go/kite-mcp-alerts"
)

// hkdfSaltConfigKey is the same constant the alerts package uses
// internally (unexported there at crypto.go:51). We hold a duplicate
// string literal here so the probe can read the salt via GetConfig
// without depending on alerts internals.
const hkdfSaltConfigKey = "hkdf_salt"

// minSecretBytes mirrors the script's gate at scripts/dr-drill-prod-
// keys.sh:79. Derivation of an AES-256 key from <32 bytes of entropy
// is allowed by the HKDF algorithm but produces a weaker effective key;
// the gate refuses to proceed.
const minSecretBytes = 32

func main() {
	dbPath := flag.String("db", "", "path to restored SQLite DB to probe")
	verbose := flag.Bool("verbose", false, "print per-row decrypt results (default: count-only summary)")
	flag.Parse()

	if err := run(*dbPath, *verbose); err != nil {
		var probeErr *probeError
		if errors.As(err, &probeErr) {
			fmt.Fprintf(os.Stderr, "DR drill probe: FAIL — %s\n", probeErr.message)
			if probeErr.hint != "" {
				fmt.Fprintf(os.Stderr, "  Hint: %s\n", probeErr.hint)
			}
			os.Exit(probeErr.code)
		}
		fmt.Fprintf(os.Stderr, "DR drill probe: FAIL — %v\n", err)
		os.Exit(1)
	}
}

// probeError carries an exit code + operator-facing message + a hint
// for the most-common cause. Using a typed error keeps run() pure and
// testable without coupling to os.Exit.
type probeError struct {
	code    int
	message string
	hint    string
}

func (e *probeError) Error() string { return e.message }

func newProbeErr(code int, message, hint string) *probeError {
	return &probeError{code: code, message: message, hint: hint}
}

// run executes the 8-phase drill and returns nil on success or a
// *probeError with the appropriate exit code on failure. Pure function
// (no os.Exit) so tests can drive it.
//
// The phase numbering matches scripts/dr-drill-prod-keys.sh:69-167.
func run(dbPath string, verbose bool) error {
	// Phase 0: gate -db flag.
	if dbPath == "" {
		return newProbeErr(1, "missing required -db flag",
			"Usage: dr-decrypt-probe -db <path-to-restored.db>")
	}
	if _, err := os.Stat(dbPath); err != nil {
		return newProbeErr(1, fmt.Sprintf("cannot stat -db path %q: %v", dbPath, err), "")
	}

	// Phase 1: gate OAUTH_JWT_SECRET.
	secret := os.Getenv("OAUTH_JWT_SECRET")
	if len(secret) < minSecretBytes {
		return newProbeErr(2,
			fmt.Sprintf("OAUTH_JWT_SECRET unset or shorter than %d bytes (got %d)", minSecretBytes, len(secret)),
			"Set OAUTH_JWT_SECRET to the same value the production server uses to encrypt this DB")
	}

	// Phase 2: open the restored DB.
	db, err := alerts.OpenDB(dbPath)
	if err != nil {
		return newProbeErr(1, fmt.Sprintf("alerts.OpenDB(%q): %v", dbPath, err), "")
	}
	defer db.Close()

	// Phase 3: read hkdf_salt from config table. Missing salt = exit-5
	// catastrophic; the restore lost the encryption context and every
	// ciphertext in the DB is permanently unreadable.
	saltHex, err := db.GetConfig(hkdfSaltConfigKey)
	if err != nil {
		// alerts.DB.GetConfig returns sql.ErrNoRows wrapped when the key
		// is missing — treat that as exit-5 catastrophic. Other errors
		// (e.g. SQL syntax) are exit-1 generic.
		return newProbeErr(5,
			fmt.Sprintf("hkdf_salt missing from config table (GetConfig: %v)", err),
			"Restore lost the encryption salt. Every encrypted column in this DB is unrecoverable. "+
				"Check the Litestream replica retains the config table.")
	}
	if saltHex == "" {
		return newProbeErr(5, "hkdf_salt config row present but value is empty",
			"Restore corruption; ciphertexts unrecoverable")
	}
	saltBytes, err := hex.DecodeString(saltHex)
	if err != nil {
		return newProbeErr(5, fmt.Sprintf("hkdf_salt is not valid hex: %v", err), "")
	}
	if len(saltBytes) != 32 {
		return newProbeErr(5,
			fmt.Sprintf("hkdf_salt is %d bytes, want 32", len(saltBytes)),
			"AES-256 requires a 32-byte HKDF salt; restore appears corrupted")
	}

	// Phase 4: re-derive the AES-256 key from secret + salt. This
	// mirrors what app/providers/manager.go does at server cold-start.
	key, err := alerts.DeriveEncryptionKeyWithSalt(secret, saltBytes)
	if err != nil {
		return newProbeErr(1, fmt.Sprintf("DeriveEncryptionKeyWithSalt: %v", err), "")
	}

	// Phase 5: arm the DB with the re-derived key.
	db.SetEncryptionKey(key)

	// Phase 6+7: probe encrypted tables. Empty plaintext from a non-
	// empty ciphertext column is the AES-GCM auth-tag failure signal
	// per algo2go/kite-mcp-alerts decrypt-path semantics — that's the
	// failure scripts/dr-drill.sh's count(*) check silently passes.
	credCount, credErr := probeCredentials(db, verbose)
	if credErr != nil {
		return credErr
	}
	tokenCount, tokenErr := probeTokens(db, verbose)
	if tokenErr != nil {
		return tokenErr
	}

	// Phase 8: summary.
	if credCount == 0 && tokenCount == 0 {
		fmt.Printf("DR drill probe: SUCCESS — hkdf_salt OK; WARNING: no canary rows present (0 credentials, 0 tokens — fresh deployment? re-run after at least one user authenticates to exercise the decrypt path end-to-end)\n")
		return nil
	}
	fmt.Printf("DR drill probe: SUCCESS — %d credentials decrypted, %d tokens decrypted, hkdf_salt OK\n",
		credCount, tokenCount)
	return nil
}

// probeCredentials returns the count of kite_credentials rows that
// successfully decrypted (i.e. APIKey and APISecret both non-empty).
// Any empty plaintext is exit-6 (AES-GCM auth-tag failure).
func probeCredentials(db *alerts.DB, verbose bool) (int, error) {
	creds, err := db.LoadCredentials()
	if err != nil {
		return 0, newProbeErr(1, fmt.Sprintf("LoadCredentials: %v", err), "")
	}
	for i, c := range creds {
		if c.APIKey == "" {
			return 0, newProbeErr(6,
				fmt.Sprintf("credentials[%d] decrypted to empty APIKey (AES-GCM auth-tag failure)", i),
				"Most likely cause: OAUTH_JWT_SECRET in this drill env != the secret that encrypted the production data. "+
					"Verify with `flyctl secrets list -a kite-mcp-server | grep OAUTH_JWT_SECRET` (Fly masks values; check digest).")
		}
		if c.APISecret == "" {
			return 0, newProbeErr(6,
				fmt.Sprintf("credentials[%d] decrypted to empty APISecret (AES-GCM auth-tag failure)", i),
				"Same likely cause: OAUTH_JWT_SECRET mismatch")
		}
		if verbose {
			fmt.Printf("  cred[%d]: email=%s api_key_len=%d api_secret_len=%d\n",
				i, c.Email, len(c.APIKey), len(c.APISecret))
		}
	}
	return len(creds), nil
}

// probeTokens returns the count of kite_tokens rows that successfully
// decrypted (i.e. AccessToken non-empty).
func probeTokens(db *alerts.DB, verbose bool) (int, error) {
	tokens, err := db.LoadTokens()
	if err != nil {
		return 0, newProbeErr(1, fmt.Sprintf("LoadTokens: %v", err), "")
	}
	for i, tk := range tokens {
		if tk.AccessToken == "" {
			return 0, newProbeErr(6,
				fmt.Sprintf("tokens[%d] decrypted to empty AccessToken (AES-GCM auth-tag failure)", i),
				"Same likely cause: OAUTH_JWT_SECRET mismatch — see scripts/dr-drill-prod-keys.sh:151-156 for diagnostic steps")
		}
		if verbose {
			fmt.Printf("  token[%d]: email=%s access_token_len=%d\n", i, tk.Email, len(tk.AccessToken))
		}
	}
	return len(tokens), nil
}
