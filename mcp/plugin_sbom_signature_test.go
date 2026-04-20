package mcp

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helper: generate an ed25519 keypair, return the PEM-encoded public
// key (for injection into the registry) and the raw private key (for
// signing test fixtures).
func newTestSigner(t *testing.T) (pubPEM string, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	// PKIX-DER is overkill for ed25519 raw keys; we use a simple
	// "ED25519 PUBLIC KEY" PEM block containing the 32-byte raw key.
	// The loader in plugin_sbom_signature.go accepts this exact form.
	block := &pem.Block{
		Type:  "ED25519 PUBLIC KEY",
		Bytes: pub,
	}
	return string(pem.EncodeToMemory(block)), priv
}

// signFixture produces the base64-encoded detached signature over the
// SBOM checksum string — the exact bytes the registry will verify
// against when RegisterSBOM runs.
func signFixture(t *testing.T, priv ed25519.PrivateKey, checksum string) string {
	t.Helper()
	sig := ed25519.Sign(priv, []byte(checksum))
	return base64.StdEncoding.EncodeToString(sig)
}

// TestRegisterPluginSBOM_ValidSignatureAccepted confirms that when a
// trusted signer key is configured and the entry carries a matching
// signature, registration succeeds.
func TestRegisterPluginSBOM_ValidSignatureAccepted(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)

	pubPEM, priv := newTestSigner(t)
	require.NoError(t, DefaultRegistry.SetTrustedSignerKey(pubPEM))
	t.Cleanup(func() { DefaultRegistry.ClearTrustedSignerKey() })

	entry := PluginSBOMEntry{
		Name:     "signed_plugin",
		Version:  "1.0.0",
		Checksum: "sha256:deadbeef",
	}
	entry.Signature = signFixture(t, priv, entry.Checksum)

	require.NoError(t, RegisterPluginSBOM(entry))
	got := ListPluginSBOM()["signed_plugin"]
	assert.Equal(t, "sha256:deadbeef", got.Checksum)
}

// TestRegisterPluginSBOM_InvalidSignatureRejected: wrong signer's key
// signs the checksum, but the registry is configured with a different
// trust anchor — registration must fail with a clear error.
func TestRegisterPluginSBOM_InvalidSignatureRejected(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)

	trustedPEM, _ := newTestSigner(t)
	_, attackerPriv := newTestSigner(t)
	require.NoError(t, DefaultRegistry.SetTrustedSignerKey(trustedPEM))
	t.Cleanup(func() { DefaultRegistry.ClearTrustedSignerKey() })

	entry := PluginSBOMEntry{
		Name:      "forged",
		Checksum:  "sha256:forgedhash",
		Signature: signFixture(t, attackerPriv, "sha256:forgedhash"),
	}

	err := RegisterPluginSBOM(entry)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature")
}

// TestRegisterPluginSBOM_TamperedChecksumRejected: the signature is
// produced by the trusted signer but over a DIFFERENT checksum than
// the one the entry carries — classic replay/substitution attack.
// Verification must fail because ed25519.Verify re-computes the digest.
func TestRegisterPluginSBOM_TamperedChecksumRejected(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)

	pubPEM, priv := newTestSigner(t)
	require.NoError(t, DefaultRegistry.SetTrustedSignerKey(pubPEM))
	t.Cleanup(func() { DefaultRegistry.ClearTrustedSignerKey() })

	// Sign one checksum, claim a different one.
	sig := signFixture(t, priv, "sha256:original")
	entry := PluginSBOMEntry{
		Name:      "tampered",
		Checksum:  "sha256:substituted",
		Signature: sig,
	}

	err := RegisterPluginSBOM(entry)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature")
}

// TestRegisterPluginSBOM_UnsignedRejectedInProd: trusted key is set,
// prod mode active, entry has no signature — must fail-hard.
func TestRegisterPluginSBOM_UnsignedRejectedInProd(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)

	pubPEM, _ := newTestSigner(t)
	require.NoError(t, DefaultRegistry.SetTrustedSignerKey(pubPEM))
	DefaultRegistry.SetDevMode(false)
	t.Cleanup(func() {
		DefaultRegistry.ClearTrustedSignerKey()
		DefaultRegistry.SetDevMode(false)
	})

	err := RegisterPluginSBOM(PluginSBOMEntry{
		Name:     "unsigned_prod",
		Checksum: "sha256:noprodsig",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsigned")
}

// TestRegisterPluginSBOM_UnsignedAllowedInDev: dev mode relaxes the
// enforcement — unsigned entries log a warning but still register.
// This preserves the local-dev ergonomics where plugin authors don't
// yet have signing infrastructure.
func TestRegisterPluginSBOM_UnsignedAllowedInDev(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)

	pubPEM, _ := newTestSigner(t)
	require.NoError(t, DefaultRegistry.SetTrustedSignerKey(pubPEM))
	DefaultRegistry.SetDevMode(true)
	t.Cleanup(func() {
		DefaultRegistry.ClearTrustedSignerKey()
		DefaultRegistry.SetDevMode(false)
	})

	require.NoError(t, RegisterPluginSBOM(PluginSBOMEntry{
		Name:     "unsigned_dev",
		Checksum: "sha256:devsig",
	}))
	assert.Contains(t, ListPluginSBOM(), "unsigned_dev")
}

// TestRegisterPluginSBOM_NoTrustedKeyLegacyBehavior: when no trusted
// key is configured (default state on today's production), the
// signature field is treated as opaque storage — both signed AND
// unsigned entries accepted. This preserves backward compatibility
// for operators who haven't enabled verification yet.
func TestRegisterPluginSBOM_NoTrustedKeyLegacyBehavior(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)
	// Deliberately do NOT call SetTrustedSignerKey.
	DefaultRegistry.ClearTrustedSignerKey()
	t.Cleanup(func() { DefaultRegistry.ClearTrustedSignerKey() })

	require.NoError(t, RegisterPluginSBOM(PluginSBOMEntry{
		Name:      "legacy_unsigned",
		Checksum:  "sha256:legacynop",
		Signature: "", // no signature
	}))
	require.NoError(t, RegisterPluginSBOM(PluginSBOMEntry{
		Name:      "legacy_with_opaque_sig",
		Checksum:  "sha256:legacyop",
		Signature: "base64-opaque-blob-not-verified",
	}))
	sbom := ListPluginSBOM()
	assert.Contains(t, sbom, "legacy_unsigned")
	assert.Contains(t, sbom, "legacy_with_opaque_sig")
}

// TestSetTrustedSignerKey_RejectsMalformed: bad PEM, non-ed25519 key,
// wrong length, and garbage should all surface as loader errors.
func TestSetTrustedSignerKey_RejectsMalformed(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()

	cases := []struct {
		name string
		pem  string
	}{
		{"empty", ""},
		{"not pem", "just a plain string"},
		{"pem wrong type", "-----BEGIN WRONG-----\nAAAAAA\n-----END WRONG-----\n"},
		{"pem right type wrong length", "-----BEGIN ED25519 PUBLIC KEY-----\ndG9vc2hvcnQ=\n-----END ED25519 PUBLIC KEY-----\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := reg.SetTrustedSignerKey(tc.pem)
			assert.Error(t, err, "malformed key should be rejected")
		})
	}
}
