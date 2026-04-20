package mcp

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"sync"
)

// Plugin signature verification closes the Phase G gap: the SBOM had
// been recording signatures for observability but never enforced them
// at plugin-load time, which meant an operator who accidentally (or
// maliciously) registered a plugin with a mismatched signature would
// see the mismatch only during an audit — long after the plugin had
// already been firing hooks and middleware.
//
// Design choices:
//
//   - Ed25519 is the only algorithm wired today. Keys are 32 bytes,
//     signatures 64 bytes, verification is constant-time and free of
//     PKCS#1 v1.5 parsing footguns. If operators need RSA or ECDSA,
//     extending parseTrustedSignerPEM to accept PKIX-DER is a localized
//     change.
//   - The signer key is configured per-Registry (not process-global)
//     so that tests constructing fresh registries via NewRegistry()
//     retain isolation. The DefaultRegistry-scoped free functions below
//     mirror the rest of the SBOM surface for ergonomic production use.
//   - "Signed" means the entry carries a detached ed25519 signature
//     (base64) over the Checksum STRING ("sha256:<hex>"). Signing the
//     checksum rather than re-hashing the binary here is intentional:
//     the host doesn't know where the plugin binary lives (compile-time
//     plugins don't have one at all), so the SBOM's pre-computed
//     Checksum is the canonical commitment.
//   - When no trusted signer key is configured, the legacy "opaque
//     signature storage" behavior is preserved: both signed and
//     unsigned entries are accepted, and the Signature field is stored
//     verbatim without verification. Opt-in enforcement.
//   - When a trusted signer key IS configured, dev-mode flips the
//     "unsigned rejected" rule to "unsigned accepted with warning",
//     because local plugin developers don't have signing infrastructure
//     and we don't want Phase G to break their inner loop.

// trustedSignerPEMType is the PEM block type the registry accepts for
// ed25519 public keys. A bare raw-key PEM rather than PKIX/DER keeps
// the on-disk format minimal and obvious at a glance. Operators who
// already have PKIX-encoded keys can strip the wrapper with `openssl
// asn1parse` — or we can add a PKIX fallback later.
const trustedSignerPEMType = "ED25519 PUBLIC KEY"

// trustedSignerRegistry is the per-Registry cryptographic trust state.
// Held under its own mutex so verification does not contend with
// RegisterSBOM's sbomMu.
type trustedSignerRegistry struct {
	mu      sync.RWMutex
	key     ed25519.PublicKey // nil when no trusted signer is configured
	devMode bool              // when true, unsigned entries warn-but-accept
	logger  *slog.Logger      // optional; nil falls back to the default slog logger
}

// SetTrustedSignerKey installs an ed25519 public key as the registry's
// trust anchor for SBOM signature verification. Pass the PEM-encoded
// key ("ED25519 PUBLIC KEY" block containing the raw 32-byte key).
// Returns a descriptive error when the PEM is malformed, wrong type,
// or the payload is not exactly ed25519.PublicKeySize bytes.
//
// Calling this more than once replaces the existing key — last-wins
// matches the rest of the registry's lifecycle semantics.
func (r *Registry) SetTrustedSignerKey(pemString string) error {
	key, err := parseTrustedSignerPEM(pemString)
	if err != nil {
		return err
	}
	r.signer.mu.Lock()
	defer r.signer.mu.Unlock()
	r.signer.key = key
	return nil
}

// ClearTrustedSignerKey drops the trust anchor, reverting to legacy
// opaque-signature-storage behavior. Primarily used by tests that mock
// registries in and out, but safe for production if an operator wants
// to temporarily disable enforcement.
func (r *Registry) ClearTrustedSignerKey() {
	r.signer.mu.Lock()
	defer r.signer.mu.Unlock()
	r.signer.key = nil
}

// SetDevMode toggles the unsigned-entry allowance. When true (dev),
// unsigned entries register with a warning. When false (prod default),
// unsigned entries are rejected IF a trusted key is configured.
func (r *Registry) SetDevMode(dev bool) {
	r.signer.mu.Lock()
	defer r.signer.mu.Unlock()
	r.signer.devMode = dev
}

// SetSignerLogger injects a slog.Logger for signature-related warnings
// (primarily the dev-mode "unsigned plugin accepted" log). Optional —
// a nil logger falls back to slog.Default() at call time.
func (r *Registry) SetSignerLogger(logger *slog.Logger) {
	r.signer.mu.Lock()
	defer r.signer.mu.Unlock()
	r.signer.logger = logger
}

// verifyEntrySignature is the hook called from RegisterSBOM. It
// implements the policy decision table:
//
//	trusted key set?  signature present?  devMode?  action
//	no                *                   *         accept (legacy)
//	yes               yes                 *         verify; reject on mismatch
//	yes               no                  no        reject (unsigned in prod)
//	yes               no                  yes       accept with warning log
//
// Returns nil when the entry may proceed, non-nil error when
// registration must fail.
func (r *Registry) verifyEntrySignature(entry PluginSBOMEntry) error {
	r.signer.mu.RLock()
	key := r.signer.key
	devMode := r.signer.devMode
	logger := r.signer.logger
	r.signer.mu.RUnlock()

	// Legacy mode — no trust anchor configured, opaque storage only.
	if key == nil {
		return nil
	}

	// Unsigned path.
	if entry.Signature == "" {
		if devMode {
			if logger == nil {
				logger = slog.Default()
			}
			logger.Warn("plugin SBOM entry registered WITHOUT signature (dev mode)",
				"plugin", entry.Name,
				"checksum", entry.Checksum,
			)
			return nil
		}
		return fmt.Errorf("mcp: plugin %q is unsigned and prod mode requires a valid signature", entry.Name)
	}

	// Signed path — verify over the checksum string bytes.
	sigBytes, err := base64.StdEncoding.DecodeString(entry.Signature)
	if err != nil {
		return fmt.Errorf("mcp: plugin %q signature is not valid base64: %w", entry.Name, err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("mcp: plugin %q signature is wrong length (got %d, want %d)", entry.Name, len(sigBytes), ed25519.SignatureSize)
	}
	if !ed25519.Verify(key, []byte(entry.Checksum), sigBytes) {
		return fmt.Errorf("mcp: plugin %q signature does not match trusted signer", entry.Name)
	}
	return nil
}

// parseTrustedSignerPEM decodes the operator-supplied PEM, validates
// the block type, and returns the raw ed25519.PublicKey. Loader errors
// are distinguishable (empty / not-PEM / wrong-type / wrong-length) so
// operators debugging a key-rotation misconfiguration can pinpoint the
// problem without source diving.
func parseTrustedSignerPEM(pemString string) (ed25519.PublicKey, error) {
	if pemString == "" {
		return nil, fmt.Errorf("mcp: trusted signer key is empty")
	}
	block, _ := pem.Decode([]byte(pemString))
	if block == nil {
		return nil, fmt.Errorf("mcp: trusted signer key is not valid PEM")
	}
	if block.Type != trustedSignerPEMType {
		return nil, fmt.Errorf("mcp: trusted signer key PEM type is %q, want %q", block.Type, trustedSignerPEMType)
	}
	if len(block.Bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("mcp: trusted signer key is %d bytes, want %d (raw ed25519 public key)", len(block.Bytes), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(block.Bytes), nil
}
