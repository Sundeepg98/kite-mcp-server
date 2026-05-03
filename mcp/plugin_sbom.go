package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

// PluginSBOMEntry is one row of the plugin Software Bill of Materials.
// It records WHAT code is currently serving each plugin: source or
// binary checksum, optional version, optional signature.
//
// Two plugin kinds populate the SBOM:
//
//   1. Compile-time plugins (tools, hooks, middleware, widgets,
//      scheduler tasks, etc.): the plugin author runs a small
//      build-time helper that hashes the plugin's source files or
//      embedded Go sources and calls RegisterPluginSBOM at init()
//      alongside their other registrations.
//   2. Subprocess plugins (riskguard SubprocessCheck): the host
//      computes a sha256 of the executable on disk when
//      RegisterSubprocessCheck is called, and stores the checksum
//      as "sha256:<hex>" — giving the operator a "did the binary
//      change?" fingerprint usable for drift detection.
//
// Signature is optional. When populated, it's a detached signature
// over the checksum using the operator's preferred scheme (sigstore
// cosign envelope, Ed25519 PKCS, whatever). The registry just STORES
// the signature; verification is the operator's job at audit time —
// the host has no trust anchor to make verification decisions on its
// own.
type PluginSBOMEntry struct {
	// Name is the plugin identifier. Must match the Name used in
	// PluginInfo and PluginHealth so the admin surface can cross-
	// reference.
	Name string `json:"name"`
	// Version is the plugin's semver or commit SHA. Optional but
	// recommended — "what version am I running?" is the first
	// question after "is it red?".
	Version string `json:"version,omitempty"`
	// Checksum is a content hash of the plugin's code. Format is
	// "sha256:<hex>" for SHA-256 (the only algorithm this package
	// produces today). Required.
	Checksum string `json:"checksum"`
	// Source is a free-form label describing WHERE the checksum
	// came from: "compile-time" (hashed source files), "binary"
	// (hashed executable on disk), "git-sha" (hashed via git
	// ls-tree). Optional.
	Source string `json:"source,omitempty"`
	// Signature is a detached signature over Checksum. Optional.
	// Format is operator-chosen; the registry does not parse it.
	Signature string `json:"signature,omitempty"`
	// Recorded is the time the entry was registered. Auto-stamped
	// by RegisterPluginSBOM if caller leaves it zero.
	Recorded time.Time `json:"recorded"`
}

// RegisterPluginSBOM stores an SBOM entry on DefaultRegistry.
// Duplicate names replace (last-wins).
func RegisterPluginSBOM(entry PluginSBOMEntry) error {
	return DefaultRegistry.RegisterSBOM(entry)
}

// ListPluginSBOM returns a snapshot of every registered SBOM entry
// on DefaultRegistry.
func ListPluginSBOM() map[string]PluginSBOMEntry {
	return DefaultRegistry.ListSBOM()
}

// ListPluginSBOMSorted returns SBOM names from DefaultRegistry in
// sorted order for deterministic admin display.
func ListPluginSBOMSorted() []string {
	DefaultRegistry.sbomMu.RLock()
	defer DefaultRegistry.sbomMu.RUnlock()
	names := make([]string, 0, len(DefaultRegistry.sbomEntries))
	for k := range DefaultRegistry.sbomEntries {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// PluginSBOMCount returns the number of registered SBOM entries on
// DefaultRegistry.
func PluginSBOMCount() int {
	return DefaultRegistry.SBOMCount()
}

// ClearPluginSBOM drops every SBOM entry on DefaultRegistry.
// Test-only.
func ClearPluginSBOM() {
	DefaultRegistry.sbomMu.Lock()
	defer DefaultRegistry.sbomMu.Unlock()
	DefaultRegistry.sbomEntries = make(map[string]PluginSBOMEntry)
}

// --- Checksum helpers ---
//
// These are thin SHA-256 wrappers that return the "sha256:<hex>"
// format the rest of the SBOM surface uses. Exposed so plugin
// authors can compute their own checksum at build / register time.

// ChecksumBytes returns the SHA-256 "sha256:<hex>" digest of the
// supplied bytes.
func ChecksumBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ChecksumFile returns the SHA-256 "sha256:<hex>" digest of the
// file at path. Streams the file rather than loading it whole —
// subprocess plugin binaries are megabytes.
func ChecksumFile(path string) (string, error) {
	// #nosec G304 -- path is the resolved binary path of an operator-supplied plugin (plugins.json). Not request input.
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("sbom: open %s: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("sbom: hash %s: %w", path, err)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
