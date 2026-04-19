package mcp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegisterPluginSBOM_StoresAndLists — happy path: register an
// SBOM entry, read it back via ListPluginSBOM.
func TestRegisterPluginSBOM_StoresAndLists(t *testing.T) {
	ClearPluginSBOM()
	defer ClearPluginSBOM()

	entry := PluginSBOMEntry{
		Name:     "my_plugin",
		Version:  "1.0.0",
		Checksum: "sha256:abc123",
		Source:   "compile-time",
	}
	require.NoError(t, RegisterPluginSBOM(entry))

	sbom := ListPluginSBOM()
	require.Contains(t, sbom, "my_plugin")
	assert.Equal(t, "sha256:abc123", sbom["my_plugin"].Checksum)
	assert.Equal(t, "1.0.0", sbom["my_plugin"].Version)
}

// TestRegisterPluginSBOM_RejectsInvalid — empty Name, empty Checksum
// are authoring errors and fail at registration.
func TestRegisterPluginSBOM_RejectsInvalid(t *testing.T) {
	ClearPluginSBOM()
	defer ClearPluginSBOM()

	assert.Error(t, RegisterPluginSBOM(PluginSBOMEntry{Name: "", Checksum: "sha256:x"}))
	assert.Error(t, RegisterPluginSBOM(PluginSBOMEntry{Name: "x", Checksum: ""}))
}

// TestRegisterPluginSBOM_LastWinsOnDuplicate — matches the other
// plugin-registries' lifecycle semantics.
func TestRegisterPluginSBOM_LastWinsOnDuplicate(t *testing.T) {
	ClearPluginSBOM()
	defer ClearPluginSBOM()

	require.NoError(t, RegisterPluginSBOM(PluginSBOMEntry{Name: "p", Checksum: "sha256:old"}))
	require.NoError(t, RegisterPluginSBOM(PluginSBOMEntry{Name: "p", Checksum: "sha256:new"}))

	sbom := ListPluginSBOM()
	assert.Len(t, sbom, 1)
	assert.Equal(t, "sha256:new", sbom["p"].Checksum)
}

// TestChecksumBytes — produces a deterministic SHA-256 hex digest
// with the "sha256:" prefix we use throughout the SBOM surface.
func TestChecksumBytes(t *testing.T) {
	got := ChecksumBytes([]byte("hello"))
	// echo -n 'hello' | sha256sum ->
	// 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
	want := "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	assert.Equal(t, want, got)
}

// TestChecksumFile — hashes a real file. Uses the standard library's
// deterministic SHA-256 output.
func TestChecksumFile(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "hello.txt")
	require.NoError(t, os.WriteFile(tmpFile, []byte("hello"), 0o644))

	got, err := ChecksumFile(tmpFile)
	require.NoError(t, err)
	assert.Equal(t, "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", got)
}

// TestChecksumFile_Missing — a missing file surfaces a clean error,
// not a panic.
func TestChecksumFile_Missing(t *testing.T) {
	_, err := ChecksumFile(filepath.Join(t.TempDir(), "does-not-exist"))
	assert.Error(t, err)
}

// TestPluginManifest_IncludesSBOM — the top-level manifest now
// carries SBOM entries alongside health + counts. One endpoint
// answers "is this plugin the version I signed off on?".
func TestPluginManifest_IncludesSBOM(t *testing.T) {
	ClearPluginSBOM()
	defer ClearPluginSBOM()

	require.NoError(t, RegisterPluginSBOM(PluginSBOMEntry{
		Name:     "x",
		Checksum: "sha256:deadbeef",
		Version:  "0.1.0",
		Source:   "compile-time",
	}))

	m := GetPluginManifest()
	require.Contains(t, m.SBOM, "x")
	assert.Equal(t, "sha256:deadbeef", m.SBOM["x"].Checksum)
}

// TestPluginSBOMCount — tracking counter for admin surface.
func TestPluginSBOMCount(t *testing.T) {
	ClearPluginSBOM()
	defer ClearPluginSBOM()

	assert.Equal(t, 0, PluginSBOMCount())
	_ = RegisterPluginSBOM(PluginSBOMEntry{Name: "a", Checksum: "sha256:1"})
	_ = RegisterPluginSBOM(PluginSBOMEntry{Name: "b", Checksum: "sha256:2"})
	assert.Equal(t, 2, PluginSBOMCount())
}

// TestPluginSBOM_OptionalSignatureField — Signature is optional; a
// missing signature is NOT an authoring error. Registry entries
// without signatures exist legitimately (compile-time plugins that
// don't go through a signing key).
func TestPluginSBOM_OptionalSignatureField(t *testing.T) {
	ClearPluginSBOM()
	defer ClearPluginSBOM()

	require.NoError(t, RegisterPluginSBOM(PluginSBOMEntry{
		Name:     "unsigned",
		Checksum: "sha256:nosig",
		// Signature deliberately omitted.
	}))

	sbom := ListPluginSBOM()
	assert.Empty(t, sbom["unsigned"].Signature)
}
