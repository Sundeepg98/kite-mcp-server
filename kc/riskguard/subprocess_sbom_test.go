package riskguard

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// Plugin#6: SBOM helper existed but was uncovered (sig-enforcement bypass).
// Proves SHA-256 emission contract + fail-open registration on missing binary.
func TestRegisterSubprocessCheckWithSBOM(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "fake-plugin.bin")
	payload := []byte("PLUGIN_BINARY_FIXTURE_v1")
	if err := os.WriteFile(bin, payload, 0o755); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(payload)
	wantPrefixed := "sha256:" + hex.EncodeToString(want[:])
	var gotName, gotChecksum string
	var gotErr error
	emit := func(name, _, checksum string, err error) {
		gotName, gotChecksum, gotErr = name, checksum, err
	}
	g := NewGuard(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := g.RegisterSubprocessCheckWithSBOM("fixture", bin, 5100, emit); err != nil {
		t.Fatalf("register: %v", err)
	}
	if gotName != "fixture" || gotChecksum != wantPrefixed || gotErr != nil {
		t.Errorf("real binary emit got (%q,%q,%v); want (fixture,%q,nil)",
			gotName, gotChecksum, gotErr, wantPrefixed)
	}
	missing := filepath.Join(tmp, "never-exists.bin")
	gotChecksum, gotErr = "sentinel", nil
	if err := g.RegisterSubprocessCheckWithSBOM("missing", missing, 5101, emit); err != nil {
		t.Fatalf("register should fail-open at missing binary; got %v", err)
	}
	if gotChecksum != "" || gotErr == nil {
		t.Errorf("missing binary emit got (%q,%v); want (\"\",non-nil)", gotChecksum, gotErr)
	}
}
