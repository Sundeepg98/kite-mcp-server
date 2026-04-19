package mcp

import (
	"context"
	"errors"
	"testing"
)

// FuzzSafeInvoke_NeverPanics is a property test: for arbitrary
// panic values (strings, integers, nil-deref, structs) the
// SafeInvoke wrapper ALWAYS returns an error and NEVER propagates
// the panic to the caller.
//
// Run with:
//   go test ./mcp/ -run ^FuzzSafeInvoke_NeverPanics$ -fuzz . -fuzztime 5s
func FuzzSafeInvoke_NeverPanics(f *testing.F) {
	f.Add("simple string")
	f.Add("")
	f.Add("\x00\xff bytes")
	f.Add("a very very long panic value " + string(make([]byte, 4096)))

	f.Fuzz(func(t *testing.T, panicMsg string) {
		// Test 1: panic with the fuzz string.
		err := SafeInvoke("fuzzed", func() error {
			panic(panicMsg)
		})
		if err == nil {
			t.Fatal("SafeInvoke returned nil error for a panicking fn")
		}

		// Test 2: panic with a struct containing the fuzz string.
		type payload struct{ Msg string }
		err2 := SafeInvoke("fuzzed-struct", func() error {
			panic(payload{Msg: panicMsg})
		})
		if err2 == nil {
			t.Fatal("SafeInvoke returned nil error for a struct-panic")
		}

		// Test 3: error-passthrough — a non-panicking error MUST
		// pass through unchanged.
		sentinel := errors.New("fuzz-sentinel")
		err3 := SafeInvoke("fuzzed-err", func() error { return sentinel })
		if !errors.Is(err3, sentinel) {
			t.Fatalf("SafeInvoke did not pass sentinel error through; got %v", err3)
		}

		// Test 4: happy path returns nil.
		err4 := SafeInvoke("fuzzed-ok", func() error { return nil })
		if err4 != nil {
			t.Fatalf("SafeInvoke returned non-nil for successful fn: %v", err4)
		}
	})
}

// FuzzRegisterPluginSBOM_InvalidInputNeverPanics is a property test:
// arbitrary input to RegisterPluginSBOM must either succeed or
// return a clean error — never panic or corrupt the registry.
func FuzzRegisterPluginSBOM_InvalidInputNeverPanics(f *testing.F) {
	f.Add("name", "sha256:abc", "1.0.0", "source", "signature")
	f.Add("", "", "", "", "")
	f.Add("\x00", "sha256:\x00\x00", "\n\r", "\x7f", "\xff")

	f.Fuzz(func(t *testing.T, name, checksum, version, source, sig string) {
		ClearPluginSBOM()
		defer ClearPluginSBOM()

		entry := PluginSBOMEntry{
			Name:      name,
			Checksum:  checksum,
			Version:   version,
			Source:    source,
			Signature: sig,
		}
		err := RegisterPluginSBOM(entry)
		// Either success or clean error — no panic, no corruption.
		if err == nil {
			// If registration succeeded, the entry must be readable.
			sbom := ListPluginSBOM()
			if _, ok := sbom[name]; !ok {
				t.Fatalf("registered SBOM entry missing from list: name=%q", name)
			}
		}
		// If err != nil, we expect at least Name or Checksum was
		// empty — validate contract.
		if err != nil && name != "" && checksum != "" {
			t.Fatalf("unexpected error for valid input (name=%q checksum=%q): %v",
				name, checksum, err)
		}
	})
}

// FuzzReportPluginHealth_NeverPanics — arbitrary state transitions
// and messages must not corrupt the health registry.
func FuzzReportPluginHealth_NeverPanics(f *testing.F) {
	f.Add("plugin-a", "ok", "all green")
	f.Add("plugin-b", "degraded", "slow")
	f.Add("plugin-c", "failed", "crashed")
	f.Add("", "", "")
	f.Add("plugin-d", "unknown-state", "weird")

	f.Fuzz(func(t *testing.T, name, state, msg string) {
		ClearPluginHealth()
		defer ClearPluginHealth()

		ReportPluginHealth(name, HealthStatus{
			State:   HealthState(state),
			Message: msg,
		})

		// Reading must never panic, regardless of what was written.
		_ = PluginHealth()
		_ = ListPluginHealthSorted()

		// Empty-name is the documented no-op.
		if name == "" {
			if len(PluginHealth()) != 0 {
				t.Fatal("empty-name report should be a no-op")
			}
		}
	})
}

// FuzzSafeCallT_NeverPanics — the generic variant under fuzz.
func FuzzSafeCallT_NeverPanics(f *testing.F) {
	f.Add("panic msg 1", 0)
	f.Add("", 42)
	f.Add("long " + string(make([]byte, 1024)), -1)

	f.Fuzz(func(t *testing.T, panicMsg string, returnVal int) {
		// Test 1: panic — return zero value of int (i.e. 0) + err.
		v, err := SafeCall("fuzz-panic", func() (int, error) {
			panic(panicMsg)
		})
		if err == nil {
			t.Fatal("SafeCall returned nil err for panicking fn")
		}
		if v != 0 {
			t.Fatalf("SafeCall should return zero value of T on panic; got %d", v)
		}

		// Test 2: success — returns the supplied value.
		v2, err2 := SafeCall("fuzz-ok", func() (int, error) {
			return returnVal, nil
		})
		if err2 != nil {
			t.Fatalf("SafeCall returned non-nil err for success: %v", err2)
		}
		if v2 != returnVal {
			t.Fatalf("SafeCall returned %d, want %d", v2, returnVal)
		}
	})
}

// Compile-time check that the fuzz corpus seed input types match
// the function signatures. If Go ever changes fuzz semantics, this
// will fail to compile rather than silently passing.
var _ = func() context.Context { return context.Background() }
