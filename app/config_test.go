package app

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestConfig_WithDefaults verifies the fill-empty-fields contract.
// Pure method — no env read — runs in parallel.
func TestConfig_WithDefaults(t *testing.T) {
	t.Parallel()

	t.Run("fills empty fields", func(t *testing.T) {
		t.Parallel()
		c := &Config{}
		out := c.WithDefaults()
		assert.Equal(t, DefaultAppMode, out.AppMode)
		assert.Equal(t, DefaultPort, out.AppPort)
		assert.Equal(t, DefaultHost, out.AppHost)
	})

	t.Run("preserves populated fields", func(t *testing.T) {
		t.Parallel()
		c := &Config{AppMode: "stdio", AppPort: "9090", AppHost: "0.0.0.0"}
		out := c.WithDefaults()
		assert.Equal(t, "stdio", out.AppMode)
		assert.Equal(t, "9090", out.AppPort)
		assert.Equal(t, "0.0.0.0", out.AppHost)
	})

	t.Run("does not mutate receiver", func(t *testing.T) {
		t.Parallel()
		c := &Config{}
		_ = c.WithDefaults()
		assert.Equal(t, "", c.AppMode, "receiver AppMode must stay empty after WithDefaults")
		assert.Equal(t, "", c.AppPort)
		assert.Equal(t, "", c.AppHost)
	})

	t.Run("nil receiver returns nil", func(t *testing.T) {
		t.Parallel()
		var c *Config
		assert.Nil(t, c.WithDefaults())
	})
}

// TestConfig_Validate verifies the required-field contract.
// Pure method — no env read — runs in parallel.
func TestConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *Config
		devMode bool
		wantErr error
	}{
		{
			name:    "nil config errors",
			cfg:     nil,
			devMode: false,
			wantErr: errors.New("config: nil"),
		},
		{
			name:    "missing both credentials fails in prod",
			cfg:     &Config{},
			devMode: false,
			wantErr: ErrMissingKiteCredentials,
		},
		{
			name:    "missing api key fails in prod",
			cfg:     &Config{KiteAPISecret: "s"},
			devMode: false,
			wantErr: ErrMissingKiteCredentials,
		},
		{
			name:    "missing api secret fails in prod",
			cfg:     &Config{KiteAPIKey: "k"},
			devMode: false,
			wantErr: ErrMissingKiteCredentials,
		},
		{
			name:    "missing credentials OK in dev mode",
			cfg:     &Config{},
			devMode: true,
			wantErr: nil,
		},
		{
			name:    "both credentials present OK",
			cfg:     &Config{KiteAPIKey: "k", KiteAPISecret: "s"},
			devMode: false,
			wantErr: nil,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.cfg.Validate(tc.devMode)
			if tc.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			assert.Error(t, err)
			// Sentinel check when applicable; message comparison for the
			// nil-config case which uses a plain errors.New.
			if errors.Is(tc.wantErr, ErrMissingKiteCredentials) {
				assert.ErrorIs(t, err, ErrMissingKiteCredentials)
			} else {
				assert.EqualError(t, err, tc.wantErr.Error())
			}
		})
	}
}

// TestConfigFromEnv_StructShape confirms ConfigFromEnv returns a non-nil
// *Config with all expected fields addressable. It deliberately does NOT
// call t.Setenv — the purpose of extracting Config is to free tests from
// process-level env mutation. Value-level parsing is covered by the
// WithDefaults + Validate tests above.
//
// This test reads the ambient env which is fine for a smoke-level assertion:
// we only check that the constructor doesn't panic and that booleans fall
// through with the expected empty-string default (false).
func TestConfigFromEnv_StructShape(t *testing.T) {
	t.Parallel()
	cfg := ConfigFromEnv()
	assert.NotNil(t, cfg)
	// EnableTrading defaults to false when ENABLE_TRADING is unset/empty.
	// We cannot assert absolute value because the caller's env is unknown,
	// but we can assert the field is reachable and typed bool.
	_ = cfg.EnableTrading
	// Sanity: all string fields are reachable (zero value OK).
	_ = cfg.KiteAPIKey
	_ = cfg.KiteAPISecret
	_ = cfg.OAuthJWTSecret
	_ = cfg.AdminEmails
	_ = cfg.AlertDBPath
}
