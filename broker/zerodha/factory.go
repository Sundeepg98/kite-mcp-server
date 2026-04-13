package zerodha

import (
	"github.com/zerodha/kite-mcp-server/broker"
)

// compile-time proof that *Factory satisfies broker.Factory.
var _ broker.Factory = (*Factory)(nil)

// compile-time proof that *Auth satisfies broker.Authenticator.
var _ broker.Authenticator = (*Auth)(nil)

// FactoryOption configures optional behavior on a Factory or Auth instance.
// The only knob in Phase 2 is the SDK constructor override used by tests.
type FactoryOption func(*factoryConfig)

// factoryConfig holds the shared, optional settings for Factory/Auth.
// Kept package-private so callers must go through FactoryOption helpers.
type factoryConfig struct {
	sdkConstructor func(apiKey string) KiteSDK
}

// WithSDKConstructor overrides the SDK constructor used by the Factory
// or Auth. In production this is never called and the default
// defaultKiteSDKConstructor (real gokiteconnect client wrapped in
// *kiteSDKAdapter) is used. Tests inject a fake to avoid HTTP.
func WithSDKConstructor(ctor func(apiKey string) KiteSDK) FactoryOption {
	return func(c *factoryConfig) {
		if ctor != nil {
			c.sdkConstructor = ctor
		}
	}
}

// applyFactoryOptions seeds a factoryConfig with the real SDK
// constructor and then applies caller overrides.
func applyFactoryOptions(opts []FactoryOption) factoryConfig {
	cfg := factoryConfig{sdkConstructor: defaultKiteSDKConstructor}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return cfg
}

// Factory creates Zerodha broker.Client instances.
type Factory struct {
	sdkConstructor func(apiKey string) KiteSDK
}

// NewFactory returns a new Zerodha broker factory. Pass
// WithSDKConstructor to inject a fake SDK for testing.
func NewFactory(opts ...FactoryOption) *Factory {
	cfg := applyFactoryOptions(opts)
	return &Factory{sdkConstructor: cfg.sdkConstructor}
}

// BrokerName returns the Zerodha broker identifier.
func (f *Factory) BrokerName() broker.Name {
	return broker.Zerodha
}

// Create returns a new unauthenticated Zerodha broker client.
func (f *Factory) Create(apiKey string) (broker.Client, error) {
	sdk := f.sdkConstructor(apiKey)
	return newClientFromSDK(sdk), nil
}

// CreateWithToken returns an authenticated Zerodha broker client.
func (f *Factory) CreateWithToken(apiKey, accessToken string) (broker.Client, error) {
	sdk := f.sdkConstructor(apiKey)
	sdk.SetAccessToken(accessToken)
	return newClientFromSDK(sdk), nil
}

// Auth handles Zerodha-specific authentication lifecycle.
type Auth struct {
	sdkConstructor func(apiKey string) KiteSDK
}

// NewAuth returns a new Zerodha authenticator. Pass WithSDKConstructor
// to inject a fake SDK for testing.
func NewAuth(opts ...FactoryOption) *Auth {
	cfg := applyFactoryOptions(opts)
	return &Auth{sdkConstructor: cfg.sdkConstructor}
}

// GetLoginURL returns the Zerodha login URL for the given API key.
func (a *Auth) GetLoginURL(apiKey string) string {
	sdk := a.sdkConstructor(apiKey)
	return sdk.GetLoginURL()
}

// ExchangeToken completes Kite authentication, returning the access token and user info.
func (a *Auth) ExchangeToken(apiKey, apiSecret, requestToken string) (broker.AuthResult, error) {
	sdk := a.sdkConstructor(apiKey)
	sess, err := sdk.GenerateSession(requestToken, apiSecret)
	if err != nil {
		return broker.AuthResult{}, err
	}
	return broker.AuthResult{
		AccessToken: sess.AccessToken,
		UserID:      sess.UserID,
		UserName:    sess.UserName,
		UserType:    sess.UserType,
		Email:       sess.Email,
	}, nil
}

// InvalidateToken invalidates a Kite access token (best-effort).
func (a *Auth) InvalidateToken(apiKey, accessToken string) error {
	sdk := a.sdkConstructor(apiKey)
	sdk.SetAccessToken(accessToken)
	_, err := sdk.InvalidateAccessToken()
	return err
}
