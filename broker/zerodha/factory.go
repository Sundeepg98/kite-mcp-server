package zerodha

import (
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/broker"
)

// compile-time proof that *Factory satisfies broker.Factory.
var _ broker.Factory = (*Factory)(nil)

// compile-time proof that *Auth satisfies broker.Authenticator.
var _ broker.Authenticator = (*Auth)(nil)

// Factory creates Zerodha broker.Client instances.
type Factory struct{}

// NewFactory returns a new Zerodha broker factory.
func NewFactory() *Factory {
	return &Factory{}
}

// BrokerName returns the Zerodha broker identifier.
func (f *Factory) BrokerName() broker.Name {
	return broker.Zerodha
}

// Create returns a new unauthenticated Zerodha broker client.
func (f *Factory) Create(apiKey string) (broker.Client, error) {
	kc := kiteconnect.New(apiKey)
	return New(kc), nil
}

// CreateWithToken returns an authenticated Zerodha broker client.
func (f *Factory) CreateWithToken(apiKey, accessToken string) (broker.Client, error) {
	kc := kiteconnect.New(apiKey)
	kc.SetAccessToken(accessToken)
	return New(kc), nil
}

// Auth handles Zerodha-specific authentication lifecycle.
type Auth struct{}

// NewAuth returns a new Zerodha authenticator.
func NewAuth() *Auth {
	return &Auth{}
}

// GetLoginURL returns the Zerodha login URL for the given API key.
func (a *Auth) GetLoginURL(apiKey string) string {
	kc := kiteconnect.New(apiKey)
	return kc.GetLoginURL()
}

// ExchangeToken completes Kite authentication, returning the access token and user info.
func (a *Auth) ExchangeToken(apiKey, apiSecret, requestToken string) (broker.AuthResult, error) {
	kc := kiteconnect.New(apiKey)
	sess, err := kc.GenerateSession(requestToken, apiSecret)
	if err != nil {
		return broker.AuthResult{}, err
	}
	return broker.AuthResult{
		AccessToken: sess.AccessToken,
		UserID:      sess.UserID,
		UserName:    sess.UserName,
		UserType:    sess.UserType,
	}, nil
}

// InvalidateToken invalidates a Kite access token (best-effort).
func (a *Auth) InvalidateToken(apiKey, accessToken string) error {
	kc := kiteconnect.New(apiKey)
	kc.SetAccessToken(accessToken)
	_, err := kc.InvalidateAccessToken()
	return err
}
