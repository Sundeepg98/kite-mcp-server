package zerodha

import (
	"errors"
	"testing"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
)

// fakeKiteSDK is a minimal KiteSDK stand-in for Phase 2 factory tests.
// Only the methods Factory/Auth actually invoke are overridden; the
// embedded KiteSDK field is nil, so any other call will panic — making
// unexpected wiring regressions loud.
type fakeKiteSDK struct {
	KiteSDK

	// recorded inputs
	setAccessTokenCalls      []string
	getLoginURLCalls         int
	generateSessionCalls     int
	invalidateAccessCalls    int
	lastGeneratedReqToken    string
	lastGeneratedAPISecret   string
	generateSessionResult    kiteconnect.UserSession
	generateSessionError     error
	getLoginURLResponse      string
	invalidateAccessResponse bool
	invalidateAccessError    error
}

func (f *fakeKiteSDK) SetAccessToken(token string) {
	f.setAccessTokenCalls = append(f.setAccessTokenCalls, token)
}

func (f *fakeKiteSDK) GetLoginURL() string {
	f.getLoginURLCalls++
	return f.getLoginURLResponse
}

func (f *fakeKiteSDK) GenerateSession(requestToken, apiSecret string) (kiteconnect.UserSession, error) {
	f.generateSessionCalls++
	f.lastGeneratedReqToken = requestToken
	f.lastGeneratedAPISecret = apiSecret
	return f.generateSessionResult, f.generateSessionError
}

func (f *fakeKiteSDK) InvalidateAccessToken() (bool, error) {
	f.invalidateAccessCalls++
	return f.invalidateAccessResponse, f.invalidateAccessError
}

// recordingConstructor returns a SDK constructor that records every
// apiKey it was called with and returns the same fake each time.
func recordingConstructor(fake *fakeKiteSDK, recordedKeys *[]string) func(apiKey string) KiteSDK {
	return func(apiKey string) KiteSDK {
		*recordedKeys = append(*recordedKeys, apiKey)
		return fake
	}
}

// --- Factory tests ---

func TestFactory_Create_UsesInjectedSDKConstructor(t *testing.T) {
	fake := &fakeKiteSDK{}
	var keys []string
	factory := NewFactory(WithSDKConstructor(recordingConstructor(fake, &keys)))

	client, err := factory.Create("test_api_key")
	if err != nil {
		t.Fatalf("Create: unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("Create: returned nil client")
	}
	if len(keys) != 1 || keys[0] != "test_api_key" {
		t.Errorf("expected constructor called once with 'test_api_key', got %v", keys)
	}
	// Create must NOT set an access token (unauthenticated path).
	if len(fake.setAccessTokenCalls) != 0 {
		t.Errorf("Create must not call SetAccessToken, got %v", fake.setAccessTokenCalls)
	}
}

func TestFactory_CreateWithToken_SetsAccessTokenOnFakeSDK(t *testing.T) {
	fake := &fakeKiteSDK{}
	var keys []string
	factory := NewFactory(WithSDKConstructor(recordingConstructor(fake, &keys)))

	client, err := factory.CreateWithToken("another_key", "tok_abc")
	if err != nil {
		t.Fatalf("CreateWithToken: unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("CreateWithToken: returned nil client")
	}
	if len(keys) != 1 || keys[0] != "another_key" {
		t.Errorf("expected constructor called once with 'another_key', got %v", keys)
	}
	if len(fake.setAccessTokenCalls) != 1 || fake.setAccessTokenCalls[0] != "tok_abc" {
		t.Errorf("expected SetAccessToken called once with 'tok_abc', got %v", fake.setAccessTokenCalls)
	}
}

func TestFactory_DefaultConstructor_UsedWhenNoOverride(t *testing.T) {
	// No WithSDKConstructor: factory must fall back to the real
	// defaultKiteSDKConstructor. We can't safely exercise it
	// (it would make network calls), but we can assert it's wired
	// via a non-nil sdkConstructor field.
	factory := NewFactory()
	if factory.sdkConstructor == nil {
		t.Fatal("default NewFactory must seed a non-nil sdkConstructor")
	}
}

func TestFactory_BrokerName_Zerodha(t *testing.T) {
	factory := NewFactory(WithSDKConstructor(recordingConstructor(&fakeKiteSDK{}, new([]string))))
	if got, want := string(factory.BrokerName()), "zerodha"; got != want {
		t.Errorf("BrokerName = %q, want %q", got, want)
	}
}

// --- Auth tests ---

func TestAuth_GetLoginURL_UsesInjectedSDK(t *testing.T) {
	fake := &fakeKiteSDK{getLoginURLResponse: "https://kite.example/login?v=3&api_key=auth_key"}
	var keys []string
	auth := NewAuth(WithSDKConstructor(recordingConstructor(fake, &keys)))

	url := auth.GetLoginURL("auth_key")
	if url != "https://kite.example/login?v=3&api_key=auth_key" {
		t.Errorf("unexpected login URL: %q", url)
	}
	if len(keys) != 1 || keys[0] != "auth_key" {
		t.Errorf("expected constructor called once with 'auth_key', got %v", keys)
	}
	if fake.getLoginURLCalls != 1 {
		t.Errorf("expected GetLoginURL called once on fake, got %d", fake.getLoginURLCalls)
	}
}

func TestAuth_ExchangeToken_HappyPath(t *testing.T) {
	fake := &fakeKiteSDK{
		generateSessionResult: kiteconnect.UserSession{
			UserProfile: kiteconnect.UserProfile{
				UserName: "Test User",
				UserType: "individual",
				Email:    "user@example.com",
			},
			UserID:      "AB1234",
			AccessToken: "access_xyz",
		},
	}
	var keys []string
	auth := NewAuth(WithSDKConstructor(recordingConstructor(fake, &keys)))

	result, err := auth.ExchangeToken("api_key_1", "api_secret_1", "req_token_1")
	if err != nil {
		t.Fatalf("ExchangeToken: unexpected error: %v", err)
	}
	if result.AccessToken != "access_xyz" {
		t.Errorf("AccessToken = %q, want 'access_xyz'", result.AccessToken)
	}
	if result.UserID != "AB1234" {
		t.Errorf("UserID = %q, want 'AB1234'", result.UserID)
	}
	if result.Email != "user@example.com" {
		t.Errorf("Email = %q, want 'user@example.com'", result.Email)
	}
	if fake.generateSessionCalls != 1 {
		t.Errorf("expected GenerateSession called once, got %d", fake.generateSessionCalls)
	}
	if fake.lastGeneratedReqToken != "req_token_1" {
		t.Errorf("lastGeneratedReqToken = %q, want 'req_token_1'", fake.lastGeneratedReqToken)
	}
	if fake.lastGeneratedAPISecret != "api_secret_1" {
		t.Errorf("lastGeneratedAPISecret = %q, want 'api_secret_1'", fake.lastGeneratedAPISecret)
	}
	if len(keys) != 1 || keys[0] != "api_key_1" {
		t.Errorf("expected constructor called once with 'api_key_1', got %v", keys)
	}
}

func TestAuth_ExchangeToken_PropagatesSDKError(t *testing.T) {
	sdkErr := errors.New("kite: invalid request token")
	fake := &fakeKiteSDK{generateSessionError: sdkErr}
	auth := NewAuth(WithSDKConstructor(recordingConstructor(fake, new([]string))))

	_, err := auth.ExchangeToken("k", "s", "t")
	if !errors.Is(err, sdkErr) {
		t.Errorf("expected wrapped SDK error, got: %v", err)
	}
}

func TestAuth_InvalidateToken_SetsAccessTokenThenInvalidates(t *testing.T) {
	fake := &fakeKiteSDK{invalidateAccessResponse: true}
	var keys []string
	auth := NewAuth(WithSDKConstructor(recordingConstructor(fake, &keys)))

	if err := auth.InvalidateToken("inv_key", "inv_tok"); err != nil {
		t.Fatalf("InvalidateToken: unexpected error: %v", err)
	}
	if len(keys) != 1 || keys[0] != "inv_key" {
		t.Errorf("expected constructor called once with 'inv_key', got %v", keys)
	}
	if len(fake.setAccessTokenCalls) != 1 || fake.setAccessTokenCalls[0] != "inv_tok" {
		t.Errorf("expected SetAccessToken('inv_tok'), got %v", fake.setAccessTokenCalls)
	}
	if fake.invalidateAccessCalls != 1 {
		t.Errorf("expected InvalidateAccessToken called once, got %d", fake.invalidateAccessCalls)
	}
}

func TestAuth_InvalidateToken_PropagatesError(t *testing.T) {
	sdkErr := errors.New("kite: token already invalid")
	fake := &fakeKiteSDK{invalidateAccessError: sdkErr}
	auth := NewAuth(WithSDKConstructor(recordingConstructor(fake, new([]string))))

	err := auth.InvalidateToken("k", "t")
	if !errors.Is(err, sdkErr) {
		t.Errorf("expected wrapped SDK error, got: %v", err)
	}
}

func TestAuth_DefaultConstructor_UsedWhenNoOverride(t *testing.T) {
	auth := NewAuth()
	if auth.sdkConstructor == nil {
		t.Fatal("default NewAuth must seed a non-nil sdkConstructor")
	}
}
