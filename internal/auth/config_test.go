package auth

import (
	"fmt"
	"testing"

	"dmh/internal/crypt"

	"github.com/stretchr/testify/require"
)

var (
	testTokenHash = "6e529315274fd842da9323d9af0805bbef21bd90d2cb30b3cab8fab882d20067" // sha256 of "example-bearer-token"
	otherHash     = "4c5dc9b7708905f77f5e5d16316b5dfb425e68cb326dcd55a860e90a7707031e" // sha256 of "test-token"
)

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		inputConfig   Config
		expectedError string
	}{
		{
			inputConfig: Config{},
		},
		{
			inputConfig: Config{
				Bearer: BearerConfig{
					Tokens: []Token{
						{Name: "admin", Hash: "not-a-hash", Scopes: []string{""}},
					},
				},
			},
		},
		{
			inputConfig:   Config{Enabled: true},
			expectedError: "bearer: auth.bearer.token is not configured, generate token with dmh-cli auth generate-bearer",
		},
		{
			inputConfig: Config{
				Enabled: true,
				Bearer: BearerConfig{
					Tokens: []Token{
						{Name: "admin", Hash: testTokenHash, Scopes: []string{"api"}},
					},
				},
				AnonymousScopes: []string{"healthz", "ready"},
			},
		},
		{
			inputConfig: Config{
				Enabled: true,
				Bearer: BearerConfig{
					Tokens: []Token{
						{Name: "admin", Hash: testTokenHash, Scopes: []string{"api"}},
					},
				},
				AnonymousScopes: []string{"healthz:"},
			},
			expectedError: "anonymous_scopes: scope healthz: cant contain empty segments",
		},
		{
			inputConfig: Config{
				Enabled: true,
				Bearer: BearerConfig{
					Tokens: []Token{
						{Name: "admin", Hash: testTokenHash, Scopes: []string{"api"}},
					},
				},
				SignedURL: SignedURLConfig{TTL: -1},
			},
			expectedError: "signed_url: ttl must be greater than 0",
		},
	}
	for _, test := range tests {
		err := test.inputConfig.Validate()
		if test.expectedError == "" {
			require.Nil(t, err)
		} else {
			require.NotNil(t, err)
			require.Equal(t, test.expectedError, err.Error())
		}
	}
}

func TestBearerValidate(t *testing.T) {
	tests := []struct {
		inputConfig   BearerConfig
		expectedError string
	}{
		{
			inputConfig:   BearerConfig{},
			expectedError: "auth.bearer.token is not configured, generate token with dmh-cli auth generate-bearer",
		},
		{
			inputConfig: BearerConfig{
				Tokens: []Token{
					{Name: "admin", Hash: testTokenHash, Scopes: []string{"api"}},
					{Name: "alive-cron", Hash: otherHash, Scopes: []string{"api:alive"}},
				},
			},
		},
		{
			inputConfig: BearerConfig{
				Tokens: []Token{
					{Name: "", Hash: testTokenHash, Scopes: []string{"api"}},
				},
			},
			expectedError: "token name is required",
		},
		{
			inputConfig: BearerConfig{
				Tokens: []Token{
					{Name: "admin", Hash: testTokenHash, Scopes: []string{"api"}},
					{Name: "admin", Hash: otherHash, Scopes: []string{"api"}},
				},
			},
			expectedError: "token name admin is duplicated",
		},
		{
			inputConfig: BearerConfig{
				Tokens: []Token{
					{Name: "admin", Hash: "not-a-hash", Scopes: []string{"api"}},
				},
			},
			expectedError: "token admin hash must be a hex encoded sha256",
		},
		{
			inputConfig: BearerConfig{
				Tokens: []Token{
					{Name: "admin", Hash: "6e529315274fd842da9323d9af0805bb", Scopes: []string{"api"}},
				},
			},
			expectedError: "token admin hash must be a hex encoded sha256",
		},
		{
			inputConfig: BearerConfig{
				Tokens: []Token{
					{Name: "admin", Hash: testTokenHash, Scopes: []string{"api"}},
					{Name: "admin2", Hash: "6E529315274FD842DA9323D9AF0805BBEF21BD90D2CB30B3CAB8FAB882D20067", Scopes: []string{"api"}},
				},
			},
			expectedError: "token admin2 hash is duplicated",
		},
		{
			inputConfig: BearerConfig{
				Tokens: []Token{
					{Name: "admin", Hash: testTokenHash, Scopes: []string{}},
				},
			},
			expectedError: "token admin must have at least one scope",
		},
		{
			inputConfig: BearerConfig{
				Tokens: []Token{
					{Name: "admin", Hash: testTokenHash, Scopes: []string{""}},
				},
			},
			expectedError: "token admin: scope cant be empty",
		},
	}
	for _, test := range tests {
		err := test.inputConfig.Validate()
		if test.expectedError == "" {
			require.Nil(t, err)
		} else {
			require.NotNil(t, err)
			require.Equal(t, test.expectedError, err.Error())
		}
	}
}

func TestValidateScope(t *testing.T) {
	tests := []struct {
		inputScope    string
		expectedError string
	}{
		{
			inputScope: "api",
		},
		{
			inputScope: "api:vault:store:client-uuid",
		},
		{
			inputScope:    "",
			expectedError: "scope cant be empty",
		},
		{
			inputScope:    "api::action",
			expectedError: "scope api::action cant contain empty segments",
		},
		{
			inputScope:    ":api",
			expectedError: "scope :api cant contain empty segments",
		},
		{
			inputScope:    "api:",
			expectedError: "scope api: cant contain empty segments",
		},
	}
	for _, test := range tests {
		err := validateScope(test.inputScope)
		if test.expectedError == "" {
			require.Nil(t, err)
		} else {
			require.NotNil(t, err)
			require.Equal(t, test.expectedError, err.Error())
		}
	}
}

func TestSignedURLValidate(t *testing.T) {
	tests := []struct {
		inputConfig    SignedURLConfig
		mockNewSecret  func() (string, error)
		expectedError  string
		expectedSecret string
		expectedTTL    int
	}{
		{
			inputConfig: SignedURLConfig{},
			expectedTTL: 24,
		},
		{
			inputConfig:    SignedURLConfig{Secret: "test-secret"},
			expectedSecret: "test-secret",
			expectedTTL:    24,
		},
		{
			inputConfig:    SignedURLConfig{Secret: "test-secret", TTL: 12},
			expectedSecret: "test-secret",
			expectedTTL:    12,
		},
		{
			inputConfig:   SignedURLConfig{Secret: "test-secret", TTL: -1},
			expectedError: "ttl must be greater than 0",
		},
		{
			inputConfig:   SignedURLConfig{},
			mockNewSecret: func() (string, error) { return "", fmt.Errorf("unable to generate signed url secret") },
			expectedError: "unable to generate signed url secret",
		},
	}
	for _, test := range tests {
		newSignedURLSecret = crypt.NewSignedURLSecret
		if test.mockNewSecret != nil {
			newSignedURLSecret = test.mockNewSecret
			defer func() { newSignedURLSecret = crypt.NewSignedURLSecret }()
		}

		err := test.inputConfig.Validate()
		if test.expectedError != "" {
			require.NotNil(t, err)
			require.Contains(t, err.Error(), test.expectedError)
			continue
		}
		require.Nil(t, err)
		require.Equal(t, test.expectedTTL, test.inputConfig.TTL)
		if test.expectedSecret != "" {
			require.Equal(t, test.expectedSecret, test.inputConfig.Secret)
		} else {
			require.NotEmpty(t, test.inputConfig.Secret)
		}
	}
}
