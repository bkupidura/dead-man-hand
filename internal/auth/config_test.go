package auth

import (
	"testing"

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
			expectedError: "auth.bearer.token is not configured, generate token with dmh-cli auth generate-bearer or explicitly disable authentication with auth.enabled: false",
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
						{Name: "", Hash: testTokenHash, Scopes: []string{"api"}},
					},
				},
			},
			expectedError: "bearer: token name is required",
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
			inputConfig: BearerConfig{},
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
