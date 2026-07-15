package crypt

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewBearerToken(t *testing.T) {
	tests := []struct {
		mockRandRead  func(b []byte) (n int, err error)
		expectedError string
	}{
		{},
		{
			mockRandRead:  func(b []byte) (int, error) { return 0, errors.New("mock rand.Read error") },
			expectedError: "unable to generate bearer token",
		},
	}

	for _, test := range tests {
		randRead = rand.Read
		if test.mockRandRead != nil {
			randRead = test.mockRandRead
			defer func() { randRead = rand.Read }()
		}

		token, err := NewBearerToken()
		if test.expectedError != "" {
			require.Error(t, err)
			require.Contains(t, err.Error(), test.expectedError)
		} else {
			require.NoError(t, err)
			require.Regexp(t, `^[a-zA-Z0-9_-]{43}$`, token.Plaintext, "Plaintext should match regex")
			require.Regexp(t, `^[a-f0-9]{64}$`, token.Hash, "Hash should match regex")
		}
	}
}

func TestNewBearerTokenUnique(t *testing.T) {
	first, err := NewBearerToken()
	require.NoError(t, err)
	second, err := NewBearerToken()
	require.NoError(t, err)

	require.NotEqual(t, first.Plaintext, second.Plaintext)
	require.NotEqual(t, first.Hash, second.Hash)
}

func TestBearerTokenRoundTrip(t *testing.T) {
	token, err := NewBearerToken()
	require.NoError(t, err)

	require.True(t, ValidateBearerToken(token.Hash, token.Plaintext))
	require.True(t, ValidateBearerToken(strings.ToUpper(token.Hash), token.Plaintext))
	require.False(t, ValidateBearerToken(token.Hash, token.Plaintext+"x"))
}

func TestBearerTokenHash(t *testing.T) {
	tests := []struct {
		inputPlaintext string
		expectedHash   string
	}{
		{
			inputPlaintext: "test-token",
			expectedHash:   "4c5dc9b7708905f77f5e5d16316b5dfb425e68cb326dcd55a860e90a7707031e",
		},
		{
			inputPlaintext: "",
			expectedHash:   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			inputPlaintext: "another-token-123",
			expectedHash:   "0f8d3aad78ba516acdbe4aa0b1e0cf9ba12b5ed5067fdec722b8a53f325a29ac",
		},
		{
			inputPlaintext: "x",
			expectedHash:   "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
		},
		{
			inputPlaintext: "example-bearer-token",
			expectedHash:   "6e529315274fd842da9323d9af0805bbef21bd90d2cb30b3cab8fab882d20067",
		},
	}

	for _, test := range tests {
		result := hex.EncodeToString(bearerTokenHash(test.inputPlaintext))
		require.Equal(t, test.expectedHash, result)
	}
}

func TestValidateBearerToken(t *testing.T) {
	tests := []struct {
		inputPlaintext string
		inputHash      string
		expectedValid  bool
	}{
		{
			inputPlaintext: "example-bearer-token",
			inputHash:      "6e529315274fd842da9323d9af0805bbef21bd90d2cb30b3cab8fab882d20067",
			expectedValid:  true,
		},
		{
			inputPlaintext: "wrong-bearer-token",
			inputHash:      "6e529315274fd842da9323d9af0805bbef21bd90d2cb30b3cab8fab882d20067",
			expectedValid:  false,
		},
		{
			inputPlaintext: "",
			inputHash:      "0e315ab5a3c73232581742811f1dcf9106d5b79e8f8d6f123456789012345678",
			expectedValid:  false,
		},
		{
			inputPlaintext: "example-bearer-token",
			inputHash:      "",
			expectedValid:  false,
		},
		{
			inputPlaintext: "",
			inputHash:      "",
			expectedValid:  false,
		},
		{
			inputPlaintext: "example-bearer-token",
			inputHash:      "6E529315274FD842DA9323D9AF0805BBEF21BD90D2CB30B3CAB8FAB882D20067",
			expectedValid:  true,
		},
		{
			inputPlaintext: "example-bearer-token",
			inputHash:      "not-a-hex-hash",
			expectedValid:  false,
		},
		{
			inputPlaintext: "example-bearer-token",
			inputHash:      "6e529315274fd842da9323d9af0805bb",
			expectedValid:  false,
		},
	}

	for _, test := range tests {
		valid := ValidateBearerToken(test.inputHash, test.inputPlaintext)
		require.Equal(t, test.expectedValid, valid)
	}
}
