package crypt

import (
	"crypto/rand"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewSignedURLSecret(t *testing.T) {
	tests := []struct {
		mockRandRead  func(b []byte) (n int, err error)
		expectedError string
	}{
		{},
		{
			mockRandRead:  func(b []byte) (int, error) { return 0, errors.New("mock rand.Read error") },
			expectedError: "unable to generate signed url secret",
		},
	}

	for _, test := range tests {
		randRead = rand.Read
		if test.mockRandRead != nil {
			randRead = test.mockRandRead
			defer func() { randRead = rand.Read }()
		}

		secret, err := NewSignedURLSecret()
		if test.expectedError != "" {
			require.Error(t, err)
			require.Contains(t, err.Error(), test.expectedError)
		} else {
			require.NoError(t, err)
			require.Regexp(t, `^[a-f0-9]{64}$`, secret)
		}
	}
}

func TestSignURL(t *testing.T) {
	tests := []struct {
		inputSecret    string
		inputPath      string
		inputExpiresAt time.Time
		expectedURL    string
	}{
		{
			inputSecret:    "test-secret",
			inputPath:      "/alive",
			inputExpiresAt: time.Unix(1700000000, 0),
			expectedURL:    "/alive?e=s44we8&s=jKmy7dtg9wy0dYV_0TP4Fw",
		},
		{
			inputSecret:    "other-secret",
			inputPath:      "/alive",
			inputExpiresAt: time.Unix(1700000000, 0),
			expectedURL:    "/alive?e=s44we8&s=8D3A_dPvguqWOKuuHMGQMA",
		},
	}

	for _, test := range tests {
		require.Equal(t, test.expectedURL, SignURL(test.inputSecret, test.inputPath, test.inputExpiresAt))
	}
}

func TestValidateSignedURL(t *testing.T) {
	tests := []struct {
		inputSecret   string
		inputPath     string
		inputURL      string
		expectedValid bool
	}{
		{
			inputSecret:   "test-secret",
			inputPath:     "/alive",
			inputURL:      SignURL("test-secret", "/alive", time.Now().Add(time.Hour)),
			expectedValid: true,
		},
		{
			inputSecret:   "test-secret",
			inputPath:     "/api/action/store",
			inputURL:      SignURL("test-secret", "/api/action/store", time.Now().Add(time.Hour)),
			expectedValid: true,
		},
		{
			inputSecret: "wrong-secret",
			inputPath:   "/alive",
			inputURL:    SignURL("test-secret", "/alive", time.Now().Add(time.Hour)),
		},
		{
			inputSecret: "test-secret",
			inputPath:   "/api/action/store",
			inputURL:    SignURL("test-secret", "/alive", time.Now().Add(time.Hour)),
		},
		{
			inputSecret: "test-secret",
			inputPath:   "/alive",
			inputURL:    SignURL("test-secret", "/alive", time.Now().Add(-time.Hour)),
		},
		{
			inputSecret: "test-secret",
			inputPath:   "/alive",
			inputURL:    "/alive?e=invalid!&s=jKmy7dtg9wy0dYV_0TP4Fw",
		},
		{
			inputSecret: "test-secret",
			inputPath:   "/alive",
			inputURL:    "/alive?e=s44we8",
		},
	}
	for _, test := range tests {
		signed, err := url.Parse(test.inputURL)
		require.NoError(t, err)
		valid := ValidateSignedURL(test.inputSecret, test.inputPath, signed.Query().Get("e"), signed.Query().Get("s"))
		require.Equal(t, test.expectedValid, valid, "url %s", test.inputURL)
	}
}
