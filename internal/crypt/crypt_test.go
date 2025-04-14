package crypt

import (
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	tests := []struct {
		inputKey                       string
		expectedCryptType              CryptInterface
		expectedError                  error
		mockAgeGenerateX255191Identity func() (*age.X25519Identity, error)
	}{
		{
			inputKey:                       "",
			expectedError:                  fmt.Errorf("mockAgeGenerateX25519Identity error"),
			mockAgeGenerateX255191Identity: func() (*age.X25519Identity, error) { return nil, fmt.Errorf("mockAgeGenerateX25519Identity error") },
		},
		{
			inputKey:      "a",
			expectedError: fmt.Errorf("malformed secret key: separator '1' at invalid position: pos=-1, len=1"),
		},
		{
			inputKey:          "",
			expectedCryptType: &Crypt{},
		},
		{
			inputKey:          "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0",
			expectedCryptType: &Crypt{},
		},
	}
	for _, test := range tests {
		ageGenerateX25519Identity = age.GenerateX25519Identity
		if test.mockAgeGenerateX255191Identity != nil {
			ageGenerateX25519Identity = test.mockAgeGenerateX255191Identity
		}
		c, err := New(test.inputKey)
		require.Equal(t, test.expectedError, err)
		require.IsType(t, test.expectedCryptType, c)
		if test.expectedError == nil && test.inputKey != "" {
			require.Equal(t, test.inputKey, c.GetPrivateKey())
		}
	}
}

func TestEncrypt(t *testing.T) {
	tests := []struct {
		inputKey          string
		inputData         string
		expectedOutput    string
		expectedError     error
		mockAgeEncrypt    func(dst io.Writer, recipients ...age.Recipient) (io.WriteCloser, error)
		mockIoWriteString func(w io.Writer, s string) (n int, err error)
	}{
		{
			inputKey:       "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0",
			inputData:      "",
			expectedOutput: "",
			expectedError:  fmt.Errorf("empty data"),
		},
		{
			inputKey:       "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0",
			inputData:      "test",
			expectedOutput: "",
			expectedError:  fmt.Errorf("mockAgeEncrypt error"),
			mockAgeEncrypt: func(dst io.Writer, recipients ...age.Recipient) (io.WriteCloser, error) {
				return nil, fmt.Errorf("mockAgeEncrypt error")
			},
		},
		{
			inputKey:          "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0",
			inputData:         "test",
			expectedOutput:    "",
			expectedError:     fmt.Errorf("mockIoWriteString error"),
			mockIoWriteString: func(w io.Writer, s string) (n int, err error) { return 0, fmt.Errorf("mockIoWriteString error") },
		},
		{
			inputKey:       "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0",
			inputData:      "test",
			expectedOutput: "test",
		},
		{
			inputKey:       "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0",
			inputData:      "data data data data",
			expectedOutput: "data data data data",
		},
		{
			inputKey: "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0",
			inputData: `multi
            line
            data
            `,
			expectedOutput: `multi
            line
            data
            `,
		},
		{
			inputKey:       "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0",
			inputData:      strings.Repeat("long data", 1000),
			expectedOutput: strings.Repeat("long data", 1000),
		},
	}
	for _, test := range tests {
		ageEncrypt = age.Encrypt
		ioWriteString = io.WriteString
		if test.mockAgeEncrypt != nil {
			ageEncrypt = test.mockAgeEncrypt
		}
		if test.mockIoWriteString != nil {
			ioWriteString = test.mockIoWriteString
		}

		c, err := New(test.inputKey)
		require.Nil(t, err)

		out, err := c.Encrypt(test.inputData)
		require.Equal(t, test.expectedError, err)

		if err != nil {
			continue
		}

		decryptedOutput, err := c.Decrypt(out)
		require.Nil(t, err)

		require.Equal(t, test.expectedOutput, decryptedOutput)
	}
}

func TestEncryptDiffOutputSameInput(t *testing.T) {
	c, err := New("")
	require.NoError(t, err)

	enc1, err := c.Encrypt("same data")
	require.Nil(t, err)

	enc2, err := c.Encrypt("same data")
	require.Nil(t, err)

	require.NotEqual(t, enc1, enc2)

}

func TestDecrypt(t *testing.T) {
	tests := []struct {
		inputKey       string
		inputData      string
		expectedOutput string
		expectedError  error
		mockAgeDecrypt func(src io.Reader, identities ...age.Identity) (io.Reader, error)
		mockIoCopy     func(dst io.Writer, src io.Reader) (written int64, err error)
	}{
		{
			inputKey:       "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0",
			inputData:      "",
			expectedOutput: "",
			expectedError:  fmt.Errorf("empty data"),
		},
		{
			inputKey:       "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0",
			inputData:      "1",
			expectedOutput: "",
			expectedError:  base64.CorruptInputError(0),
		},
		{
			inputKey:       "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0",
			inputData:      "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBQOGpYV1g4cDFJMEZtWVZCbU9qeVFGdWU2aU5QVzV4bDErbEVBTzE3Vkd3Cjh6Z09NRHIvTGVTOWpweW4rZ3ZlREM4eFJxUzhQa2lmSWw2U0c5UVZGYWMKLS0tIFA3RTBZOEo3a1ZNYm9rd2pscXJLR0NrVDQ4SzRwZE0vWmNPWVM4TTUrYnMK7hTjaIsTD4MJdMN9IrND5KPfSV14dObevcULUqA0YQm4d9sJ",
			expectedOutput: "",
			expectedError:  fmt.Errorf("mockAgeDecrypt error"),
			mockAgeDecrypt: func(src io.Reader, identities ...age.Identity) (io.Reader, error) {
				return nil, fmt.Errorf("mockAgeDecrypt error")
			},
		},
		{
			inputKey:       "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0",
			inputData:      "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBQOGpYV1g4cDFJMEZtWVZCbU9qeVFGdWU2aU5QVzV4bDErbEVBTzE3Vkd3Cjh6Z09NRHIvTGVTOWpweW4rZ3ZlREM4eFJxUzhQa2lmSWw2U0c5UVZGYWMKLS0tIFA3RTBZOEo3a1ZNYm9rd2pscXJLR0NrVDQ4SzRwZE0vWmNPWVM4TTUrYnMK7hTjaIsTD4MJdMN9IrND5KPfSV14dObevcULUqA0YQm4d9sJ",
			expectedOutput: "",
			expectedError:  fmt.Errorf("mockIoCopy error"),
			mockIoCopy: func(dst io.Writer, src io.Reader) (written int64, err error) {
				return 0, fmt.Errorf("mockIoCopy error")
			},
		},
		{
			inputKey:       "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0",
			inputData:      "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBqYi9heG5OREg1OGtWaVVZKzcvbkxtUGI3a1FkNGJoS21vUkx2MWJ5NlNjCm9RRWw3cm45MjZqSER0Y1d5VFhIODlWUmF1RnlEUGlvUlI4OGdRaHdyOFEKLS0tIERSZ3JnTFY4YUtjelNtV1dWRXoyN2VhRkRxREk1NG4rRXAyZ29GU3ZtS0kKhVMDuRIJHGXia7fFN/qB08WMMpfLVDL+fgIBPENHxYnfntWomPUvFpe3xJbT5tkGP50H",
			expectedOutput: "data data data data",
		},
		{
			inputKey:  "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0",
			inputData: "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBwTEtFbHZnR3YvTkRUWXhUQVNEU01rNDNvSE0zL1VHaFQwclNnMDFCN1EwCnpnRzF5RC9paUF5ZzE5b0VBUHpkYzQzU2sybjNHc2lUbXU1clpINlIwSE0KLS0tIG92WUpwcG1KWnpCbEdVUXFYRm1zMWttaG1tWVVjNkxBbW5UeGw1dW9tcEkKgOc3rBe1dwG424648INj2pzhbABZDMVMCzoS4gCchG6IgFQfs5l2nc0iZqiqZFRYc8aOXH9dlfSk5eWIvY6dDdFWb0wa0C2JeZmTUB5kps927bdx",
			expectedOutput: `multi
            line
            data
            `,
		},
		{
			inputKey:       "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0",
			inputData:      "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",
			expectedOutput: strings.Repeat("long data", 1000),
		},
	}
	for _, test := range tests {
		ageDecrypt = age.Decrypt
		ioCopy = io.Copy
		if test.mockAgeDecrypt != nil {
			ageDecrypt = test.mockAgeDecrypt
		}
		if test.mockIoCopy != nil {
			ioCopy = test.mockIoCopy
		}

		c, err := New(test.inputKey)
		require.Nil(t, err)

		out, err := c.Decrypt(test.inputData)
		require.Equal(t, test.expectedError, err)
		require.Equal(t, test.expectedOutput, out)
	}
}

func TestDecryptionWithWrongKey(t *testing.T) {
	c1, err := New("")
	require.Nil(t, err)

	encrypted, err := c1.Encrypt("test data")
	require.Nil(t, err)

	c2, err := New("")
	require.Nil(t, err)

	decrypted, err := c2.Decrypt(encrypted)
	require.Equal(t, "", decrypted)
	require.Error(t, err)
}

func TestRoundTrip(t *testing.T) {
	tests := []struct {
		data string
	}{
		{"hello world"},
		{"!@#$%^&*()"},
		{"line1\nline2\nline3"},
		{strings.Repeat("a", 10000)},
	}

	for _, test := range tests {
		c, err := New("")
		require.Nil(t, err)

		encrypted, err := c.Encrypt(test.data)
		require.Nil(t, err)

		decrypted, err := c.Decrypt(encrypted)
		require.Nil(t, err)

		require.Equal(t, test.data, decrypted)
	}
}

func TestDecryptTamperedData(t *testing.T) {
	c, err := New("")
	require.Nil(t, err)

	original := "sensitive data"
	encrypted, err := c.Encrypt(original)
	require.Nil(t, err)

	decoded, err := base64.StdEncoding.DecodeString(encrypted)
	require.Nil(t, err)

	decoded[10] ^= 0xFF
	tampered := base64.StdEncoding.EncodeToString(decoded)

	_, err = c.Decrypt(tampered)
	require.Error(t, err)
}
