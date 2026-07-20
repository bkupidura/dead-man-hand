package vault

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOptionsValidate(t *testing.T) {
	tests := []struct {
		inputOptions  *Options
		expectedError string
	}{
		{
			inputOptions: &Options{
				SavePath: "vault.json",
				Key:      "AGE-SECRET-KEY-1GEUMZFAZD42WGZFGATTTJHV4SURK8LU507QVCAKXKJP6UTFMJTCS0E3QJ4",
			},
		},
		{
			inputOptions: &Options{
				Key: "AGE-SECRET-KEY-1GEUMZFAZD42WGZFGATTTJHV4SURK8LU507QVCAKXKJP6UTFMJTCS0E3QJ4",
			},
			expectedError: "vault.file is required",
		},
		{
			inputOptions: &Options{
				SavePath: "vault.json",
			},
			expectedError: "vault.key is required",
		},
		{
			inputOptions: &Options{
				SavePath: "vault.json",
				Key:      "not-a-valid-age-key",
			},
			expectedError: "vault.key must be a valid age private key",
		},
	}
	for _, test := range tests {
		err := test.inputOptions.Validate()
		if test.expectedError == "" {
			require.Nil(t, err)
		} else {
			require.NotNil(t, err)
			require.Equal(t, test.expectedError, err.Error())
		}
	}
}
