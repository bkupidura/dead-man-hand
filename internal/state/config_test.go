package state

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
				SavePath:        "state.json",
				VaultURL:        "http://127.0.0.1:8080",
				VaultClientUUID: "client-uuid",
			},
		},
		{
			inputOptions: &Options{
				VaultURL:        "http://127.0.0.1:8080",
				VaultClientUUID: "client-uuid",
			},
			expectedError: "state.file is required",
		},
		{
			inputOptions: &Options{
				SavePath: "state.json",
				VaultURL: "http://127.0.0.1:8080",
			},
			expectedError: "remote_vault.client_uuid is required",
		},
		{
			inputOptions: &Options{
				SavePath:        "state.json",
				VaultClientUUID: "client-uuid",
			},
			expectedError: "remote_vault.url is required",
		},
		{
			inputOptions: &Options{
				SavePath:        "state.json",
				VaultURL:        "not a valid url",
				VaultClientUUID: "client-uuid",
			},
			expectedError: "remote_vault.url must be a valid HTTP URL",
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
