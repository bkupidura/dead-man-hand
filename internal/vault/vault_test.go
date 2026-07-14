package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"dmh/internal/crypt"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockCrypt struct {
	mock.Mock
}

func (m *mockCrypt) Encrypt(data string) (string, error) {
	args := m.Called(data)
	return args.String(0), args.Error(1)
}

func (m *mockCrypt) Decrypt(data string) (string, error) {
	args := m.Called(data)
	return args.String(0), args.Error(1)
}

func (m *mockCrypt) GetPrivateKey() string {
	args := m.Called()
	return args.String(0)
}

func TestNew(t *testing.T) {
	vaultFile := "test_vault.json"
	tests := []struct {
		inputOptions          *Options
		expectedVault         func() VaultInterface
		expectedErrorContains string
		vaultPathFunc         func()
	}{
		{
			inputOptions: &Options{
				SavePath:          vaultFile,
				Key:               "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0",
				SecretProcessUnit: time.Hour,
			},
			expectedVault: func() VaultInterface {
				return &Vault{
					data:              map[string]*VaultData{},
					key:               "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0",
					savePath:          vaultFile,
					secretProcessUnit: time.Hour,
				}
			},
			vaultPathFunc: func() {},
		},
		{
			inputOptions: &Options{
				SavePath:          vaultFile,
				Key:               "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0",
				SecretProcessUnit: time.Millisecond,
			},
			expectedVault: func() VaultInterface {
				return nil
			},
			expectedErrorContains: "SecretProcessUnit must be bigger than second",
			vaultPathFunc:         func() {},
		},
		{
			inputOptions: &Options{
				SavePath:          vaultFile,
				Key:               "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0",
				SecretProcessUnit: time.Second,
			},
			expectedVault: func() VaultInterface {
				return nil
			},
			vaultPathFunc: func() {
				f, err := os.Create(vaultFile)
				require.Nil(t, err)
				defer f.Close()
				_, err = f.WriteString(`{"broken json`)
				require.Nil(t, err)
			},
			expectedErrorContains: "unexpected EOF",
		},
		{
			inputOptions: &Options{
				SavePath:          vaultFile,
				Key:               "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0",
				SecretProcessUnit: time.Hour,
			},
			expectedVault: func() VaultInterface {
				mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
				require.Nil(t, err)
				return &Vault{
					data: map[string]*VaultData{
						"testClientUUID": {
							LastSeen: mockTime,
							Secrets: map[string]*Secret{
								"testSecret1": {
									Key:          "test",
									ProcessAfter: 10,
								},
								"testSecret2": {
									Key:          "test2",
									ProcessAfter: 10,
								},
							},
						},
						"testClientUUID2": {
							LastSeen: mockTime,
							Secrets: map[string]*Secret{
								"testSecret3": {
									Key:          "test",
									ProcessAfter: 10,
								},
							},
						},
					},
					key:               "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0",
					savePath:          vaultFile,
					secretProcessUnit: time.Hour,
				}
			},
			vaultPathFunc: func() {
				f, err := os.Create(vaultFile)
				require.Nil(t, err)
				defer f.Close()
				_, err = f.WriteString(`{"testClientUUID":{"last_seen":"2025-03-26T14:55:40.119447+01:00","secrets":{"testSecret1":{"key":"test","process_after":10},"testSecret2":{"key":"test2","process_after":10}}},"testClientUUID2":{"last_seen":"2025-03-26T14:55:40.119447+01:00","secrets":{"testSecret3":{"key":"test","process_after":10}}}}`)
				require.Nil(t, err)
			},
		},
		{
			inputOptions: &Options{
				Key:               "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0",
				SavePath:          "test_blocker_vault/vault.json",
				SecretProcessUnit: time.Second,
			},
			expectedVault:         func() VaultInterface { return nil },
			expectedErrorContains: "unable to open vault file",
			vaultPathFunc: func() {
				require.NoError(t, os.WriteFile("test_blocker_vault", []byte("x"), 0600))
			},
		},
	}
	for _, test := range tests {
		os.Remove(vaultFile)
		test.vaultPathFunc()
		defer os.Remove(vaultFile)
		defer os.Remove("test_blocker_vault")

		v, err := New(test.inputOptions)
		if test.expectedErrorContains == "" {
			require.NoError(t, err)
		} else {
			require.ErrorContains(t, err, test.expectedErrorContains)
		}
		require.Equal(t, test.expectedVault(), v)
	}
}

func TestUpdateLastSeen(t *testing.T) {
	vaultFile := "test_vault.json"
	os.Remove(vaultFile)
	defer os.Remove(vaultFile)
	mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
	require.Nil(t, err)

	v := &Vault{
		data: map[string]*VaultData{
			"testClientUUID": {
				LastSeen: mockTime,
				Secrets:  map[string]*Secret{},
			},
		},
		savePath: vaultFile,
	}

	for _, clientUUID := range []string{"testClientUUID", "newClientUUID"} {
		v.UpdateLastSeen(clientUUID)

		vaultData, ok := v.data[clientUUID]
		require.True(t, ok, "expected key %s to exist in the map", clientUUID)

		require.GreaterOrEqual(t, float64(1), time.Since(vaultData.LastSeen).Seconds())
	}

}

func TestGetSecret(t *testing.T) {
	tests := []struct {
		inputVault      func() *Vault
		inputClientUUID string
		inputSecretUUID string
		expectedSecret  *Secret
		mockCryptNew    func(string) (crypt.CryptInterface, error)
		expectedError   error
	}{
		{
			inputVault: func() *Vault {
				v := &Vault{
					data: map[string]*VaultData{
						"testClientUUID": {
							LastSeen: time.Now(),
							Secrets: map[string]*Secret{
								"testSecretUUID": {
									Key:          "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBnTTYreTRpQnFtU1lBcFZ6SVBaelBJMTdOMXRHdGswQ2dWb3ZiZ1daQWpRCmNQTWlZMFZpekV4WnVxUmRneEhLYmlOWitNa0FVZDBtMmlWUjRxL3NmSlkKLS0tIEdUdk13TTdwMEhYOVkrQ2IvSFk0UEFwYWRWVTlUQjhCYjhBSUdUWUdvWDgKTI1UILFd211V7M6mdgRZuVdsJYF8wNUL7KGZa3RYFzJWntY7",
									ProcessAfter: 10,
								},
							},
						},
						"testClientUUID2": {
							LastSeen: time.Now(),
							Secrets: map[string]*Secret{
								"testSecretUUID2": {
									Key:          "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBQK0doYUZSUnlLdE1tekpuMy92bVJkYUk3eXcrV0JSTWNHZVFqODFxdlh3CkF3TFVSdzRTYjgyUVc5VGd6OWVHVnlHU1ZOUjNYOXIzaDN2eDV0UXRkbWMKLS0tIFp3bHNOaG13bHdwZFVNYTNxcUtJSzZBVjVmdk9XL2pxUU1QdmNpNDJTS3cKm9vBYgATSTfFLlJP7YOipBLj+Xo7BXRzf9IqfsCtTK1F2ngcWw",
									ProcessAfter: 10,
								},
							},
						},
					},
					key:               "AGE-SECRET-KEY-1GEUMZFAZD42WGZFGATTTJHV4SURK8LU507QVCAKXKJP6UTFMJTCS0E3QJ4",
					secretProcessUnit: time.Hour,
				}
				return v
			},
			inputClientUUID: "testClientUUID3",
			inputSecretUUID: "testSecretUUID",
			expectedError:   fmt.Errorf("secret testClientUUID3/testSecretUUID is missing"),
		},
		{
			inputVault: func() *Vault {
				v := &Vault{
					data: map[string]*VaultData{
						"testClientUUID": {
							LastSeen: time.Now(),
							Secrets: map[string]*Secret{
								"testSecretUUID": {
									Key:          "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBnTTYreTRpQnFtU1lBcFZ6SVBaelBJMTdOMXRHdGswQ2dWb3ZiZ1daQWpRCmNQTWlZMFZpekV4WnVxUmRneEhLYmlOWitNa0FVZDBtMmlWUjRxL3NmSlkKLS0tIEdUdk13TTdwMEhYOVkrQ2IvSFk0UEFwYWRWVTlUQjhCYjhBSUdUWUdvWDgKTI1UILFd211V7M6mdgRZuVdsJYF8wNUL7KGZa3RYFzJWntY7",
									ProcessAfter: 10,
								},
							},
						},
						"testClientUUID2": {
							LastSeen: time.Now(),
							Secrets: map[string]*Secret{
								"testSecretUUID2": {
									Key:          "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBQK0doYUZSUnlLdE1tekpuMy92bVJkYUk3eXcrV0JSTWNHZVFqODFxdlh3CkF3TFVSdzRTYjgyUVc5VGd6OWVHVnlHU1ZOUjNYOXIzaDN2eDV0UXRkbWMKLS0tIFp3bHNOaG13bHdwZFVNYTNxcUtJSzZBVjVmdk9XL2pxUU1QdmNpNDJTS3cKm9vBYgATSTfFLlJP7YOipBLj+Xo7BXRzf9IqfsCtTK1F2ngcWw",
									ProcessAfter: 10,
								},
							},
						},
					},
					key:               "AGE-SECRET-KEY-1GEUMZFAZD42WGZFGATTTJHV4SURK8LU507QVCAKXKJP6UTFMJTCS0E3QJ4",
					secretProcessUnit: time.Hour,
				}
				return v
			},
			inputClientUUID: "testClientUUID",
			inputSecretUUID: "testSecretUUID3",
			expectedError:   fmt.Errorf("secret testClientUUID/testSecretUUID3 is missing"),
		},
		{
			inputVault: func() *Vault {
				v := &Vault{
					data: map[string]*VaultData{
						"testClientUUID": {
							LastSeen: time.Now(),
							Secrets: map[string]*Secret{
								"testSecretUUID": {
									Key:          "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBnTTYreTRpQnFtU1lBcFZ6SVBaelBJMTdOMXRHdGswQ2dWb3ZiZ1daQWpRCmNQTWlZMFZpekV4WnVxUmRneEhLYmlOWitNa0FVZDBtMmlWUjRxL3NmSlkKLS0tIEdUdk13TTdwMEhYOVkrQ2IvSFk0UEFwYWRWVTlUQjhCYjhBSUdUWUdvWDgKTI1UILFd211V7M6mdgRZuVdsJYF8wNUL7KGZa3RYFzJWntY7",
									ProcessAfter: 10,
								},
							},
						},
						"testClientUUID2": {
							LastSeen: time.Now(),
							Secrets: map[string]*Secret{
								"testSecretUUID2": {
									Key:          "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBQK0doYUZSUnlLdE1tekpuMy92bVJkYUk3eXcrV0JSTWNHZVFqODFxdlh3CkF3TFVSdzRTYjgyUVc5VGd6OWVHVnlHU1ZOUjNYOXIzaDN2eDV0UXRkbWMKLS0tIFp3bHNOaG13bHdwZFVNYTNxcUtJSzZBVjVmdk9XL2pxUU1QdmNpNDJTS3cKm9vBYgATSTfFLlJP7YOipBLj+Xo7BXRzf9IqfsCtTK1F2ngcWw",
									ProcessAfter: 10,
								},
							},
						},
					},
					key:               "AGE-SECRET-KEY-1GEUMZFAZD42WGZFGATTTJHV4SURK8LU507QVCAKXKJP6UTFMJTCS0E3QJ4",
					secretProcessUnit: time.Hour,
				}
				return v
			},
			inputClientUUID: "testClientUUID",
			inputSecretUUID: "testSecretUUID",
			expectedError:   fmt.Errorf("secret testClientUUID/testSecretUUID %w", ErrSecretNotReleased),
		},
		{
			inputVault: func() *Vault {
				mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
				require.Nil(t, err)
				v := &Vault{
					data: map[string]*VaultData{
						"testClientUUID": {
							LastSeen: mockTime,
							Secrets: map[string]*Secret{
								"testSecretUUID": {
									Key:          "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBnTTYreTRpQnFtU1lBcFZ6SVBaelBJMTdOMXRHdGswQ2dWb3ZiZ1daQWpRCmNQTWlZMFZpekV4WnVxUmRneEhLYmlOWitNa0FVZDBtMmlWUjRxL3NmSlkKLS0tIEdUdk13TTdwMEhYOVkrQ2IvSFk0UEFwYWRWVTlUQjhCYjhBSUdUWUdvWDgKTI1UILFd211V7M6mdgRZuVdsJYF8wNUL7KGZa3RYFzJWntY7",
									ProcessAfter: 10,
								},
							},
						},
						"testClientUUID2": {
							LastSeen: time.Now(),
							Secrets: map[string]*Secret{
								"testSecretUUID2": {
									Key:          "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBQK0doYUZSUnlLdE1tekpuMy92bVJkYUk3eXcrV0JSTWNHZVFqODFxdlh3CkF3TFVSdzRTYjgyUVc5VGd6OWVHVnlHU1ZOUjNYOXIzaDN2eDV0UXRkbWMKLS0tIFp3bHNOaG13bHdwZFVNYTNxcUtJSzZBVjVmdk9XL2pxUU1QdmNpNDJTS3cKm9vBYgATSTfFLlJP7YOipBLj+Xo7BXRzf9IqfsCtTK1F2ngcWw",
									ProcessAfter: 10,
								},
							},
						},
					},
					key:               "AGE-SECRET-KEY-1GEUMZFAZD42WGZFGATTTJHV4SURK8LU507QVCAKXKJP6UTFMJTCS0E3QJ4",
					secretProcessUnit: time.Hour,
				}
				return v
			},
			inputClientUUID: "testClientUUID2",
			inputSecretUUID: "testSecretUUID2",
			expectedError:   fmt.Errorf("secret testClientUUID2/testSecretUUID2 %w", ErrSecretNotReleased),
		},
		{
			inputVault: func() *Vault {
				now := time.Now()
				nowMinus9 := now.Add(-9 * time.Hour)
				v := &Vault{
					data: map[string]*VaultData{
						"testClientUUID": {
							LastSeen: nowMinus9,
							Secrets: map[string]*Secret{
								"testSecretUUID": {
									Key:          "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBnTTYreTRpQnFtU1lBcFZ6SVBaelBJMTdOMXRHdGswQ2dWb3ZiZ1daQWpRCmNQTWlZMFZpekV4WnVxUmRneEhLYmlOWitNa0FVZDBtMmlWUjRxL3NmSlkKLS0tIEdUdk13TTdwMEhYOVkrQ2IvSFk0UEFwYWRWVTlUQjhCYjhBSUdUWUdvWDgKTI1UILFd211V7M6mdgRZuVdsJYF8wNUL7KGZa3RYFzJWntY7",
									ProcessAfter: 10,
								},
							},
						},
						"testClientUUID2": {
							LastSeen: time.Now(),
							Secrets: map[string]*Secret{
								"testSecretUUID2": {
									Key:          "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBQK0doYUZSUnlLdE1tekpuMy92bVJkYUk3eXcrV0JSTWNHZVFqODFxdlh3CkF3TFVSdzRTYjgyUVc5VGd6OWVHVnlHU1ZOUjNYOXIzaDN2eDV0UXRkbWMKLS0tIFp3bHNOaG13bHdwZFVNYTNxcUtJSzZBVjVmdk9XL2pxUU1QdmNpNDJTS3cKm9vBYgATSTfFLlJP7YOipBLj+Xo7BXRzf9IqfsCtTK1F2ngcWw",
									ProcessAfter: 10,
								},
							},
						},
					},
					key:               "AGE-SECRET-KEY-1GEUMZFAZD42WGZFGATTTJHV4SURK8LU507QVCAKXKJP6UTFMJTCS0E3QJ4",
					secretProcessUnit: time.Hour,
				}
				return v
			},
			inputClientUUID: "testClientUUID",
			inputSecretUUID: "testSecretUUID",
			expectedError:   fmt.Errorf("secret testClientUUID/testSecretUUID %w", ErrSecretNotReleased),
		},
		{
			inputVault: func() *Vault {
				mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
				require.Nil(t, err)
				v := &Vault{
					data: map[string]*VaultData{
						"testClientUUID": {
							LastSeen: mockTime,
							Secrets: map[string]*Secret{
								"testSecretUUID": {
									Key:          "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBnTTYreTRpQnFtU1lBcFZ6SVBaelBJMTdOMXRHdGswQ2dWb3ZiZ1daQWpRCmNQTWlZMFZpekV4WnVxUmRneEhLYmlOWitNa0FVZDBtMmlWUjRxL3NmSlkKLS0tIEdUdk13TTdwMEhYOVkrQ2IvSFk0UEFwYWRWVTlUQjhCYjhBSUdUWUdvWDgKTI1UILFd211V7M6mdgRZuVdsJYF8wNUL7KGZa3RYFzJWntY7",
									ProcessAfter: 10,
								},
							},
						},
						"testClientUUID2": {
							LastSeen: time.Now(),
							Secrets: map[string]*Secret{
								"testSecretUUID2": {
									Key:          "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBQK0doYUZSUnlLdE1tekpuMy92bVJkYUk3eXcrV0JSTWNHZVFqODFxdlh3CkF3TFVSdzRTYjgyUVc5VGd6OWVHVnlHU1ZOUjNYOXIzaDN2eDV0UXRkbWMKLS0tIFp3bHNOaG13bHdwZFVNYTNxcUtJSzZBVjVmdk9XL2pxUU1QdmNpNDJTS3cKm9vBYgATSTfFLlJP7YOipBLj+Xo7BXRzf9IqfsCtTK1F2ngcWw",
									ProcessAfter: 10,
								},
							},
						},
					},
					key:               "AGE-SECRET-KEY-1GEUMZFAZD42WGZFGATTTJHV4SURK8LU507QVCAKXKJP6UTFMJTCS0E3QJ4",
					secretProcessUnit: time.Hour,
				}
				return v
			},
			inputClientUUID: "testClientUUID",
			inputSecretUUID: "testSecretUUID",
			mockCryptNew: func(string) (crypt.CryptInterface, error) {
				return nil, fmt.Errorf("mockCryptNew error")
			},
			expectedError: fmt.Errorf("mockCryptNew error"),
		},
		{
			inputVault: func() *Vault {
				mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
				require.Nil(t, err)
				v := &Vault{
					data: map[string]*VaultData{
						"testClientUUID": {
							LastSeen: mockTime,
							Secrets: map[string]*Secret{
								"testSecretUUID": {
									Key:          "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBnTTYreTRpQnFtU1lBcFZ6SVBaelBJMTdOMXRHdGswQ2dWb3ZiZ1daQWpRCmNQTWlZMFZpekV4WnVxUmRneEhLYmlOWitNa0FVZDBtMmlWUjRxL3NmSlkKLS0tIEdUdk13TTdwMEhYOVkrQ2IvSFk0UEFwYWRWVTlUQjhCYjhBSUdUWUdvWDgKTI1UILFd211V7M6mdgRZuVdsJYF8wNUL7KGZa3RYFzJWntY7",
									ProcessAfter: 10,
								},
							},
						},
						"testClientUUID2": {
							LastSeen: time.Now(),
							Secrets: map[string]*Secret{
								"testSecretUUID2": {
									Key:          "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBQK0doYUZSUnlLdE1tekpuMy92bVJkYUk3eXcrV0JSTWNHZVFqODFxdlh3CkF3TFVSdzRTYjgyUVc5VGd6OWVHVnlHU1ZOUjNYOXIzaDN2eDV0UXRkbWMKLS0tIFp3bHNOaG13bHdwZFVNYTNxcUtJSzZBVjVmdk9XL2pxUU1QdmNpNDJTS3cKm9vBYgATSTfFLlJP7YOipBLj+Xo7BXRzf9IqfsCtTK1F2ngcWw",
									ProcessAfter: 10,
								},
							},
						},
					},
					key:               "AGE-SECRET-KEY-1GEUMZFAZD42WGZFGATTTJHV4SURK8LU507QVCAKXKJP6UTFMJTCS0E3QJ4",
					secretProcessUnit: time.Hour,
				}
				return v
			},
			inputClientUUID: "testClientUUID",
			inputSecretUUID: "testSecretUUID",
			mockCryptNew: func(string) (crypt.CryptInterface, error) {
				c := new(mockCrypt)
				c.On("Decrypt", "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBnTTYreTRpQnFtU1lBcFZ6SVBaelBJMTdOMXRHdGswQ2dWb3ZiZ1daQWpRCmNQTWlZMFZpekV4WnVxUmRneEhLYmlOWitNa0FVZDBtMmlWUjRxL3NmSlkKLS0tIEdUdk13TTdwMEhYOVkrQ2IvSFk0UEFwYWRWVTlUQjhCYjhBSUdUWUdvWDgKTI1UILFd211V7M6mdgRZuVdsJYF8wNUL7KGZa3RYFzJWntY7").Return("", fmt.Errorf("mockCryptNew error"))
				return c, nil
			},
			expectedError: fmt.Errorf("mockCryptNew error"),
		},
		{
			inputVault: func() *Vault {
				now := time.Now()
				nowMinus11 := now.Add(-11 * time.Hour)
				v := &Vault{
					data: map[string]*VaultData{
						"testClientUUID": {
							LastSeen: nowMinus11,
							Secrets: map[string]*Secret{
								"testSecretUUID": {
									Key:            "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBnTTYreTRpQnFtU1lBcFZ6SVBaelBJMTdOMXRHdGswQ2dWb3ZiZ1daQWpRCmNQTWlZMFZpekV4WnVxUmRneEhLYmlOWitNa0FVZDBtMmlWUjRxL3NmSlkKLS0tIEdUdk13TTdwMEhYOVkrQ2IvSFk0UEFwYWRWVTlUQjhCYjhBSUdUWUdvWDgKTI1UILFd211V7M6mdgRZuVdsJYF8wNUL7KGZa3RYFzJWntY7",
									ProcessAfter:   10,
									EncryptionMeta: EncryptionMeta{Kind: "X25519"},
								},
							},
						},
						"testClientUUID2": {
							LastSeen: time.Now(),
							Secrets: map[string]*Secret{
								"testSecretUUID2": {
									Key:            "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBQK0doYUZSUnlLdE1tekpuMy92bVJkYUk3eXcrV0JSTWNHZVFqODFxdlh3CkF3TFVSdzRTYjgyUVc5VGd6OWVHVnlHU1ZOUjNYOXIzaDN2eDV0UXRkbWMKLS0tIFp3bHNOaG13bHdwZFVNYTNxcUtJSzZBVjVmdk9XL2pxUU1QdmNpNDJTS3cKm9vBYgATSTfFLlJP7YOipBLj+Xo7BXRzf9IqfsCtTK1F2ngcWw",
									ProcessAfter:   10,
									EncryptionMeta: EncryptionMeta{Kind: "X25519"},
								},
							},
						},
					},
					key:               "AGE-SECRET-KEY-1GEUMZFAZD42WGZFGATTTJHV4SURK8LU507QVCAKXKJP6UTFMJTCS0E3QJ4",
					secretProcessUnit: time.Hour,
				}
				return v
			},
			inputClientUUID: "testClientUUID",
			inputSecretUUID: "testSecretUUID",
			expectedSecret: &Secret{
				Key:            "test",
				ProcessAfter:   10,
				EncryptionMeta: EncryptionMeta{Kind: "X25519"},
			},
		},
		{
			inputVault: func() *Vault {
				mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
				require.Nil(t, err)
				v := &Vault{
					data: map[string]*VaultData{
						"testClientUUID": {
							LastSeen: mockTime,
							Secrets: map[string]*Secret{
								"testSecretUUID": {
									Key:            "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBnTTYreTRpQnFtU1lBcFZ6SVBaelBJMTdOMXRHdGswQ2dWb3ZiZ1daQWpRCmNQTWlZMFZpekV4WnVxUmRneEhLYmlOWitNa0FVZDBtMmlWUjRxL3NmSlkKLS0tIEdUdk13TTdwMEhYOVkrQ2IvSFk0UEFwYWRWVTlUQjhCYjhBSUdUWUdvWDgKTI1UILFd211V7M6mdgRZuVdsJYF8wNUL7KGZa3RYFzJWntY7",
									ProcessAfter:   10,
									EncryptionMeta: EncryptionMeta{Kind: "X25519"},
								},
							},
						},
						"testClientUUID2": {
							LastSeen: time.Now(),
							Secrets: map[string]*Secret{
								"testSecretUUID2": {
									Key:            "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBQK0doYUZSUnlLdE1tekpuMy92bVJkYUk3eXcrV0JSTWNHZVFqODFxdlh3CkF3TFVSdzRTYjgyUVc5VGd6OWVHVnlHU1ZOUjNYOXIzaDN2eDV0UXRkbWMKLS0tIFp3bHNOaG13bHdwZFVNYTNxcUtJSzZBVjVmdk9XL2pxUU1QdmNpNDJTS3cKm9vBYgATSTfFLlJP7YOipBLj+Xo7BXRzf9IqfsCtTK1F2ngcWw",
									ProcessAfter:   10,
									EncryptionMeta: EncryptionMeta{Kind: "X25519"},
								},
							},
						},
					},
					key:               "AGE-SECRET-KEY-1GEUMZFAZD42WGZFGATTTJHV4SURK8LU507QVCAKXKJP6UTFMJTCS0E3QJ4",
					secretProcessUnit: time.Hour,
				}
				return v
			},
			inputClientUUID: "testClientUUID",
			inputSecretUUID: "testSecretUUID",
			expectedSecret: &Secret{
				Key:            "test",
				ProcessAfter:   10,
				EncryptionMeta: EncryptionMeta{Kind: "X25519"},
			},
		},
	}

	for _, test := range tests {
		cryptNew = crypt.New
		if test.mockCryptNew != nil {
			cryptNew = test.mockCryptNew
			defer func() {
				cryptNew = crypt.New
			}()
		}
		v := test.inputVault()
		secret, err := v.GetSecret(test.inputClientUUID, test.inputSecretUUID)
		require.Equal(t, test.expectedError, err)
		require.Equal(t, test.expectedSecret, secret)
	}
}

func TestAddSecret(t *testing.T) {
	tests := []struct {
		inputVault      func() *Vault
		inputClientUUID string
		inputSecretUUID string
		inputSecret     *Secret
		expectedSecret  *Secret
		mockCryptNew    func(string) (crypt.CryptInterface, error)
		expectedError   error
	}{
		{
			inputVault: func() *Vault {
				mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
				require.Nil(t, err)
				v := &Vault{
					savePath: "test_vault.json",
					data: map[string]*VaultData{
						"testClientUUID": {
							LastSeen: mockTime,
							Secrets: map[string]*Secret{
								"testSecretUUID": {
									Key:          "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBnTTYreTRpQnFtU1lBcFZ6SVBaelBJMTdOMXRHdGswQ2dWb3ZiZ1daQWpRCmNQTWlZMFZpekV4WnVxUmRneEhLYmlOWitNa0FVZDBtMmlWUjRxL3NmSlkKLS0tIEdUdk13TTdwMEhYOVkrQ2IvSFk0UEFwYWRWVTlUQjhCYjhBSUdUWUdvWDgKTI1UILFd211V7M6mdgRZuVdsJYF8wNUL7KGZa3RYFzJWntY7",
									ProcessAfter: 10,
								},
							},
						},
						"testClientUUID2": {
							LastSeen: time.Now(),
							Secrets: map[string]*Secret{
								"testSecretUUID2": {
									Key:          "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBQK0doYUZSUnlLdE1tekpuMy92bVJkYUk3eXcrV0JSTWNHZVFqODFxdlh3CkF3TFVSdzRTYjgyUVc5VGd6OWVHVnlHU1ZOUjNYOXIzaDN2eDV0UXRkbWMKLS0tIFp3bHNOaG13bHdwZFVNYTNxcUtJSzZBVjVmdk9XL2pxUU1QdmNpNDJTS3cKm9vBYgATSTfFLlJP7YOipBLj+Xo7BXRzf9IqfsCtTK1F2ngcWw==",
									ProcessAfter: 10,
								},
							},
						},
					},
					key:               "AGE-SECRET-KEY-1GEUMZFAZD42WGZFGATTTJHV4SURK8LU507QVCAKXKJP6UTFMJTCS0E3QJ4",
					secretProcessUnit: time.Hour,
				}
				return v
			},
			inputClientUUID: "testClientUUID",
			inputSecretUUID: "testSecretUUID",
			inputSecret: &Secret{
				Key:          "test2",
				ProcessAfter: 10,
			},
			expectedError: fmt.Errorf("secret testClientUUID/testSecretUUID already exists"),
		},
		{
			inputVault: func() *Vault {
				mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
				require.Nil(t, err)
				v := &Vault{
					savePath: "test_vault.json",
					data: map[string]*VaultData{
						"testClientUUID": {
							LastSeen: mockTime,
							Secrets: map[string]*Secret{
								"testSecretUUID": {
									Key:          "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBnTTYreTRpQnFtU1lBcFZ6SVBaelBJMTdOMXRHdGswQ2dWb3ZiZ1daQWpRCmNQTWlZMFZpekV4WnVxUmRneEhLYmlOWitNa0FVZDBtMmlWUjRxL3NmSlkKLS0tIEdUdk13TTdwMEhYOVkrQ2IvSFk0UEFwYWRWVTlUQjhCYjhBSUdUWUdvWDgKTI1UILFd211V7M6mdgRZuVdsJYF8wNUL7KGZa3RYFzJWntY7",
									ProcessAfter: 10,
								},
							},
						},
						"testClientUUID2": {
							LastSeen: time.Now(),
							Secrets: map[string]*Secret{
								"testSecretUUID2": {
									Key:          "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBQK0doYUZSUnlLdE1tekpuMy92bVJkYUk3eXcrV0JSTWNHZVFqODFxdlh3CkF3TFVSdzRTYjgyUVc5VGd6OWVHVnlHU1ZOUjNYOXIzaDN2eDV0UXRkbWMKLS0tIFp3bHNOaG13bHdwZFVNYTNxcUtJSzZBVjVmdk9XL2pxUU1QdmNpNDJTS3cKm9vBYgATSTfFLlJP7YOipBLj+Xo7BXRzf9IqfsCtTK1F2ngcWw==",
									ProcessAfter: 10,
								},
							},
						},
					},
					key:               "AGE-SECRET-KEY-1GEUMZFAZD42WGZFGATTTJHV4SURK8LU507QVCAKXKJP6UTFMJTCS0E3QJ4",
					secretProcessUnit: time.Hour,
				}
				return v
			},
			inputClientUUID: "testClientUUID",
			inputSecretUUID: "testSecretUUID2",
			inputSecret: &Secret{
				Key:          "test2",
				ProcessAfter: 10,
			},
			mockCryptNew: func(string) (crypt.CryptInterface, error) {
				return nil, fmt.Errorf("mockCryptNew error")
			},
			expectedError: fmt.Errorf("mockCryptNew error"),
		},
		{
			inputVault: func() *Vault {
				mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
				require.Nil(t, err)
				v := &Vault{
					savePath: "test_vault.json",
					data: map[string]*VaultData{
						"testClientUUID": {
							LastSeen: mockTime,
							Secrets: map[string]*Secret{
								"testSecretUUID": {
									Key:          "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBnTTYreTRpQnFtU1lBcFZ6SVBaelBJMTdOMXRHdGswQ2dWb3ZiZ1daQWpRCmNQTWlZMFZpekV4WnVxUmRneEhLYmlOWitNa0FVZDBtMmlWUjRxL3NmSlkKLS0tIEdUdk13TTdwMEhYOVkrQ2IvSFk0UEFwYWRWVTlUQjhCYjhBSUdUWUdvWDgKTI1UILFd211V7M6mdgRZuVdsJYF8wNUL7KGZa3RYFzJWntY7",
									ProcessAfter: 10,
								},
							},
						},
						"testClientUUID2": {
							LastSeen: time.Now(),
							Secrets: map[string]*Secret{
								"testSecretUUID2": {
									Key:          "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBQK0doYUZSUnlLdE1tekpuMy92bVJkYUk3eXcrV0JSTWNHZVFqODFxdlh3CkF3TFVSdzRTYjgyUVc5VGd6OWVHVnlHU1ZOUjNYOXIzaDN2eDV0UXRkbWMKLS0tIFp3bHNOaG13bHdwZFVNYTNxcUtJSzZBVjVmdk9XL2pxUU1QdmNpNDJTS3cKm9vBYgATSTfFLlJP7YOipBLj+Xo7BXRzf9IqfsCtTK1F2ngcWw==",
									ProcessAfter: 10,
								},
							},
						},
					},
					key:               "AGE-SECRET-KEY-1GEUMZFAZD42WGZFGATTTJHV4SURK8LU507QVCAKXKJP6UTFMJTCS0E3QJ4",
					secretProcessUnit: time.Hour,
				}
				return v
			},
			inputClientUUID: "testClientUUID",
			inputSecretUUID: "testSecretUUID2",
			inputSecret: &Secret{
				Key:          "test2",
				ProcessAfter: 10,
			},
			mockCryptNew: func(string) (crypt.CryptInterface, error) {
				c := new(mockCrypt)
				c.On("Encrypt", "test2").Return("", fmt.Errorf("mockCryptNew error"))
				return c, nil
			},
			expectedError: fmt.Errorf("mockCryptNew error"),
		},
		{
			inputVault: func() *Vault {
				mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
				require.Nil(t, err)
				v := &Vault{
					savePath: "test_vault.json",
					data: map[string]*VaultData{
						"testClientUUID": {
							LastSeen: mockTime,
							Secrets: map[string]*Secret{
								"testSecretUUID": {
									Key:          "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBnTTYreTRpQnFtU1lBcFZ6SVBaelBJMTdOMXRHdGswQ2dWb3ZiZ1daQWpRCmNQTWlZMFZpekV4WnVxUmRneEhLYmlOWitNa0FVZDBtMmlWUjRxL3NmSlkKLS0tIEdUdk13TTdwMEhYOVkrQ2IvSFk0UEFwYWRWVTlUQjhCYjhBSUdUWUdvWDgKTI1UILFd211V7M6mdgRZuVdsJYF8wNUL7KGZa3RYFzJWntY7",
									ProcessAfter: 10,
								},
							},
						},
						"testClientUUID2": {
							LastSeen: time.Now(),
							Secrets: map[string]*Secret{
								"testSecretUUID2": {
									Key:          "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBQK0doYUZSUnlLdE1tekpuMy92bVJkYUk3eXcrV0JSTWNHZVFqODFxdlh3CkF3TFVSdzRTYjgyUVc5VGd6OWVHVnlHU1ZOUjNYOXIzaDN2eDV0UXRkbWMKLS0tIFp3bHNOaG13bHdwZFVNYTNxcUtJSzZBVjVmdk9XL2pxUU1QdmNpNDJTS3cKm9vBYgATSTfFLlJP7YOipBLj+Xo7BXRzf9IqfsCtTK1F2ngcWw==",
									ProcessAfter: 10,
								},
							},
						},
					},
					key:               "AGE-SECRET-KEY-1GEUMZFAZD42WGZFGATTTJHV4SURK8LU507QVCAKXKJP6UTFMJTCS0E3QJ4",
					secretProcessUnit: time.Hour,
				}
				return v
			},
			inputClientUUID: "testClientUUID",
			inputSecretUUID: "testSecretUUID2",
			inputSecret: &Secret{
				Key:          "test2",
				ProcessAfter: 10,
			},
			expectedSecret: &Secret{
				Key:            "test2",
				ProcessAfter:   10,
				EncryptionMeta: EncryptionMeta{Kind: "X25519"},
			},
		},
	}
	vaultFile := "test_vault.json"
	os.Remove(vaultFile)
	defer os.Remove(vaultFile)
	for _, test := range tests {
		cryptNew = crypt.New
		if test.mockCryptNew != nil {
			cryptNew = test.mockCryptNew
			defer func() {
				cryptNew = crypt.New
			}()
		}
		v := test.inputVault()
		err := v.AddSecret(test.inputClientUUID, test.inputSecretUUID, test.inputSecret)
		require.Equal(t, test.expectedError, err)
		if err == nil {
			secret, err := v.GetSecret(test.inputClientUUID, test.inputSecretUUID)
			require.Nil(t, err)
			require.Equal(t, test.expectedSecret, secret)

			encryptedSecret, ok := v.data[test.inputClientUUID].Secrets[test.inputSecretUUID]
			require.True(t, ok)

			require.NotEqual(t, encryptedSecret.Key, secret.Key)
		}
	}
}

func TestDeleteSecret(t *testing.T) {
	tests := []struct {
		inputVault      func() *Vault
		inputClientUUID string
		inputSecretUUID string
		expectedSecrets map[string]*Secret
		expectedError   error
	}{
		{
			inputVault: func() *Vault {
				v := &Vault{
					savePath: "test_vault.json",
					data: map[string]*VaultData{
						"testClientUUID": {
							LastSeen: time.Now(),
							Secrets: map[string]*Secret{
								"testSecretUUID": {
									Key:          "test",
									ProcessAfter: 10,
								},
								"testSecretUUID2": {
									Key:          "test2",
									ProcessAfter: 10,
								},
							},
						},
						"testClientUUID2": {
							LastSeen: time.Now(),
							Secrets: map[string]*Secret{
								"testSecretUUID2": {
									Key:          "test2",
									ProcessAfter: 10,
								},
							},
						},
					},
					secretProcessUnit: time.Hour,
				}
				return v
			},
			inputClientUUID: "testClientUUID",
			inputSecretUUID: "testSecretUUID3",
			expectedError:   fmt.Errorf("secret testClientUUID/testSecretUUID3 is missing"),
			expectedSecrets: map[string]*Secret{
				"testSecretUUID": {
					Key:          "test",
					ProcessAfter: 10,
				},
				"testSecretUUID2": {
					Key:          "test2",
					ProcessAfter: 10,
				},
			},
		},
		{
			inputVault: func() *Vault {
				v := &Vault{
					savePath: "test_vault.json",
					data: map[string]*VaultData{
						"testClientUUID": {
							LastSeen: time.Now(),
							Secrets: map[string]*Secret{
								"testSecretUUID": {
									Key:          "test",
									ProcessAfter: 10,
								},
								"testSecretUUID2": {
									Key:          "test2",
									ProcessAfter: 10,
								},
							},
						},
						"testClientUUID2": {
							LastSeen: time.Now(),
							Secrets: map[string]*Secret{
								"testSecretUUID2": {
									Key:          "test2",
									ProcessAfter: 10,
								},
							},
						},
					},
					secretProcessUnit: time.Hour,
				}
				return v
			},
			inputClientUUID: "testClientUUID",
			inputSecretUUID: "testSecretUUID",
			expectedError:   fmt.Errorf("secret testClientUUID/testSecretUUID %w", ErrSecretNotReleased),
			expectedSecrets: map[string]*Secret{
				"testSecretUUID": {
					Key:          "test",
					ProcessAfter: 10,
				},
				"testSecretUUID2": {
					Key:          "test2",
					ProcessAfter: 10,
				},
			},
		},
		{
			inputVault: func() *Vault {
				now := time.Now()
				nowMinus9 := now.Add(-9 * time.Hour)
				v := &Vault{
					savePath: "test_vault.json",
					data: map[string]*VaultData{
						"testClientUUID": {
							LastSeen: nowMinus9,
							Secrets: map[string]*Secret{
								"testSecretUUID": {
									Key:          "test",
									ProcessAfter: 10,
								},
								"testSecretUUID2": {
									Key:          "test2",
									ProcessAfter: 10,
								},
							},
						},
						"testClientUUID2": {
							LastSeen: time.Now(),
							Secrets: map[string]*Secret{
								"testSecretUUID2": {
									Key:          "test2",
									ProcessAfter: 10,
								},
							},
						},
					},
					secretProcessUnit: time.Hour,
				}
				return v
			},
			inputClientUUID: "testClientUUID",
			inputSecretUUID: "testSecretUUID",
			expectedError:   fmt.Errorf("secret testClientUUID/testSecretUUID %w", ErrSecretNotReleased),
			expectedSecrets: map[string]*Secret{
				"testSecretUUID": {
					Key:          "test",
					ProcessAfter: 10,
				},
				"testSecretUUID2": {
					Key:          "test2",
					ProcessAfter: 10,
				},
			},
		},
		{
			inputVault: func() *Vault {
				now := time.Now()
				nowMinus11 := now.Add(-11 * time.Hour)
				v := &Vault{
					savePath: "test_vault.json",
					data: map[string]*VaultData{
						"testClientUUID": {
							LastSeen: nowMinus11,
							Secrets: map[string]*Secret{
								"testSecretUUID": {
									Key:          "test",
									ProcessAfter: 10,
								},
								"testSecretUUID2": {
									Key:          "test2",
									ProcessAfter: 10,
								},
							},
						},
						"testClientUUID2": {
							LastSeen: time.Now(),
							Secrets: map[string]*Secret{
								"testSecretUUID2": {
									Key:          "test2",
									ProcessAfter: 10,
								},
							},
						},
					},
					secretProcessUnit: time.Hour,
				}
				return v
			},
			inputClientUUID: "testClientUUID",
			inputSecretUUID: "testSecretUUID",
			expectedSecrets: map[string]*Secret{
				"testSecretUUID2": {
					Key:          "test2",
					ProcessAfter: 10,
				},
			},
		},
		{
			inputVault: func() *Vault {
				now := time.Now()
				nowMinus11 := now.Add(-11 * time.Hour)
				v := &Vault{
					savePath: "test_vault.json",
					data: map[string]*VaultData{
						"testClientUUID": {
							LastSeen: nowMinus11,
							Secrets: map[string]*Secret{
								"testSecretUUID": {
									Key:          "test",
									ProcessAfter: 10,
								},
							},
						},
						"testClientUUID2": {
							LastSeen: time.Now(),
							Secrets: map[string]*Secret{
								"testSecretUUID2": {
									Key:          "test2",
									ProcessAfter: 10,
								},
							},
						},
					},
					secretProcessUnit: time.Hour,
				}
				return v
			},
			inputClientUUID: "testClientUUID",
			inputSecretUUID: "testSecretUUID",
			expectedSecrets: map[string]*Secret{},
		},
		{
			inputVault: func() *Vault {
				return &Vault{
					savePath:          "test_vault.json",
					data:              map[string]*VaultData{},
					secretProcessUnit: time.Hour,
				}
			},
			inputClientUUID: "unknownClientUUID",
			inputSecretUUID: "testSecretUUID",
			expectedError:   fmt.Errorf("secret unknownClientUUID/testSecretUUID is missing"),
		},
	}
	vaultFile := "test_vault.json"
	os.Remove(vaultFile)
	defer os.Remove(vaultFile)
	for _, test := range tests {
		v := test.inputVault()
		err := v.DeleteSecret(test.inputClientUUID, test.inputSecretUUID)
		require.Equal(t, test.expectedError, err)
		if test.expectedSecrets == nil {
			require.NotContains(t, v.data, test.inputClientUUID)
		} else {
			require.Equal(t, test.expectedSecrets, v.data[test.inputClientUUID].Secrets)
		}
	}
}

func TestSave(t *testing.T) {
	tests := []struct {
		inputData       func() map[string]*VaultData
		expectedData    string
		mockAtomicWrite func(string, []byte, os.FileMode) error
		mockJsonMarshal func(any) ([]byte, error)
		shouldPanic     bool
	}{
		{
			inputData: func() map[string]*VaultData {
				return map[string]*VaultData{"fail": {Secrets: map[string]*Secret{}}}
			},
			mockJsonMarshal: func(any) ([]byte, error) { return nil, fmt.Errorf("mockJsonMarshal error") },
			shouldPanic:     true,
		},
		{
			inputData: func() map[string]*VaultData {
				mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
				require.Nil(t, err)
				d := map[string]*VaultData{
					"testClientUUID": {
						LastSeen: mockTime,
						Secrets: map[string]*Secret{
							"testSecret1": {
								Key:            "encrypted",
								ProcessAfter:   10,
								EncryptionMeta: EncryptionMeta{Kind: "X25519"},
							},
							"testSecret2": {
								Key:            "encrypted2",
								ProcessAfter:   10,
								EncryptionMeta: EncryptionMeta{Kind: "X25519"},
							},
						},
					},
				}
				return d
			},
			mockAtomicWrite: func(string, []byte, os.FileMode) error { return fmt.Errorf("mockAtomicWrite error") },
			shouldPanic:     true,
		},
		{
			inputData: func() map[string]*VaultData {
				mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
				require.Nil(t, err)
				d := map[string]*VaultData{
					"testClientUUID": {
						LastSeen: mockTime,
						Secrets: map[string]*Secret{
							"testSecret1": {
								Key:            "encrypted",
								ProcessAfter:   10,
								EncryptionMeta: EncryptionMeta{Kind: "X25519"},
							},
							"testSecret2": {
								Key:            "encrypted2",
								ProcessAfter:   10,
								EncryptionMeta: EncryptionMeta{Kind: "X25519"},
							},
						},
					},
					"testClientUUID2": {
						LastSeen: mockTime,
						Secrets: map[string]*Secret{
							"testSecret3": {
								Key:            "encrypted3",
								ProcessAfter:   10,
								EncryptionMeta: EncryptionMeta{Kind: "X25519"},
							},
						},
					},
				}
				return d
			},
			expectedData: `{"testClientUUID":{"last_seen":"2025-03-26T14:55:40.119447+01:00","secrets":{"testSecret1":{"key":"encrypted","process_after":10,"encryption":{"kind":"X25519"}},"testSecret2":{"key":"encrypted2","process_after":10,"encryption":{"kind":"X25519"}}}},"testClientUUID2":{"last_seen":"2025-03-26T14:55:40.119447+01:00","secrets":{"testSecret3":{"key":"encrypted3","process_after":10,"encryption":{"kind":"X25519"}}}}}`,
		},
		{
			inputData: func() map[string]*VaultData {
				return map[string]*VaultData{"fail": {Secrets: map[string]*Secret{}}}
			},
			mockAtomicWrite: func(string, []byte, os.FileMode) error {
				return fmt.Errorf("mockAtomicWrite write error")
			},
			shouldPanic: true,
		},
	}
	oldAtomicWrite := atomicWrite
	defer func() {
		atomicWrite = oldAtomicWrite
		jsonMarshal = json.Marshal
	}()
	for _, test := range tests {
		atomicWrite = oldAtomicWrite
		if test.mockAtomicWrite != nil {
			atomicWrite = test.mockAtomicWrite
		}

		jsonMarshal = json.Marshal
		if test.mockJsonMarshal != nil {
			jsonMarshal = test.mockJsonMarshal
		}

		os.Remove("test_vault.json")
		defer os.Remove("test_vault.json")

		v := &Vault{
			data:     test.inputData(),
			savePath: "test_vault.json",
		}

		if test.shouldPanic {
			require.Panics(t, v.save)
		} else {
			v.save()
			data, err := os.ReadFile("test_vault.json")
			require.Nil(t, err)
			require.Equal(t, test.expectedData, string(data))
		}
	}
}

func TestAtomicWriteUsesRestrictivePermissions(t *testing.T) {
	path := "test_perms_vault.json"
	os.Remove(path)
	defer os.Remove(path)

	require.NoError(t, atomicWrite(path, []byte("{}"), 0600))

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())

	// Open failure (missing directory) must surface as an error.
	require.Error(t, atomicWrite("nonexistent-dir/vault.json", []byte("{}"), 0600))
}

func TestNewTightensExistingFilePermissions(t *testing.T) {
	path := "test_perms_new_vault.json"
	os.Remove(path)
	defer os.Remove(path)

	// World-readable file left by an older version.
	require.NoError(t, os.WriteFile(path, []byte(`{}`), 0644))

	_, err := New(&Options{SavePath: path, SecretProcessUnit: time.Hour})
	require.NoError(t, err)

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestNewChmodFailureIsNotFatal(t *testing.T) {
	path := "test_chmod_vault.json"
	os.Remove(path)
	defer os.Remove(path)

	require.NoError(t, os.WriteFile(path, []byte(`{}`), 0644))

	oldOsChmod := osChmod
	defer func() { osChmod = oldOsChmod }()
	osChmod = func(string, os.FileMode) error { return fmt.Errorf("mockOsChmod error") }

	_, err := New(&Options{SavePath: path, SecretProcessUnit: time.Hour})
	require.NoError(t, err)
}
