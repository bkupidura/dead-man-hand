package main

import (
	"fmt"
	"os"
	"testing"

	"dmh/internal/execute"
	"dmh/internal/state"
	"dmh/internal/vault"

	"github.com/stretchr/testify/require"
)

func TestReadingConfig(t *testing.T) {
	tests := []struct {
		inputConfig  func()
		envConfigVar string
		mockStateNew func(*state.Options) (state.StateInterface, error)
	}{
		{
			inputConfig: func() {
			},
		},
		{
			inputConfig: func() {
			},
			envConfigVar: "non-existing.yaml",
		},
		{
			inputConfig: func() {
				f, err := os.Create("existing.yaml")
				require.Nil(t, err)
				defer f.Close()
				_, err = f.WriteString(`
                                components: ['dmh']
                                state:
                                  file: test.yaml
                                action:
                                  process_unit: minute
                                remote_vault:
                                  url: http://127.0.0.1:8080
                                  client_uuid: uuid`)
				require.Nil(t, err)
			},
			envConfigVar: "existing.yaml",
			mockStateNew: func(*state.Options) (state.StateInterface, error) {
				return nil, fmt.Errorf("mockStateNew error")
			},
		},
	}
	for _, test := range tests {
		test.inputConfig()
		if test.envConfigVar != "" {
			err := os.Setenv("DMH_CONFIG_FILE", test.envConfigVar)
			require.Nil(t, err)
			defer os.Remove(test.envConfigVar)
		} else {
			os.Unsetenv("DMH_CONFIG_FILE")
		}
		stateNew = state.New
		if test.mockStateNew != nil {
			stateNew = test.mockStateNew
			defer func() {
				stateNew = state.New
			}()
		}
		require.Panics(t, main)
	}
}

func TestComponentsErrors(t *testing.T) {
	tests := []struct {
		mockStateNew   func(*state.Options) (state.StateInterface, error)
		mockExecuteNew func(*execute.Options) (execute.ExecuteInterface, error)
		mockVaultNew   func(*vault.Options) (vault.VaultInterface, error)
	}{
		{
			mockStateNew: func(*state.Options) (state.StateInterface, error) {
				return nil, fmt.Errorf("mockStateNew error")
			},
		},
		{
			mockExecuteNew: func(*execute.Options) (execute.ExecuteInterface, error) {
				return nil, fmt.Errorf("mockExecuteNew error")
			},
		},
		{
			mockVaultNew: func(*vault.Options) (vault.VaultInterface, error) {
				return nil, fmt.Errorf("mockVaultNew error")
			},
		},
	}
	f, err := os.Create("TestDMHComponentErrors.yaml")
	defer os.Remove("TestDMHComponentErrors.yaml")
	require.Nil(t, err)
	defer f.Close()
	_, err = f.WriteString(`
               components: ['dmh', 'vault']
               state:
                 file: test.yaml
               remote_vault:
                 url: http://test.com
                 client_uuid: uuid
               vault:
                 file: test2.yaml
                 key: key
             `)
	require.Nil(t, err)
	err = os.Setenv("DMH_CONFIG_FILE", "TestDMHComponentErrors.yaml")
	require.Nil(t, err)
	for _, test := range tests {
		stateNew = state.New
		if test.mockStateNew != nil {
			stateNew = test.mockStateNew
			defer func() {
				stateNew = state.New
			}()
		}
		executeNew = execute.New
		if test.mockExecuteNew != nil {
			executeNew = test.mockExecuteNew
			defer func() {
				executeNew = execute.New
			}()
		}
		vaultNew = vault.New
		if test.mockVaultNew != nil {
			vaultNew = test.mockVaultNew
			defer func() {
				vaultNew = vault.New
			}()
		}
		require.Panics(t, main)
	}
}
