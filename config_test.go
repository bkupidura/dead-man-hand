//go:build !integration
// +build !integration

package main

import (
	"os"
	"testing"
	"time"

	"dmh/internal/auth"
	"dmh/internal/execute"
	"dmh/internal/state"
	"dmh/internal/vault"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/knadh/koanf/v2"
	"github.com/stretchr/testify/require"
)

func TestStateOptions(t *testing.T) {
	tests := []struct {
		inputYAML    string
		expectedOpts *state.Options
		shouldPanic  bool
	}{
		{
			inputYAML: "remote_vault:\n  url: http://test\n  client_uuid: uuid\n  token: tok\nstate:\n  file: state.json",
			expectedOpts: &state.Options{
				VaultURL:        "http://test",
				VaultClientUUID: "uuid",
				VaultToken:      "tok",
				SavePath:        "state.json",
			},
		},
		{
			inputYAML:   "remote_vault:\n  client_uuid: uuid\nstate:\n  file: state.json",
			shouldPanic: true,
		},
	}
	for _, test := range tests {
		k := koanf.New(".")
		require.Nil(t, k.Load(rawbytes.Provider([]byte(test.inputYAML)), yaml.Parser()))
		if test.shouldPanic {
			require.Panics(t, func() { stateOptions(k) })
		} else {
			require.Equal(t, test.expectedOpts, stateOptions(k))
		}
	}
}

func TestVaultOptions(t *testing.T) {
	tests := []struct {
		inputYAML    string
		expectedOpts *vault.Options
		shouldPanic  bool
	}{
		{
			inputYAML: "vault:\n  key: AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0\n  file: vault.json",
			expectedOpts: &vault.Options{
				Key:               "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0",
				SavePath:          "vault.json",
				SecretProcessUnit: time.Hour,
			},
		},
		{
			inputYAML:   "vault:\n  file: vault.json",
			shouldPanic: true,
		},
	}
	for _, test := range tests {
		k := koanf.New(".")
		require.Nil(t, k.Load(rawbytes.Provider([]byte(test.inputYAML)), yaml.Parser()))
		if test.shouldPanic {
			require.Panics(t, func() { vaultOptions(k) })
		} else {
			require.Equal(t, test.expectedOpts, vaultOptions(k))
		}
	}
}

func TestProcessUnit(t *testing.T) {
	tests := []struct {
		inputYAML    string
		expectedUnit time.Duration
	}{
		{
			inputYAML:    "action:\n  process_unit: second",
			expectedUnit: time.Second,
		},
		{
			inputYAML:    "action:\n  process_unit: minute",
			expectedUnit: time.Minute,
		},
		{
			inputYAML:    "action:\n  process_unit: hour",
			expectedUnit: time.Hour,
		},
		{
			inputYAML:    "action:\n  process_unit: wrong",
			expectedUnit: time.Hour,
		},
		{
			inputYAML:    "components:\n  - dmh",
			expectedUnit: time.Hour,
		},
	}
	for _, test := range tests {
		k := koanf.New(".")
		require.Nil(t, k.Load(rawbytes.Provider([]byte(test.inputYAML)), yaml.Parser()))
		require.Equal(t, test.expectedUnit, processUnit(k), "yaml %q", test.inputYAML)
	}
}

func TestReadConfig(t *testing.T) {
	tests := []struct {
		configFunc    func(string)
		shouldPanic   bool
		expectedKoanf func() *koanf.Koanf
	}{
		{
			configFunc:  func(string) {},
			shouldPanic: true,
		},
		{
			configFunc: func(configFile string) {
				f, err := os.Create(configFile)
				require.Nil(t, err)
				defer f.Close()
				_, err = f.WriteString(`
                                something: 1
                                `)
				require.Nil(t, err)
			},
			shouldPanic: true,
		},
		{
			configFunc: func(configFile string) {
				f, err := os.Create(configFile)
				require.Nil(t, err)
				defer f.Close()
				_, err = f.WriteString(`
                                components: []
                                `)
				require.Nil(t, err)
			},
			shouldPanic: true,
		},
		{
			configFunc: func(configFile string) {
				f, err := os.Create(configFile)
				require.Nil(t, err)
				defer f.Close()
				_, err = f.WriteString(`
                                components:
                                - dmh
                                state:
                                  file: test.json
                                remote_vault:
                                  client_uuid: test
                                  url: http://test
                                `)
				require.Nil(t, err)
			},
			expectedKoanf: func() *koanf.Koanf {
				b := []byte(`
                                components:
                                - dmh
                                remote_vault:
                                  client_uuid: test
                                  url: http://test
                                state:
                                  file: test.json
                                `)
				k := koanf.New(".")
				err := k.Load(rawbytes.Provider(b), yaml.Parser())
				require.Nil(t, err)
				return k
			},
		},
		{
			configFunc: func(configFile string) {
				f, err := os.Create(configFile)
				require.Nil(t, err)
				defer f.Close()
				_, err = f.WriteString(`
                                components:
                                - dmh
                                - unknown
                                state:
                                  file: test.json
                                remote_vault:
                                  client_uuid: test
                                  url: http://test
                                `)
				require.Nil(t, err)
			},
			expectedKoanf: func() *koanf.Koanf {
				b := []byte(`
                                components:
                                - dmh
                                - unknown
                                remote_vault:
                                  client_uuid: test
                                  url: http://test
                                state:
                                  file: test.json
                                `)
				k := koanf.New(".")
				err := k.Load(rawbytes.Provider(b), yaml.Parser())
				require.Nil(t, err)
				return k
			},
		},
		{
			configFunc: func(configFile string) {
				f, err := os.Create(configFile)
				require.Nil(t, err)
				defer f.Close()
				_, err = f.WriteString(`
                                components:
                                - vault
                                vault:
                                  key: AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0
                                  file: test.json
                                `)
				require.Nil(t, err)
			},
			expectedKoanf: func() *koanf.Koanf {
				b := []byte(`
                                components:
                                - vault
                                vault:
                                  key: AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0
                                  file: test.json
                                `)
				k := koanf.New(".")
				err := k.Load(rawbytes.Provider(b), yaml.Parser())
				require.Nil(t, err)
				return k
			},
		},
		{
			configFunc: func(configFile string) {
				f, err := os.Create(configFile)
				require.Nil(t, err)
				defer f.Close()
				_, err = f.WriteString(`
                                components:
                                - vault
                                - dmh
                                vault:
                                  key: AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0
                                  file: test.json
                                remote_vault:
                                  client_uuid: test
                                  url: http://test
                                state:
                                  file: test.json
                                `)
				require.Nil(t, err)
			},
			expectedKoanf: func() *koanf.Koanf {
				b := []byte(`
                                components:
                                - vault
                                - dmh
                                vault:
                                  key: AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0
                                  file: test.json
                                remote_vault:
                                  client_uuid: test
                                  url: http://test
                                state:
                                  file: test.json
                                `)
				k := koanf.New(".")
				err := k.Load(rawbytes.Provider(b), yaml.Parser())
				require.Nil(t, err)
				return k
			},
		},
	}
	for _, test := range tests {
		configFile := "test_config.yaml"
		os.Remove(configFile)
		test.configFunc(configFile)
		defer os.Remove(configFile)
		if test.shouldPanic {
			require.Panics(t, func() {
				readConfig(configFile)
			})
		} else {
			k := readConfig(configFile)
			expectedK := test.expectedKoanf()
			require.Equal(t, expectedK, k)
		}
	}
}

func TestReadConfigEnv(t *testing.T) {
	tests := []struct {
		inputEnv      []map[string]string
		shouldPanic   bool
		expectedKoanf func() *koanf.Koanf
	}{
		{
			inputEnv: []map[string]string{
				{
					"DMH_COMPONENTS":  "vault,",
					"DMH_VAULT__FILE": "vault.json",
					"DMH_VAULT__KEY":  "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0",
				},
			},
			expectedKoanf: func() *koanf.Koanf {
				b := []byte(`
                                components:
                                  - vault
                                  - ""
                                vault:
                                  file: vault.json
                                  key: AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0
                                `)
				k := koanf.New(".")
				err := k.Load(rawbytes.Provider(b), yaml.Parser())
				require.Nil(t, err)
				return k
			},
		},
		{
			inputEnv: []map[string]string{
				{
					"DMH_COMPONENTS":                "dmh,",
					"DMH_REMOTE_VAULT__CLIENT_UUID": "test",
					"DMH_REMOTE_VAULT__URL":         "http://test",
					"DMH_STATE__FILE":               "state.json",
				},
			},
			expectedKoanf: func() *koanf.Koanf {
				b := []byte(`
                                components:
                                  - dmh
                                  - ""
                                remote_vault:
                                  client_uuid: test
                                  url: http://test
                                state:
                                  file: state.json
                                `)
				k := koanf.New(".")
				err := k.Load(rawbytes.Provider(b), yaml.Parser())
				require.Nil(t, err)
				return k
			},
		},
		{
			inputEnv: []map[string]string{
				{
					"DMH_COMPONENTS":                "dmh,vault",
					"DMH_REMOTE_VAULT__CLIENT_UUID": "test",
					"DMH_REMOTE_VAULT__URL":         "http://test",
					"DMH_STATE__FILE":               "state.json",
					"DMH_VAULT__FILE":               "vault.json",
					"DMH_VAULT__KEY":                "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0",
				},
			},
			expectedKoanf: func() *koanf.Koanf {
				b := []byte(`
                                components:
                                  - dmh
                                  - vault
                                remote_vault:
                                  client_uuid: test
                                  url: http://test
                                state:
                                  file: state.json
                                vault:
                                  file: vault.json
                                  key: AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0
                                `)
				k := koanf.New(".")
				err := k.Load(rawbytes.Provider(b), yaml.Parser())
				require.Nil(t, err)
				return k
			},
		},
		{
			inputEnv: []map[string]string{
				{
					"DMH_COMPONENTS":            "vault,",
					"DMH_VAULT__FILE":           "vault.json",
					"DMH_VAULT__KEY":            "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0",
					"DMH_AUTH__ANONYMOUS_SCOPE": "healthz,ready",
				},
			},
			expectedKoanf: func() *koanf.Koanf {
				b := []byte(`
                                components:
                                  - vault
                                  - ""
                                vault:
                                  file: vault.json
                                  key: AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0
                                auth:
                                  anonymous_scope:
                                    - healthz
                                    - ready
                                `)
				k := koanf.New(".")
				err := k.Load(rawbytes.Provider(b), yaml.Parser())
				require.Nil(t, err)
				return k
			},
		},
		{
			inputEnv: []map[string]string{
				{
					"DMH_COMPONENTS":  "vault,",
					"DMH_VAULT__FILE": "vault.json",
					"DMH_VAULT__KEY":  "part-one,part-two",
				},
			},
			expectedKoanf: func() *koanf.Koanf {
				b := []byte(`
                                components:
                                  - vault
                                  - ""
                                vault:
                                  file: vault.json
                                  key: "part-one,part-two"
                                `)
				k := koanf.New(".")
				err := k.Load(rawbytes.Provider(b), yaml.Parser())
				require.Nil(t, err)
				return k
			},
		},
	}
	configFile := "test_config.yaml"
	os.Remove(configFile)
	f, err := os.Create(configFile)
	require.Nil(t, err)
	defer f.Close()
	defer os.Remove(configFile)
	for _, test := range tests {
		for _, e := range test.inputEnv {
			for k, v := range e {
				err := os.Setenv(k, v)
				require.Nil(t, err)
			}
		}
		if test.shouldPanic {
			require.Panics(t, func() {
				readConfig(configFile)
			})
		} else {
			k := readConfig(configFile)
			marshaledK, err := k.Marshal(yaml.Parser())
			require.Nil(t, err)

			expectedK := test.expectedKoanf()
			marshaledExpectedK, err := expectedK.Marshal(yaml.Parser())
			require.Nil(t, err)

			require.Equal(t, marshaledExpectedK, marshaledK)
		}
		for _, e := range test.inputEnv {
			for k := range e {
				err := os.Unsetenv(k)
				require.Nil(t, err)
			}
		}
	}
}

func TestReadConfigMergeEnvFile(t *testing.T) {
	configFile := "test_read_config_merge_env_file.yaml"
	f, err := os.Create(configFile)
	require.Nil(t, err)
	defer os.Remove(configFile)
	defer f.Close()
	_, err = f.WriteString(`
        components:
        - vault
        - dmh
        vault:
          file: test.json
        remote_vault:
          client_uuid: test
          url: http://test
        state:
          file: test.json
        `)
	require.Nil(t, err)

	err = os.Setenv("DMH_VAULT__KEY", "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0")
	defer func() {
		err = os.Unsetenv("DMH_VAULT__KEY")
		require.Nil(t, err)
	}()

	k := readConfig(configFile)
	marshaledK, err := k.Marshal(yaml.Parser())
	require.Nil(t, err)

	expectedConfig := []byte(`
                                components:
                                - vault
                                - dmh
                                vault:
                                  key: AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0
                                  file: test.json
                                remote_vault:
                                  client_uuid: test
                                  url: http://test
                                state:
                                  file: test.json
                                `)
	expectedK := koanf.New(".")
	err = expectedK.Load(rawbytes.Provider(expectedConfig), yaml.Parser())
	require.Nil(t, err)

	marshaledExpectedK, err := expectedK.Marshal(yaml.Parser())
	require.Nil(t, err)

	require.Equal(t, marshaledExpectedK, marshaledK)

}

func TestGetAuthConfig(t *testing.T) {
	tests := []struct {
		koanfFunc      func() *koanf.Koanf
		shouldPanic    bool
		expectedConfig auth.Config
	}{
		{
			koanfFunc: func() *koanf.Koanf {
				b := []byte(`
                                something: 1
                                `)
				k := koanf.New(".")
				err := k.Load(rawbytes.Provider(b), yaml.Parser())
				require.Nil(t, err)
				return k
			},
			shouldPanic: true,
		},
		{
			koanfFunc: func() *koanf.Koanf {
				b := []byte(`
                                auth:
                                  enabled: true
                                `)
				k := koanf.New(".")
				err := k.Load(rawbytes.Provider(b), yaml.Parser())
				require.Nil(t, err)
				return k
			},
			shouldPanic: true,
		},
		{
			koanfFunc: func() *koanf.Koanf {
				b := []byte(`
                                auth:
                                  enabled: false
                                `)
				k := koanf.New(".")
				err := k.Load(rawbytes.Provider(b), yaml.Parser())
				require.Nil(t, err)
				return k
			},
			expectedConfig: auth.Config{
				Enabled: false,
			},
		},
		{
			koanfFunc: func() *koanf.Koanf {
				b := []byte(`
                                auth:
                                  anonymous_scope:
                                    - healthz
                                    - ready
                                  bearer:
                                    token:
                                      - name: admin
                                        hash: 6e529315274fd842da9323d9af0805bbef21bd90d2cb30b3cab8fab882d20067
                                        scope:
                                          - api
                                      - name: alive-cron
                                        hash: 4c5dc9b7708905f77f5e5d16316b5dfb425e68cb326dcd55a860e90a7707031e
                                        scope:
                                          - api:alive
                                `)
				k := koanf.New(".")
				err := k.Load(rawbytes.Provider(b), yaml.Parser())
				require.Nil(t, err)
				return k
			},
			expectedConfig: auth.Config{
				Enabled:         true,
				AnonymousScopes: []string{"healthz", "ready"},
				Bearer: auth.BearerConfig{
					Tokens: []auth.Token{
						{Name: "admin", Hash: "6e529315274fd842da9323d9af0805bbef21bd90d2cb30b3cab8fab882d20067", Scopes: []string{"api"}},
						{Name: "alive-cron", Hash: "4c5dc9b7708905f77f5e5d16316b5dfb425e68cb326dcd55a860e90a7707031e", Scopes: []string{"api:alive"}},
					},
				},
				SignedURL: auth.SignedURLConfig{TTL: 24},
			},
		},
		{
			koanfFunc: func() *koanf.Koanf {
				b := []byte(`
                                auth:
                                  bearer:
                                    token: 10
                                `)
				k := koanf.New(".")
				err := k.Load(rawbytes.Provider(b), yaml.Parser())
				require.Nil(t, err)
				return k
			},
			shouldPanic: true,
		},
	}
	for _, test := range tests {
		k := test.koanfFunc()
		if test.shouldPanic {
			require.Panics(t, func() {
				getAuthConfig(k)
			})
		} else {
			config := getAuthConfig(k)
			// Signed URL secret is random generated (covered by auth package tests),
			// drop it to compare rest of the config.
			config.SignedURL.Secret = ""
			require.Equal(t, test.expectedConfig, config)
		}
	}
}

func TestGetBulkSMSConfig(t *testing.T) {
	tests := []struct {
		koanfFunc      func() *koanf.Koanf
		shouldPanic    bool
		expectedConfig execute.BulkSMSConfig
	}{
		{
			koanfFunc: func() *koanf.Koanf {
				b := []byte(`
                                execute:
                                  plugin:
                                    bulksms:
                                      token: 10
                                `)
				k := koanf.New(".")
				err := k.Load(rawbytes.Provider(b), yaml.Parser())
				require.Nil(t, err)
				return k
			},
			shouldPanic: true,
		},
		{
			koanfFunc: func() *koanf.Koanf {
				b := []byte(`
                                execute:
                                  plugin:
                                    missing:
                                      data: 10
                                `)
				k := koanf.New(".")
				err := k.Load(rawbytes.Provider(b), yaml.Parser())
				require.Nil(t, err)
				return k
			},
			expectedConfig: execute.BulkSMSConfig{
				Token: execute.BulkSMSToken{
					ID:     "",
					Secret: "",
				},
			},
		},
		{
			koanfFunc: func() *koanf.Koanf {
				b := []byte(`
                                execute:
                                  plugin:
                                    bulksms:
                                      token:
                                        id: id
                                        secret: secret
                                `)
				k := koanf.New(".")
				err := k.Load(rawbytes.Provider(b), yaml.Parser())
				require.Nil(t, err)
				return k
			},
			expectedConfig: execute.BulkSMSConfig{
				Token: execute.BulkSMSToken{
					ID:     "id",
					Secret: "secret",
				},
				RoutingGroup: "STANDARD",
			},
		},
		{
			koanfFunc: func() *koanf.Koanf {
				b := []byte(`
                                execute:
                                  plugin:
                                    bulksms:
                                      token:
                                        id: id
                                `)
				k := koanf.New(".")
				err := k.Load(rawbytes.Provider(b), yaml.Parser())
				require.Nil(t, err)
				return k
			},
			shouldPanic: true,
		},
	}
	for _, test := range tests {
		k := test.koanfFunc()
		if test.shouldPanic {
			require.Panics(t, func() {
				getBulkSMSConfig(k)
			})
		} else {
			config := getBulkSMSConfig(k)
			require.Equal(t, test.expectedConfig, config)
		}
	}
}

func TestGetMailConfig(t *testing.T) {
	tests := []struct {
		koanfFunc      func() *koanf.Koanf
		shouldPanic    bool
		expectedConfig execute.MailConfig
	}{
		{
			koanfFunc: func() *koanf.Koanf {
				b := []byte(`
                                execute:
                                  plugin:
                                    missing:
                                      data: 10
                                `)
				k := koanf.New(".")
				err := k.Load(rawbytes.Provider(b), yaml.Parser())
				require.Nil(t, err)
				return k
			},
			expectedConfig: execute.MailConfig{},
		},
		{
			koanfFunc: func() *koanf.Koanf {
				b := []byte(`execute:
  plugin:
    mail:
      tls_insecure:
        - not
        - a
        - bool
`)
				k := koanf.New(".")
				err := k.Load(rawbytes.Provider(b), yaml.Parser())
				require.Nil(t, err)
				return k
			},
			shouldPanic: true,
		},
		{
			koanfFunc: func() *koanf.Koanf {
				b := []byte(`
                                execute:
                                  plugin:
                                    mail:
                                      username: test
                                      password: password
                                      server: server
                                      from: from@address
                                      tls_policy: no_tls
                                `)
				k := koanf.New(".")
				err := k.Load(rawbytes.Provider(b), yaml.Parser())
				require.Nil(t, err)
				return k
			},
			expectedConfig: execute.MailConfig{
				Username:  "test",
				Password:  "password",
				Server:    "server",
				From:      "from@address",
				TLSPolicy: "no_tls",
			},
		},
		{
			koanfFunc: func() *koanf.Koanf {
				b := []byte(`
                                execute:
                                  plugin:
                                    mail:
                                      server: server
                                      from: not-a-valid-address
                                `)
				k := koanf.New(".")
				err := k.Load(rawbytes.Provider(b), yaml.Parser())
				require.Nil(t, err)
				return k
			},
			shouldPanic: true,
		},
	}
	for _, test := range tests {
		k := test.koanfFunc()
		if test.shouldPanic {
			didPanic := false
			func() {
				defer func() {
					if r := recover(); r != nil {
						didPanic = true
					}
				}()
				getMailConfig(k)
			}()
			require.True(t, didPanic, "expected panic but did not get one")
		} else {
			config := getMailConfig(k)
			require.Equal(t, test.expectedConfig, config)
		}
	}
}
