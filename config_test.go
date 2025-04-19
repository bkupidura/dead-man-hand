package main

import (
	"os"
	"testing"

	"dmh/internal/execute"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/knadh/koanf/v2"
	"github.com/stretchr/testify/require"
)

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
                                components:
                                - dmh
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
                                - vault
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
                                - vault
                                vault:
                                  key: test
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
                                - vault
                                vault:
                                  key: test
                                  file: test.json
                                `)
				require.Nil(t, err)
			},
			expectedKoanf: func() *koanf.Koanf {
				b := []byte(`
                                components:
                                - vault
                                vault:
                                  key: test
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
                                  key: test
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
                                  key: test
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
					"DMH_COMPONENTS":                "dmh,",
					"DMH_REMOTE_VAULT__CLIENT_UUID": "test",
					"DMH_REMOTE_VAULT__URL":         "http://test",
				},
			},
			shouldPanic: true,
		},
		{
			inputEnv: []map[string]string{
				{
					"DMH_COMPONENTS":  "vault,",
					"DMH_VAULT__FILE": "vault.json",
				},
			},
			shouldPanic: true,
		},
		{
			inputEnv: []map[string]string{
				{
					"DMH_COMPONENTS":  "vault,",
					"DMH_VAULT__FILE": "vault.json",
					"DMH_VAULT__KEY":  "test",
				},
			},
			expectedKoanf: func() *koanf.Koanf {
				b := []byte(`
                                components:
                                  - vault
                                  - ""
                                vault:
                                  file: vault.json
                                  key: test
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
					"DMH_VAULT__KEY":                "test",
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
                                  key: test
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

func TestGetAliveConfig(t *testing.T) {
	tests := []struct {
		koanfFunc      func() *koanf.Koanf
		shouldPanic    bool
		expectedConfig aliveConfig
	}{
		{
			koanfFunc: func() *koanf.Koanf {
				b := []byte(`
                                alive:
                                  - process_after: 10
                                    min_interval: 2
                                    kind: bulksms
                                    data: 10
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
                                alive:
                                  - process_after: 0
                                    min_interval: 2
                                    kind: bulksms
                                    data:
                                      message: test
                                      destination: ["1111"]
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
                                alive:
                                  - process_after: 1
                                    min_interval: -1
                                    kind: bulksms
                                    data:
                                      message: test
                                      destination: ["1111"]
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
                                alive:
                                  - process_after: 10
                                    min_interval: 0
                                    kind: bulksms
                                    data:
                                      message: test
                                      destination: ["1111"]
                                `)
				k := koanf.New(".")
				err := k.Load(rawbytes.Provider(b), yaml.Parser())
				require.Nil(t, err)
				return k
			},
			expectedConfig: aliveConfig{
				Alive: []aliveItem{
					{
						ProcessAfter: 10,
						MinInterval:  0,
						Kind:         "bulksms",
						Data: map[string]interface{}{
							"message":     "test",
							"destination": []interface{}{"1111"},
						},
					},
				},
			},
		},
		{
			koanfFunc: func() *koanf.Koanf {
				b := []byte(`
                                alive:
                                  - process_after: 10
                                    min_interval: 2
                                    kind: bulksms
                                    data:
                                      message: test
                                      destination: ["1111"]
                                `)
				k := koanf.New(".")
				err := k.Load(rawbytes.Provider(b), yaml.Parser())
				require.Nil(t, err)
				return k
			},
			expectedConfig: aliveConfig{
				Alive: []aliveItem{
					{
						ProcessAfter: 10,
						MinInterval:  2,
						Kind:         "bulksms",
						Data: map[string]interface{}{
							"message":     "test",
							"destination": []interface{}{"1111"},
						},
					},
				},
			},
		},
	}
	for _, test := range tests {
		k := test.koanfFunc()
		if test.shouldPanic {
			require.Panics(t, func() {
				getAliveConfig(k)
			})
		} else {
			config := getAliveConfig(k)
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
			},
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
	}
	for _, test := range tests {
		k := test.koanfFunc()
		if test.shouldPanic {
			require.Panics(t, func() {
				getBulkSMSConfig(k)
			})
		} else {
			config := getMailConfig(k)
			require.Equal(t, test.expectedConfig, config)
		}
	}
}
