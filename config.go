package main

import (
	"log"
	"slices"
	"strings"

	"dmh/internal/execute"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

type aliveConfig struct {
	Alive []aliveItem `koanf:"alive"`
}

type aliveItem struct {
	MinInterval  int                    `koanf:"min_interval"`
	ProcessAfter int                    `koanf:"process_after"`
	Kind         string                 `koanf:"kind"`
	Data         map[string]interface{} `koanf:"data"`
}

// readConfig reads configFile and feeds it to koanf.
// readConfig can be feeded from env variables:
// DMH_REMOTE_VAULT__URL=http://test -> remote_vault.url=http://test
// DMH_COMPONETS = "dmh," -> componets=["dmh"]
// It will also ensure that required keys for enabled component are present.
func readConfig(configFile string) *koanf.Koanf {
	k := koanf.New(".")
	if err := k.Load(file.Provider(configFile), yaml.Parser()); err != nil {
		log.Panicf("error loading config %s: %v", configFile, err)
	}

	k.Load(env.ProviderWithValue("DMH_", ".", func(s string, v string) (string, interface{}) {
		key := strings.Replace(strings.ToLower(strings.TrimPrefix(s, "DMH_")), "__", ".", -1)

		// If there is a coma in the value, split the value into a slice by the comma.
		if strings.Contains(v, ",") {
			return key, strings.Split(v, ",")
		}
		// Otherwise, return the plain string.
		return key, v
	}), nil)

	requiredKeys := []string{"components"}

	for _, configKey := range requiredKeys {
		if !k.Exists(configKey) {
			log.Panicf("required config key %s is not defined", configKey)
		}
	}

	requiredKeysForComponents := []string{}
	enabledComponents := k.Strings("components")

	if slices.Contains(enabledComponents, "dmh") {
		requiredKeysForComponents = append(requiredKeysForComponents, "state.file", "remote_vault.client_uuid", "remote_vault.url")
	}
	if slices.Contains(enabledComponents, "vault") {
		requiredKeysForComponents = append(requiredKeysForComponents, "vault.file", "vault.key")
	}

	for _, configKey := range requiredKeysForComponents {
		if !k.Exists(configKey) {
			log.Panicf("required config key %s is not defined", configKey)
		}
	}

	return k
}

// getAliveConfig returns parsed `alive` section.
func getAliveConfig(k *koanf.Koanf) aliveConfig {
	var config aliveConfig
	if err := k.Unmarshal("", &config); err != nil {
		log.Panicf("unable to unmarshal config: %s", err)
	}
	for _, alive := range config.Alive {
		if alive.ProcessAfter <= 0 {
			log.Panicf("alive process_after should be greater than 0")
		}
		if alive.MinInterval < 0 {
			log.Panicf("alive min_interval should be greater or equal 0")
		}
	}
	return config
}

// getBulkSMSConfig returns parsed config for bulksms execute plugin.
func getBulkSMSConfig(k *koanf.Koanf) execute.BulkSMSConfig {
	var config execute.BulkSMSConfig
	if err := k.Unmarshal("execute.plugin.bulksms", &config); err != nil {
		log.Panicf("unable to unmarshal config: %s", err)
	}
	return config
}

// getMailConfig returns parsed config for mail execute plugin.
func getMailConfig(k *koanf.Koanf) execute.MailConfig {
	var config execute.MailConfig
	if err := k.Unmarshal("execute.plugin.mail", &config); err != nil {
		log.Panicf("unable to unmarshal config: %s", err)
	}
	return config
}
