package main

import (
	"log"
	"net/url"
	"slices"
	"strings"

	"dmh/internal/crypt"
	"dmh/internal/execute"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

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

	k.Load(env.ProviderWithValue("DMH_", ".", func(s string, v string) (string, any) {
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

	if len(k.Strings("components")) == 0 {
		log.Panicf("required config key components cant be empty")
	}

	enabledComponents := k.Strings("components")

	if slices.Contains(enabledComponents, "dmh") {
		for _, configKey := range []string{"state.file", "remote_vault.client_uuid", "remote_vault.url"} {
			if !k.Exists(configKey) {
				log.Panicf("required config key %s is not defined", configKey)
			}
			if k.String(configKey) == "" {
				log.Panicf("required config key %s cant be empty", configKey)
			}
		}
		if _, err := url.ParseRequestURI(k.String("remote_vault.url")); err != nil {
			log.Panicf("remote_vault.url must be a valid HTTP URL")
		}
	}
	if slices.Contains(enabledComponents, "vault") {
		for _, configKey := range []string{"vault.file", "vault.key"} {
			if !k.Exists(configKey) {
				log.Panicf("required config key %s is not defined", configKey)
			}
			if k.String(configKey) == "" {
				log.Panicf("required config key %s cant be empty", configKey)
			}
		}
		if _, err := crypt.New(k.String("vault.key")); err != nil {
			log.Panicf("vault.key must be a valid age private key")
		}
	}

	return k
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
