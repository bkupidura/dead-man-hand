package main

import (
	"log"
	"slices"
	"strings"
	"time"

	"dmh/internal/auth"
	"dmh/internal/execute"
	"dmh/internal/state"
	"dmh/internal/vault"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// envListKeys are comma-split when set from an environment variable, other keys keep commas verbatim.
var envListKeys = []string{"components", "auth.anonymous_scope"}

// readConfig reads configFile and feeds it to koanf.
// readConfig can be feeded from env variables:
// DMH_REMOTE_VAULT__URL=http://test -> remote_vault.url=http://test
// DMH_COMPONENTS = "dmh," -> components=["dmh"]
// It will also ensure that required keys for enabled component are present.
func readConfig(configFile string) *koanf.Koanf {
	k := koanf.New(".")
	if err := k.Load(file.Provider(configFile), yaml.Parser()); err != nil {
		log.Panicf("error loading config %s: %v", configFile, err)
	}

	k.Load(env.ProviderWithValue("DMH_", ".", func(s string, v string) (string, any) {
		key := strings.Replace(strings.ToLower(strings.TrimPrefix(s, "DMH_")), "__", ".", -1)

		if slices.Contains(envListKeys, key) && strings.Contains(v, ",") {
			return key, strings.Split(v, ",")
		}
		return key, v
	}), nil)

	requiredKeys := []string{"components"}

	for _, configKey := range requiredKeys {
		if !k.Exists(configKey) {
			log.Panicf("required config key %s is not defined", configKey)
		}
	}

	enabledComponents := k.Strings("components")
	if len(enabledComponents) == 0 {
		log.Panicf("required config key components cant be empty")
	}

	for _, component := range enabledComponents {
		if !slices.Contains([]string{"dmh", "vault"}, component) {
			log.Printf("unknown component %s enabled, supported components: dmh, vault", component)
		}
	}

	if slices.Contains(enabledComponents, "dmh") && slices.Contains(enabledComponents, "vault") {
		log.Printf("dmh and vault component enabled, check https://github.com/bkupidura/dead-man-hand/wiki/Security#run-dmh-and-vault-on-different-servers--locations")
	}

	return k
}

// stateOptions maps config into state.Options and validates it.
func stateOptions(k *koanf.Koanf) *state.Options {
	o := &state.Options{
		VaultURL:        k.String("remote_vault.url"),
		VaultClientUUID: k.String("remote_vault.client_uuid"),
		VaultToken:      k.String("remote_vault.token"),
		SavePath:        k.String("state.file"),
	}
	if err := o.Validate(); err != nil {
		log.Panicf("invalid dmh config: %s", err)
	}
	return o
}

// vaultOptions maps config into vault.Options and validates it.
func vaultOptions(k *koanf.Koanf) *vault.Options {
	o := &vault.Options{
		Key:               k.String("vault.key"),
		SavePath:          k.String("vault.file"),
		SecretProcessUnit: processUnit(k),
	}
	if err := o.Validate(); err != nil {
		log.Panicf("invalid vault config: %s", err)
	}
	return o
}

// processUnit maps action.process_unit config into a time unit.
func processUnit(k *koanf.Koanf) time.Duration {
	switch k.String("action.process_unit") {
	case "second":
		return time.Second
	case "minute":
		return time.Minute
	default:
		return time.Hour
	}
}

// getAuthConfig returns parsed and validated auth config.
// Authentication can be disabled with explicit auth.enabled: false.
func getAuthConfig(k *koanf.Koanf) auth.Config {
	config := auth.Config{Enabled: true}
	if err := k.Unmarshal("auth", &config); err != nil {
		log.Panicf("unable to unmarshal config: %s", err)
	}
	if err := config.Validate(); err != nil {
		log.Panicf("invalid auth config: %s", err)
	}
	return config
}

// getBulkSMSConfig returns parsed config for bulksms execute plugin.
// When the config section is present, it is validated at startup.
func getBulkSMSConfig(k *koanf.Koanf) execute.BulkSMSConfig {
	var config execute.BulkSMSConfig
	if err := k.Unmarshal("execute.plugin.bulksms", &config); err != nil {
		log.Panicf("unable to unmarshal config: %s", err)
	}
	if k.Exists("execute.plugin.bulksms") {
		if err := config.Validate(); err != nil {
			log.Panicf("invalid execute.plugin.bulksms config: %s", err)
		}
	}
	return config
}

// getMailConfig returns parsed config for mail execute plugin.
// When the config section is present, it is validated at startup.
func getMailConfig(k *koanf.Koanf) execute.MailConfig {
	var config execute.MailConfig
	if err := k.Unmarshal("execute.plugin.mail", &config); err != nil {
		log.Panicf("unable to unmarshal config: %s", err)
	}
	if k.Exists("execute.plugin.mail") {
		if err := config.Validate(); err != nil {
			log.Panicf("invalid execute.plugin.mail config: %s", err)
		}
	}
	return config
}
