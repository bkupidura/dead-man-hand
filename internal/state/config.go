package state

import (
	"fmt"
	"log"
	"net/url"
	"strings"
)

// Validate checks state (dmh) component configuration.
func (o *Options) Validate() error {
	if o.SavePath == "" {
		return fmt.Errorf("state.file is required")
	}
	if o.VaultClientUUID == "" {
		return fmt.Errorf("remote_vault.client_uuid is required")
	}
	if o.VaultURL == "" {
		return fmt.Errorf("remote_vault.url is required")
	}
	if _, err := url.ParseRequestURI(o.VaultURL); err != nil {
		return fmt.Errorf("remote_vault.url must be a valid HTTP URL")
	}
	if strings.HasPrefix(strings.ToLower(o.VaultURL), "http://") {
		log.Printf("remote_vault.url uses plain http, check https://github.com/bkupidura/dead-man-hand/wiki/Security#use-tls-for-every-connection-strongly-recommended")
	}
	return nil
}
