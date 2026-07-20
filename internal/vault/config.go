package vault

import (
	"fmt"

	"dmh/internal/crypt"
)

// Validate checks vault component configuration.
func (o *Options) Validate() error {
	if o.SavePath == "" {
		return fmt.Errorf("vault.file is required")
	}
	if o.Key == "" {
		return fmt.Errorf("vault.key is required")
	}
	if _, err := crypt.NewAge(o.Key); err != nil {
		return fmt.Errorf("vault.key must be a valid age private key")
	}
	return nil
}
