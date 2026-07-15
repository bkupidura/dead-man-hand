package auth

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Token describes single named bearer token.
// Hash is hex-encoded sha256 of token plaintext, generated with dmh-cli.
type Token struct {
	Name   string   `koanf:"name"`
	Hash   string   `koanf:"hash"`
	Scopes []string `koanf:"scope"`
}

// BearerConfig describes bearer token authentication config.
type BearerConfig struct {
	Tokens []Token `koanf:"token"`
}

// Config describes authentication config.
// AnonymousScopes lists scopes granted to every request, even without any credential.
// Every authentication mechanism lives in its own subtree.
type Config struct {
	Enabled         bool         `koanf:"enabled"`
	AnonymousScopes []string     `koanf:"anonymous_scope"`
	Bearer          BearerConfig `koanf:"bearer"`
}

// Validate checks Config. Disabled config is always valid and not checked further.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if len(c.Bearer.Tokens) == 0 {
		return fmt.Errorf("auth.bearer.token is not configured, generate token with dmh-cli auth generate-bearer or explicitly disable authentication with auth.enabled: false")
	}
	for _, scope := range c.AnonymousScopes {
		if err := validateScope(scope); err != nil {
			return fmt.Errorf("anonymous_scopes: %w", err)
		}
	}
	if err := c.Bearer.Validate(); err != nil {
		return fmt.Errorf("bearer: %w", err)
	}
	return nil
}

// Validate checks BearerConfig.
func (b *BearerConfig) Validate() error {
	seenName := map[string]bool{}
	seenHash := map[string]bool{}
	for _, token := range b.Tokens {
		if token.Name == "" {
			return fmt.Errorf("token name is required")
		}
		if seenName[token.Name] {
			return fmt.Errorf("token name %s is duplicated", token.Name)
		}
		seenName[token.Name] = true

		decodedHash, err := hex.DecodeString(token.Hash)
		if err != nil || len(decodedHash) != 32 {
			return fmt.Errorf("token %s hash must be a hex encoded sha256", token.Name)
		}
		normalizedHash := strings.ToLower(token.Hash)
		if seenHash[normalizedHash] {
			return fmt.Errorf("token %s hash is duplicated", token.Name)
		}
		seenHash[normalizedHash] = true

		if len(token.Scopes) == 0 {
			return fmt.Errorf("token %s must have at least one scope", token.Name)
		}
		for _, scope := range token.Scopes {
			if err := validateScope(scope); err != nil {
				return fmt.Errorf("token %s: %w", token.Name, err)
			}
		}
	}
	return nil
}

// validateScope checks single scope format.
func validateScope(scope string) error {
	if scope == "" {
		return fmt.Errorf("scope cant be empty")
	}
	for _, segment := range strings.Split(scope, ":") {
		if segment == "" {
			return fmt.Errorf("scope %s cant contain empty segments", scope)
		}
	}
	return nil
}
