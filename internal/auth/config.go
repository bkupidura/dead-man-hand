package auth

import (
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"dmh/internal/crypt"
)

// defaultSignedURLTTL is used when auth.signed_url.ttl is not configured.
const defaultSignedURLTTL = 24

var (
	// mocks for tests
	newSignedURLSecret = crypt.NewSignedURLSecret
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

// SignedURLConfig describes HMAC signed URL authentication config.
// Secret is used to sign URLs, when empty it is generated on every start,
// which invalidates all previously generated URLs.
// TTL sets for how many hours generated URLs are valid.
type SignedURLConfig struct {
	Secret string `koanf:"secret"`
	TTL    int    `koanf:"ttl"`
}

// Config describes authentication config.
// Enabled is the single global switch, when false NO authentication or
// authorization is done at all.
// AnonymousScopes lists paths (in scope notation) which have authentication
// disabled.
type Config struct {
	Enabled         bool            `koanf:"enabled"`
	AnonymousScopes []string        `koanf:"anonymous_scope"`
	Bearer          BearerConfig    `koanf:"bearer"`
	SignedURL       SignedURLConfig `koanf:"signed_url"`
}

// Validate checks Config.
func (c *Config) Validate() error {
	if !c.Enabled {
		log.Printf("authentication is DISABLED, check https://github.com/bkupidura/dead-man-hand/wiki/Security#enable-authentication")
		return nil
	}
	for _, scope := range c.AnonymousScopes {
		if err := validateScope(scope); err != nil {
			return fmt.Errorf("anonymous_scopes: %w", err)
		}
	}
	if err := c.Bearer.Validate(); err != nil {
		return fmt.Errorf("bearer: %w", err)
	}
	if err := c.SignedURL.Validate(); err != nil {
		return fmt.Errorf("signed_url: %w", err)
	}
	return nil
}

// Validate normalizes and checks SignedURLConfig.
func (s *SignedURLConfig) Validate() error {
	if s.Secret == "" {
		secret, err := newSignedURLSecret()
		if err != nil {
			return err
		}
		s.Secret = secret
		log.Printf("auth.signed_url.secret is not configured, random secret was generated")
	}
	if s.TTL == 0 {
		s.TTL = defaultSignedURLTTL
	}
	if s.TTL < 0 {
		return fmt.Errorf("ttl must be greater than 0")
	}
	return nil
}

// Validate checks BearerConfig.
func (b *BearerConfig) Validate() error {
	if len(b.Tokens) == 0 {
		return fmt.Errorf("auth.bearer.token is not configured, generate token with dmh-cli auth generate-bearer")
	}

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
