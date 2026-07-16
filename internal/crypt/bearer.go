package crypt

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

var (
	// mocks for tests
	randRead = rand.Read
)

// bearerTokenBytes is the number of random bytes in a bearer token.
const bearerTokenBytes = 32

// BearerToken holds a generated bearer token together with its sha256 hash.
type BearerToken struct {
	Plaintext string
	Hash      string
}

// NewBearerToken generates a cryptographically random bearer token.
func NewBearerToken() (BearerToken, error) {
	b := make([]byte, bearerTokenBytes)
	if _, err := randRead(b); err != nil {
		return BearerToken{}, fmt.Errorf("unable to generate bearer token: %w", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(b)
	return BearerToken{
		Plaintext: plaintext,
		Hash:      hex.EncodeToString(bearerTokenHash(plaintext)),
	}, nil
}

// bearerTokenHash returns the raw sha256 of a bearer token string.
func bearerTokenHash(plaintext string) []byte {
	sum := sha256.Sum256([]byte(plaintext))
	return sum[:]
}

// ValidateBearerToken reports whether presented is a valid bearer token for the given stored hash.
func ValidateBearerToken(storedHash, presented string) bool {
	stored, err := hex.DecodeString(storedHash)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(bearerTokenHash(presented), stored) == 1
}
