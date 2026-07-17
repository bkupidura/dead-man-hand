package crypt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// signedURLSigLen is number of hmac-sha256 bytes used in signature.
// Truncation to 128 bits is sanctioned by RFC 2104 and keeps URLs short.
const signedURLSigLen = 16

// signedURLSecretBytes is the number of random bytes in a signed URL secret.
const signedURLSecretBytes = 32

var (
	// mocks for tests
	timeNow = time.Now
)

// NewSignedURLSecret generates random secret used for URL signing.
func NewSignedURLSecret() (string, error) {
	buf := make([]byte, signedURLSecretBytes)
	if _, err := randRead(buf); err != nil {
		return "", fmt.Errorf("unable to generate signed url secret: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// signURLPayload returns base64url encoded, truncated hmac-sha256 signature.
func signURLPayload(secret string, path string, expires int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%s\n%d", path, expires)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:signedURLSigLen])
}

// SignURL returns path with e (base36 encoded expires) and s (signature)
// query parameters attached.
func SignURL(secret string, path string, expiresAt time.Time) string {
	expires := expiresAt.Unix()
	return fmt.Sprintf("%s?e=%s&s=%s", path, strconv.FormatInt(expires, 36), signURLPayload(secret, path, expires))
}

// ValidateSignedURL reports whether sig is valid signature of path with
// expires (base36 encoded unix time, e query parameter) still in the future.
func ValidateSignedURL(secret string, path string, expires string, sig string) bool {
	if sig == "" {
		return false
	}
	expiresUnix, err := strconv.ParseInt(expires, 36, 64)
	if err != nil {
		return false
	}
	if timeNow().Unix() > expiresUnix {
		return false
	}
	return hmac.Equal([]byte(signURLPayload(secret, path, expiresUnix)), []byte(sig))
}
