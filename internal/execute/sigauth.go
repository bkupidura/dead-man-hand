package execute

import (
	"regexp"
	"strings"
	"time"

	"dmh/internal/crypt"
	"dmh/internal/state"
)

// sigAuthPlaceholder matches {sig_auth:<path>} in action data, expanded on
// execution into a signed /<path> URL with e and s query parameters attached.
// <path> is one or more lowercase segments joined by single '/' (eg. alive or
// api/action/store/<uuid>).
var sigAuthPlaceholder = regexp.MustCompile(`\{sig_auth:([a-z0-9_-]+(?:/[a-z0-9_-]+)*)\}`)

var (
	// mocks for tests
	timeNow = time.Now
)

// expandSigAuth replaces sigAuthPlaceholder occurrences with a freshly signed
// path. Without a secret (auth disabled) it expands to the plain page path.
func (e *Execute) expandSigAuth(a *state.Action) {
	a.Data = sigAuthPlaceholder.ReplaceAllStringFunc(a.Data, func(placeholder string) string {
		path := "/" + sigAuthPlaceholder.FindStringSubmatch(placeholder)[1]
		if e.signedURLSecret == "" {
			return strings.TrimPrefix(path, "/")
		}
		expiresAt := timeNow().Add(time.Duration(e.signedURLTTL) * time.Hour)
		return strings.TrimPrefix(crypt.SignURL(e.signedURLSecret, path, expiresAt), "/")
	})
}

// SigAuthPaths returns the /<page> paths referenced in data.
func SigAuthPaths(data string) []string {
	matches := sigAuthPlaceholder.FindAllStringSubmatch(data, -1)
	paths := make([]string, 0, len(matches))
	for _, match := range matches {
		paths = append(paths, "/"+match[1])
	}
	return paths
}
