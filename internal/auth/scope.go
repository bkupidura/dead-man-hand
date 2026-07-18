package auth

import (
	"fmt"
	"strings"
)

// segments splits s into non-empty parts around sep.
func segments(s string, sep rune) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == sep })
}

// pathSegments splits URL path into segments.
func pathSegments(urlPath string) []string {
	return segments(urlPath, '/')
}

// scopeSegments splits scope into segments.
func scopeSegments(scope string) []string {
	return segments(scope, ':')
}

// pathScope converts URL path into scope notation (segments joined by ':').
func pathScope(urlPath string) string {
	return strings.Join(pathSegments(urlPath), ":")
}

// scopeCovers reports whether scope covers URL path segments.
// Scope segments are separated by ':' and matched segment-wise as path prefix,
// so 'api:vault:store:uuid-A' covers /api/vault/store/uuid-A and everything below it,
// but not /api/vault/store/uuid-AB.
// Empty scope (no segments) covers nothing - default deny.
func scopeCovers(scope string, path []string) bool {
	scopeSegs := scopeSegments(scope)
	if len(scopeSegs) == 0 || len(scopeSegs) > len(path) {
		return false
	}
	for i, segment := range scopeSegs {
		if segment != path[i] {
			return false
		}
	}
	return true
}

// anyScopeCovers reports whether any of the scopes covers URL path segments.
func anyScopeCovers(scopes []string, path []string) bool {
	for _, scope := range scopes {
		if scopeCovers(scope, path) {
			return true
		}
	}
	return false
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
