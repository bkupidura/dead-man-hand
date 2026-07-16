package auth

import (
	"strings"
)

// scopeCovers reports whether scope covers URL path segments.
// Scope segments are separated by ':' and matched segment-wise as path prefix,
// so 'api:vault:store:uuid-A' covers /api/vault/store/uuid-A and everything below it,
// but not /api/vault/store/uuid-AB.
func scopeCovers(scope string, path []string) bool {
	segments := strings.Split(scope, ":")
	if len(segments) > len(path) {
		return false
	}
	for i, segment := range segments {
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

// pathSegments splits URL path into segments.
func pathSegments(urlPath string) []string {
	return strings.FieldsFunc(urlPath, func(r rune) bool { return r == '/' })
}
