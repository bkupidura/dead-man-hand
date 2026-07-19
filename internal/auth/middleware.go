package auth

import (
	"context"
	"net/http"
	"strings"

	"dmh/internal/crypt"
)

type contextKey int

const identityContextKey contextKey = iota

// Identity describes authenticated requester.
// It is stored in request context by authenticators and consumed by Authorizer.
type Identity struct {
	Name   string
	Scopes []string
}

// IdentityFromContext returns Identity stored in ctx or nil.
func IdentityFromContext(ctx context.Context) *Identity {
	identity, _ := ctx.Value(identityContextKey).(*Identity)
	return identity
}

// ContextWithIdentity returns ctx with Identity attached.
func ContextWithIdentity(ctx context.Context, identity *Identity) context.Context {
	return context.WithValue(ctx, identityContextKey, identity)
}

// BearerAuthenticator returns middleware which resolves Authorization header
// into Identity stored in request context.
// Identity already resolved by other authenticators is never overwritten.
// It never rejects requests, authorization is done by Authorizer.
func BearerAuthenticator(tokens []Token) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IdentityFromContext(r.Context()) == nil {
				if presented := bearerFromHeader(r); presented != "" {
					for _, token := range tokens {
						if crypt.ValidateBearerToken(token.Hash, presented) {
							r = r.WithContext(ContextWithIdentity(r.Context(), &Identity{
								Name:   token.Name,
								Scopes: token.Scopes,
							}))
							break
						}
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SignedURLAuthenticator returns middleware which resolves valid signed URL
// (e and s query parameters) into Identity.
// Identity scope is derived from the signed path, so valid signature authorizes
// exactly the URL which was signed and nothing else.
// It never rejects requests, authorization is done by Authorizer.
func SignedURLAuthenticator(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IdentityFromContext(r.Context()) == nil {
				query := r.URL.Query()
				if crypt.ValidateSignedURL(secret, r.URL.Path, query.Get("e"), query.Get("s")) {
					r = r.WithContext(ContextWithIdentity(r.Context(), &Identity{
						Name:   "signed-url",
						Scopes: []string{pathScope(r.URL.Path)},
					}))
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Authorizer returns middleware enforcing scope based authorization (default deny).
// Request is allowed when its path is covered by anonymous scope or Identity scope.
func Authorizer(anonymousScopes []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if anyScopeCovers(anonymousScopes, pathSegments(r.URL.Path)) || IdentityCovers(r, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			w.Header().Set("WWW-Authenticate", `Bearer realm="dmh"`)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"status":"Unauthorized."}` + "\n"))
		})
	}
}

// IdentityCovers reports whether the request Identity scope covers urlPath.
func IdentityCovers(r *http.Request, urlPath string) bool {
	identity := IdentityFromContext(r.Context())
	return identity != nil && anyScopeCovers(identity.Scopes, pathSegments(urlPath))
}

// bearerFromHeader extracts bearer token from Authorization header.
func bearerFromHeader(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
