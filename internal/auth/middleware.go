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
// It never rejects requests, authorization is done by Authorizer.
func BearerAuthenticator(tokens []Token) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			presented := bearerFromHeader(r)
			if presented != "" {
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
			next.ServeHTTP(w, r)
		})
	}
}

// Authorizer returns middleware enforcing scope based authorization (default deny).
// Request is allowed when its path is covered by anonymous scope or Identity scope.
func Authorizer(anonymousScopes []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := pathSegments(r.URL.Path)

			if anyScopeCovers(anonymousScopes, path) {
				next.ServeHTTP(w, r)
				return
			}

			if identity := IdentityFromContext(r.Context()); identity != nil && anyScopeCovers(identity.Scopes, path) {
				next.ServeHTTP(w, r)
				return
			}

			// Same 401 for missing and insufficient token, so endpoints cant be probed.
			w.Header().Set("WWW-Authenticate", `Bearer realm="dmh"`)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"status":"Unauthorized."}` + "\n"))
		})
	}
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
