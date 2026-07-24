package auth

import (
	"context"
	"net/http"
	"strings"

	"dmh/internal/crypt"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

type contextKey int

const identityContextKey contextKey = iota

// AuthType identifies the mechanism that attempted or established an Identity.
type AuthType string

const (
	AuthTypeBearer    AuthType = "bearer"
	AuthTypeSignedURL AuthType = "signed_url"
	AuthTypeAnonymous AuthType = "anonymous"
)

// Identity describes the requester and, once the auth chain has run, the
// outcome of authentication/authorization for the request.
// Name is set only when a credential actually resolved to a principal.
// Type and Reason are populated even on failure (e.g. Type=bearer,
// Reason=invalid_token).
type Identity struct {
	Name   string
	Scopes []string
	Type   AuthType
	Reason string
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

// ensureIdentity returns r with an Identity in its context, reusing one already
// present.
func ensureIdentity(r *http.Request) (*http.Request, *Identity) {
	if id := IdentityFromContext(r.Context()); id != nil {
		return r, id
	}
	id := &Identity{}
	return r.WithContext(ContextWithIdentity(r.Context(), id)), id
}

// SeedIdentity returns middleware which attaches an empty Identity to request
// context, filled in place by the authenticators.
func SeedIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r, _ = ensureIdentity(r)
		next.ServeHTTP(w, r)
	})
}

// BearerAuthenticator returns middleware which resolves Authorization header
// into Identity stored in request context.
// Identity already resolved by other authenticators is never overwritten.
// It never rejects requests, authorization is done by Authorizer.
func BearerAuthenticator(tokens []Token) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r, id := ensureIdentity(r)
			if id.Name == "" {
				if presented := bearerFromHeader(r); presented != "" {
					id.Type = AuthTypeBearer
					id.Reason = "invalid_token"
					for _, token := range tokens {
						if crypt.ValidateBearerToken(token.Hash, presented) {
							id.Name = token.Name
							id.Scopes = token.Scopes
							id.Reason = ""
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
			r, id := ensureIdentity(r)
			if id.Name == "" {
				query := r.URL.Query()
				if query.Get("e") != "" || query.Get("s") != "" {
					id.Type = AuthTypeSignedURL
					id.Reason = "invalid_signature"
					path := requestPath(r)
					if crypt.ValidateSignedURL(secret, path, query.Get("e"), query.Get("s")) {
						id.Name = "signed-url"
						id.Scopes = []string{pathScope(path)}
						id.Reason = ""
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// requestPath returns the path chi's router dispatches this request on
// (cleaned by middleware.CleanPath), falling back to r.URL.Path when chi
// hasn't set one.
func requestPath(r *http.Request) string {
	if rctx := chi.RouteContext(r.Context()); rctx != nil && rctx.RoutePath != "" {
		return rctx.RoutePath
	}
	return r.URL.Path
}

// Authorizer returns middleware enforcing scope based authorization (default deny).
// Request is allowed when its path is covered by anonymous scope or Identity scope.
func Authorizer(anonymousScopes []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r, id := ensureIdentity(r)
			path := requestPath(r)

			if anyScopeCovers(anonymousScopes, pathSegments(path)) || IdentityCovers(r, path) {
				if id.Name == "" {
					id.Type = AuthTypeAnonymous
				}
				id.Reason = ""
				next.ServeHTTP(w, r)
				return
			}

			switch {
			case id.Name != "":
				id.Reason = "insufficient_scope"
			case id.Reason == "":
				id.Reason = "missing_credentials"
			}

			w.Header().Set("WWW-Authenticate", `Bearer realm="dmh"`)
			render.Status(r, http.StatusUnauthorized)
			render.JSON(w, r, map[string]string{"status": "Unauthorized."})
		})
	}
}

// IdentityCovers reports whether the request Identity scope covers urlPath.
func IdentityCovers(r *http.Request, urlPath string) bool {
	identity := IdentityFromContext(r.Context())
	return identity != nil && identity.Name != "" && anyScopeCovers(identity.Scopes, pathSegments(urlPath))
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
