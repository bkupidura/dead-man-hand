package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"dmh/internal/crypt"

	"github.com/stretchr/testify/require"
)

func TestIdentityFromContext(t *testing.T) {
	tests := []struct {
		inputContext     context.Context
		expectedIdentity *Identity
	}{
		{
			inputContext: context.Background(),
		},
		{
			inputContext: context.WithValue(context.Background(), identityContextKey, "not-an-identity"),
		},
		{
			inputContext:     ContextWithIdentity(context.Background(), &Identity{Name: "admin", Scopes: []string{"api"}}),
			expectedIdentity: &Identity{Name: "admin", Scopes: []string{"api"}},
		},
	}
	for _, test := range tests {
		require.Equal(t, test.expectedIdentity, IdentityFromContext(test.inputContext))
	}
}

func TestContextWithIdentity(t *testing.T) {
	tests := []struct {
		inputIdentity *Identity
	}{
		{inputIdentity: nil},
		{inputIdentity: &Identity{Name: "admin", Scopes: []string{"api"}}},
		{inputIdentity: &Identity{Name: "signed-url", Scopes: []string{"api:alive", "healthz"}}},
	}
	for _, test := range tests {
		ctx := ContextWithIdentity(context.Background(), test.inputIdentity)
		require.Equal(t, test.inputIdentity, IdentityFromContext(ctx))
	}
}

func TestBearerFromHeader(t *testing.T) {
	tests := []struct {
		inputAuthorizationHeader string
		expectedToken            string
	}{
		{inputAuthorizationHeader: "", expectedToken: ""},
		{inputAuthorizationHeader: "Bearer example-bearer-token", expectedToken: "example-bearer-token"},
		{inputAuthorizationHeader: "bearer example-bearer-token", expectedToken: "example-bearer-token"},
		{inputAuthorizationHeader: "BEARER example-bearer-token", expectedToken: "example-bearer-token"},
		{inputAuthorizationHeader: "Bearer  spaced-token", expectedToken: "spaced-token"},
		{inputAuthorizationHeader: "Basic dXNlcjpwYXNz", expectedToken: ""},
		{inputAuthorizationHeader: "example-bearer-token", expectedToken: ""},
		{inputAuthorizationHeader: "Bearer", expectedToken: ""},
	}
	for _, test := range tests {
		req := httptest.NewRequest("GET", "/api/action", nil)
		if test.inputAuthorizationHeader != "" {
			req.Header.Set("Authorization", test.inputAuthorizationHeader)
		}
		require.Equal(t, test.expectedToken, bearerFromHeader(req), "header %q", test.inputAuthorizationHeader)
	}
}

func TestBearerAuthenticator(t *testing.T) {
	tokens := []Token{
		{Name: "admin", Hash: testTokenHash, Scopes: []string{"api"}},
		{Name: "alive-cron", Hash: otherHash, Scopes: []string{"api:alive"}},
	}
	tests := []struct {
		inputAuthorizationHeader string
		inputIdentity            *Identity
		expectedIdentity         *Identity
	}{
		{
			inputAuthorizationHeader: "",
			expectedIdentity:         nil,
		},
		{
			inputAuthorizationHeader: "Bearer example-bearer-token",
			expectedIdentity:         &Identity{Name: "admin", Scopes: []string{"api"}},
		},
		{
			inputAuthorizationHeader: "Bearer test-token",
			expectedIdentity:         &Identity{Name: "alive-cron", Scopes: []string{"api:alive"}},
		},
		{
			inputAuthorizationHeader: "Bearer unknown-token",
			expectedIdentity:         nil,
		},
		{
			inputAuthorizationHeader: "Bearer example-bearer-token",
			inputIdentity:            &Identity{Name: "signed-url", Scopes: []string{"alive"}},
			expectedIdentity:         &Identity{Name: "signed-url", Scopes: []string{"alive"}},
		},
	}
	for _, test := range tests {
		var gotIdentity *Identity
		handler := BearerAuthenticator(tokens)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotIdentity = IdentityFromContext(r.Context())
		}))

		req := httptest.NewRequest("GET", "/api/action", nil)
		if test.inputAuthorizationHeader != "" {
			req.Header.Set("Authorization", test.inputAuthorizationHeader)
		}
		if test.inputIdentity != nil {
			req = req.WithContext(ContextWithIdentity(req.Context(), test.inputIdentity))
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		require.Equal(t, test.expectedIdentity, gotIdentity, "header %q", test.inputAuthorizationHeader)
	}
}

func TestAuthorizer(t *testing.T) {
	tests := []struct {
		inputAnonymousScopes []string
		inputIdentity        *Identity
		inputPath            string
		expectedCode         int
	}{
		{
			inputAnonymousScopes: []string{"healthz"},
			inputPath:            "/healthz",
			expectedCode:         http.StatusOK,
		},
		{
			inputPath:    "/healthz",
			expectedCode: http.StatusUnauthorized,
		},
		{
			inputPath:    "/api/action/store",
			expectedCode: http.StatusUnauthorized,
		},
		{
			inputIdentity: &Identity{Name: "admin", Scopes: []string{"api"}},
			inputPath:     "/api/action/store",
			expectedCode:  http.StatusOK,
		},
		{
			inputIdentity: &Identity{Name: "alive-cron", Scopes: []string{"api:alive"}},
			inputPath:     "/api/action/store",
			expectedCode:  http.StatusUnauthorized,
		},
		{
			inputIdentity: &Identity{Name: "alive-cron", Scopes: []string{"api:alive"}},
			inputPath:     "/api/alive",
			expectedCode:  http.StatusOK,
		},
		{
			inputIdentity: &Identity{Name: "dmh", Scopes: []string{"api:vault:store:uuid-A", "api:vault:alive:uuid-A"}},
			inputPath:     "/api/vault/store/uuid-A",
			expectedCode:  http.StatusOK,
		},
		{
			inputIdentity: &Identity{Name: "dmh", Scopes: []string{"api:vault:store:uuid-A", "api:vault:alive:uuid-A"}},
			inputPath:     "/api/vault/store/uuid-AB",
			expectedCode:  http.StatusUnauthorized,
		},
		{
			inputAnonymousScopes: []string{"healthz"},
			inputIdentity:        &Identity{Name: "admin", Scopes: []string{"api"}},
			inputPath:            "/",
			expectedCode:         http.StatusUnauthorized,
		},
		{
			inputAnonymousScopes: []string{"healthz", "ready"},
			inputPath:            "/ready",
			expectedCode:         http.StatusOK,
		},
		{
			inputAnonymousScopes: []string{"healthz", "ready"},
			inputPath:            "/metrics",
			expectedCode:         http.StatusUnauthorized,
		},
		{
			inputIdentity: &Identity{Name: "dmh", Scopes: []string{"api:vault:store:uuid-A", "api:vault:alive:uuid-A"}},
			inputPath:     "/api/vault/alive/uuid-A",
			expectedCode:  http.StatusOK,
		},
	}
	for _, test := range tests {
		handler := Authorizer(test.inputAnonymousScopes)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("GET", test.inputPath, nil)
		if test.inputIdentity != nil {
			req = req.WithContext(ContextWithIdentity(req.Context(), test.inputIdentity))
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		require.Equal(t, test.expectedCode, w.Code, "path %s identity %+v", test.inputPath, test.inputIdentity)
		if test.expectedCode == http.StatusUnauthorized {
			require.Equal(t, `Bearer realm="dmh"`, w.Header().Get("WWW-Authenticate"))
			require.JSONEq(t, `{"status":"Unauthorized."}`, w.Body.String())
		}
	}
}

func TestIdentityCovers(t *testing.T) {
	tests := []struct {
		inputIdentity  *Identity
		inputPath      string
		expectedCovers bool
	}{
		{
			// No identity covers nothing.
			inputPath:      "/api/action/store",
			expectedCovers: false,
		},
		{
			inputIdentity:  &Identity{Name: "admin", Scopes: []string{"api"}},
			inputPath:      "/api/action/store",
			expectedCovers: true,
		},
		{
			inputIdentity:  &Identity{Name: "admin", Scopes: []string{"api"}},
			inputPath:      "/alive",
			expectedCovers: false,
		},
		{
			inputIdentity:  &Identity{Name: "alive-cron", Scopes: []string{"alive"}},
			inputPath:      "/alive",
			expectedCovers: true,
		},
		{
			// Any of the identity scopes covering is enough.
			inputIdentity:  &Identity{Name: "multi", Scopes: []string{"metrics", "alive"}},
			inputPath:      "/alive",
			expectedCovers: true,
		},
		{
			inputIdentity:  &Identity{Name: "dmh", Scopes: []string{"api:vault:store:uuid-A"}},
			inputPath:      "/api/vault/store/uuid-A/deeper",
			expectedCovers: true,
		},
		{
			inputIdentity:  &Identity{Name: "empty", Scopes: []string{}},
			inputPath:      "/alive",
			expectedCovers: false,
		},
	}
	for _, test := range tests {
		req := httptest.NewRequest("GET", test.inputPath, nil)
		if test.inputIdentity != nil {
			req = req.WithContext(ContextWithIdentity(req.Context(), test.inputIdentity))
		}
		require.Equal(t, test.expectedCovers, IdentityCovers(req, test.inputPath), "path %s identity %+v", test.inputPath, test.inputIdentity)
	}
}

func TestMiddlewareChain(t *testing.T) {
	token, err := crypt.NewBearerToken()
	require.Nil(t, err)

	tokens := []Token{
		{Name: "cli", Hash: token.Hash, Scopes: []string{"api:action", "api:alive"}},
	}
	anonymousScopes := []string{"healthz"}
	secret := "test-secret"

	handler := BearerAuthenticator(tokens)(SignedURLAuthenticator(secret)(Authorizer(anonymousScopes)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))))

	tests := []struct {
		inputURL     string
		inputToken   string
		expectedCode int
	}{
		{inputURL: "/healthz", inputToken: "", expectedCode: http.StatusOK},
		{inputURL: "/api/action/store", inputToken: token.Plaintext, expectedCode: http.StatusOK},
		{inputURL: "/api/alive", inputToken: token.Plaintext, expectedCode: http.StatusOK},
		{inputURL: "/api/action/store", inputToken: "", expectedCode: http.StatusUnauthorized},
		{inputURL: "/api/action/store", inputToken: "wrong-token", expectedCode: http.StatusUnauthorized},
		{inputURL: "/api/vault/store/uuid", inputToken: token.Plaintext, expectedCode: http.StatusUnauthorized},
		{inputURL: "/metrics", inputToken: token.Plaintext, expectedCode: http.StatusUnauthorized},
		{inputURL: crypt.SignURL(secret, "/api/vault/store/uuid", time.Now().Add(time.Hour)), expectedCode: http.StatusOK},
		{inputURL: crypt.SignURL("wrong-secret", "/api/vault/store/uuid", time.Now().Add(time.Hour)), expectedCode: http.StatusUnauthorized},
		// bearer identity is resolved first and never overwritten, its scopes dont cover vault
		{inputURL: crypt.SignURL(secret, "/api/vault/store/uuid", time.Now().Add(time.Hour)), inputToken: token.Plaintext, expectedCode: http.StatusUnauthorized},
	}
	for _, test := range tests {
		req := httptest.NewRequest("GET", test.inputURL, nil)
		if test.inputToken != "" {
			req.Header.Set("Authorization", "Bearer "+test.inputToken)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		require.Equal(t, test.expectedCode, w.Code, "url %s token %q", test.inputURL, test.inputToken)
	}
}

func TestSignedURLAuthenticator(t *testing.T) {
	tests := []struct {
		inputURL         string
		inputIdentity    *Identity
		expectedIdentity *Identity
	}{
		{
			inputURL:         crypt.SignURL("test-secret", "/alive", time.Now().Add(time.Hour)),
			expectedIdentity: &Identity{Name: "signed-url", Scopes: []string{"alive"}},
		},
		{
			inputURL:         crypt.SignURL("test-secret", "/api/action/store", time.Now().Add(time.Hour)),
			expectedIdentity: &Identity{Name: "signed-url", Scopes: []string{"api:action:store"}},
		},
		{
			inputURL: "/alive",
		},
		{
			inputURL: crypt.SignURL("wrong-secret", "/alive", time.Now().Add(time.Hour)),
		},
		{
			inputURL:         crypt.SignURL("test-secret", "/alive", time.Now().Add(time.Hour)),
			inputIdentity:    &Identity{Name: "bearer", Scopes: []string{"api"}},
			expectedIdentity: &Identity{Name: "bearer", Scopes: []string{"api"}},
		},
	}

	for _, test := range tests {
		var gotIdentity *Identity
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotIdentity = IdentityFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		})

		req, err := http.NewRequest("GET", test.inputURL, nil)
		require.Nil(t, err)
		if test.inputIdentity != nil {
			req = req.WithContext(ContextWithIdentity(req.Context(), test.inputIdentity))
		}
		w := httptest.NewRecorder()

		SignedURLAuthenticator("test-secret")(next).ServeHTTP(w, req)

		require.Equal(t, test.expectedIdentity, gotIdentity, "url %s", test.inputURL)
	}
}
