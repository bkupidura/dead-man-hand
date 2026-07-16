package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"dmh/internal/crypt"

	"github.com/stretchr/testify/require"
)

func TestBearerAuthenticator(t *testing.T) {
	tokens := []Token{
		{Name: "admin", Hash: testTokenHash, Scopes: []string{"api"}},
		{Name: "alive-cron", Hash: otherHash, Scopes: []string{"api:alive"}},
	}
	tests := []struct {
		inputAuthorizationHeader string
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
			inputAuthorizationHeader: "bearer example-bearer-token",
			expectedIdentity:         &Identity{Name: "admin", Scopes: []string{"api"}},
		},
		{
			inputAuthorizationHeader: "BEARER test-token",
			expectedIdentity:         &Identity{Name: "alive-cron", Scopes: []string{"api:alive"}},
		},
		{
			inputAuthorizationHeader: "Bearer unknown-token",
			expectedIdentity:         nil,
		},
		{
			inputAuthorizationHeader: "Basic example-bearer-token",
			expectedIdentity:         nil,
		},
		{
			inputAuthorizationHeader: "example-bearer-token",
			expectedIdentity:         nil,
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

func TestMiddlewareChain(t *testing.T) {
	token, err := crypt.NewBearerToken()
	require.Nil(t, err)

	tokens := []Token{
		{Name: "cli", Hash: token.Hash, Scopes: []string{"api:action", "api:alive"}},
	}
	anonymousScopes := []string{"healthz"}

	handler := BearerAuthenticator(tokens)(Authorizer(anonymousScopes)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	tests := []struct {
		inputPath    string
		inputToken   string
		expectedCode int
	}{
		{inputPath: "/healthz", inputToken: "", expectedCode: http.StatusOK},
		{inputPath: "/api/action/store", inputToken: token.Plaintext, expectedCode: http.StatusOK},
		{inputPath: "/api/alive", inputToken: token.Plaintext, expectedCode: http.StatusOK},
		{inputPath: "/api/action/store", inputToken: "", expectedCode: http.StatusUnauthorized},
		{inputPath: "/api/action/store", inputToken: "wrong-token", expectedCode: http.StatusUnauthorized},
		{inputPath: "/api/vault/store/uuid", inputToken: token.Plaintext, expectedCode: http.StatusUnauthorized},
		{inputPath: "/metrics", inputToken: token.Plaintext, expectedCode: http.StatusUnauthorized},
	}
	for _, test := range tests {
		req := httptest.NewRequest("GET", test.inputPath, nil)
		if test.inputToken != "" {
			req.Header.Set("Authorization", "Bearer "+test.inputToken)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		require.Equal(t, test.expectedCode, w.Code, "path %s token %q", test.inputPath, test.inputToken)
	}
}
