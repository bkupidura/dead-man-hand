package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"dmh/internal/auth"
	"dmh/internal/state"
	"dmh/internal/vault"

	"github.com/stretchr/testify/require"
)

// testAuthConfig returns enabled auth config with two tokens,
// "test" (plaintext example-bearer-token) with given scopes and "test2" (plaintext test-token) with api:vault scope.
func testAuthConfig(scopes []string, anonymousScopes []string) auth.Config {
	return auth.Config{
		Enabled:         true,
		AnonymousScopes: anonymousScopes,
		Bearer: auth.BearerConfig{
			Tokens: []auth.Token{
				{Name: "test", Hash: "6e529315274fd842da9323d9af0805bbef21bd90d2cb30b3cab8fab882d20067", Scopes: scopes},
				{Name: "test2", Hash: "4c5dc9b7708905f77f5e5d16316b5dfb425e68cb326dcd55a860e90a7707031e", Scopes: []string{"api:vault"}},
			},
		},
	}
}

func TestNewRouter(t *testing.T) {
	tests := []struct {
		inputOptions  func() *Options
		method        string
		path          string
		authorization string
		statusCode    int
	}{
		{
			inputOptions: func() *Options {
				return &Options{State: new(mockState)}
			},
			method:     "GET",
			path:       "/healthz",
			statusCode: http.StatusOK,
		},
		{
			inputOptions: func() *Options {
				return &Options{State: new(mockState)}
			},
			method:     "GET",
			path:       "/ready",
			statusCode: http.StatusOK,
		},
		{
			inputOptions: func() *Options {
				return &Options{State: new(mockState)}
			},
			method:     "GET",
			path:       "/metrics",
			statusCode: http.StatusOK,
		},
		{
			inputOptions: func() *Options {
				s := new(mockState)
				return &Options{State: s, DMHEnabled: true}
			},
			method:     "GET",
			path:       "/api/alive",
			statusCode: http.StatusInternalServerError,
		},
		{
			inputOptions: func() *Options {
				s := new(mockState)
				return &Options{State: s, DMHEnabled: true}
			},
			method:     "POST",
			path:       "/api/alive",
			statusCode: http.StatusMethodNotAllowed,
		},
		{
			inputOptions: func() *Options {
				s := new(mockState)
				return &Options{State: s, DMHEnabled: false}
			},
			method:     "GET",
			path:       "/api/alive",
			statusCode: http.StatusNotFound,
		},
		{
			inputOptions: func() *Options {
				s := new(mockState)
				return &Options{State: s, DMHEnabled: false}
			},
			method:     "POST",
			path:       "/api/alive",
			statusCode: http.StatusNotFound,
		},
		{
			inputOptions: func() *Options {
				s := new(mockState)
				return &Options{State: s, DMHEnabled: true}
			},
			method:     "GET",
			path:       "/alive",
			statusCode: http.StatusOK,
		},
		{
			inputOptions: func() *Options {
				s := new(mockState)
				return &Options{State: s, DMHEnabled: false}
			},
			method:     "GET",
			path:       "/alive",
			statusCode: http.StatusNotFound,
		},
		{
			inputOptions: func() *Options {
				s := new(mockState)
				return &Options{State: s, DMHEnabled: true}
			},
			method:     "POST",
			path:       "/alive",
			statusCode: http.StatusInternalServerError,
		},
		{
			inputOptions: func() *Options {
				s := new(mockState)
				return &Options{State: s, DMHEnabled: false}
			},
			method:     "POST",
			path:       "/alive",
			statusCode: http.StatusNotFound,
		},
		{
			inputOptions: func() *Options {
				s := new(mockState)
				return &Options{State: s, DMHEnabled: true}
			},
			method:     "POST",
			path:       "/api/action/test",
			statusCode: http.StatusBadRequest,
		},
		{
			inputOptions: func() *Options {
				s := new(mockState)
				return &Options{State: s, DMHEnabled: false}
			},
			method:     "POST",
			path:       "/api/action/test",
			statusCode: http.StatusNotFound,
		},
		{
			inputOptions: func() *Options {
				s := new(mockState)
				s.On("GetActions").Return([]*state.EncryptedAction{})
				return &Options{State: s, DMHEnabled: true}
			},
			method:     "GET",
			path:       "/api/action/store",
			statusCode: http.StatusOK,
		},
		{
			inputOptions: func() *Options {
				s := new(mockState)
				return &Options{State: s, DMHEnabled: false}
			},
			method:     "GET",
			path:       "/api/action/store",
			statusCode: http.StatusNotFound,
		},
		{
			inputOptions: func() *Options {
				s := new(mockState)
				return &Options{State: s, DMHEnabled: true}
			},
			method:     "POST",
			path:       "/api/action/store",
			statusCode: http.StatusBadRequest,
		},
		{
			inputOptions: func() *Options {
				s := new(mockState)
				return &Options{State: s, DMHEnabled: false}
			},
			method:     "POST",
			path:       "/api/action/store",
			statusCode: http.StatusNotFound,
		},
		{
			inputOptions: func() *Options {
				s := new(mockState)
				s.On("GetAction", "test").Return(&state.EncryptedAction{UUID: "test", Action: state.Action{Kind: "mail", Data: "test", ProcessAfter: 10}}, 0)
				return &Options{State: s, DMHEnabled: true}
			},
			method:     "GET",
			path:       "/api/action/store/test",
			statusCode: http.StatusOK,
		},
		{
			inputOptions: func() *Options {
				s := new(mockState)
				return &Options{State: s, DMHEnabled: false}
			},
			method:     "GET",
			path:       "/api/action/store/test",
			statusCode: http.StatusNotFound,
		},
		{
			inputOptions: func() *Options {
				s := new(mockState)
				s.On("DeleteAction", "test").Return(nil)
				return &Options{State: s, DMHEnabled: true}
			},
			method:     "DELETE",
			path:       "/api/action/store/test",
			statusCode: http.StatusOK,
		},
		{
			inputOptions: func() *Options {
				s := new(mockState)
				return &Options{State: s, DMHEnabled: false}
			},
			method:     "DELETE",
			path:       "/api/action/store/test",
			statusCode: http.StatusNotFound,
		},
		{
			inputOptions: func() *Options {
				v := new(mockVault)
				v.On("UpdateLastSeen", "client-uuid").Return()
				return &Options{Vault: v, VaultEnabled: true}
			},
			method:     "GET",
			path:       "/api/vault/alive/client-uuid",
			statusCode: http.StatusOK,
		},
		{
			inputOptions: func() *Options {
				v := new(mockVault)
				return &Options{Vault: v, VaultEnabled: false}
			},
			method:     "GET",
			path:       "/api/vault/alive/client-uuid",
			statusCode: http.StatusNotFound,
		},
		{
			inputOptions: func() *Options {
				v := new(mockVault)
				v.On("GetSecret", "client-uuid", "secret-uuid").Return(&vault.Secret{Key: "test", ProcessAfter: 10}, nil)
				return &Options{Vault: v, VaultEnabled: true}
			},
			method:     "GET",
			path:       "/api/vault/store/client-uuid/secret-uuid",
			statusCode: http.StatusOK,
		},
		{
			inputOptions: func() *Options {
				v := new(mockVault)
				return &Options{Vault: v, VaultEnabled: false}
			},
			method:     "GET",
			path:       "/api/vault/store/client-uuid/secret-uuid",
			statusCode: http.StatusNotFound,
		},
		{
			inputOptions: func() *Options {
				v := new(mockVault)
				return &Options{Vault: v, VaultEnabled: true}
			},
			method:     "POST",
			path:       "/api/vault/store/client-uuid/secret-uuid",
			statusCode: http.StatusBadRequest,
		},
		{
			inputOptions: func() *Options {
				v := new(mockVault)
				return &Options{Vault: v, VaultEnabled: false}
			},
			method:     "POST",
			path:       "/api/vault/store/client-uuid/secret-uuid",
			statusCode: http.StatusNotFound,
		},
		{
			inputOptions: func() *Options {
				v := new(mockVault)
				v.On("DeleteSecret", "client-uuid", "secret-uuid").Return(nil)
				return &Options{Vault: v, VaultEnabled: true}
			},
			method:     "DELETE",
			path:       "/api/vault/store/client-uuid/secret-uuid",
			statusCode: http.StatusOK,
		},
		{
			inputOptions: func() *Options {
				v := new(mockVault)
				return &Options{Vault: v, VaultEnabled: false}
			},
			method:     "DELETE",
			path:       "/api/vault/store/client-uuid/secret-uuid",
			statusCode: http.StatusNotFound,
		},
		{
			inputOptions: func() *Options {
				return &Options{State: new(mockState), Debug: true}
			},
			method:     "GET",
			path:       "/debug/pprof/",
			statusCode: http.StatusOK,
		},
		{
			inputOptions: func() *Options {
				return &Options{State: new(mockState)}
			},
			method:     "GET",
			path:       "/debug/pprof/",
			statusCode: http.StatusNotFound,
		},
		{
			inputOptions: func() *Options {
				return &Options{State: new(mockState), Auth: testAuthConfig([]string{"api"}, []string{"healthz"})}
			},
			method:     "GET",
			path:       "/healthz",
			statusCode: http.StatusOK,
		},
		{
			inputOptions: func() *Options {
				return &Options{State: new(mockState), Auth: testAuthConfig([]string{"api"}, []string{"healthz"})}
			},
			method:     "GET",
			path:       "/ready",
			statusCode: http.StatusUnauthorized,
		},
		{
			inputOptions: func() *Options {
				s := new(mockState)
				return &Options{State: s, DMHEnabled: true, Auth: testAuthConfig([]string{"api"}, nil)}
			},
			method:     "GET",
			path:       "/api/action/store",
			statusCode: http.StatusUnauthorized,
		},
		{
			inputOptions: func() *Options {
				s := new(mockState)
				s.On("GetActions").Return([]*state.EncryptedAction{})
				return &Options{State: s, DMHEnabled: true, Auth: testAuthConfig([]string{"api"}, nil)}
			},
			method:        "GET",
			path:          "/api/action/store",
			authorization: "Bearer example-bearer-token",
			statusCode:    http.StatusOK,
		},
		{
			inputOptions: func() *Options {
				s := new(mockState)
				return &Options{State: s, DMHEnabled: true, Auth: testAuthConfig([]string{"api:alive"}, nil)}
			},
			method:        "GET",
			path:          "/api/action/store",
			authorization: "Bearer example-bearer-token",
			statusCode:    http.StatusUnauthorized,
		},
		{
			inputOptions: func() *Options {
				s := new(mockState)
				return &Options{State: s, DMHEnabled: true, Auth: testAuthConfig([]string{"api"}, nil)}
			},
			method:        "GET",
			path:          "/api/action/store",
			authorization: "Bearer unknown-token",
			statusCode:    http.StatusUnauthorized,
		},
		{
			inputOptions: func() *Options {
				return &Options{State: new(mockState), Auth: testAuthConfig([]string{"metrics"}, nil)}
			},
			method:     "GET",
			path:       "/metrics",
			statusCode: http.StatusUnauthorized,
		},
		{
			inputOptions: func() *Options {
				return &Options{State: new(mockState), Auth: testAuthConfig([]string{"metrics"}, nil)}
			},
			method:        "GET",
			path:          "/metrics",
			authorization: "Bearer example-bearer-token",
			statusCode:    http.StatusOK,
		},
		{
			inputOptions: func() *Options {
				return &Options{State: new(mockState), Auth: testAuthConfig([]string{"api"}, []string{"healthz", "ready"})}
			},
			method:     "GET",
			path:       "/ready",
			statusCode: http.StatusOK,
		},
		{
			inputOptions: func() *Options {
				v := new(mockVault)
				v.On("GetSecret", "client-uuid", "secret-uuid").Return(&vault.Secret{Key: "test", ProcessAfter: 10}, nil)
				return &Options{Vault: v, VaultEnabled: true, Auth: testAuthConfig([]string{"api:action"}, nil)}
			},
			method:        "GET",
			path:          "/api/vault/store/client-uuid/secret-uuid",
			authorization: "Bearer test-token",
			statusCode:    http.StatusOK,
		},
		{
			inputOptions: func() *Options {
				s := new(mockState)
				return &Options{State: s, DMHEnabled: true, Auth: testAuthConfig([]string{"api:action"}, nil)}
			},
			method:        "GET",
			path:          "/api/action/store",
			authorization: "Bearer test-token",
			statusCode:    http.StatusUnauthorized,
		},
	}

	for _, test := range tests {
		router := NewRouter(test.inputOptions())

		req, err := http.NewRequest(test.method, test.path, nil)
		require.Nil(t, err)
		if test.authorization != "" {
			req.Header.Set("Authorization", test.authorization)
		}

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		require.Equal(t, test.statusCode, w.Code)
	}
}
