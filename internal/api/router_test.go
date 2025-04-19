package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"dmh/internal/state"
	"dmh/internal/vault"

	"github.com/stretchr/testify/require"
)

func TestNewRouter(t *testing.T) {
	tests := []struct {
		inputOptions func() *Options
		method       string
		path         string
		statusCode   int
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
				s.On("UpdateLastSeen").Return()
				return &Options{State: s, DMHEnabled: true}
			},
			method:     "GET",
			path:       "/api/alive",
			statusCode: http.StatusInternalServerError,
		},
		{
			inputOptions: func() *Options {
				s := new(mockState)
				s.On("UpdateLastSeen").Return()
				return &Options{State: s, DMHEnabled: true}
			},
			method:     "POST",
			path:       "/api/alive",
			statusCode: http.StatusInternalServerError,
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
	}

	for _, test := range tests {
		router := NewRouter(test.inputOptions())

		req, err := http.NewRequest(test.method, test.path, nil)
		require.Nil(t, err)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		require.Equal(t, test.statusCode, w.Code)
	}
}
