package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScopeCovers(t *testing.T) {
	tests := []struct {
		inputScope    string
		inputPath     string
		expectedCover bool
	}{
		{inputScope: "api", inputPath: "/api", expectedCover: true},
		{inputScope: "api", inputPath: "/api/action/store", expectedCover: true},
		{inputScope: "api:action", inputPath: "/api/action", expectedCover: true},
		{inputScope: "api:action", inputPath: "/api/action/", expectedCover: true},
		{inputScope: "api:action", inputPath: "/api/action/store/uuid", expectedCover: true},
		{inputScope: "api:action:store", inputPath: "/api/action", expectedCover: false},
		{inputScope: "api:action", inputPath: "/api/actionx", expectedCover: false},
		{inputScope: "api:vault:store:uuid-A", inputPath: "/api/vault/store/uuid-A", expectedCover: true},
		{inputScope: "api:vault:store:uuid-A", inputPath: "/api/vault/store/uuid-A/deeper", expectedCover: true},
		{inputScope: "api:vault:store:uuid-A", inputPath: "/api/vault/store/uuid-AB", expectedCover: false},
		{inputScope: "api:vault:store:uuid-AB", inputPath: "/api/vault/store/uuid-A", expectedCover: false},
		{inputScope: "metrics", inputPath: "/metrics", expectedCover: true},
		{inputScope: "metrics", inputPath: "/api/metrics", expectedCover: false},
		{inputScope: "API", inputPath: "/api", expectedCover: false},
		{inputScope: "api", inputPath: "/", expectedCover: false},
	}
	for _, test := range tests {
		cover := scopeCovers(test.inputScope, pathSegments(test.inputPath))
		require.Equal(t, test.expectedCover, cover, "scope %s path %s", test.inputScope, test.inputPath)
	}
}

func TestAnyScopeCovers(t *testing.T) {
	tests := []struct {
		inputScopes   []string
		inputPath     string
		expectedCover bool
	}{
		{inputScopes: []string{}, inputPath: "/api/action", expectedCover: false},
		{inputScopes: nil, inputPath: "/api/action", expectedCover: false},
		{inputScopes: []string{"api:action"}, inputPath: "/api/action", expectedCover: true},
		{inputScopes: []string{"api:vault", "api:action"}, inputPath: "/api/action", expectedCover: true},
		{inputScopes: []string{"api:action", "api:vault"}, inputPath: "/api/vault/store", expectedCover: true},
		{inputScopes: []string{"api:vault", "metrics"}, inputPath: "/api/action", expectedCover: false},
		{inputScopes: []string{"healthz", "ready"}, inputPath: "/", expectedCover: false},
	}
	for _, test := range tests {
		cover := anyScopeCovers(test.inputScopes, pathSegments(test.inputPath))
		require.Equal(t, test.expectedCover, cover, "scopes %v path %s", test.inputScopes, test.inputPath)
	}
}

func TestPathSegments(t *testing.T) {
	tests := []struct {
		inputPath        string
		expectedSegments []string
	}{
		{inputPath: "/", expectedSegments: []string{}},
		{inputPath: "", expectedSegments: []string{}},
		{inputPath: "/api/action", expectedSegments: []string{"api", "action"}},
		{inputPath: "/api/action/", expectedSegments: []string{"api", "action"}},
		{inputPath: "//api//action", expectedSegments: []string{"api", "action"}},
	}
	for _, test := range tests {
		require.Equal(t, test.expectedSegments, pathSegments(test.inputPath))
	}
}
