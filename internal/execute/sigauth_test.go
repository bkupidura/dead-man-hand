package execute

import (
	"testing"
	"time"

	"dmh/internal/crypt"
	"dmh/internal/state"

	"github.com/stretchr/testify/require"
)

func TestExpandSigAuth(t *testing.T) {
	tests := []struct {
		inputExecute *Execute
		inputAction  *state.Action
		expectedData string
	}{
		{
			inputExecute: &Execute{signedURLSecret: "test-secret", signedURLTTL: 24},
			inputAction:  &state.Action{Kind: "mail", Data: `{"message": "visit https://dmh.example.com/{sig_auth:alive}"}`},
			expectedData: `{"message": "visit https://dmh.example.com` + crypt.SignURL("test-secret", "/alive", time.Unix(1700000000, 0).Add(24*time.Hour)) + `"}`,
		},
		{
			inputExecute: &Execute{signedURLSecret: "test-secret", signedURLTTL: 24},
			inputAction:  &state.Action{Kind: "mail", Data: `{"message": "no placeholder"}`},
			expectedData: `{"message": "no placeholder"}`,
		},
		{
			inputExecute: &Execute{signedURLSecret: "test-secret", signedURLTTL: 24},
			inputAction:  &state.Action{Kind: "mail", Data: `{"message": "/{sig_auth:alive} and /{sig_auth:alive}"}`},
			expectedData: `{"message": "` + crypt.SignURL("test-secret", "/alive", time.Unix(1700000000, 0).Add(24*time.Hour)) + ` and ` + crypt.SignURL("test-secret", "/alive", time.Unix(1700000000, 0).Add(24*time.Hour)) + `"}`,
		},
		{
			inputExecute: &Execute{},
			inputAction:  &state.Action{Kind: "mail", Data: `{"message": "visit https://dmh.example.com/{sig_auth:alive}"}`},
			expectedData: `{"message": "visit https://dmh.example.com/alive"}`,
		},
		{
			inputExecute: &Execute{signedURLSecret: "test-secret", signedURLTTL: 24},
			inputAction:  &state.Action{Kind: "mail", Data: `{"message": "visit https://dmh.example.com/{sig_auth:unknown}"}`},
			expectedData: `{"message": "visit https://dmh.example.com` + crypt.SignURL("test-secret", "/unknown", time.Unix(1700000000, 0).Add(24*time.Hour)) + `"}`,
		},
		{
			inputExecute: &Execute{signedURLSecret: "test-secret", signedURLTTL: 24},
			inputAction:  &state.Action{Kind: "mail", Data: `{"message": "/{sig_auth:api/action/store/9acc344e-a65b-4675-9723-5664c0e73c76}"}`},
			expectedData: `{"message": "` + crypt.SignURL("test-secret", "/api/action/store/9acc344e-a65b-4675-9723-5664c0e73c76", time.Unix(1700000000, 0).Add(24*time.Hour)) + `"}`,
		},
		{
			inputExecute: &Execute{signedURLSecret: "test-secret", signedURLTTL: 24},
			inputAction:  &state.Action{Kind: "mail", Data: `{"message": "{sig_auth:api/} {sig_auth:api//action} {sig_auth:api:action} {sig_auth:} {sig_auth:Alive}"}`},
			expectedData: `{"message": "{sig_auth:api/} {sig_auth:api//action} {sig_auth:api:action} {sig_auth:} {sig_auth:Alive}"}`,
		},
	}
	for _, test := range tests {
		timeNow = func() time.Time { return time.Unix(1700000000, 0) }
		defer func() { timeNow = time.Now }()

		test.inputExecute.expandSigAuth(test.inputAction)
		require.Equal(t, test.expectedData, test.inputAction.Data)
	}
}

func TestSigAuthPaths(t *testing.T) {
	tests := []struct {
		inputData     string
		expectedPaths []string
	}{
		{
			inputData:     `{"message": "no placeholder"}`,
			expectedPaths: []string{},
		},
		{
			inputData:     `{"message": "https://dmh.example.com/{sig_auth:alive}"}`,
			expectedPaths: []string{"/alive"},
		},
		{
			inputData:     `{"message": "/{sig_auth:alive} and /{sig_auth:metrics}"}`,
			expectedPaths: []string{"/alive", "/metrics"},
		},
		{
			inputData: `{"message": "/{sig_auth:alive} /{sig_auth:api/action/store} /{sig_auth:api/action/store/9acc344e-a65b-4675-9723-5664c0e73c76} /{sig_auth:api/vault/store/client-uuid/secret-uuid}"}`,
			expectedPaths: []string{
				"/alive",
				"/api/action/store",
				"/api/action/store/9acc344e-a65b-4675-9723-5664c0e73c76",
				"/api/vault/store/client-uuid/secret-uuid",
			},
		},
		{
			inputData:     `{"message": "{sig_auth:api/} {sig_auth:api//action} {sig_auth:api:action} {sig_auth:} {sig_auth:Alive}"}`,
			expectedPaths: []string{},
		},
	}
	for _, test := range tests {
		require.Equal(t, test.expectedPaths, SigAuthPaths(test.inputData), "data %s", test.inputData)
	}
}
