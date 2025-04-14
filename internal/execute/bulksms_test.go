package execute

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"dmh/internal/state"

	"github.com/stretchr/testify/require"
)

func TestBulkSMSRun(t *testing.T) {
	tests := []struct {
		inputPlugin     *ExecuteBulkSMS
		inputEndpoint   func(string) string
		mockJsonMarshal func(any) ([]byte, error)
		fakeHTTPServer  func() *httptest.Server
		expectedError   bool
	}{
		{
			inputPlugin: &ExecuteBulkSMS{},
			mockJsonMarshal: func(any) ([]byte, error) {
				return []byte{}, fmt.Errorf("mockJsonMarshal error")
			},
			expectedError: true,
		},
		{
			inputPlugin:   &ExecuteBulkSMS{},
			inputEndpoint: func(string) string { return "broken\r" },
			expectedError: true,
		},
		{
			inputPlugin:   &ExecuteBulkSMS{},
			inputEndpoint: func(string) string { return "http://non-existing" },
			expectedError: true,
		},
		{
			inputPlugin:   &ExecuteBulkSMS{Message: "test", Destination: []string{"1234", "567"}, config: BulkSMSConfig{RoutingGroup: "standard", Token: BulkSMSToken{ID: "token2", Secret: "secret2"}}},
			inputEndpoint: func(url string) string { return url },
			fakeHTTPServer: func() *httptest.Server {
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					contentType := r.Header.Get("Content-Type")
					require.Equal(t, "application/json", contentType)
					body, err := io.ReadAll(r.Body)
					require.Nil(t, err)
					require.Equal(t, `{"body":"test","encoding":"UNICODE","routingGroup":"STANDARD","to":["1234","567"]}`, string(body))
					require.Equal(t, "Basic dG9rZW4yOnNlY3JldDI=", r.Header.Get("Authorization"))
					w.WriteHeader(http.StatusBadRequest)
				}))
				return s
			},
			expectedError: true,
		},
		{
			inputPlugin:   &ExecuteBulkSMS{Message: "test", Destination: []string{"1234", "567"}, config: BulkSMSConfig{RoutingGroup: "standard", Token: BulkSMSToken{ID: "token", Secret: "secret"}}},
			inputEndpoint: func(url string) string { return url },
			fakeHTTPServer: func() *httptest.Server {
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					contentType := r.Header.Get("Content-Type")
					require.Equal(t, "application/json", contentType)
					body, err := io.ReadAll(r.Body)
					require.Nil(t, err)
					require.Equal(t, `{"body":"test","encoding":"UNICODE","routingGroup":"STANDARD","to":["1234","567"]}`, string(body))
					require.Equal(t, "Basic dG9rZW46c2VjcmV0", r.Header.Get("Authorization"))
					w.WriteHeader(http.StatusCreated)
				}))
				return s
			},
		},
	}
	for _, test := range tests {
		jsonMarshal = json.Marshal
		endpoint = "https://api.bulksms.com/v1/messages"
		if test.mockJsonMarshal != nil {
			jsonMarshal = test.mockJsonMarshal
			defer func() {
				jsonMarshal = json.Marshal
			}()
		}
		var fakeServer *httptest.Server
		var fakeURL string
		if test.fakeHTTPServer != nil {
			fakeServer = test.fakeHTTPServer()
			fakeURL = fakeServer.URL
			defer fakeServer.Close()

		}
		if test.inputEndpoint != nil {
			endpoint = test.inputEndpoint(fakeURL)
			defer func() {
				endpoint = "https://api.bulksms.com/v1/messages"
			}()
		}
		plugin := test.inputPlugin
		err := plugin.Run()
		if test.expectedError {
			require.NotNil(t, err)
		} else {
			require.Nil(t, err)
		}
	}
}

func TestBulkSMSPopulate(t *testing.T) {
	tests := []struct {
		inputPlugin   *ExecuteBulkSMS
		inputAction   *state.Action
		expectedError string
	}{
		{
			inputPlugin:   &ExecuteBulkSMS{},
			inputAction:   &state.Action{Kind: "bulksms", Data: `{"broken"`},
			expectedError: "unexpected end of JSON input",
		},
		{
			inputPlugin:   &ExecuteBulkSMS{},
			inputAction:   &state.Action{Kind: "bulksms", Data: `{"message": ""}`},
			expectedError: "message must be provided",
		},
		{
			inputPlugin:   &ExecuteBulkSMS{},
			inputAction:   &state.Action{Kind: "bulksms", Data: `{"message": "test", "destination": []}`},
			expectedError: "destination must be provided",
		},
		{
			inputPlugin:   &ExecuteBulkSMS{},
			inputAction:   &state.Action{Kind: "bulksms", Data: `{"message": "test", "destination": ["+12345", "+123aa"]}`},
			expectedError: "destination must be a number",
		},
		{
			inputPlugin: &ExecuteBulkSMS{},
			inputAction: &state.Action{Kind: "bulksms", Data: `{"message": "test", "destination": ["+12345", "+12356"]}`},
		},
	}
	for _, test := range tests {
		plugin := test.inputPlugin
		err := plugin.Populate(test.inputAction)
		if test.expectedError == "" {
			require.Nil(t, err)
		} else {
			require.NotNil(t, err)
			require.Equal(t, test.expectedError, err.Error())
		}
	}
}

func TestBulkSMSPopulateConfig(t *testing.T) {
	tests := []struct {
		inputExecute   *Execute
		expectedError  error
		expectedConfig BulkSMSConfig
	}{
		{
			inputExecute: &Execute{
				bulkSMSConf: BulkSMSConfig{
					Token: BulkSMSToken{ID: "", Secret: "secret"},
				},
			},
			expectedError: fmt.Errorf("config token id and secret must be provided"),
			expectedConfig: BulkSMSConfig{
				Token: BulkSMSToken{ID: "", Secret: "secret"},
			},
		},
		{
			inputExecute: &Execute{
				bulkSMSConf: BulkSMSConfig{
					Token: BulkSMSToken{ID: "id", Secret: ""},
				},
			},
			expectedError: fmt.Errorf("config token id and secret must be provided"),
			expectedConfig: BulkSMSConfig{
				Token: BulkSMSToken{ID: "id", Secret: ""},
			},
		},
		{
			inputExecute: &Execute{
				bulkSMSConf: BulkSMSConfig{
					Token:        BulkSMSToken{ID: "id", Secret: "secret"},
					RoutingGroup: "test",
				},
			},
			expectedError: fmt.Errorf("routing_group must be one of economy, standard or premium"),
			expectedConfig: BulkSMSConfig{
				Token:        BulkSMSToken{ID: "id", Secret: "secret"},
				RoutingGroup: "test",
			},
		},
		{
			inputExecute: &Execute{
				bulkSMSConf: BulkSMSConfig{
					Token: BulkSMSToken{ID: "id", Secret: "secret"},
				},
			},
			expectedConfig: BulkSMSConfig{
				Token:        BulkSMSToken{ID: "id", Secret: "secret"},
				RoutingGroup: "standard",
			},
		},
		{
			inputExecute: &Execute{
				bulkSMSConf: BulkSMSConfig{
					Token:        BulkSMSToken{ID: "id", Secret: "secret"},
					RoutingGroup: "premium",
				},
			},
			expectedConfig: BulkSMSConfig{
				Token:        BulkSMSToken{ID: "id", Secret: "secret"},
				RoutingGroup: "premium",
			},
		},
	}
	for _, test := range tests {
		plugin := &ExecuteBulkSMS{}
		err := plugin.PopulateConfig(test.inputExecute)
		require.Equal(t, test.expectedError, err)
		require.Equal(t, test.expectedConfig, plugin.config)
	}
}
