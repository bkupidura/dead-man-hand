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

func TestJsonPostRun(t *testing.T) {
	tests := []struct {
		inputPlugin     func(string) *ExecuteJSONPost
		mockJsonMarshal func(any) ([]byte, error)
		fakeHTTPServer  func() *httptest.Server
		expectedError   bool
	}{
		{
			inputPlugin: func(string) *ExecuteJSONPost {
				return &ExecuteJSONPost{
					Data: map[string]any{"test": "test"},
				}
			},
			mockJsonMarshal: func(any) ([]byte, error) {
				return []byte{}, fmt.Errorf("mockJsonMarshal error")
			},
			expectedError: true,
		},
		{
			inputPlugin: func(string) *ExecuteJSONPost {
				return &ExecuteJSONPost{
					URL:  "broken\r",
					Data: map[string]any{"test": "test"},
				}
			},
			expectedError: true,
		},
		{
			inputPlugin: func(string) *ExecuteJSONPost {
				return &ExecuteJSONPost{
					URL:  "http://non-existing",
					Data: map[string]any{"test": "test"},
				}
			},
			expectedError: true,
		},
		{
			inputPlugin: func(url string) *ExecuteJSONPost {
				return &ExecuteJSONPost{
					URL:         url,
					Data:        map[string]any{"test": "test", "data": true},
					Headers:     map[string]string{"header1": "value1", "header2": "value2"},
					SuccessCode: []int{http.StatusCreated},
				}
			},
			fakeHTTPServer: func() *httptest.Server {
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					contentType := r.Header.Get("Content-Type")
					require.Equal(t, "application/json", contentType)
					body, err := io.ReadAll(r.Body)
					require.Nil(t, err)
					require.Equal(t, `{"data":true,"test":"test"}`, string(body))
					require.Equal(t, "value1", r.Header.Get("header1"))
					require.Equal(t, "value2", r.Header.Get("header2"))
					w.WriteHeader(http.StatusOK)
				}))
				return s
			},
			expectedError: true,
		},
		{
			inputPlugin: func(url string) *ExecuteJSONPost {
				return &ExecuteJSONPost{
					URL:         url,
					Data:        map[string]any{"test": "test", "data": true},
					Headers:     map[string]string{"header1": "value1", "header2": "value2"},
					SuccessCode: []int{http.StatusCreated},
				}
			},
			fakeHTTPServer: func() *httptest.Server {
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					contentType := r.Header.Get("Content-Type")
					require.Equal(t, "application/json", contentType)
					body, err := io.ReadAll(r.Body)
					require.Nil(t, err)
					require.Equal(t, `{"data":true,"test":"test"}`, string(body))
					require.Equal(t, "value1", r.Header.Get("header1"))
					require.Equal(t, "value2", r.Header.Get("header2"))
					w.WriteHeader(http.StatusCreated)
				}))
				return s
			},
		},
	}
	for _, test := range tests {
		jsonMarshal = json.Marshal
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
		plugin := test.inputPlugin(fakeURL)
		err := plugin.Run()
		if test.expectedError {
			require.NotNil(t, err)
		} else {
			require.Nil(t, err)
		}
	}
}

func TestJsonPostPopulate(t *testing.T) {
	tests := []struct {
		inputPlugin   *ExecuteJSONPost
		inputAction   *state.Action
		expectedError string
	}{
		{
			inputPlugin:   &ExecuteJSONPost{},
			inputAction:   &state.Action{Kind: "json_post", Data: `{"broken"`},
			expectedError: "unexpected end of JSON input",
		},
		{
			inputPlugin:   &ExecuteJSONPost{},
			inputAction:   &state.Action{Kind: "json_post", Data: `{"url": ""}`},
			expectedError: "url must be provided",
		},
		{
			inputPlugin:   &ExecuteJSONPost{},
			inputAction:   &state.Action{Kind: "json_post", Data: `{"url": "test", "success_code":[]}`},
			expectedError: "success_code must be provided",
		},
		{
			inputPlugin:   &ExecuteJSONPost{},
			inputAction:   &state.Action{Kind: "json_post", Data: `{"url": "test", "success_code":[200], "data": {}}`},
			expectedError: "data must be provided",
		},
		{
			inputPlugin: &ExecuteJSONPost{},
			inputAction: &state.Action{Kind: "json_post", Data: `{"url": "test", "success_code":[200], "data": {"test": "test"}}`},
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

func TestJsonPostPopulateConfig(t *testing.T) {
	plugin := &ExecuteJSONPost{}
	err := plugin.PopulateConfig(&Execute{})
	require.Nil(t, err)
}
