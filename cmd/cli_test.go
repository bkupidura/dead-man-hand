package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

func TestActionAddRequiredParams(t *testing.T) {
	tests := []struct {
		inputParams   []string
		expectedError string
	}{
		{
			inputParams:   []string{},
			expectedError: `Required flags "data, kind, process-after" not set`,
		},
		{
			inputParams:   []string{"--data", `{"test": "test"}`},
			expectedError: `Required flags "kind, process-after" not set`,
		},
		{
			inputParams:   []string{"--data", `{"test": "test"}`, "--kind", "test"},
			expectedError: `Required flag "process-after" not set`,
		},
		{
			inputParams:   []string{"--data", `{"test": "test"}`, "--kind", "test", "--process-after", "10"},
			expectedError: `request failed: Post "http://127.0.0.1:8080/api/action/store": dial tcp 127.0.0.1:8080: connect: connection refused`,
		},
	}
	for _, test := range tests {
		params := []string{"dmh-cli", "action", "add"}
		cmd := createCLI()
		err := cmd.Run(context.Background(), append(params, test.inputParams...))
		if test.expectedError != "" {
			require.Equal(t, test.expectedError, err.Error())
		} else {
			require.Nil(t, err)
		}
	}
}

func TestActionTestRequiredParams(t *testing.T) {
	tests := []struct {
		inputParams   []string
		expectedError string
	}{
		{
			inputParams:   []string{},
			expectedError: `Required flags "data, kind" not set`,
		},
		{
			inputParams:   []string{"--data", `{"test": "test"}`},
			expectedError: `Required flag "kind" not set`,
		},
		{
			inputParams:   []string{"--data", `{"test": "test"}`, "--kind", "test"},
			expectedError: `request failed: Post "http://127.0.0.1:8080/api/action/test": dial tcp 127.0.0.1:8080: connect: connection refused`,
		},
	}
	for _, test := range tests {
		params := []string{"dmh-cli", "action", "test"}
		cmd := createCLI()
		err := cmd.Run(context.Background(), append(params, test.inputParams...))
		if test.expectedError != "" {
			require.Equal(t, test.expectedError, err.Error())
		} else {
			require.Nil(t, err)
		}
	}
}

func TestActionDeleteRequiredParams(t *testing.T) {
	tests := []struct {
		inputParams   []string
		expectedError string
	}{
		{
			inputParams:   []string{},
			expectedError: `Required flag "uuid" not set`,
		},
		{
			inputParams:   []string{"--uuid", "random-uuid"},
			expectedError: `request failed: Delete "http://127.0.0.1:8080/api/action/store/random-uuid": dial tcp 127.0.0.1:8080: connect: connection refused`,
		},
	}
	for _, test := range tests {
		params := []string{"dmh-cli", "action", "delete"}
		cmd := createCLI()
		err := cmd.Run(context.Background(), append(params, test.inputParams...))
		if test.expectedError != "" {
			require.Equal(t, test.expectedError, err.Error())
		} else {
			require.Nil(t, err)
		}
	}
}

func TestUpdateAlive(t *testing.T) {
	tests := []struct {
		inputServer   string
		mockHandler   http.HandlerFunc
		expectedError string
	}{
		{
			inputServer:   "\r",
			expectedError: `unable to parse address: parse "\r": net/url: invalid control character in URL`,
		},
		{
			expectedError: `request failed: Get "http://127.0.0.1:8080/api/alive": dial tcp 127.0.0.1:8080: connect: connection refused`,
		},
		{
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectedError: "server returned status 500: ",
		},
		{
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
		},
	}
	for _, test := range tests {
		var fakeServer *httptest.Server
		if test.mockHandler != nil {
			fakeServer = httptest.NewServer(test.mockHandler)
			defer fakeServer.Close()

			originalGetClient := getClient
			defer func() { getClient = originalGetClient }()
			getClient = func(*cli.Command) *http.Client {
				return fakeServer.Client()
			}
		}

		cmd := createCLI()
		var params []string
		if test.inputServer != "" {
			params = []string{"dmh-cli", "alive", "update", "--server", test.inputServer}
		} else if fakeServer != nil {
			params = []string{"dmh-cli", "alive", "update", "--server", fakeServer.URL}
		} else {
			params = []string{"dmh-cli", "alive", "update"}
		}

		err := cmd.Run(context.Background(), params)
		if test.expectedError == "" {
			require.Nil(t, err)
		} else {
			require.NotNil(t, err)
			require.Equal(t, test.expectedError, err.Error())
		}

	}
}

func TestListActions(t *testing.T) {
	tests := []struct {
		mockHandler   http.HandlerFunc
		expectedError string
		inputServer   string
	}{
		{
			inputServer:   "\r",
			expectedError: `unable to parse address: parse "\r": net/url: invalid control character in URL`,
		},
		{
			expectedError: `request failed: Get "http://127.0.0.1:8080/api/action/store": dial tcp 127.0.0.1:8080: connect: connection refused`,
		},
		{
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectedError: "server returned status 500: ",
		},
		{
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
		},
	}
	for _, test := range tests {
		var fakeServer *httptest.Server
		if test.mockHandler != nil {
			fakeServer = httptest.NewServer(test.mockHandler)
			defer fakeServer.Close()

			originalGetClient := getClient
			defer func() { getClient = originalGetClient }()
			getClient = func(*cli.Command) *http.Client {
				return fakeServer.Client()
			}
		}

		cmd := createCLI()
		var params []string
		if test.inputServer != "" {
			params = []string{"dmh-cli", "action", "list", "--server", test.inputServer}
		} else if fakeServer != nil {
			params = []string{"dmh-cli", "action", "list", "--server", fakeServer.URL}
		} else {
			params = []string{"dmh-cli", "action", "list"}
		}

		err := cmd.Run(context.Background(), params)
		if test.expectedError == "" {
			require.Nil(t, err)
		} else {
			require.NotNil(t, err)
			require.Equal(t, test.expectedError, err.Error())
		}

	}
}

func TestAddAction(t *testing.T) {
	tests := []struct {
		mockHandler   http.HandlerFunc
		inputParams   []string
		inputServer   string
		expectedError string
	}{
		{
			inputParams:   []string{"--data", "", "--kind", "", "--process-after", "10", "--comment", "comment", "--min-interval", "3"},
			expectedError: "data is required",
		},
		{
			inputParams:   []string{"--data", `{"test": true}`, "--kind", "", "--process-after", "10", "--comment", "comment", "--min-interval", "3"},
			expectedError: "kind is required",
		},
		{
			inputServer:   "\r",
			inputParams:   []string{"--data", `{"test": true}`, "--kind", "test", "--process-after", "10", "--comment", "comment", "--min-interval", "3"},
			expectedError: `unable to parse address: parse "\r": net/url: invalid control character in URL`,
		},
		{
			inputParams:   []string{"--data", `{"test": true}`, "--kind", "test", "--process-after", "10", "--comment", "comment", "--min-interval", "3"},
			expectedError: `request failed: Post "http://127.0.0.1:8080/api/action/store": dial tcp 127.0.0.1:8080: connect: connection refused`,
		},
		{
			inputParams: []string{"--data", `{"test": true}`, "--kind", "test", "--process-after", "10", "--comment", "comment", "--min-interval", "3"},
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectedError: "server returned status 500: ",
		},
		{
			inputParams: []string{"--data", `{"test": true}`, "--kind", "test", "--process-after", "10", "--comment", "comment", "--min-interval", "3"},
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
			},
		},
	}
	for _, test := range tests {
		var fakeServer *httptest.Server
		if test.mockHandler != nil {
			fakeServer = httptest.NewServer(test.mockHandler)
			defer fakeServer.Close()

			originalGetClient := getClient
			defer func() { getClient = originalGetClient }()
			getClient = func(*cli.Command) *http.Client {
				return fakeServer.Client()
			}
		}

		cmd := createCLI()
		var params []string
		if test.inputServer != "" {
			params = []string{"dmh-cli", "action", "add", "--server", test.inputServer}
		} else if fakeServer != nil {
			params = []string{"dmh-cli", "action", "add", "--server", fakeServer.URL}
		} else {
			params = []string{"dmh-cli", "action", "add"}
		}

		params = append(params, test.inputParams...)

		err := cmd.Run(context.Background(), params)
		if test.expectedError == "" {
			require.Nil(t, err)
		} else {
			require.NotNil(t, err)
			require.Equal(t, test.expectedError, err.Error())
		}

	}
}

func TestTestAction(t *testing.T) {
	tests := []struct {
		mockHandler   http.HandlerFunc
		inputParams   []string
		inputServer   string
		expectedError string
	}{
		{
			inputParams:   []string{"--data", "", "--kind", ""},
			expectedError: "data is required",
		},
		{
			inputParams:   []string{"--data", `{"test": true}`, "--kind", ""},
			expectedError: "kind is required",
		},
		{
			inputServer:   "\r",
			inputParams:   []string{"--data", `{"test": true}`, "--kind", "test"},
			expectedError: `unable to parse address: parse "\r": net/url: invalid control character in URL`,
		},
		{
			inputParams:   []string{"--data", `{"test": true}`, "--kind", "test"},
			expectedError: `request failed: Post "http://127.0.0.1:8080/api/action/test": dial tcp 127.0.0.1:8080: connect: connection refused`,
		},
		{
			inputParams: []string{"--data", `{"test": true}`, "--kind", "test"},
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectedError: "server returned status 500: ",
		},
		{
			inputParams: []string{"--data", `{"test": true}`, "--kind", "test"},
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
		},
	}
	for _, test := range tests {
		var fakeServer *httptest.Server
		if test.mockHandler != nil {
			fakeServer = httptest.NewServer(test.mockHandler)
			defer fakeServer.Close()

			originalGetClient := getClient
			defer func() { getClient = originalGetClient }()
			getClient = func(*cli.Command) *http.Client {
				return fakeServer.Client()
			}
		}

		cmd := createCLI()
		var params []string
		if test.inputServer != "" {
			params = []string{"dmh-cli", "action", "test", "--server", test.inputServer}
		} else if fakeServer != nil {
			params = []string{"dmh-cli", "action", "test", "--server", fakeServer.URL}
		} else {
			params = []string{"dmh-cli", "action", "test"}
		}

		params = append(params, test.inputParams...)

		err := cmd.Run(context.Background(), params)
		if test.expectedError == "" {
			require.Nil(t, err)
		} else {
			require.NotNil(t, err)
			require.Equal(t, test.expectedError, err.Error())
		}

	}
}

func TestDeleteAction(t *testing.T) {
	tests := []struct {
		mockHandler   http.HandlerFunc
		inputParams   []string
		inputServer   string
		expectedError string
	}{
		{
			inputParams:   []string{"--uuid", ""},
			expectedError: "uuid is required",
		},
		{
			inputServer:   "\r",
			inputParams:   []string{"--uuid", "test-uuid"},
			expectedError: `unable to parse address: parse "\r": net/url: invalid control character in URL`,
		},
		{
			inputParams:   []string{"--uuid", "test-uuid"},
			expectedError: `request failed: Delete "http://127.0.0.1:8080/api/action/store/test-uuid": dial tcp 127.0.0.1:8080: connect: connection refused`,
		},
		{
			inputParams: []string{"--uuid", "test-uuid"},
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectedError: "server returned status 500: ",
		},
		{
			inputParams: []string{"--uuid", "test-uuid"},
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
		},
	}
	for _, test := range tests {
		var fakeServer *httptest.Server
		if test.mockHandler != nil {
			fakeServer = httptest.NewServer(test.mockHandler)
			defer fakeServer.Close()

			originalGetClient := getClient
			defer func() { getClient = originalGetClient }()
			getClient = func(*cli.Command) *http.Client {
				return fakeServer.Client()
			}
		}

		cmd := createCLI()
		var params []string
		if test.inputServer != "" {
			params = []string{"dmh-cli", "action", "delete", "--server", test.inputServer}
		} else if fakeServer != nil {
			params = []string{"dmh-cli", "action", "delete", "--server", fakeServer.URL}
		} else {
			params = []string{"dmh-cli", "action", "delete"}
		}

		params = append(params, test.inputParams...)

		err := cmd.Run(context.Background(), params)
		if test.expectedError == "" {
			require.Nil(t, err)
		} else {
			require.NotNil(t, err)
			require.Equal(t, test.expectedError, err.Error())
		}

	}
}
