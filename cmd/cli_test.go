package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"dmh/internal/state"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
	"gopkg.in/yaml.v3"
)

func TestActionAddRequiredParams(t *testing.T) {
	tests := []struct {
		inputParams   []string
		expectedError string
	}{
		{
			inputParams:   []string{},
			expectedError: "data is required",
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
		mockHandler     http.HandlerFunc
		inputParams     []string
		inputServer     string
		expectedError   string
		checkBody       func(*testing.T, []byte)
		mockJsonMarshal func(v any) ([]byte, error)
	}{
		{
			inputParams:   []string{"--data", "", "--kind", "test", "--process-after", "10"},
			expectedError: "data is required",
		},
		{
			inputServer:   "\r",
			inputParams:   []string{"--data", `{"test": true}`, "--kind", "test", "--process-after", "10"},
			expectedError: `unable to parse address: parse "\r": net/url: invalid control character in URL`,
		},
		{
			inputParams:   []string{"--data", `{"test": true}`, "--kind", "test", "--process-after", "10"},
			expectedError: `request failed: Post "http://127.0.0.1:8080/api/action/store": dial tcp 127.0.0.1:8080: connect: connection refused`,
		},
		{
			inputParams: []string{"--data", `{"test": true}`, "--kind", "test", "--process-after", "10"},
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectedError: "server returned status 500: ",
		},
		{
			inputParams: []string{"--data", `{"test": true}`, "--kind", "test", "--process-after", "10"},
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
			},
		},
		{
			inputParams:   []string{"--data", "{}", "--kind", "test", "--process-after", "10"},
			expectedError: "failed to marshal JSON",
			mockJsonMarshal: func(v any) ([]byte, error) {
				return nil, fmt.Errorf("forced marshal error")
			},
		},
		{
			inputParams: []string{
				"--kind", "json_post",
				"--data", `{"url": "https://api.example.com/alert"}`,
				"--process-after", "24",
				"--min-interval", "6",
				"--comment", "Critical alert",
			},
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
			},
			checkBody: func(t *testing.T, body []byte) {
				var act state.Action
				require.NoError(t, json.Unmarshal(body, &act))
				require.Equal(t, "json_post", act.Kind)
				require.Equal(t, `{"url": "https://api.example.com/alert"}`, act.Data)
				require.Equal(t, 24, act.ProcessAfter)
				require.Equal(t, 6, act.MinInterval)
				require.Equal(t, "Critical alert", act.Comment)
			},
		},
	}
	for _, test := range tests {
		var capturedBody []byte
		var fakeServer *httptest.Server
		if test.mockHandler != nil {
			wrappedHandler := func(w http.ResponseWriter, r *http.Request) {
				capturedBody, _ = io.ReadAll(r.Body)
				test.mockHandler(w, r)
			}
			fakeServer = httptest.NewServer(http.HandlerFunc(wrappedHandler))
			defer fakeServer.Close()

			originalGetClient := getClient
			defer func() { getClient = originalGetClient }()
			getClient = func(*cli.Command) *http.Client {
				return fakeServer.Client()
			}
		}

		jsonMarshal = json.Marshal
		if test.mockJsonMarshal != nil {
			jsonMarshal = test.mockJsonMarshal
		}
		defer func() { jsonMarshal = json.Marshal }()

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
			require.Contains(t, err.Error(), test.expectedError)
		}

		if test.checkBody != nil {
			test.checkBody(t, capturedBody)
		}
	}
}

func TestTestAction(t *testing.T) {
	tests := []struct {
		mockHandler     http.HandlerFunc
		inputParams     []string
		inputServer     string
		expectedError   string
		mockJsonMarshal func(v any) ([]byte, error)
	}{
		{
			inputParams:   []string{"--data", "", "--kind", "test"},
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
		{
			inputParams:   []string{"--data", "{}", "--kind", "test"},
			expectedError: "failed to marshal JSON",
			mockJsonMarshal: func(v any) ([]byte, error) {
				return nil, fmt.Errorf("forced marshal error")
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

		jsonMarshal = json.Marshal
		if test.mockJsonMarshal != nil {
			jsonMarshal = test.mockJsonMarshal
		}
		defer func() { jsonMarshal = json.Marshal }()

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
			require.Contains(t, err.Error(), test.expectedError)
		}
	}
}

func TestDeleteAction(t *testing.T) {
	tests := []struct {
		mockHandler    http.HandlerFunc
		inputParams    []string
		inputServer    string
		expectedError  string
		mockNewRequest func(method, url string, body io.Reader) (*http.Request, error)
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
		{
			inputParams:   []string{"--uuid", "test-uuid"},
			expectedError: "failed to create request",
			mockNewRequest: func(method, url string, body io.Reader) (*http.Request, error) {
				return nil, fmt.Errorf("forced newRequest error")
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

		newRequest = http.NewRequest
		if test.mockNewRequest != nil {
			newRequest = test.mockNewRequest
		}
		defer func() { newRequest = http.NewRequest }()

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
			require.Contains(t, err.Error(), test.expectedError)
		}
	}
}

func TestAddActionFromFile(t *testing.T) {
	tests := []struct {
		fileContent   string
		mockHandler   http.HandlerFunc
		inputServer   string
		inputFile     string
		expectedError string
	}{
		{
			inputFile:     "/nonexistent/actions.yaml",
			expectedError: "unable to load actions from file",
		},
		{
			inputFile:     "testdata/invalid.yaml",
			fileContent:   "kind: [invalid",
			expectedError: "unable to load actions from file",
		},
		{
			inputFile:     "testdata/empty.yaml",
			fileContent:   "",
			expectedError: "no actions found in file",
		},
		{
			inputFile: "testdata/with-comment.yaml",
			fileContent: `- kind: test
  data: '{"test": true}'
  process_after: 12
  comment: test comment
`,
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
			},
		},
		{
			inputFile: "testdata/mixed.yaml",
			fileContent: `- kind: test
  data: '{"test": true}'
  process_after: 12
- kind: ""
  data: ""
  process_after: 12
`,
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
			},
			expectedError: "unable to load actions from file: action #2: data is required",
		},
		{
			inputFile: "testdata/server-error.yaml",
			fileContent: `- kind: test
  data: '{"test": true}'
  process_after: 12
`,
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectedError: "1 of 1 actions failed to add",
		},
		{
			inputFile: "testdata/all-success.yaml",
			fileContent: `- kind: test
  data: '{"test": true}'
  process_after: 10
- kind: webhook
  data: '{"url": "https://example.com"}'
  process_after: 24
`,
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
			},
		},
	}

	os.MkdirAll("testdata", 0755)
	defer os.RemoveAll("testdata")

	for _, test := range tests {
		if test.fileContent != "" || test.inputFile == "testdata/empty.yaml" {
			err := os.WriteFile(test.inputFile, []byte(test.fileContent), 0644)
			require.NoError(t, err)
		}

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
			params = []string{"dmh-cli", "action", "add", "--server", test.inputServer, "--file", test.inputFile}
		} else if fakeServer != nil {
			params = []string{"dmh-cli", "action", "add", "--server", fakeServer.URL, "--file", test.inputFile}
		} else {
			params = []string{"dmh-cli", "action", "add", "--file", test.inputFile}
		}

		err := cmd.Run(context.Background(), params)

		if test.expectedError != "" {
			require.NotNil(t, err)
			require.Contains(t, err.Error(), test.expectedError)
		} else {
			require.Nil(t, err)
		}
	}
}

func TestLoadActionsFromFile(t *testing.T) {
	tests := []struct {
		fileContent   string
		inputFile     string
		expectedError string
		expectedLen   int
	}{
		{
			inputFile:   "testdata/load-valid.yaml",
			fileContent: "- kind: test\n  data: '{\"test\": true}'\n  process_after: 10\n- kind: webhook\n  data: '{\"url\": \"https://example.com\"}'\n  process_after: 24\n",
			expectedLen: 2,
		},
		{
			inputFile:     "testdata/load-invalid.yaml",
			fileContent:   "kind: [invalid",
			expectedError: "yaml:",
		},
		{
			inputFile:     "testdata/nonexistent.yaml",
			expectedError: "no such file or directory",
		},
		{
			inputFile:   "testdata/load-empty.yaml",
			fileContent: "",
			expectedLen: 0,
		},
		{
			inputFile: "testdata/native-single.yaml",
			fileContent: `- kind: dummy
  data:
    message: test message
    fail_on_run: false
  process_after: 12
`,
			expectedLen: 1,
		},
		{
			inputFile: "testdata/native-multiple.yaml",
			fileContent: `- kind: dummy
  data:
    message: first
  process_after: 10
- kind: dummy
  data:
    message: second
  process_after: 20
`,
			expectedLen: 2,
		},
		{
			inputFile: "testdata/native-mixed.yaml",
			fileContent: `- kind: dummy
  data: '{"message": "string format"}'
  process_after: 10
- kind: dummy
  data:
    message: native format
  process_after: 20
`,
			expectedLen: 2,
		},
		{
			inputFile: "testdata/native-empty-msg.yaml",
			fileContent: `- kind: dummy
  data:
    message: ""
  process_after: 12
`,
			expectedLen: 1,
		},
		{
			inputFile: "testdata/load-invalid-action.yaml",
			fileContent: `- kind: dummy
  data: '{"message": "test"}'
  process_after: 0
`,
			expectedError: "action #1: process_after should be greater than 0",
		},
	}

	os.MkdirAll("testdata", 0755)
	defer os.RemoveAll("testdata")

	for _, test := range tests {
		if test.fileContent != "" || test.inputFile == "testdata/load-empty.yaml" {
			err := os.WriteFile(test.inputFile, []byte(test.fileContent), 0644)
			require.NoError(t, err)
		}

		actions, err := loadActionsFromFile(test.inputFile)

		if test.expectedError != "" {
			require.Error(t, err)
			require.Contains(t, err.Error(), test.expectedError)
		} else {
			require.NoError(t, err)
			require.Len(t, actions, test.expectedLen)
		}
	}
}

func TestCreateAction(t *testing.T) {
	tests := []struct {
		action          *state.Action
		mockHandler     http.HandlerFunc
		mockJsonMarshal func(v any) ([]byte, error)
		inputServer     string
		expectedError   string
		checkBody       func(*testing.T, []byte)
	}{
		{
			action:        &state.Action{Kind: "test", ProcessAfter: 10},
			expectedError: "data is required",
		},
		{
			action:          &state.Action{Kind: "test", Data: `{"test": true}`, ProcessAfter: 10},
			expectedError:   "failed to marshal JSON",
			mockJsonMarshal: func(v any) ([]byte, error) { return nil, fmt.Errorf("forced marshal error") },
		},
		{
			action:        &state.Action{Kind: "test", Data: `{"test": true}`, ProcessAfter: 10},
			inputServer:   "\r",
			expectedError: "unable to parse address",
		},
		{
			action:        &state.Action{Kind: "test", Data: `{"test": true}`, ProcessAfter: 10},
			expectedError: "request failed",
		},
		{
			action: &state.Action{Kind: "test", Data: `{"test": true}`, ProcessAfter: 10},
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectedError: "server returned status 500",
		},
		{
			action: &state.Action{Kind: "json_post", Data: `{"url": "https://api.example.com/alert"}`, ProcessAfter: 24, MinInterval: 6, Comment: "Critical alert"},
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
			},
			checkBody: func(t *testing.T, body []byte) {
				var act state.Action
				require.NoError(t, json.Unmarshal(body, &act))
				require.Equal(t, "json_post", act.Kind)
				require.Equal(t, `{"url": "https://api.example.com/alert"}`, act.Data)
				require.Equal(t, 24, act.ProcessAfter)
				require.Equal(t, 6, act.MinInterval)
				require.Equal(t, "Critical alert", act.Comment)
			},
		},
	}

	for _, test := range tests {
		var capturedBody []byte
		var fakeServer *httptest.Server
		if test.mockHandler != nil {
			wrappedHandler := func(w http.ResponseWriter, r *http.Request) {
				capturedBody, _ = io.ReadAll(r.Body)
				test.mockHandler(w, r)
			}
			fakeServer = httptest.NewServer(http.HandlerFunc(wrappedHandler))
			defer fakeServer.Close()

			originalGetClient := getClient
			defer func() { getClient = originalGetClient }()
			getClient = func(*cli.Command) *http.Client {
				return fakeServer.Client()
			}
		}

		jsonMarshal = json.Marshal
		if test.mockJsonMarshal != nil {
			jsonMarshal = test.mockJsonMarshal
		}
		defer func() { jsonMarshal = json.Marshal }()

		cmd := createCLI()
		if test.inputServer != "" {
			cmd.Set("server", test.inputServer)
		} else if fakeServer != nil {
			cmd.Set("server", fakeServer.URL)
		}

		err := createAction(cmd, test.action)

		if test.expectedError == "" {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), test.expectedError)
		}

		if test.checkBody != nil {
			test.checkBody(t, capturedBody)
		}
	}
}

func TestGetClient(t *testing.T) {
	client := getClient(nil)
	require.NotNil(t, client)
	require.Equal(t, 5*time.Second, client.Timeout)
}

func TestActionDataUnmarshalYAML(t *testing.T) {
	tests := []struct {
		yamlStr     string
		expected    string
		expectError bool
	}{
		{
			yamlStr:  "data: '{\"message\": \"hello\"}'",
			expected: "{\"message\": \"hello\"}",
		},
		{
			yamlStr:  "data:\n  message: hello\n  count: 5",
			expected: `{"count":5,"message":"hello"}`,
		},
		{
			yamlStr: `data:
  message: Hello
  destination:
    - "12345"
    - "67890"`,
			expected: `{"destination":["12345","67890"],"message":"Hello"}`,
		},
		{
			yamlStr: `data:
  enabled: true
  disabled: false`,
			expected: `{"disabled":false,"enabled":true}`,
		},
		{
			yamlStr:  `data: ""`,
			expected: ``,
		},
		{
			yamlStr:  `data:`,
			expected: ``,
		},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			var entry actionFileEntry
			err := yaml.Unmarshal([]byte(tt.yamlStr), &entry)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, entry.Data.Value)
			}
		})
	}
}
