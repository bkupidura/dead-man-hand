package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"testing"

	"dmh/internal/crypt"
	"dmh/internal/state"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
	"gopkg.in/yaml.v3"
)

func TestUpdateAlive(t *testing.T) {
	tests := []struct {
		inputServer   string
		inputTokenEnv string
		mockHandler   http.HandlerFunc
		expectedError string
	}{
		{
			inputTokenEnv: "env-token",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "Bearer env-token", r.Header.Get("Authorization"))
				w.WriteHeader(http.StatusOK)
			},
		},
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
				require.Equal(t, "/api/alive", r.URL.Path)
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

		if test.inputTokenEnv != "" {
			err := os.Setenv("DMH_TOKEN", test.inputTokenEnv)
			require.Nil(t, err)
		} else {
			os.Unsetenv("DMH_TOKEN")
		}
		defer os.Unsetenv("DMH_TOKEN")

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
		inputToken    string
	}{
		{
			inputToken: "test-token",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
				w.WriteHeader(http.StatusOK)
			},
		},
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
				require.Equal(t, "/api/action/store", r.URL.Path)
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
		if test.inputToken != "" {
			params = append(params, "--token", test.inputToken)
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
		inputParams   []string
		inputFile     string
		fileContent   string
		mockHandler   http.HandlerFunc
		expectedError string
	}{
		{
			inputFile:     "/nonexistent/actions.yaml",
			expectedError: "unable to load actions from file",
		},
		{
			inputFile: "testdata/add-success.yaml",
			fileContent: `- kind: test
  data: '{"test": true}'
  process_after: 10
`,
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
			},
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
	}

	os.MkdirAll("testdata", 0755)
	defer os.RemoveAll("testdata")

	for _, test := range tests {
		if test.fileContent != "" {
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
		params := []string{"dmh-cli", "action", "add"}
		if fakeServer != nil {
			params = append(params, "--server", fakeServer.URL)
		}
		if test.inputFile != "" {
			params = append(params, "--file", test.inputFile)
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

func TestTestAction(t *testing.T) {
	tests := []struct {
		inputParams   []string
		inputFile     string
		fileContent   string
		mockHandler   http.HandlerFunc
		expectedError string
	}{
		{
			inputFile:     "/nonexistent/actions.yaml",
			expectedError: "unable to load actions from file",
		},
		{
			inputFile: "testdata/test-success.yaml",
			fileContent: `- kind: test
  data: '{"test": true}'
  process_after: 10
`,
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
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
				w.WriteHeader(http.StatusOK)
			},
		},
	}

	os.MkdirAll("testdata", 0755)
	defer os.RemoveAll("testdata")

	for _, test := range tests {
		if test.fileContent != "" {
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
		params := []string{"dmh-cli", "action", "test"}
		if fakeServer != nil {
			params = append(params, "--server", fakeServer.URL)
		}
		if test.inputFile != "" {
			params = append(params, "--file", test.inputFile)
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
		inputParams   []string
		inputServer   string
		mockHandler   http.HandlerFunc
		expectedError string
	}{
		{
			inputParams:   []string{},
			expectedError: `Required flag "uuid" not set`,
		},
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
				require.Equal(t, "DELETE", r.Method)
				require.Equal(t, "/api/action/store/test-uuid", r.URL.Path)
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
			require.Contains(t, err.Error(), test.expectedError)
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
		mockHandler   http.HandlerFunc
		expectedError string
	}{
		{
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectedError: "server returned status 500: ",
		},
		{
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "/api/action/store", r.URL.Path)
				w.WriteHeader(http.StatusCreated)
			},
		},
	}

	for _, test := range tests {
		fakeServer := httptest.NewServer(test.mockHandler)
		defer fakeServer.Close()

		originalGetClient := getClient
		defer func() { getClient = originalGetClient }()
		getClient = func(*cli.Command) *http.Client {
			return fakeServer.Client()
		}

		cmd := createCLI()
		cmd.Set("server", fakeServer.URL)

		err := createAction(cmd, &state.Action{Kind: "test", Data: `{"test": true}`, ProcessAfter: 10})

		if test.expectedError == "" {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), test.expectedError)
		}
	}
}

func TestGetClient(t *testing.T) {
	client := getClient(nil)
	require.NotNil(t, client)
	require.Equal(t, httpClientTimeout, client.Timeout)
}

func TestActionDataUnmarshalYAML(t *testing.T) {
	tests := []struct {
		yamlStr         string
		expected        string
		mockJsonMarshal func(v any) ([]byte, error)
		expectError     bool
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
		{
			yamlStr:     "data:\n  ? [1, 2]\n  : value",
			expectError: true,
		},
		{
			yamlStr:         "data:\n  message: hello",
			mockJsonMarshal: func(v any) ([]byte, error) { return nil, fmt.Errorf("forced marshal error") },
			expectError:     true,
		},
	}

	for _, test := range tests {
		jsonMarshal = json.Marshal
		if test.mockJsonMarshal != nil {
			jsonMarshal = test.mockJsonMarshal
		}
		defer func() { jsonMarshal = json.Marshal }()

		var entry actionFileEntry
		err := yaml.Unmarshal([]byte(test.yamlStr), &entry)
		if test.expectError {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			require.Equal(t, test.expected, entry.Data.Value)
		}
	}
}

// captureCLIOutput runs the CLI with the given args and returns captured stdout.
func captureCLIOutput(t *testing.T, args ...string) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	cmd := createCLI()
	runErr := cmd.Run(context.Background(), args)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String(), runErr
}

func TestGenBearer(t *testing.T) {
	tests := []struct {
		mockToken     func() (crypt.BearerToken, error)
		expectedError string
		expectedRegex []string
	}{
		{
			expectedRegex: []string{`BearerToken:\s*[a-zA-Z0-9_-]{43}`, `SHA256:\s*[a-f0-9]{64}`},
		},
		{
			mockToken:     func() (crypt.BearerToken, error) { return crypt.BearerToken{}, fmt.Errorf("crypto failure") },
			expectedError: "crypto failure",
		},
	}

	for _, test := range tests {
		original := newBearerToken
		defer func() { newBearerToken = original }()
		if test.mockToken != nil {
			newBearerToken = test.mockToken
		}

		out, err := captureCLIOutput(t, "dmh-cli", "auth", "generate-bearer")

		if test.expectedError != "" {
			require.NotNil(t, err)
			require.Equal(t, test.expectedError, err.Error())
		} else {
			require.Nil(t, err)
			require.Contains(t, out, "BearerToken:")
			require.Contains(t, out, "SHA256:")

			for _, pattern := range test.expectedRegex {
				require.Regexp(t, `(?m)`+pattern, out)
			}

			tokenMatch := regexp.MustCompile(`BearerToken:\s*(\S+)`).FindStringSubmatch(out)
			require.Len(t, tokenMatch, 2)
			hashMatch := regexp.MustCompile(`SHA256:\s*(\S+)`).FindStringSubmatch(out)
			require.Len(t, hashMatch, 2)
			require.True(t, crypt.ValidateBearerToken(hashMatch[1], tokenMatch[1]))
		}
	}
}

func TestCreateCLI(t *testing.T) {
	cmd := createCLI()
	require.Equal(t, "dmh-client", cmd.Name)
	require.Equal(t, "1.0.0", cmd.Version)

	var flagNames []string
	for _, f := range cmd.Flags {
		flagNames = append(flagNames, f.Names()...)
	}
	require.Contains(t, flagNames, "server")
	require.Contains(t, flagNames, "token")

	var cmdNames []string
	for _, c := range cmd.Commands {
		cmdNames = append(cmdNames, c.Name)
	}
	require.ElementsMatch(t, []string{"alive", "action", "auth"}, cmdNames)
}

func TestDoRequest(t *testing.T) {
	tests := []struct {
		method         string
		inputToken     string
		body           []byte
		mockHandler    http.HandlerFunc
		mockNewRequest func(method, url string, body io.Reader) (*http.Request, error)
		expectedError  string
	}{
		{
			method:     "GET",
			inputToken: "test-token",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "GET", r.Method)
				require.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
				require.Empty(t, r.Header.Get("Content-Type"))
				body, err := io.ReadAll(r.Body)
				require.Nil(t, err)
				require.Empty(t, body)
				w.WriteHeader(http.StatusOK)
			},
		},
		{
			method: "GET",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "GET", r.Method)
				require.Empty(t, r.Header.Get("Authorization"))
				require.Empty(t, r.Header.Get("Content-Type"))
				w.WriteHeader(http.StatusOK)
			},
		},
		{
			method: "POST",
			body:   []byte(`{"test": true}`),
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "POST", r.Method)
				require.Empty(t, r.Header.Get("Authorization"))
				require.Equal(t, "application/json", r.Header.Get("Content-Type"))
				body, err := io.ReadAll(r.Body)
				require.Nil(t, err)
				require.Equal(t, `{"test": true}`, string(body))
				w.WriteHeader(http.StatusOK)
			},
		},
		{
			method:     "POST",
			inputToken: "post-token",
			body:       []byte(`{"post": true}`),
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "POST", r.Method)
				require.Equal(t, "Bearer post-token", r.Header.Get("Authorization"))
				require.Equal(t, "application/json", r.Header.Get("Content-Type"))
				body, err := io.ReadAll(r.Body)
				require.Nil(t, err)
				require.Equal(t, `{"post": true}`, string(body))
				w.WriteHeader(http.StatusOK)
			},
		},
		{
			method:     "DELETE",
			inputToken: "delete-token",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "DELETE", r.Method)
				require.Equal(t, "Bearer delete-token", r.Header.Get("Authorization"))
				require.Empty(t, r.Header.Get("Content-Type"))
				body, err := io.ReadAll(r.Body)
				require.Nil(t, err)
				require.Empty(t, body)
				w.WriteHeader(http.StatusOK)
			},
		},
		{
			method: "POST",
			mockNewRequest: func(method, url string, body io.Reader) (*http.Request, error) {
				return nil, fmt.Errorf("forced newRequest error")
			},
			expectedError: "forced newRequest error",
		},
	}

	os.Unsetenv("DMH_TOKEN")

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
		if test.inputToken != "" {
			cmd.Set("token", test.inputToken)
		}

		serverURL := defaultServerAddr
		if fakeServer != nil {
			serverURL = fakeServer.URL
		}

		resp, err := doRequest(cmd, test.method, serverURL, test.body)
		if test.expectedError == "" {
			require.Nil(t, err)
			resp.Body.Close()
		} else {
			require.NotNil(t, err)
			require.Contains(t, err.Error(), test.expectedError)
		}
	}
}

func TestSendAction(t *testing.T) {
	tests := []struct {
		action          *state.Action
		mockHandler     http.HandlerFunc
		mockJsonMarshal func(v any) ([]byte, error)
		inputServer     string
		wantStatus      int
		expectedError   string
		checkBody       func(*testing.T, []byte)
	}{
		{
			action:        &state.Action{},
			expectedError: "data is required",
		},
		{
			action:          &state.Action{Kind: "test", Data: `{"test": true}`, ProcessAfter: 10},
			mockJsonMarshal: func(v any) ([]byte, error) { return nil, fmt.Errorf("forced marshal error") },
			expectedError:   "failed to marshal JSON",
		},
		{
			action:        &state.Action{Kind: "test", Data: `{"test": true}`, ProcessAfter: 10},
			inputServer:   "\r",
			expectedError: `unable to parse address: parse "\r": net/url: invalid control character in URL`,
		},
		{
			action:        &state.Action{Kind: "test", Data: `{"test": true}`, ProcessAfter: 10},
			wantStatus:    http.StatusCreated,
			expectedError: `request failed: Post "http://127.0.0.1:8080/api/action/store": dial tcp 127.0.0.1:8080: connect: connection refused`,
		},
		{
			action: &state.Action{Kind: "test", Data: `{"test": true}`, ProcessAfter: 10},
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantStatus:    http.StatusCreated,
			expectedError: "server returned status 500: ",
		},
		{
			action: &state.Action{Kind: "json_post", Data: `{"url": "https://api.example.com/alert"}`, ProcessAfter: 24, MinInterval: 6, Comment: "Critical alert"},
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "POST", r.Method)
				require.Equal(t, "/api/action/store", r.URL.Path)
				w.WriteHeader(http.StatusCreated)
			},
			wantStatus: http.StatusCreated,
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

		err := sendAction(cmd, test.action, "store", test.wantStatus)

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

func TestSendTestAction(t *testing.T) {
	tests := []struct {
		mockHandler   http.HandlerFunc
		expectedError string
	}{
		{
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectedError: "server returned status 500: ",
		},
		{
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "/api/action/test", r.URL.Path)
				w.WriteHeader(http.StatusOK)
			},
		},
	}

	for _, test := range tests {
		fakeServer := httptest.NewServer(test.mockHandler)
		defer fakeServer.Close()

		originalGetClient := getClient
		defer func() { getClient = originalGetClient }()
		getClient = func(*cli.Command) *http.Client {
			return fakeServer.Client()
		}

		cmd := createCLI()
		cmd.Set("server", fakeServer.URL)

		err := sendTestAction(cmd, &state.Action{Kind: "test", Data: `{"test": true}`, ProcessAfter: 10})

		if test.expectedError == "" {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), test.expectedError)
		}
	}
}

func TestProcessActionsFromFile(t *testing.T) {
	twoActionsYAML := `- kind: test
  data: '{"test": true}'
  process_after: 10
- kind: webhook
  data: '{"url": "https://example.com"}'
  process_after: 24
`
	tests := []struct {
		inputFile     string
		fileContent   string
		failFirstSend bool
		expectedError string
		expectedSent  int
	}{
		{
			inputFile:     "/nonexistent/actions.yaml",
			expectedError: "unable to load actions from file",
		},
		{
			inputFile:     "testdata/process-empty.yaml",
			fileContent:   "",
			expectedError: "no actions found in file",
		},
		{
			inputFile:     "testdata/process-partial-failure.yaml",
			fileContent:   twoActionsYAML,
			failFirstSend: true,
			expectedError: "1 of 2 actions failed",
			expectedSent:  2,
		},
		{
			inputFile:    "testdata/process-all-success.yaml",
			fileContent:  twoActionsYAML,
			expectedSent: 2,
		},
	}

	os.MkdirAll("testdata", 0755)
	defer os.RemoveAll("testdata")

	for _, test := range tests {
		if test.fileContent != "" || test.inputFile == "testdata/process-empty.yaml" {
			err := os.WriteFile(test.inputFile, []byte(test.fileContent), 0644)
			require.NoError(t, err)
		}

		sent := 0
		send := func(cmd *cli.Command, a *state.Action) error {
			sent++
			if test.failFirstSend && sent == 1 {
				return fmt.Errorf("forced send error")
			}
			return nil
		}

		err := processActionsFromFile(nil, test.inputFile, send)

		if test.expectedError != "" {
			require.Error(t, err)
			require.Contains(t, err.Error(), test.expectedError)
		} else {
			require.NoError(t, err)
		}
		require.Equal(t, test.expectedSent, sent)
	}
}
