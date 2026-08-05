package execute

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"testing"

	"dmh/internal/state"

	"github.com/stretchr/testify/require"
)

func TestExecuteExecRun(t *testing.T) {
	t.Setenv("EXEC_TEST_ISOLATION_PROBE", "visible-from-parent")

	tests := []struct {
		inputPlugin   func() *ExecuteExec
		expectedError string
	}{
		{
			inputPlugin: func() *ExecuteExec {
				return &ExecuteExec{Path: "/bin/sh", Args: []string{"-c", "exit 0"}, Timeout: 5, ExitCode: []int{0}}
			},
		},
		{
			inputPlugin: func() *ExecuteExec {
				return &ExecuteExec{Path: "/bin/sh", Args: []string{"-c", "exit 1"}, Timeout: 5, ExitCode: []int{0}}
			},
			expectedError: "exec /bin/sh exited with unexpected code 1",
		},
		{
			inputPlugin: func() *ExecuteExec {
				return &ExecuteExec{Path: "/bin/sh", Args: []string{"-c", "sleep 5"}, Timeout: 1, ExitCode: []int{0}}
			},
			expectedError: "exec /bin/sh timed out after 1s",
		},
		{
			inputPlugin: func() *ExecuteExec {
				return &ExecuteExec{Path: "/nonexistent/binary/for/testing", Timeout: 5, ExitCode: []int{0}}
			},
			expectedError: "unable to run /nonexistent/binary/for/testing:",
		},
		{
			inputPlugin: func() *ExecuteExec {
				return &ExecuteExec{Path: "/bin/sh", Args: []string{"-c", "echo hello world"}, Timeout: 5, ExitCode: []int{0}, OutputRegex: "hello"}
			},
		},
		{
			inputPlugin: func() *ExecuteExec {
				return &ExecuteExec{Path: "/bin/sh", Args: []string{"-c", "echo hello world"}, Timeout: 5, ExitCode: []int{0}, OutputRegex: "goodbye"}
			},
			expectedError: "exec /bin/sh output did not match output_regex",
		},
		{
			inputPlugin: func() *ExecuteExec {
				return &ExecuteExec{Path: "/bin/sh", Args: []string{"-c", "echo hello"}, Timeout: 5, ExitCode: []int{0}, OutputRegex: "[invalid("}
			},
			expectedError: "output_regex is not a valid regex: error parsing regexp: missing closing ]: `[invalid(`",
		},
		{
			inputPlugin: func() *ExecuteExec {
				return &ExecuteExec{Path: "/bin/sh", Args: []string{"-c", `test -z "$EXEC_TEST_ISOLATION_PROBE"`}, Timeout: 5, ExitCode: []int{0}}
			},
		},
		{
			inputPlugin: func() *ExecuteExec {
				return &ExecuteExec{
					Path: "/bin/sh", Args: []string{"-c", `test "$EXEC_TEST_ENV" = "from-env"`}, Timeout: 5, ExitCode: []int{0},
					Env: map[string]string{"EXEC_TEST_ENV": "from-env"},
				}
			},
		},
		{
			inputPlugin: func() *ExecuteExec {
				return &ExecuteExec{
					Path: "/bin/sh", Args: []string{"-c", `test "$EXEC_TEST_ISOLATION_PROBE" = "visible-from-parent"`}, Timeout: 5, ExitCode: []int{0},
					InheritEnv: true,
				}
			},
		},
	}
	for _, test := range tests {
		plugin := test.inputPlugin()
		err := plugin.Run()
		if test.expectedError == "" {
			require.Nil(t, err)
		} else {
			require.NotNil(t, err)
			require.Contains(t, err.Error(), test.expectedError)
		}
	}
}

func TestExecuteExecPopulate(t *testing.T) {
	tests := []struct {
		inputPlugin   *ExecuteExec
		inputAction   *state.Action
		expectedError string
		expectedPath  string
	}{
		{
			inputPlugin:   &ExecuteExec{},
			inputAction:   &state.Action{Kind: "exec", Data: `{"broken"`},
			expectedError: "unexpected end of JSON input",
			expectedPath:  "",
		},
		{
			inputPlugin:   &ExecuteExec{},
			inputAction:   &state.Action{Kind: "exec", Data: `{"path": "relative/path"}`},
			expectedError: "path must be an absolute path",
			expectedPath:  "relative/path",
		},
		{
			inputPlugin:   &ExecuteExec{config: ExecConfig{AllowedPaths: []string{"/other/path"}}},
			inputAction:   &state.Action{Kind: "exec", Data: `{"path": "/usr/local/bin/script.sh"}`},
			expectedError: "path /usr/local/bin/script.sh is not permitted by execute.plugin.exec config",
			expectedPath:  "/usr/local/bin/script.sh",
		},
		{
			inputPlugin:   &ExecuteExec{config: ExecConfig{AllowedPaths: []string{"/usr/local/bin/"}, MaxTimeout: 300}},
			inputAction:   &state.Action{Kind: "exec", Data: `{"path": "/usr/local/bin/../../bin/sh", "timeout": 30, "exit_code": [0]}`},
			expectedError: "path /usr/bin/sh is not permitted by execute.plugin.exec config",
			expectedPath:  "/usr/bin/sh",
		},
		{
			inputPlugin:  &ExecuteExec{config: ExecConfig{AllowedPaths: []string{"/usr/local/bin/"}, MaxTimeout: 300}},
			inputAction:  &state.Action{Kind: "exec", Data: `{"path": "/usr/local/bin/../bin/script.sh", "timeout": 30, "exit_code": [0]}`},
			expectedPath: "/usr/local/bin/script.sh",
		},
		{
			inputPlugin:  &ExecuteExec{config: ExecConfig{AllowedPaths: []string{"/usr/local/bin/script.sh"}, MaxTimeout: 300}},
			inputAction:  &state.Action{Kind: "exec", Data: `{"path": "/usr/local/bin/./script.sh", "timeout": 30, "exit_code": [0]}`},
			expectedPath: "/usr/local/bin/script.sh",
		},
		{
			inputPlugin:   &ExecuteExec{config: ExecConfig{AllowedPaths: []string{"/usr/local/bin/script.sh"}, MaxTimeout: 300}},
			inputAction:   &state.Action{Kind: "exec", Data: `{"path": "/usr/local/bin/script.sh"}`},
			expectedError: "timeout must be provided",
			expectedPath:  "/usr/local/bin/script.sh",
		},
		{
			inputPlugin:   &ExecuteExec{config: ExecConfig{AllowedPaths: []string{"/usr/local/bin/script.sh"}, MaxTimeout: 300}},
			inputAction:   &state.Action{Kind: "exec", Data: `{"path": "/usr/local/bin/script.sh", "timeout": 301}`},
			expectedError: "timeout must not exceed 300 seconds",
			expectedPath:  "/usr/local/bin/script.sh",
		},
		{
			inputPlugin:   &ExecuteExec{config: ExecConfig{AllowedPaths: []string{"/usr/local/bin/script.sh"}, MaxTimeout: 60}},
			inputAction:   &state.Action{Kind: "exec", Data: `{"path": "/usr/local/bin/script.sh", "timeout": 61}`},
			expectedError: "timeout must not exceed 60 seconds",
			expectedPath:  "/usr/local/bin/script.sh",
		},
		{
			inputPlugin:   &ExecuteExec{config: ExecConfig{AllowedPaths: []string{"/usr/local/bin/script.sh"}, MaxTimeout: 300}},
			inputAction:   &state.Action{Kind: "exec", Data: `{"path": "/usr/local/bin/script.sh", "timeout": 30}`},
			expectedError: "exit_code must be provided",
			expectedPath:  "/usr/local/bin/script.sh",
		},
		{
			inputPlugin:   &ExecuteExec{config: ExecConfig{AllowedPaths: []string{"/usr/local/bin/script.sh"}, MaxTimeout: 300}},
			inputAction:   &state.Action{Kind: "exec", Data: `{"path": "/usr/local/bin/script.sh", "timeout": 30, "exit_code": [0], "output_regex": "[invalid("}`},
			expectedError: "output_regex is not a valid regex: error parsing regexp: missing closing ]: `[invalid(`",
			expectedPath:  "/usr/local/bin/script.sh",
		},
		{
			inputPlugin:  &ExecuteExec{config: ExecConfig{AllowedPaths: []string{"/usr/local/bin/script.sh"}, MaxTimeout: 300}},
			inputAction:  &state.Action{Kind: "exec", Data: `{"path": "/usr/local/bin/script.sh", "args": ["--full"], "timeout": 30, "exit_code": [0], "output_regex": "^ok$"}`},
			expectedPath: "/usr/local/bin/script.sh",
		},
	}
	for _, test := range tests {
		plugin := test.inputPlugin
		err := plugin.populate(test.inputAction)
		if test.expectedError == "" {
			require.Nil(t, err)
		} else {
			require.NotNil(t, err)
			require.Equal(t, test.expectedError, err.Error())
		}
		require.Equal(t, test.expectedPath, plugin.Path)
	}
}

func TestExecuteExecPopulateConfig(t *testing.T) {
	tests := []struct {
		inputExecute   *Execute
		expectedError  error
		expectedConfig ExecConfig
	}{
		{
			inputExecute:   &Execute{execConf: ExecConfig{AllowedPaths: []string{"relative/path"}}},
			expectedError:  fmt.Errorf("allowed_paths entries must be absolute paths"),
			expectedConfig: ExecConfig{AllowedPaths: []string{"relative/path"}},
		},
		{
			inputExecute:   &Execute{execConf: ExecConfig{AllowedPaths: []string{"/usr/local/bin/script.sh"}}},
			expectedConfig: ExecConfig{AllowedPaths: []string{"/usr/local/bin/script.sh"}, MaxTimeout: 300},
		},
	}
	for _, test := range tests {
		plugin := &ExecuteExec{}
		err := plugin.populateConfig(test.inputExecute)
		require.Equal(t, test.expectedError, err)
		require.Equal(t, test.expectedConfig, plugin.config)
	}
}

func TestExecConfigValidate(t *testing.T) {
	tests := []struct {
		inputConfig         ExecConfig
		expectedError       error
		expectedConfig      ExecConfig
		expectedLogContains string
	}{
		{
			inputConfig:    ExecConfig{AllowedPaths: []string{"relative/path"}},
			expectedError:  fmt.Errorf("allowed_paths entries must be absolute paths"),
			expectedConfig: ExecConfig{AllowedPaths: []string{"relative/path"}},
		},
		{
			inputConfig:    ExecConfig{AllowedPaths: []string{"/path", "relative/path"}},
			expectedError:  fmt.Errorf("allowed_paths entries must be absolute paths"),
			expectedConfig: ExecConfig{AllowedPaths: []string{"/path", "relative/path"}},
		},
		{
			inputConfig:    ExecConfig{DeniedPaths: []string{"relative/path"}},
			expectedError:  fmt.Errorf("denied_paths entries must be absolute paths"),
			expectedConfig: ExecConfig{DeniedPaths: []string{"relative/path"}},
		},
		{
			inputConfig:    ExecConfig{DeniedPaths: []string{"/path", "relative/path"}},
			expectedError:  fmt.Errorf("denied_paths entries must be absolute paths"),
			expectedConfig: ExecConfig{DeniedPaths: []string{"/path", "relative/path"}},
		},
		{
			inputConfig:         ExecConfig{},
			expectedConfig:      ExecConfig{MaxTimeout: 300},
			expectedLogContains: "execute.plugin.exec has no allowed_paths or denied_paths configured",
		},
		{
			inputConfig:    ExecConfig{AllowedPaths: []string{"/usr/local/bin/script.sh"}},
			expectedConfig: ExecConfig{AllowedPaths: []string{"/usr/local/bin/script.sh"}, MaxTimeout: 300},
		},
		{
			inputConfig:    ExecConfig{AllowedPaths: []string{"/usr/local/bin/script.sh"}, MaxTimeout: 600},
			expectedConfig: ExecConfig{AllowedPaths: []string{"/usr/local/bin/script.sh"}, MaxTimeout: 600},
		},
	}
	for _, test := range tests {
		buf := &bytes.Buffer{}
		log.SetOutput(buf)

		err := test.inputConfig.Validate()

		log.SetOutput(os.Stderr)

		require.Equal(t, test.expectedError, err)
		require.Equal(t, test.expectedConfig, test.inputConfig)
		if test.expectedLogContains != "" {
			require.Contains(t, buf.String(), test.expectedLogContains)
		}
	}
}

func TestPathMatches(t *testing.T) {
	tests := []struct {
		inputEntries  []string
		inputPath     string
		expectedMatch bool
	}{
		{inputEntries: []string{}, inputPath: "/usr/local/bin/script.sh"},
		{inputEntries: []string{"/usr/local/bin/script.sh"}, inputPath: "/usr/local/bin/script.sh", expectedMatch: true},
		{inputEntries: []string{"/usr/local/bin/other.sh"}, inputPath: "/usr/local/bin/script.sh"},
		{inputEntries: []string{"/usr/local/bin/"}, inputPath: "/usr/local/bin/script.sh", expectedMatch: true},
		{inputEntries: []string{"/usr/local/bin/"}, inputPath: "/usr/local/binary/script.sh"},
		{inputEntries: []string{"/opt/"}, inputPath: "/usr/local/bin/script.sh"},
	}
	for _, test := range tests {
		require.Equal(t, test.expectedMatch, pathMatches(test.inputEntries, test.inputPath))
	}
}

func TestPathIsPermitted(t *testing.T) {
	tests := []struct {
		inputConfig    ExecConfig
		inputPath      string
		expectedResult bool
	}{
		{
			inputConfig:    ExecConfig{},
			inputPath:      "/usr/local/bin/script.sh",
			expectedResult: true,
		},
		{
			inputConfig:    ExecConfig{DeniedPaths: []string{"/usr/local/bin/script.sh"}},
			inputPath:      "/usr/local/bin/script.sh",
			expectedResult: false,
		},
		{
			inputConfig:    ExecConfig{DeniedPaths: []string{"/usr/local/bin/other.sh"}},
			inputPath:      "/usr/local/bin/script.sh",
			expectedResult: true,
		},
		{
			inputConfig:    ExecConfig{AllowedPaths: []string{"/usr/local/bin/script.sh"}},
			inputPath:      "/usr/local/bin/script.sh",
			expectedResult: true,
		},
		{
			inputConfig:    ExecConfig{AllowedPaths: []string{"/usr/local/bin/other.sh"}},
			inputPath:      "/usr/local/bin/script.sh",
			expectedResult: false,
		},
		{
			inputConfig: ExecConfig{
				AllowedPaths: []string{"/usr/local/bin/"},
				DeniedPaths:  []string{"/usr/local/bin/script.sh"},
			},
			inputPath:      "/usr/local/bin/script.sh",
			expectedResult: false,
		},
	}
	for _, test := range tests {
		require.Equal(t, test.expectedResult, pathIsPermitted(test.inputConfig, test.inputPath))
	}
}

func TestExecOutputBufferWrite(t *testing.T) {
	tests := []struct {
		inputLimit    int
		inputWrites   []string
		expectedBytes string
	}{
		{
			inputLimit:    100,
			inputWrites:   []string{"hello", " world"},
			expectedBytes: "hello world",
		},
		{
			inputLimit:    5,
			inputWrites:   []string{"hello", " world"},
			expectedBytes: "hello",
		},
		{
			inputLimit:    3,
			inputWrites:   []string{"he", "llo"},
			expectedBytes: "hel",
		},
		{
			inputLimit:    0,
			inputWrites:   []string{"hello"},
			expectedBytes: "",
		},
	}
	for _, test := range tests {
		w := &execOutputBuffer{limit: test.inputLimit}
		for _, chunk := range test.inputWrites {
			n, err := w.Write([]byte(chunk))
			require.Nil(t, err)
			require.Equal(t, len(chunk), n)
		}
		require.Equal(t, test.expectedBytes, w.buf.String())
	}
}
