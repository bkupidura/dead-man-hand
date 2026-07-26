package execute

import (
	"fmt"
	"testing"

	"dmh/internal/state"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	tests := []struct {
		inputOptions    *Options
		expectedError   error
		expectedExecute func() ExecuteInterface
	}{
		{
			inputOptions: &Options{
				BulkSMSConf: BulkSMSConfig{
					Token: BulkSMSToken{
						ID:     "id",
						Secret: "secret",
					},
				},
				MailConf: MailConfig{
					From:      "from@address",
					Username:  "username",
					Password:  "password",
					Server:    "server",
					TLSPolicy: "no_tls",
				},
			},
			expectedExecute: func() ExecuteInterface {
				return &Execute{
					bulkSMSConf: BulkSMSConfig{
						Token: BulkSMSToken{
							ID:     "id",
							Secret: "secret",
						},
					},
					mailConf: MailConfig{
						From:      "from@address",
						Username:  "username",
						Password:  "password",
						Server:    "server",
						TLSPolicy: "no_tls",
					},
				}
			},
		},
		{
			inputOptions: &Options{
				SignedURLSecret: "test-secret",
				SignedURLTTL:    24,
			},
			expectedExecute: func() ExecuteInterface {
				return &Execute{
					signedURLSecret: "test-secret",
					signedURLTTL:    24,
				}
			},
		},
	}
	for _, test := range tests {
		e, err := New(test.inputOptions)
		require.Equal(t, test.expectedError, err)
		expectedE := test.expectedExecute()
		require.Equal(t, expectedE, e)
	}
}

func TestRun(t *testing.T) {
	tests := []struct {
		inputExecute  *Execute
		inputAction   *state.Action
		expectedError error
	}{
		{
			inputExecute:  &Execute{},
			inputAction:   &state.Action{Kind: "dummy", Data: `{"fail_on_run": false, "fail_on_populate": true, "fail_on_populate_config": false}`},
			expectedError: fmt.Errorf("FailOnPopulate error"),
		},
		{
			inputExecute:  &Execute{},
			inputAction:   &state.Action{Kind: "dummy", Data: `{"fail_on_run": false, "fail_on_populate": false, "fail_on_populate_config": true, "message": "test"}`},
			expectedError: fmt.Errorf("FailOnPopulateConfig error"),
		},
		{
			inputExecute:  &Execute{},
			inputAction:   &state.Action{Kind: "dummy", Data: `{"fail_on_run": true, "fail_on_populate": false, "fail_on_populate_config": false, "message": "test"}`},
			expectedError: fmt.Errorf("FailOnRun error"),
		},
		{
			inputExecute: &Execute{},
			inputAction:  &state.Action{Kind: "dummy", Data: `{"fail_on_run": false, "fail_on_populate": false, "fail_on_populate_config": false, "message": "test"}`},
		},
	}
	for _, test := range tests {
		err := test.inputExecute.Run(test.inputAction)
		require.Equal(t, test.expectedError, err)
	}
}

func TestPrepare(t *testing.T) {
	tests := []struct {
		inputExecute  *Execute
		inputAction   *state.Action
		expectedError error
		expectedData  executeData
	}{
		{
			inputExecute: &Execute{},
			inputAction: &state.Action{
				Kind: "json_post", Data: `{"url":"", "success_code": [200], "data": {"test": "value"}}`,
			},
			expectedError: fmt.Errorf("url must be provided"),
		},
		{
			inputExecute: &Execute{},
			inputAction: &state.Action{
				Kind: "json_post", Data: `{"url":"test", "success_code": [200], "data": {"test": "value"}}`,
			},
			expectedData: &ExecuteJSONPost{
				URL: "test", SuccessCode: []int{200}, Data: map[string]any{"test": "value"},
			},
		},
		{
			inputExecute: &Execute{
				bulkSMSConf: BulkSMSConfig{
					Token: BulkSMSToken{ID: "id", Secret: "secret"},
				},
			},
			inputAction: &state.Action{
				Kind: "bulksms", Data: `{"message": "", "destination": ["11111"]}`,
			},
			expectedError: fmt.Errorf("message must be provided"),
		},
		{
			inputExecute: &Execute{},
			inputAction: &state.Action{
				Kind: "bulksms", Data: `{"message": "test", "destination": ["11111"]}`,
			},
			expectedError: fmt.Errorf("config token id and secret must be provided"),
		},
		{
			inputExecute: &Execute{
				bulkSMSConf: BulkSMSConfig{
					Token: BulkSMSToken{ID: "id", Secret: "secret"},
				},
			},
			inputAction: &state.Action{
				Kind: "bulksms", Data: `{"message": "test", "destination": ["11111"]}`,
			},
			expectedData: &ExecuteBulkSMS{
				Message: "test", Destination: []string{"11111"},
				config: BulkSMSConfig{
					Token:        BulkSMSToken{ID: "id", Secret: "secret"},
					RoutingGroup: "STANDARD",
				},
			},
		},
		{
			inputExecute: &Execute{
				mailConf: MailConfig{
					From:      "from@address",
					Username:  "username",
					Password:  "password",
					Server:    "server",
					TLSPolicy: "no_tls",
				},
			},
			inputAction: &state.Action{
				Kind: "mail", Data: `{"message": "", "destination": ["test@test.com"], "subject": "test"}`,
			},
			expectedError: fmt.Errorf("message must be provided"),
		},
		{
			inputExecute: &Execute{},
			inputAction: &state.Action{
				Kind: "mail", Data: `{"message": "test", "destination": ["test@test.com"], "subject": "test"}`,
			},
			expectedError: fmt.Errorf("server must be provided"),
		},
		{
			inputExecute: &Execute{
				mailConf: MailConfig{
					From:      "from@address",
					Username:  "username",
					Password:  "password",
					Server:    "server",
					TLSPolicy: "no_tls",
				},
			},
			inputAction: &state.Action{
				Kind: "mail", Data: `{"message": "test", "destination": ["test@test.com"], "subject": "test"}`,
			},
			expectedData: &ExecuteMail{
				Message: "test", Destination: []string{"test@test.com"}, Subject: "test",
				config: MailConfig{
					From:      "from@address",
					Username:  "username",
					Password:  "password",
					Server:    "server",
					TLSPolicy: "no_tls",
				},
			},
		},
		{
			inputExecute: &Execute{},
			inputAction: &state.Action{
				Kind: "dummy", Data: `{"message": ""}`,
			},
			expectedError: fmt.Errorf("message must be provided"),
		},
		{
			inputExecute: &Execute{},
			inputAction: &state.Action{
				Kind: "dummy", Data: `{"message": "test"}`,
			},
			expectedData: &ExecuteDummy{
				Message: "test", FailOnRun: false, FailOnPopulate: false, FailOnPopulateConfig: false,
			},
		},
		{
			inputExecute: &Execute{},
			inputAction: &state.Action{
				Kind: "dummy", Data: `{"fail_on_populate_config": true, "message": "test"}`,
			},
			expectedError: fmt.Errorf("FailOnPopulateConfig error"),
		},
		{
			inputExecute: &Execute{
				execConf: ExecConfig{AllowedPaths: []string{"relative/path"}},
			},
			inputAction: &state.Action{
				Kind: "exec", Data: `{"path": "/usr/local/bin/script.sh", "timeout": 10, "exit_code": [0]}`,
			},
			expectedError: fmt.Errorf("allowed_paths entries must be absolute paths"),
		},
		{
			inputExecute: &Execute{
				execConf: ExecConfig{AllowedPaths: []string{"/other/path"}},
			},
			inputAction: &state.Action{
				Kind: "exec", Data: `{"path": "/usr/local/bin/script.sh", "timeout": 10, "exit_code": [0]}`,
			},
			expectedError: fmt.Errorf("path /usr/local/bin/script.sh is not permitted by execute.plugin.exec config"),
		},
		{
			inputExecute: &Execute{
				execConf: ExecConfig{AllowedPaths: []string{"/usr/local/bin/script.sh"}},
			},
			inputAction: &state.Action{
				Kind: "exec", Data: `{"path": "/usr/local/bin/script.sh", "args": ["--full"], "timeout": 10, "exit_code": [0]}`,
			},
			expectedData: &ExecuteExec{
				Path: "/usr/local/bin/script.sh", Args: []string{"--full"}, Timeout: 10, ExitCode: []int{0},
				config: ExecConfig{AllowedPaths: []string{"/usr/local/bin/script.sh"}, MaxTimeout: 300},
			},
		},
		{
			inputExecute: &Execute{},
			inputAction: &state.Action{
				Kind: "non-existing", Data: `{}`,
			},
			expectedError: fmt.Errorf("unknown kind non-existing"),
		},
	}
	for _, test := range tests {
		ed, err := test.inputExecute.prepare(test.inputAction)
		require.Equal(t, test.expectedError, err)
		require.Equal(t, test.expectedData, ed)
	}
}

func TestCheckAction(t *testing.T) {
	tests := []struct {
		inputExecute  *Execute
		inputAction   *state.Action
		expectedError error
	}{
		{
			inputExecute:  &Execute{},
			inputAction:   &state.Action{Kind: "dummy", Data: `{"fail_on_run": false, "fail_on_populate": true, "fail_on_populate_config": false}`},
			expectedError: fmt.Errorf("FailOnPopulate error"),
		},
		{
			inputExecute:  &Execute{},
			inputAction:   &state.Action{Kind: "dummy", Data: `{"fail_on_run": false, "fail_on_populate": false, "fail_on_populate_config": true, "message": "test"}`},
			expectedError: fmt.Errorf("FailOnPopulateConfig error"),
		},
		{
			inputExecute: &Execute{},
			inputAction:  &state.Action{Kind: "dummy", Data: `{"fail_on_run": true, "fail_on_populate": false, "fail_on_populate_config": false, "message": "test"}`},
		},
		{
			inputExecute:  &Execute{},
			inputAction:   &state.Action{Kind: "non-existing", Data: `{}`},
			expectedError: fmt.Errorf("unknown kind non-existing"),
		},
	}
	for _, test := range tests {
		err := test.inputExecute.CheckAction(test.inputAction)
		require.Equal(t, test.expectedError, err)
	}
}
