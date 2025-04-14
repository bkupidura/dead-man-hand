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

func TestUnmarshalActionData(t *testing.T) {
	tests := []struct {
		inputAction   *state.Action
		expectedError error
		expectedData  ExecuteData
	}{
		{
			inputAction: &state.Action{
				Kind: "json_post", Data: `{"url":"", "success_code": [200], "data": {"test": "value"}}`,
			},
			expectedError: fmt.Errorf("url must be provided"),
			expectedData: &ExecuteJSONPost{
				URL: "", SuccessCode: []int{200}, Data: map[string]interface{}{"test": "value"},
			},
		},
		{
			inputAction: &state.Action{
				Kind: "json_post", Data: `{"url":"test", "success_code": [200], "data": {"test": "value"}}`,
			},
			expectedData: &ExecuteJSONPost{
				URL: "test", SuccessCode: []int{200}, Data: map[string]interface{}{"test": "value"},
			},
		},
		{
			inputAction: &state.Action{
				Kind: "bulksms", Data: `{"message": "", "destination": ["11111"]}`,
			},
			expectedError: fmt.Errorf("message must be provided"),
			expectedData: &ExecuteBulkSMS{
				Message: "", Destination: []string{"11111"},
			},
		},
		{
			inputAction: &state.Action{
				Kind: "bulksms", Data: `{"message": "test", "destination": ["11111"]}`,
			},
			expectedData: &ExecuteBulkSMS{
				Message: "test", Destination: []string{"11111"},
			},
		},
		{
			inputAction: &state.Action{
				Kind: "mail", Data: `{"message": "", "destination": ["test@test.com"], "subject": "test"}`,
			},
			expectedError: fmt.Errorf("message must be provided"),
			expectedData: &ExecuteMail{
				Message: "", Destination: []string{"test@test.com"}, Subject: "test",
			},
		},
		{
			inputAction: &state.Action{
				Kind: "mail", Data: `{"message": "test", "destination": ["test@test.com"], "subject": "test"}`,
			},
			expectedData: &ExecuteMail{
				Message: "test", Destination: []string{"test@test.com"}, Subject: "test",
			},
		},
		{
			inputAction: &state.Action{
				Kind: "dummy", Data: `{"message": ""}`,
			},
			expectedError: fmt.Errorf("message must be provided"),
			expectedData: &ExecuteDummy{
				Message: "", FailOnRun: false, FailOnPopulate: false, FailOnPopulateConfig: false,
			},
		},
		{
			inputAction: &state.Action{
				Kind: "dummy", Data: `{"message": "test"}`,
			},
			expectedData: &ExecuteDummy{
				Message: "test", FailOnRun: false, FailOnPopulate: false, FailOnPopulateConfig: false,
			},
		},
		{
			inputAction: &state.Action{
				Kind: "non-existing", Data: `{}`,
			},
			expectedError: fmt.Errorf("unknown kind non-existing"),
		},
	}
	for _, test := range tests {
		ed, err := UnmarshalActionData(test.inputAction)
		require.Equal(t, test.expectedError, err)
		require.Equal(t, test.expectedData, ed)
	}
}
