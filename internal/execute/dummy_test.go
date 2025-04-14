package execute

import (
	"fmt"
	"testing"

	"dmh/internal/state"

	"github.com/stretchr/testify/require"
)

func TestDummyRun(t *testing.T) {
	tests := []struct {
		inputPlugin   *ExecuteDummy
		expectedError error
	}{
		{
			inputPlugin:   &ExecuteDummy{FailOnRun: true},
			expectedError: fmt.Errorf("FailOnRun error"),
		},
		{
			inputPlugin: &ExecuteDummy{FailOnRun: false},
		},
	}
	for _, test := range tests {
		plugin := test.inputPlugin
		err := plugin.Run()
		require.Equal(t, test.expectedError, err)
	}
}

func TestDummyPopulate(t *testing.T) {
	tests := []struct {
		inputPlugin   *ExecuteDummy
		inputAction   *state.Action
		expectedError string
	}{
		{
			inputPlugin:   &ExecuteDummy{},
			inputAction:   &state.Action{Kind: "dummy", Data: `{"broken"`},
			expectedError: "unexpected end of JSON input",
		},
		{
			inputPlugin:   &ExecuteDummy{},
			inputAction:   &state.Action{Kind: "dummy", Data: `{"fail_on_populate": true}`},
			expectedError: "FailOnPopulate error",
		},
		{
			inputPlugin:   &ExecuteDummy{},
			inputAction:   &state.Action{Kind: "dummy", Data: `{}`},
			expectedError: "message must be provided",
		},
		{
			inputPlugin: &ExecuteDummy{},
			inputAction: &state.Action{Kind: "dummy", Data: `{"message": "test"}`},
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

func TestDummyPopulateConfig(t *testing.T) {
	tests := []struct {
		inputPlugin   *ExecuteDummy
		expectedError error
	}{
		{
			inputPlugin:   &ExecuteDummy{FailOnPopulateConfig: true},
			expectedError: fmt.Errorf("FailOnPopulateConfig error"),
		},
		{
			inputPlugin: &ExecuteDummy{FailOnPopulateConfig: false},
		},
	}
	for _, test := range tests {
		plugin := test.inputPlugin
		err := plugin.PopulateConfig(&Execute{})
		require.Equal(t, test.expectedError, err)
	}
}
