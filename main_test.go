//go:build !integration
// +build !integration

package main

import (
	"fmt"
	"os"
	"testing"
	"time"

	"dmh/internal/execute"
	"dmh/internal/state"
	"dmh/internal/vault"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockState struct {
	mock.Mock
}

func (m *mockState) UpdateLastSeen() {
	m.Called()
}

func (m *mockState) GetLastSeen() time.Time {
	args := m.Called()
	return args.Get(0).(time.Time)
}

func (m *mockState) GetActions() []*state.EncryptedAction {
	args := m.Called()
	return args.Get(0).([]*state.EncryptedAction)
}

func (m *mockState) AddAction(action *state.Action) error {
	args := m.Called(action)
	return args.Error(0)
}

func (m *mockState) GetAction(uuid string) (*state.EncryptedAction, int) {
	args := m.Called(uuid)
	if args.Get(0) == nil {
		return nil, args.Int(1)
	}
	return args.Get(0).(*state.EncryptedAction), args.Int(1)
}

func (m *mockState) DeleteAction(uuid string) error {
	args := m.Called(uuid)
	return args.Error(0)
}

func (m *mockState) MarkActionAsProcessed(uuid string) error {
	args := m.Called(uuid)
	return args.Error(0)
}

func (m *mockState) DecryptAction(uuid string) (*state.Action, error) {
	args := m.Called(uuid)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*state.Action), args.Error(1)
}

func (m *mockState) UpdateActionLastRun(uuid string) error {
	args := m.Called(uuid)
	return args.Error(0)
}

func (m *mockState) GetActionLastRun(uuid string) (time.Time, error) {
	args := m.Called(uuid)
	return args.Get(0).(time.Time), args.Error(1)
}

type mockExecute struct {
	mock.Mock
}

func (e *mockExecute) Run(action *state.Action) error {
	args := e.Called(action)
	return args.Error(0)
}

func TestReadingConfig(t *testing.T) {
	tests := []struct {
		inputConfig  func()
		envConfigVar string
		mockStateNew func(*state.Options) (state.StateInterface, error)
	}{
		{
			inputConfig: func() {
			},
		},
		{
			inputConfig: func() {
			},
			envConfigVar: "non-existing.yaml",
		},
		{
			inputConfig: func() {
				f, err := os.Create("existing.yaml")
				require.Nil(t, err)
				defer f.Close()
				_, err = f.WriteString(`
                                components: ['dmh']
                                state:
                                  file: test.yaml
                                action:
                                  process_unit: minute
                                remote_vault:
                                  url: http://127.0.0.1:8080
                                  client_uuid: uuid`)
				require.Nil(t, err)
			},
			envConfigVar: "existing.yaml",
			mockStateNew: func(*state.Options) (state.StateInterface, error) {
				return nil, fmt.Errorf("mockStateNew error")
			},
		},
	}
	for _, test := range tests {
		test.inputConfig()
		if test.envConfigVar != "" {
			err := os.Setenv("DMH_CONFIG_FILE", test.envConfigVar)
			require.Nil(t, err)
			defer os.Remove(test.envConfigVar)
		} else {
			os.Unsetenv("DMH_CONFIG_FILE")
		}
		stateNew = state.New
		if test.mockStateNew != nil {
			stateNew = test.mockStateNew
			defer func() {
				stateNew = state.New
			}()
		}
		require.Panics(t, main)
	}
}

func TestActionProcessUnit(t *testing.T) {
	configFile := "test_action_process_unit.yaml"
	tests := []struct {
		inputConfig               func()
		expectedActionProcessUnit time.Duration
	}{
		{
			inputConfig: func() {
				f, err := os.Create(configFile)
				require.Nil(t, err)
				defer f.Close()
				_, err = f.WriteString(`
                                components: ['dmh']
                                state:
                                  file: test.yaml
                                action:
                                  process_unit: second
                                remote_vault:
                                  url: http://127.0.0.1:8080
                                  client_uuid: uuid`)
				require.Nil(t, err)
			},
			expectedActionProcessUnit: time.Second,
		},
		{
			inputConfig: func() {
				f, err := os.Create(configFile)
				require.Nil(t, err)
				defer f.Close()
				_, err = f.WriteString(`
                                components: ['dmh']
                                state:
                                  file: test.yaml
                                action:
                                  process_unit: minute
                                remote_vault:
                                  url: http://127.0.0.1:8080
                                  client_uuid: uuid`)
				require.Nil(t, err)
			},
			expectedActionProcessUnit: time.Minute,
		},
		{
			inputConfig: func() {
				f, err := os.Create(configFile)
				require.Nil(t, err)
				defer f.Close()
				_, err = f.WriteString(`
                                components: ['dmh']
                                state:
                                  file: test.yaml
                                action:
                                  process_unit: hour
                                remote_vault:
                                  url: http://127.0.0.1:8080
                                  client_uuid: uuid`)
				require.Nil(t, err)
			},
			expectedActionProcessUnit: time.Hour,
		},
		{
			inputConfig: func() {
				f, err := os.Create(configFile)
				require.Nil(t, err)
				defer f.Close()
				_, err = f.WriteString(`
                                components: ['dmh']
                                state:
                                  file: test.yaml
                                action:
                                  process_unit: wrong
                                remote_vault:
                                  url: http://127.0.0.1:8080
                                  client_uuid: uuid`)
				require.Nil(t, err)
			},
			expectedActionProcessUnit: time.Hour,
		},
		{
			inputConfig: func() {
				f, err := os.Create(configFile)
				require.Nil(t, err)
				defer f.Close()
				_, err = f.WriteString(`
                                components: ['dmh']
                                state:
                                  file: test.yaml
                                remote_vault:
                                  url: http://127.0.0.1:8080
                                  client_uuid: uuid`)
				require.Nil(t, err)
			},
			expectedActionProcessUnit: time.Hour,
		},
	}
	for _, test := range tests {
		test.inputConfig()
		err := os.Setenv("DMH_CONFIG_FILE", configFile)
		require.Nil(t, err)
		defer os.Remove(configFile)
		stateNew = func(*state.Options) (state.StateInterface, error) {
			return nil, fmt.Errorf("mockStateNew error")
		}
		defer func() {
			stateNew = state.New
		}()
		require.Panics(t, main)
		require.Equal(t, test.expectedActionProcessUnit, actionProcessUnit)
	}

}

func TestComponentsErrors(t *testing.T) {
	tests := []struct {
		mockStateNew   func(*state.Options) (state.StateInterface, error)
		mockExecuteNew func(*execute.Options) (execute.ExecuteInterface, error)
		mockVaultNew   func(*vault.Options) (vault.VaultInterface, error)
	}{
		{
			mockStateNew: func(*state.Options) (state.StateInterface, error) {
				return nil, fmt.Errorf("mockStateNew error")
			},
		},
		{
			mockExecuteNew: func(*execute.Options) (execute.ExecuteInterface, error) {
				return nil, fmt.Errorf("mockExecuteNew error")
			},
		},
		{
			mockVaultNew: func(*vault.Options) (vault.VaultInterface, error) {
				return nil, fmt.Errorf("mockVaultNew error")
			},
		},
	}
	f, err := os.Create("TestDMHComponentErrors.yaml")
	defer os.Remove("TestDMHComponentErrors.yaml")
	require.Nil(t, err)
	defer f.Close()
	_, err = f.WriteString(`
               components: ['dmh', 'vault']
               state:
                 file: test.yaml
               remote_vault:
                 url: http://test.com
                 client_uuid: uuid
               vault:
                 file: test2.yaml
                 key: key
             `)
	require.Nil(t, err)
	err = os.Setenv("DMH_CONFIG_FILE", "TestDMHComponentErrors.yaml")
	require.Nil(t, err)
	for _, test := range tests {
		stateNew = state.New
		if test.mockStateNew != nil {
			stateNew = test.mockStateNew
			defer func() {
				stateNew = state.New
			}()
		}
		executeNew = execute.New
		if test.mockExecuteNew != nil {
			executeNew = test.mockExecuteNew
			defer func() {
				executeNew = execute.New
			}()
		}
		vaultNew = vault.New
		if test.mockVaultNew != nil {
			vaultNew = test.mockVaultNew
			defer func() {
				vaultNew = vault.New
			}()
		}
		require.Panics(t, main)
	}
}

func TestDispatcher(t *testing.T) {
	tests := []struct {
		inputState           func() state.StateInterface
		inputExecute         func() execute.ExecuteInterface
		expectedActions      func() []*state.EncryptedAction
		expectedStateCalls   map[string]int
		expectedExecuteCalls map[string]int
	}{
		{
			inputState: func() state.StateInterface {
				s := new(mockState)
				s.On("GetActions").Return([]*state.EncryptedAction{})
				return s
			},
			inputExecute: func() execute.ExecuteInterface {
				e := new(mockExecute)
				return e
			},
			expectedStateCalls: map[string]int{
				"GetActions": 1,
			},
		},
		{
			inputState: func() state.StateInterface {
				s := new(mockState)
				s.On("GetActions").Return([]*state.EncryptedAction{
					{Processed: 2},
					{Processed: 2},
				})
				return s
			},
			inputExecute: func() execute.ExecuteInterface {
				e := new(mockExecute)
				return e
			},
			expectedStateCalls: map[string]int{
				"GetActions": 1,
			},
		},
		{
			inputState: func() state.StateInterface {
				mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
				require.Nil(t, err)
				s := new(mockState)
				s.On("GetActions").Return([]*state.EncryptedAction{
					{Processed: 2},
					{Processed: 2},
					{Processed: 0, UUID: "test-uuid", Action: state.Action{ProcessAfter: 10}},
				})
				s.On("GetLastSeen").Return(mockTime)
				s.On("GetActionLastRun", "test-uuid").Return(time.Time{}, fmt.Errorf("mockGetActionLastRun"))
				return s
			},
			inputExecute: func() execute.ExecuteInterface {
				e := new(mockExecute)
				return e
			},
			expectedStateCalls: map[string]int{
				"GetActions":       1,
				"GetLastSeen":      1,
				"GetActionLastRun": 1,
			},
		},
		{
			inputState: func() state.StateInterface {
				mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
				require.Nil(t, err)
				s := new(mockState)
				s.On("GetActions").Return([]*state.EncryptedAction{
					{Processed: 2},
					{Processed: 2},
					{Processed: 0, UUID: "test-uuid", Action: state.Action{ProcessAfter: 10}},
				})
				s.On("GetLastSeen").Return(mockTime)
				s.On("GetActionLastRun", "test-uuid").Return(mockTime, nil)
				s.On("DecryptAction", "test-uuid").Return(nil, fmt.Errorf("mockDecryptAction error"))
				return s
			},
			inputExecute: func() execute.ExecuteInterface {
				e := new(mockExecute)
				return e
			},
			expectedStateCalls: map[string]int{
				"GetActions":       1,
				"GetLastSeen":      1,
				"GetActionLastRun": 1,
				"DecryptAction":    1,
			},
		},
		{
			inputState: func() state.StateInterface {
				mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
				require.Nil(t, err)
				s := new(mockState)
				s.On("GetActions").Return([]*state.EncryptedAction{
					{Processed: 2},
					{Processed: 2},
					{Processed: 0, UUID: "test-uuid", Action: state.Action{ProcessAfter: 10, Kind: "dummy", Data: `{"message": "test"}`}},
				})
				s.On("GetLastSeen").Return(mockTime)
				s.On("GetActionLastRun", "test-uuid").Return(mockTime, nil)
				s.On("DecryptAction", "test-uuid").Return(&state.Action{ProcessAfter: 10, Kind: "dummy", Data: `{"message": "test"}`}, nil)
				return s
			},
			inputExecute: func() execute.ExecuteInterface {
				e := new(mockExecute)
				e.On("Run", &state.Action{ProcessAfter: 10, Kind: "dummy", Data: `{"message": "test"}`}).Return(fmt.Errorf("mockRun error"))
				return e
			},
			expectedStateCalls: map[string]int{
				"GetActions":       1,
				"GetLastSeen":      1,
				"GetActionLastRun": 1,
				"DecryptAction":    1,
			},
			expectedExecuteCalls: map[string]int{
				"Run": 1,
			},
		},
		{
			inputState: func() state.StateInterface {
				mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
				require.Nil(t, err)
				s := new(mockState)
				s.On("GetActions").Return([]*state.EncryptedAction{
					{Processed: 2},
					{Processed: 2},
					{Processed: 0, UUID: "test-uuid", Action: state.Action{ProcessAfter: 10, Kind: "dummy", Data: `{"message": "test"}`}},
				})
				s.On("GetLastSeen").Return(mockTime)
				s.On("GetActionLastRun", "test-uuid").Return(mockTime, nil)
				s.On("DecryptAction", "test-uuid").Return(&state.Action{ProcessAfter: 10, Kind: "dummy", Data: `{"message": "test"}`}, nil)
				s.On("UpdateActionLastRun", "test-uuid").Return(fmt.Errorf("mockUpdateActionLastRun error"))
				return s
			},
			inputExecute: func() execute.ExecuteInterface {
				e := new(mockExecute)
				e.On("Run", &state.Action{ProcessAfter: 10, Kind: "dummy", Data: `{"message": "test"}`}).Return(nil)
				return e
			},
			expectedActions: func() []*state.EncryptedAction {
				return []*state.EncryptedAction{
					{Processed: 2},
					{Processed: 2},
					{Processed: 0, UUID: "test-uuid", Action: state.Action{ProcessAfter: 10, Kind: "dummy", Data: `{"message": "test"}`}},
				}
			},
			expectedStateCalls: map[string]int{
				"GetActions":          2,
				"GetLastSeen":         1,
				"GetActionLastRun":    1,
				"DecryptAction":       1,
				"UpdateActionLastRun": 1,
			},
			expectedExecuteCalls: map[string]int{
				"Run": 1,
			},
		},
		{
			inputState: func() state.StateInterface {
				mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
				require.Nil(t, err)
				s := new(mockState)
				s.On("GetActions").Return([]*state.EncryptedAction{
					{Processed: 2},
					{Processed: 2},
					{Processed: 0, UUID: "test-uuid", Action: state.Action{ProcessAfter: 10, Kind: "dummy", Data: `{"message": "test"}`}},
				}).Once()
				s.On("GetActions").Return([]*state.EncryptedAction{
					{Processed: 2},
					{Processed: 2},
					{Processed: 0, UUID: "test-uuid", LastRun: mockTime, Action: state.Action{ProcessAfter: 10, Kind: "dummy", Data: `{"message": "test"}`}},
				}).Once()
				s.On("GetLastSeen").Return(mockTime)
				s.On("GetActionLastRun", "test-uuid").Return(mockTime, nil)
				s.On("DecryptAction", "test-uuid").Return(&state.Action{ProcessAfter: 10, Kind: "dummy", Data: `{"message": "test"}`}, nil)
				s.On("UpdateActionLastRun", "test-uuid").Return(nil)
				s.On("MarkActionAsProcessed", "test-uuid").Return(fmt.Errorf("mockMarkActionAsProcessed error"))
				return s
			},
			inputExecute: func() execute.ExecuteInterface {
				e := new(mockExecute)
				e.On("Run", &state.Action{ProcessAfter: 10, Kind: "dummy", Data: `{"message": "test"}`}).Return(nil)
				return e
			},
			expectedActions: func() []*state.EncryptedAction {
				mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
				require.Nil(t, err)
				return []*state.EncryptedAction{
					{Processed: 2},
					{Processed: 2},
					{Processed: 0, UUID: "test-uuid", LastRun: mockTime, Action: state.Action{ProcessAfter: 10, Kind: "dummy", Data: `{"message": "test"}`}},
				}
			},
			expectedStateCalls: map[string]int{
				"GetActions":            2,
				"GetLastSeen":           1,
				"GetActionLastRun":      1,
				"DecryptAction":         1,
				"UpdateActionLastRun":   1,
				"MarkActionAsProcessed": 1,
			},
			expectedExecuteCalls: map[string]int{
				"Run": 1,
			},
		},
		{
			inputState: func() state.StateInterface {
				mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
				require.Nil(t, err)
				s := new(mockState)
				s.On("GetActions").Return([]*state.EncryptedAction{
					{Processed: 2},
					{Processed: 2},
					{Processed: 0, UUID: "test-uuid", Action: state.Action{ProcessAfter: 10, Kind: "dummy", Data: `{"message": "test"}`}},
				}).Once()
				s.On("GetActions").Return([]*state.EncryptedAction{
					{Processed: 2},
					{Processed: 2},
					{Processed: 2, UUID: "test-uuid", LastRun: mockTime, Action: state.Action{ProcessAfter: 10, Kind: "dummy", Data: `{"message": "test"}`}},
				}).Once()
				s.On("GetLastSeen").Return(mockTime)
				s.On("GetActionLastRun", "test-uuid").Return(mockTime, nil)
				s.On("DecryptAction", "test-uuid").Return(&state.Action{ProcessAfter: 10, Kind: "dummy", Data: `{"message": "test"}`}, nil)
				s.On("UpdateActionLastRun", "test-uuid").Return(nil)
				s.On("MarkActionAsProcessed", "test-uuid").Return(nil)
				return s
			},
			inputExecute: func() execute.ExecuteInterface {
				e := new(mockExecute)
				e.On("Run", &state.Action{ProcessAfter: 10, Kind: "dummy", Data: `{"message": "test"}`}).Return(nil)
				return e
			},
			expectedActions: func() []*state.EncryptedAction {
				mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
				require.Nil(t, err)
				return []*state.EncryptedAction{
					{Processed: 2},
					{Processed: 2},
					{Processed: 2, UUID: "test-uuid", LastRun: mockTime, Action: state.Action{ProcessAfter: 10, Kind: "dummy", Data: `{"message": "test"}`}},
				}
			},
			expectedStateCalls: map[string]int{
				"GetActions":            2,
				"GetLastSeen":           1,
				"GetActionLastRun":      1,
				"DecryptAction":         1,
				"UpdateActionLastRun":   1,
				"MarkActionAsProcessed": 1,
			},
			expectedExecuteCalls: map[string]int{
				"Run": 1,
			},
		},
		{
			inputState: func() state.StateInterface {
				mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
				require.Nil(t, err)
				s := new(mockState)
				s.On("GetActions").Return([]*state.EncryptedAction{
					{Processed: 2},
					{Processed: 2},
					{Processed: 0, UUID: "test-uuid", Action: state.Action{ProcessAfter: 10, MinInterval: 10, Kind: "dummy", Data: `{"message": "test"}`}},
				}).Once()
				s.On("GetActions").Return([]*state.EncryptedAction{
					{Processed: 2},
					{Processed: 2},
					{Processed: 0, UUID: "test-uuid", LastRun: mockTime, Action: state.Action{ProcessAfter: 10, MinInterval: 10, Kind: "dummy", Data: `{"message": "test"}`}},
				}).Once()
				s.On("GetLastSeen").Return(mockTime)
				s.On("GetActionLastRun", "test-uuid").Return(mockTime, nil)
				s.On("DecryptAction", "test-uuid").Return(&state.Action{ProcessAfter: 10, MinInterval: 10, Kind: "dummy", Data: `{"message": "test"}`}, nil)
				s.On("UpdateActionLastRun", "test-uuid").Return(nil)
				return s
			},
			inputExecute: func() execute.ExecuteInterface {
				e := new(mockExecute)
				e.On("Run", &state.Action{ProcessAfter: 10, MinInterval: 10, Kind: "dummy", Data: `{"message": "test"}`}).Return(nil)
				return e
			},
			expectedActions: func() []*state.EncryptedAction {
				mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
				require.Nil(t, err)
				return []*state.EncryptedAction{
					{Processed: 2},
					{Processed: 2},
					{Processed: 0, UUID: "test-uuid", LastRun: mockTime, Action: state.Action{ProcessAfter: 10, MinInterval: 10, Kind: "dummy", Data: `{"message": "test"}`}},
				}
			},
			expectedStateCalls: map[string]int{
				"GetActions":          2,
				"GetLastSeen":         1,
				"GetActionLastRun":    1,
				"DecryptAction":       1,
				"UpdateActionLastRun": 1,
			},
			expectedExecuteCalls: map[string]int{
				"Run": 1,
			},
		},
	}
	getActionsInterval = 2
	getActionsIntervalUnit = time.Second
	defer func() {
		getActionsInterval = 5
		getActionsIntervalUnit = time.Minute
	}()
	for _, test := range tests {
		s := test.inputState()
		e := test.inputExecute()
		chStop := make(chan bool)
		go dispatcher(s, e, time.Second, chStop)
		time.Sleep(time.Duration(3) * getActionsIntervalUnit)
		chStop <- true
		if test.expectedActions != nil {
			require.Equal(t, test.expectedActions(), s.GetActions())
		}
		if test.expectedStateCalls != nil {
			for k, v := range test.expectedStateCalls {
				s.(*mockState).AssertNumberOfCalls(t, k, v)
			}
		}
		if test.expectedExecuteCalls != nil {
			for k, v := range test.expectedExecuteCalls {
				e.(*mockExecute).AssertNumberOfCalls(t, k, v)
			}
		}
	}
}
