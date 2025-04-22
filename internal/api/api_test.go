package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"dmh/internal/execute"
	"dmh/internal/state"
	"dmh/internal/vault"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
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

type mockVault struct {
	mock.Mock
}

func (m *mockVault) UpdateLastSeen(clientUUID string) {
	m.Called(clientUUID)
}

func (m *mockVault) GetSecret(clientUUID string, secretUUID string) (*vault.Secret, error) {
	args := m.Called(clientUUID, secretUUID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*vault.Secret), args.Error(1)
}

func (m *mockVault) AddSecret(clientUUID string, secretUUID string, secret *vault.Secret) error {
	args := m.Called(clientUUID, secretUUID, secret)
	return args.Error(0)
}

func (m *mockVault) DeleteSecret(clientUUID string, secretUUID string) error {
	args := m.Called(clientUUID, secretUUID)
	return args.Error(0)
}

type mockExecute struct {
	mock.Mock
}

func (e *mockExecute) Run(action *state.Action) error {
	args := e.Called(action)
	return args.Error(0)
}

func TestHealthHandler(t *testing.T) {
	req, err := http.NewRequest("GET", "/health", nil)
	require.Nil(t, err)
	w := httptest.NewRecorder()

	handler := healthHandler()

	handler(w, req)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestAliveHandler(t *testing.T) {
	tests := []struct {
		inputVaultURL        string
		inputVaultClientUUID string
		fakeHTTPServer       func() *httptest.Server
		expectedCode         int
	}{
		{
			inputVaultURL:        "http://wrong\r",
			inputVaultClientUUID: "test",
			expectedCode:         http.StatusInternalServerError,
		},
		{
			inputVaultURL:        "http://broken",
			inputVaultClientUUID: "test",
			expectedCode:         http.StatusInternalServerError,
		},
		{
			inputVaultURL:        "",
			inputVaultClientUUID: "test",
			fakeHTTPServer: func() *httptest.Server {
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					require.Equal(t, "/api/vault/alive/test", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}))
				return s
			},
			expectedCode: http.StatusInternalServerError,
		},
		{
			inputVaultURL:        "",
			inputVaultClientUUID: "test",
			fakeHTTPServer: func() *httptest.Server {
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					require.Equal(t, "/api/vault/alive/test", r.URL.Path)
					w.WriteHeader(http.StatusOK)
				}))
				return s
			},
			expectedCode: http.StatusOK,
		},
	}

	for _, test := range tests {
		req, err := http.NewRequest("GET", "/api/alive", nil)
		require.Nil(t, err)
		w := httptest.NewRecorder()

		s := new(mockState)
		s.On("UpdateLastSeen").Return()
		if test.fakeHTTPServer != nil {
			fakeServer := test.fakeHTTPServer()
			defer fakeServer.Close()
			test.inputVaultURL = fakeServer.URL

		}

		handler := aliveHandler(s, test.inputVaultURL, test.inputVaultClientUUID)

		handler(w, req)
		require.Equal(t, test.expectedCode, w.Code)
	}
}

func TestVaultAliveHandler(t *testing.T) {
	tests := []struct {
		inputClientUUID string
		expectedCode    int
	}{
		{
			inputClientUUID: "",
			expectedCode:    http.StatusNotFound,
		},
		{
			inputClientUUID: "test",
			expectedCode:    http.StatusOK,
		},
	}
	for _, test := range tests {
		req, err := http.NewRequest("GET", fmt.Sprintf("/api/vault/alive/%s", test.inputClientUUID), nil)
		require.Nil(t, err)

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("clientUUID", test.inputClientUUID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, ctx))

		w := httptest.NewRecorder()

		v := new(mockVault)
		v.On("UpdateLastSeen", test.inputClientUUID).Return()

		handler := vaultAliveHandler(v)

		handler(w, req)
		require.Equal(t, test.expectedCode, w.Code)
	}
}

func TestTestActionHandler(t *testing.T) {
	tests := []struct {
		payload         string
		mockExecuteFunc func() execute.ExecuteInterface
		expectedCode    int
	}{
		{
			payload: `{"kind": "bulksms", "data": "{\"test\": 10}}`,
			mockExecuteFunc: func() execute.ExecuteInterface {
				e := new(mockExecute)
				return e
			},
			expectedCode: http.StatusBadRequest,
		},
		{
			payload: `{"kind": "bulksms", "process_after": 10, "data": "{\"message\": \"test\", \"destination\": [\"1111\"]}"}`,
			mockExecuteFunc: func() execute.ExecuteInterface {
				e := new(mockExecute)
				e.On("Run", &state.Action{Kind: "bulksms", Data: "{\"message\": \"test\", \"destination\": [\"1111\"]}", ProcessAfter: 10}).Return(fmt.Errorf("mockExecuteFunc error"))
				return e
			},
			expectedCode: http.StatusBadRequest,
		},
		{
			payload: `{"kind": "bulksms", "process_after": 5, "data": "{\"message\": \"test\", \"destination\": [\"1111\"]}"}`,
			mockExecuteFunc: func() execute.ExecuteInterface {
				e := new(mockExecute)
				e.On("Run", &state.Action{Kind: "bulksms", Data: "{\"message\": \"test\", \"destination\": [\"1111\"]}", ProcessAfter: 5}).Return(nil)
				return e
			},
			expectedCode: http.StatusOK,
		},
	}
	for _, test := range tests {
		reqBody := bytes.NewBufferString(test.payload)
		req, err := http.NewRequest("POST", "/api/action/test", reqBody)
		require.Nil(t, err)
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		e := test.mockExecuteFunc()

		handler := testActionHandler(e)

		handler(w, req)
		require.Equal(t, test.expectedCode, w.Code)
	}
}

func TestListActionsHandler(t *testing.T) {
	tests := []struct {
		mockStateFunc    func() state.StateInterface
		expectedCode     int
		expectedResponse []*state.EncryptedAction
	}{
		{
			mockStateFunc: func() state.StateInterface {
				s := new(mockState)
				s.On("GetActions").Return([]*state.EncryptedAction{})
				return s
			},
			expectedCode:     http.StatusOK,
			expectedResponse: []*state.EncryptedAction{},
		},
		{
			mockStateFunc: func() state.StateInterface {
				s := new(mockState)
				s.On("GetActions").Return([]*state.EncryptedAction{
					{UUID: "test1", Action: state.Action{}},
					{UUID: "test2", Action: state.Action{}},
				})
				return s
			},
			expectedCode: http.StatusOK,
			expectedResponse: []*state.EncryptedAction{
				{UUID: "test1", Action: state.Action{}},
				{UUID: "test2", Action: state.Action{}},
			},
		},
	}
	for _, test := range tests {
		req, err := http.NewRequest("GET", "/api/action/store", nil)
		require.Nil(t, err)
		w := httptest.NewRecorder()

		s := test.mockStateFunc()

		handler := listActionsHandler(s)

		handler(w, req)
		require.Equal(t, test.expectedCode, w.Code)

		contentType := w.Header().Get("Content-Type")
		require.Equal(t, "application/json", contentType)

		var response []*state.EncryptedAction
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.Nil(t, err)
		require.Equal(t, test.expectedResponse, response)
	}
}

func TestAddActionRequestBind(t *testing.T) {
	tests := []struct {
		payload       string
		expectedError error
		expectedReq   *addTestActionRequest
	}{
		{
			payload:       `{"kind": "", "data": "test", "process_after": 10}`,
			expectedError: fmt.Errorf("unknown kind "),
			expectedReq: &addTestActionRequest{
				Kind:         "",
				Data:         "test",
				ProcessAfter: 10,
			},
		},
		{
			payload:       `{"data": "test", "process_after": 10}`,
			expectedError: fmt.Errorf("unknown kind "),
			expectedReq: &addTestActionRequest{
				Kind:         "",
				Data:         "test",
				ProcessAfter: 10,
			},
		},
		{
			payload:       `{"kind": "bulksms", "data": "{\"message\":\"test\",\"destination\":[\"111\"]}", "process_after": 0}`,
			expectedError: fmt.Errorf("process_after should be greater than 0"),
			expectedReq: &addTestActionRequest{
				Kind:         "bulksms",
				Data:         "{\"message\":\"test\",\"destination\":[\"111\"]}",
				ProcessAfter: 0,
			},
		},
		{
			payload:       `{"kind": "bulksms", "data": "{\"message\":\"test\",\"destination\":[\"111\"]}", "process_after": -10}`,
			expectedError: fmt.Errorf("process_after should be greater than 0"),
			expectedReq: &addTestActionRequest{
				Kind:         "bulksms",
				Data:         "{\"message\":\"test\",\"destination\":[\"111\"]}",
				ProcessAfter: -10,
			},
		},
		{
			payload:       `{"kind": "bulksms", "data": "{\"message\":\"test\",\"destination\":[\"111\"]}", "process_after": 10, "min_interval": -1}`,
			expectedError: fmt.Errorf("min_interval should be greater or equal 0"),
			expectedReq: &addTestActionRequest{
				Kind:         "bulksms",
				Data:         "{\"message\":\"test\",\"destination\":[\"111\"]}",
				ProcessAfter: 10,
				MinInterval:  -1,
			},
		},
		{
			payload: `{"kind": "bulksms", "data": "{\"message\":\"test\",\"destination\":[\"111\"]}", "process_after": 10, "min_interval": 0}`,
			expectedReq: &addTestActionRequest{
				Kind:         "bulksms",
				Data:         "{\"message\":\"test\",\"destination\":[\"111\"]}",
				ProcessAfter: 10,
				MinInterval:  0,
			},
		},
		{
			payload: `{"kind": "bulksms", "data": "{\"message\":\"test\",\"destination\":[\"111\"]}", "process_after": 10, "min_interval": 10}`,
			expectedReq: &addTestActionRequest{
				Kind:         "bulksms",
				Data:         "{\"message\":\"test\",\"destination\":[\"111\"]}",
				ProcessAfter: 10,
				MinInterval:  10,
			},
		},
	}
	for _, test := range tests {
		reqBody := bytes.NewBufferString(test.payload)
		req, err := http.NewRequest("POST", "/api/action/store", reqBody)
		require.Nil(t, err)
		req.Header.Set("Content-Type", "application/json")

		ctx := context.WithValue(req.Context(), chi.RouteCtxKey, chi.NewRouteContext())
		req = req.WithContext(ctx)

		parsedReq := &addTestActionRequest{}
		err = render.Bind(req, parsedReq)

		require.Equal(t, test.expectedError, err)
		require.Equal(t, test.expectedReq, parsedReq)
	}
}

func TestAddActionHandler(t *testing.T) {
	tests := []struct {
		payload         string
		mockStateFunc   func() state.StateInterface
		expectedCode    int
		expectedActions []*state.EncryptedAction
	}{
		{
			payload: `{"kind": "bulksms", "data": "{\"message\":\"test\",\"destination\":[\"123\"]", "process_after": 10}`,
			mockStateFunc: func() state.StateInterface {
				s, err := state.New(&state.Options{})
				require.Nil(t, err)
				return s
			},
			expectedCode:    http.StatusBadRequest,
			expectedActions: []*state.EncryptedAction{},
		},
		{
			payload: `{"kind": "bulksms", "data": "{\"message\":\"test\",\"destination\":[\"123\"]}", "process_after": 10}`,
			mockStateFunc: func() state.StateInterface {
				s := new(mockState)
				s.On("AddAction", &state.Action{Kind: "bulksms", Data: "{\"message\":\"test\",\"destination\":[\"123\"]}", ProcessAfter: 10, Comment: ""}).Return(fmt.Errorf("mockState error"))
				s.On("GetActions").Return([]*state.EncryptedAction{})
				return s
			},
			expectedCode:    http.StatusInternalServerError,
			expectedActions: []*state.EncryptedAction{},
		},
		{
			payload: `{"kind": "bulksms", "data": "{\"message\":\"test\",\"destination\":[\"123\"]}", "process_after": 10}`,
			mockStateFunc: func() state.StateInterface {
				s := new(mockState)
				s.On("AddAction", &state.Action{Kind: "bulksms", Data: "{\"message\":\"test\",\"destination\":[\"123\"]}", ProcessAfter: 10, Comment: ""}).Return(nil)
				s.On("GetActions").Return([]*state.EncryptedAction{
					{Action: state.Action{Kind: "bulksms", Data: "encrypted", ProcessAfter: 10, Comment: ""}},
				})
				return s
			},
			expectedCode: http.StatusCreated,
			expectedActions: []*state.EncryptedAction{
				{Action: state.Action{Kind: "bulksms", Data: "encrypted", ProcessAfter: 10, Comment: ""}},
			},
		},
		{
			payload: `{"kind": "bulksms", "data": "{\"message\":\"test\",\"destination\":[\"123\"]}", "process_after": 10}`,
			mockStateFunc: func() state.StateInterface {
				s := new(mockState)
				s.On("AddAction", &state.Action{Kind: "bulksms", Data: "{\"message\":\"test\",\"destination\":[\"123\"]}", ProcessAfter: 10, Comment: ""}).Return(nil)
				s.On("GetActions").Return([]*state.EncryptedAction{
					{Action: state.Action{Kind: "bulksms", Data: "encrypted", ProcessAfter: 20, Comment: ""}},
					{Action: state.Action{Kind: "bulksms", Data: "encrypted2", ProcessAfter: 10, Comment: ""}},
				})
				return s
			},
			expectedCode: http.StatusCreated,
			expectedActions: []*state.EncryptedAction{
				{Action: state.Action{Kind: "bulksms", Data: "encrypted", ProcessAfter: 20, Comment: ""}},
				{Action: state.Action{Kind: "bulksms", Data: "encrypted2", ProcessAfter: 10, Comment: ""}},
			},
		},
	}
	for _, test := range tests {
		reqBody := bytes.NewBufferString(test.payload)
		req, err := http.NewRequest("POST", "/api/action/store", reqBody)
		require.Nil(t, err)
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		s := test.mockStateFunc()

		handler := addActionHandler(s)

		handler(w, req)
		require.Equal(t, test.expectedCode, w.Code)
		actions := s.GetActions()
		require.Equal(t, len(test.expectedActions), len(actions))
		for i, ta := range test.expectedActions {
			require.Equal(t, ta.Action.Kind, actions[i].Action.Kind)
			require.Equal(t, ta.Action.ProcessAfter, actions[i].Action.ProcessAfter)
			require.Equal(t, ta.Action.Comment, actions[i].Action.Comment)
			require.Equal(t, ta.Action.Data, actions[i].Action.Data)
		}
	}
}

func TestAddVaultSecretRequest(t *testing.T) {
	tests := []struct {
		payload       string
		expectedError error
		expectedReq   *addVaultSecretRequest
	}{
		{
			payload:       `{"key": "", "process_after": 10}`,
			expectedError: fmt.Errorf("key must be provided"),
			expectedReq: &addVaultSecretRequest{
				Key:          "",
				ProcessAfter: 10,
			},
		},
		{
			payload:       `{"key": "test", "process_after": 0}`,
			expectedError: fmt.Errorf("process_after should be greater than 0"),
			expectedReq: &addVaultSecretRequest{
				Key:          "test",
				ProcessAfter: 0,
			},
		},
		{
			payload:       `{"key": "test", "process_after": -10}`,
			expectedError: fmt.Errorf("process_after should be greater than 0"),
			expectedReq: &addVaultSecretRequest{
				Key:          "test",
				ProcessAfter: -10,
			},
		},
		{
			payload: `{"key": "test", "process_after": 15}`,
			expectedReq: &addVaultSecretRequest{
				Key:          "test",
				ProcessAfter: 15,
			},
		},
	}
	for _, test := range tests {
		reqBody := bytes.NewBufferString(test.payload)
		req, err := http.NewRequest("POST", "/api/vault/store/client-uuid/secret-uuid", reqBody)
		require.Nil(t, err)
		req.Header.Set("Content-Type", "application/json")

		ctx := context.WithValue(req.Context(), chi.RouteCtxKey, chi.NewRouteContext())
		req = req.WithContext(ctx)

		parsedReq := &addVaultSecretRequest{}
		err = render.Bind(req, parsedReq)

		require.Equal(t, test.expectedError, err)
		require.Equal(t, test.expectedReq, parsedReq)
	}
}

func TestAddVaultSecretHandler(t *testing.T) {
	tests := []struct {
		payload         string
		inputClientUUID string
		inputSecretUUID string
		mockVaultFunc   func() vault.VaultInterface
		expectedCode    int
	}{
		{
			payload:         `{"key": "test", "process_after": 10}`,
			inputClientUUID: "",
			inputSecretUUID: "secret-uuid",
			mockVaultFunc: func() vault.VaultInterface {
				v := new(mockVault)
				return v
			},
			expectedCode: http.StatusBadRequest,
		},
		{
			payload:         `{"key": "test", "process_after": 10}`,
			inputClientUUID: "client-uuid",
			inputSecretUUID: "",
			mockVaultFunc: func() vault.VaultInterface {
				v := new(mockVault)
				return v
			},
			expectedCode: http.StatusBadRequest,
		},
		{
			payload:         `{"process_after": 10}`,
			inputClientUUID: "client-uuid",
			inputSecretUUID: "secret-uuid",
			mockVaultFunc: func() vault.VaultInterface {
				v := new(mockVault)
				return v
			},
			expectedCode: http.StatusBadRequest,
		},
		{
			payload:         `{"key": "test", "process_after": 10}`,
			inputClientUUID: "client-uuid",
			inputSecretUUID: "secret-uuid",
			mockVaultFunc: func() vault.VaultInterface {
				v := new(mockVault)
				v.On("AddSecret", "client-uuid", "secret-uuid", &vault.Secret{Key: "test", ProcessAfter: 10}).Return(fmt.Errorf("mockVault error"))
				return v
			},
			expectedCode: http.StatusBadRequest,
		},
		{
			payload:         `{"key": "test", "process_after": 10}`,
			inputClientUUID: "client-uuid",
			inputSecretUUID: "secret-uuid",
			mockVaultFunc: func() vault.VaultInterface {
				v := new(mockVault)
				v.On("AddSecret", "client-uuid", "secret-uuid", &vault.Secret{Key: "test", ProcessAfter: 10}).Return(nil)
				return v
			},
			expectedCode: http.StatusCreated,
		},
	}
	for _, test := range tests {
		reqBody := bytes.NewBufferString(test.payload)
		req, err := http.NewRequest("POST", fmt.Sprintf("/api/vault/store/%s/%s", test.inputClientUUID, test.inputSecretUUID), reqBody)
		require.Nil(t, err)
		req.Header.Set("Content-Type", "application/json")

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("clientUUID", test.inputClientUUID)
		ctx.URLParams.Add("secretUUID", test.inputSecretUUID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, ctx))

		w := httptest.NewRecorder()
		v := test.mockVaultFunc()

		handler := addVaultSecretHandler(v)

		handler(w, req)
		require.Equal(t, test.expectedCode, w.Code)
	}
}

func TestGetActionHandler(t *testing.T) {
	tests := []struct {
		actionUUID       string
		mockStateFunc    func() state.StateInterface
		expectedCode     int
		expectedResponse *state.EncryptedAction
	}{
		{
			actionUUID: "",
			mockStateFunc: func() state.StateInterface {
				s := new(mockState)
				s.On("GetAction", "").Return(nil, -1)
				return s
			},
			expectedCode: http.StatusNotFound,
		},
		{
			actionUUID: "test",
			mockStateFunc: func() state.StateInterface {
				s := new(mockState)
				s.On("GetAction", "test").Return(nil, -1)
				return s
			},
			expectedCode: http.StatusNotFound,
		},
		{
			actionUUID: "test",
			mockStateFunc: func() state.StateInterface {
				s := new(mockState)
				s.On("GetAction", "test").Return(&state.EncryptedAction{UUID: "test", Action: state.Action{Kind: "mail", Data: "encrypted", ProcessAfter: 10}}, 0)
				return s
			},
			expectedCode:     http.StatusOK,
			expectedResponse: &state.EncryptedAction{UUID: "test", Action: state.Action{Kind: "mail", Data: "encrypted", ProcessAfter: 10}},
		},
	}
	for _, test := range tests {
		req, err := http.NewRequest("GET", fmt.Sprintf("/api/action/store/%s", test.actionUUID), nil)
		require.Nil(t, err)

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("actionUUID", test.actionUUID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, ctx))

		w := httptest.NewRecorder()
		s := test.mockStateFunc()

		handler := getActionHandler(s)

		handler(w, req)
		require.Equal(t, test.expectedCode, w.Code)

		contentType := w.Header().Get("Content-Type")
		require.Equal(t, "application/json", contentType)

		if test.expectedCode < 300 {
			var response *state.EncryptedAction
			err = json.Unmarshal(w.Body.Bytes(), &response)
			require.Nil(t, err)
			require.Equal(t, test.expectedResponse, response)
		}

	}
}

func TestGetVaultSecretHandler(t *testing.T) {
	tests := []struct {
		inputClientUUID  string
		inputSecretUUID  string
		mockVaultFunc    func() vault.VaultInterface
		expectedCode     int
		expectedResponse *vault.Secret
	}{
		{
			inputClientUUID: "client-uuid",
			inputSecretUUID: "secret-uuid",
			mockVaultFunc: func() vault.VaultInterface {
				v := new(mockVault)
				v.On("GetSecret", "client-uuid", "secret-uuid").Return(nil, fmt.Errorf("mockVault error"))
				return v
			},
			expectedCode: http.StatusNotFound,
		},
		{
			inputClientUUID: "client-uuid",
			inputSecretUUID: "secret-uuid",
			mockVaultFunc: func() vault.VaultInterface {
				v := new(mockVault)
				v.On("GetSecret", "client-uuid", "secret-uuid").Return(&vault.Secret{Key: "test", ProcessAfter: 10}, nil)
				return v
			},
			expectedCode:     http.StatusOK,
			expectedResponse: &vault.Secret{Key: "test", ProcessAfter: 10},
		},
	}
	for _, test := range tests {
		req, err := http.NewRequest("GET", fmt.Sprintf("/api/vault/store/%s/%s", test.inputClientUUID, test.inputSecretUUID), nil)
		require.Nil(t, err)

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("clientUUID", test.inputClientUUID)
		ctx.URLParams.Add("secretUUID", test.inputSecretUUID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, ctx))

		w := httptest.NewRecorder()
		v := test.mockVaultFunc()

		handler := getVaultSecretHandler(v)

		handler(w, req)
		require.Equal(t, test.expectedCode, w.Code)

		contentType := w.Header().Get("Content-Type")
		require.Equal(t, "application/json", contentType)

		if test.expectedCode < 300 {
			var response *vault.Secret
			err = json.Unmarshal(w.Body.Bytes(), &response)
			require.Nil(t, err)
			require.Equal(t, test.expectedResponse, response)
		}

	}
}

func TestDeleteActionHandler(t *testing.T) {
	tests := []struct {
		actionUUID    string
		mockStateFunc func() state.StateInterface
		expectedCode  int
	}{
		{
			actionUUID: "",
			mockStateFunc: func() state.StateInterface {
				s := new(mockState)
				s.On("DeleteAction", "").Return(fmt.Errorf("missing action"))
				return s
			},
			expectedCode: http.StatusNotFound,
		},
		{
			actionUUID: "test",
			mockStateFunc: func() state.StateInterface {
				s := new(mockState)
				s.On("DeleteAction", "test").Return(fmt.Errorf("missing action"))
				return s
			},
			expectedCode: http.StatusNotFound,
		},
		{
			actionUUID: "test",
			mockStateFunc: func() state.StateInterface {
				s := new(mockState)
				s.On("DeleteAction", "test").Return(nil)
				return s
			},
			expectedCode: http.StatusOK,
		},
	}
	for _, test := range tests {
		req, err := http.NewRequest("DELETE", fmt.Sprintf("/api/action/store/%s", test.actionUUID), nil)
		require.Nil(t, err)

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("actionUUID", test.actionUUID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, ctx))

		w := httptest.NewRecorder()
		s := test.mockStateFunc()

		handler := deleteActionHandler(s)

		handler(w, req)
		require.Equal(t, test.expectedCode, w.Code)

		contentType := w.Header().Get("Content-Type")
		require.Equal(t, "application/json", contentType)

	}
}

func TestDeleteVaultSecretHandler(t *testing.T) {
	tests := []struct {
		inputClientUUID string
		inputSecretUUID string
		mockVaultFunc   func() vault.VaultInterface
		expectedCode    int
	}{
		{
			inputClientUUID: "client-uuid",
			inputSecretUUID: "secret-uuid",
			mockVaultFunc: func() vault.VaultInterface {
				v := new(mockVault)
				v.On("DeleteSecret", "client-uuid", "secret-uuid").Return(fmt.Errorf("mockVault error"))
				return v
			},
			expectedCode: http.StatusNotFound,
		},
		{
			inputClientUUID: "client-uuid",
			inputSecretUUID: "secret-uuid",
			mockVaultFunc: func() vault.VaultInterface {
				v := new(mockVault)
				v.On("DeleteSecret", "client-uuid", "secret-uuid").Return(nil)
				return v
			},
			expectedCode: http.StatusOK,
		},
	}
	for _, test := range tests {
		req, err := http.NewRequest("DELETE", fmt.Sprintf("/api/vault/store/%s/%s", test.inputClientUUID, test.inputSecretUUID), nil)
		require.Nil(t, err)

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("clientUUID", test.inputClientUUID)
		ctx.URLParams.Add("secretUUID", test.inputSecretUUID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, ctx))

		w := httptest.NewRecorder()
		v := test.mockVaultFunc()

		handler := deleteVaultSecretHandler(v)

		handler(w, req)
		require.Equal(t, test.expectedCode, w.Code)

		contentType := w.Header().Get("Content-Type")
		require.Equal(t, "application/json", contentType)

	}
}
