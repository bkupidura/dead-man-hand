package state

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"dmh/internal/crypt"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockCrypt struct {
	mock.Mock
}

func (m *mockCrypt) Encrypt(data string) (string, error) {
	args := m.Called(data)
	return args.String(0), args.Error(1)
}

func (m *mockCrypt) Decrypt(data string) (string, error) {
	args := m.Called(data)
	return args.String(0), args.Error(1)
}

func (m *mockCrypt) GetPrivateKey() string {
	args := m.Called()
	return args.String(0)
}

type failWriter struct {
	mock.Mock
}

func (f *failWriter) Write(p []byte) (n int, err error) {
	args := f.Called(p)
	return args.Int(0), args.Error(1)
}
func (f *failWriter) Close() error {
	args := f.Called()
	return args.Error(0)
}

type failFile struct {
	*failWriter
}

func (f *failFile) Write(p []byte) (n int, err error) {
	return f.failWriter.Write(p)
}
func (f *failFile) Close() error {
	return f.failWriter.Close()
}

func TestNew(t *testing.T) {
	tests := []struct {
		inputOptions  *Options
		expectedError error
		expectedState func() StateInterface
		statePathFunc func()
	}{
		{
			inputOptions: &Options{
				VaultURL:        "https://dmh-vault.com/endpoint",
				VaultClientUUID: "random-uuid",
				SavePath:        "test_state.json",
			},
			expectedState: func() StateInterface {
				return &State{
					data: &data{
						LastSeen: time.Now(),
						Actions:  []*EncryptedAction{},
					},
					vaultURL:        "https://dmh-vault.com/endpoint",
					vaultClientUUID: "random-uuid",
				}
			},
			statePathFunc: func() {},
		},
		{
			inputOptions: &Options{
				VaultURL:        "https://dmh-vault.com/endpoint",
				VaultClientUUID: "random-uuid",
				SavePath:        "test_state.json",
			},
			expectedState: func() StateInterface {
				return &State{
					data: &data{
						LastSeen: time.Now(),
						Actions:  []*EncryptedAction{},
					},
					vaultURL:        "https://dmh-vault.com/endpoint",
					vaultClientUUID: "random-uuid",
					savePath:        "test_state.json",
				}
			},
			expectedError: fmt.Errorf("unexpected EOF"),
			statePathFunc: func() {
				f, err := os.Create("test_state.json")
				require.Nil(t, err)
				defer f.Close()
				_, err = f.WriteString(`{"broken json`)
				require.Nil(t, err)
			},
		},
		{
			inputOptions: &Options{
				VaultURL:        "https://dmh-vault.com/endpoint",
				VaultClientUUID: "random-uuid",
				SavePath:        "test_state.json",
			},
			expectedState: func() StateInterface {
				mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
				require.Nil(t, err)
				return &State{
					data: &data{
						LastSeen: mockTime,
						Actions: []*EncryptedAction{
							{
								Action: Action{
									Kind:         "mail",
									ProcessAfter: 10,
									Comment:      "",
									Data:         "some-encrypted-content",
								},
								UUID:      "9acc344e-a65b-4675-9723-5664c0e73c76",
								Processed: 0,
							},
							{
								Action: Action{
									Kind:         "mail",
									ProcessAfter: 10,
									Comment:      "test",
									Data:         "some-encrypted-content2",
								},
								UUID:      "7df7c024-d0a8-4183-83fa-373ea4a7735a",
								Processed: 1,
							},
						},
					},
					vaultURL:        "https://dmh-vault.com/endpoint",
					vaultClientUUID: "random-uuid",
					savePath:        "test_state.json",
				}
			},
			statePathFunc: func() {
				f, err := os.Create("test_state.json")
				require.Nil(t, err)
				defer f.Close()
				_, err = f.WriteString(`{"last_seen":"2025-03-26T14:55:40.119447+01:00","actions":[{"uuid":"9acc344e-a65b-4675-9723-5664c0e73c76","kind":"mail","data":"some-encrypted-content","process_after":10,"comment":"","processed":0},{"uuid":"7df7c024-d0a8-4183-83fa-373ea4a7735a","kind":"mail","data":"some-encrypted-content2","process_after":10,"comment":"test","processed":1}]}`)
				require.Nil(t, err)
			},
		},
	}
	for _, test := range tests {
		os.Remove("test_state.json")
		test.statePathFunc()
		defer os.Remove("test_state.json")

		s, err := New(test.inputOptions)

		require.Equal(t, test.expectedError, err)

		if err != nil {
			continue
		}

		expectedState := test.expectedState()

		require.GreaterOrEqual(t, float64(1), expectedState.(*State).data.LastSeen.Sub(s.(*State).data.LastSeen).Seconds())
		require.Equal(t, expectedState.(*State).data.Actions, s.(*State).data.Actions)
	}
}

func TestUpdateLastSeen(t *testing.T) {
	os.Remove("test_state.json")
	defer os.Remove("test_state.json")
	mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
	require.Nil(t, err)

	s := &State{
		data: &data{
			LastSeen: mockTime,
		},
		savePath: "test_state.json",
	}
	s.UpdateLastSeen()
	require.GreaterOrEqual(t, float64(1), time.Since(s.data.LastSeen).Seconds())
}

func TestGetLastSeen(t *testing.T) {
	mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
	require.Nil(t, err)

	s := &State{
		data: &data{
			LastSeen: mockTime,
		},
	}
	require.Equal(t, s.data.LastSeen, s.GetLastSeen())
}

func TestUpdateActionLastRun(t *testing.T) {
	os.Remove("test_state.json")
	defer os.Remove("test_state.json")

	s := &State{
		data: &data{
			Actions: []*EncryptedAction{
				{UUID: "test"},
			},
		},
		savePath: "test_state.json",
	}
	err := s.UpdateActionLastRun("non-existing")
	require.NotNil(t, err)
	err = s.UpdateActionLastRun("test")
	require.Nil(t, err)
	require.GreaterOrEqual(t, float64(1), time.Since(s.data.Actions[0].LastRun).Seconds())
}

func TestGetActionLastRun(t *testing.T) {
	mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
	require.Nil(t, err)

	s := &State{
		data: &data{
			LastSeen: mockTime,
			Actions: []*EncryptedAction{
				{UUID: "test", LastRun: mockTime},
			},
		},
	}
	lr, err := s.GetActionLastRun("non-existing")
	require.NotNil(t, err)
	require.Equal(t, time.Time{}, lr)

	lr, err = s.GetActionLastRun("test")
	require.Nil(t, err)
	require.Equal(t, s.data.Actions[0].LastRun, lr)
}

func TestAddAction(t *testing.T) {
	tests := []struct {
		inputAction     []*Action
		inputState      func() *State
		expectedError   bool
		expectedActions []*EncryptedAction
		mockCryptFunc   func(string) (crypt.CryptInterface, error)
		mockJsonMarshal func(any) ([]byte, error)
		fakeHTTPServer  func() *httptest.Server
	}{
		{
			inputAction: []*Action{
				{
					Kind:         "mail",
					ProcessAfter: 10,
					Comment:      "a",
					Data:         "test",
				},
			},
			inputState: func() *State {
				s := &State{
					data: &data{
						LastSeen: time.Now(),
						Actions:  []*EncryptedAction{},
					},
					vaultURL:        "",
					vaultClientUUID: "random-uuid",
					savePath:        "test_state.json",
				}
				return s
			},
			mockCryptFunc: func(string) (crypt.CryptInterface, error) {
				return nil, fmt.Errorf("mockCryptFunc error")
			},
			expectedError: true,
		},
		{
			inputAction: []*Action{
				{
					Kind:         "mail",
					ProcessAfter: 10,
					Comment:      "a",
					Data:         "test",
				},
			},
			inputState: func() *State {
				s := &State{
					data: &data{
						LastSeen: time.Now(),
						Actions:  []*EncryptedAction{},
					},
					vaultURL:        "\r",
					vaultClientUUID: "random-uuid",
					savePath:        "test_state.json",
				}
				return s
			},
			mockCryptFunc: func(string) (crypt.CryptInterface, error) {
				c := new(mockCrypt)
				return c, nil
			},
			expectedError: true,
		},
		{
			inputAction: []*Action{
				{
					Kind:         "mail",
					ProcessAfter: 10,
					Comment:      "a",
					Data:         "test",
				},
			},
			inputState: func() *State {
				s := &State{
					data: &data{
						LastSeen: time.Now(),
						Actions:  []*EncryptedAction{},
					},
					vaultURL:        "",
					vaultClientUUID: "random-uuid",
					savePath:        "test_state.json",
				}
				return s
			},
			mockCryptFunc: func(string) (crypt.CryptInterface, error) {
				c := new(mockCrypt)
				c.On("Encrypt", "test").Return("", fmt.Errorf("mockCrypt error"))
				return c, nil
			},
			expectedError: true,
		},
		{
			inputAction: []*Action{
				{
					Kind:         "mail",
					ProcessAfter: 10,
					Comment:      "a",
					Data:         "test",
				},
			},
			inputState: func() *State {
				s := &State{
					data: &data{
						LastSeen: time.Now(),
						Actions:  []*EncryptedAction{},
					},
					vaultURL:        "",
					vaultClientUUID: "random-uuid",
					savePath:        "test_state.json",
				}
				return s
			},
			mockJsonMarshal: func(any) ([]byte, error) {
				return []byte{}, fmt.Errorf("mockJsonMarshal error")
			},
			expectedError: true,
		},
		{
			inputAction: []*Action{
				{
					Kind:         "mail",
					ProcessAfter: 10,
					Comment:      "a",
					Data:         "test",
				},
			},
			inputState: func() *State {
				s := &State{
					data: &data{
						LastSeen: time.Now(),
						Actions:  []*EncryptedAction{},
					},
					vaultURL:        "http://broken",
					vaultClientUUID: "random-uuid",
					savePath:        "test_state.json",
				}
				return s
			},
			expectedError: true,
		},
		{
			inputAction: []*Action{
				{
					Kind:         "mail",
					ProcessAfter: 10,
					Comment:      "a",
					Data:         "test",
				},
			},
			inputState: func() *State {
				s := &State{
					data: &data{
						LastSeen: time.Now(),
						Actions:  []*EncryptedAction{},
					},
					vaultURL:        "",
					vaultClientUUID: "random-uuid",
					savePath:        "test_state.json",
				}
				return s
			},
			expectedError: true,
			fakeHTTPServer: func() *httptest.Server {
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNotFound)
				}))
				return s
			},
		},
		{
			inputAction: []*Action{
				{
					Kind:         "mail",
					ProcessAfter: 10,
					Comment:      "a",
					Data:         "test",
				},
			},
			inputState: func() *State {
				s := &State{
					data: &data{
						LastSeen: time.Now(),
						Actions:  []*EncryptedAction{},
					},
					vaultURL:        "",
					vaultClientUUID: "random-uuid",
					savePath:        "test_state.json",
				}
				return s
			},
			fakeHTTPServer: func() *httptest.Server {
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					contentType := r.Header.Get("Content-Type")
					require.Equal(t, "application/json", contentType)
					body, err := io.ReadAll(r.Body)
					require.Nil(t, err)
					require.Equal(t, "{\"key\":\"AGE-SECRET-KEY-1CUGTTN4UQCDCFQAY7QM8C4RM4KGE7LN47D5SUU9MQVHEPDPWR04Q5NN5D8\",\"process_after\":10,\"encryption\":{\"kind\":\"\"}}", string(body))
					w.WriteHeader(http.StatusCreated)
				}))
				return s
			},
			mockCryptFunc: func(string) (crypt.CryptInterface, error) {
				c, err := crypt.New("AGE-SECRET-KEY-1CUGTTN4UQCDCFQAY7QM8C4RM4KGE7LN47D5SUU9MQVHEPDPWR04Q5NN5D8")
				require.Nil(t, err)
				return c, nil
			},
			expectedActions: []*EncryptedAction{
				{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 10,
						Comment:      "a",
						Data:         "encrypted",
					},
					Processed: 0,
					EncryptionMeta: EncryptionMeta{
						Kind:     "X25519",
						VaultURL: "",
					},
				},
			},
		},
		{
			inputAction: []*Action{
				{
					Kind:         "mail",
					ProcessAfter: 20,
					Comment:      "test",
					Data:         "test2",
				},
				{
					Kind:         "mail",
					ProcessAfter: 10,
					Comment:      "a",
					Data:         "test",
				},
			},
			inputState: func() *State {
				s := &State{
					data: &data{
						LastSeen: time.Now(),
						Actions:  []*EncryptedAction{},
					},
					vaultURL:        "",
					vaultClientUUID: "random-uuid",
					savePath:        "test_state.json",
				}
				return s
			},
			expectedActions: []*EncryptedAction{
				{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 20,
						Comment:      "test",
						Data:         "encrypted1",
					},
					Processed: 0,
					EncryptionMeta: EncryptionMeta{
						Kind:     "X25519",
						VaultURL: "",
					},
				},
				{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 10,
						Comment:      "a",
						Data:         "encrypted2",
					},
					Processed: 0,
					EncryptionMeta: EncryptionMeta{
						Kind:     "X25519",
						VaultURL: "",
					},
				},
			},
			fakeHTTPServer: func() *httptest.Server {
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					contentType := r.Header.Get("Content-Type")
					require.Equal(t, "application/json", contentType)
					w.WriteHeader(http.StatusCreated)
				}))
				return s
			},
			mockCryptFunc: func(string) (crypt.CryptInterface, error) {
				c, err := crypt.New("")
				require.Nil(t, err)
				return c, nil
			},
		},
	}
	for _, test := range tests {
		os.Remove("test_state.json")
		defer os.Remove("test_state.json")

		cryptNew = crypt.New
		if test.mockCryptFunc != nil {
			cryptNew = test.mockCryptFunc
			defer func() {
				cryptNew = crypt.New
			}()

		}

		jsonMarshal = json.Marshal
		if test.mockJsonMarshal != nil {
			jsonMarshal = test.mockJsonMarshal
			defer func() {
				jsonMarshal = json.Marshal
			}()
		}

		s := test.inputState()

		var fakeServer *httptest.Server
		if test.fakeHTTPServer != nil {
			fakeServer = test.fakeHTTPServer()
			defer fakeServer.Close()
			s.vaultURL = fakeServer.URL

		}

		for _, a := range test.inputAction {
			err := s.AddAction(a)
			if test.expectedError {
				require.Error(t, err)
			} else {
				require.Nil(t, err)
			}
		}

		require.Equal(t, len(test.expectedActions), len(s.data.Actions))
		for i, a := range test.expectedActions {
			require.Equal(t, a.Action.Kind, s.data.Actions[i].Action.Kind)
			require.Equal(t, a.Action.ProcessAfter, s.data.Actions[i].Action.ProcessAfter)
			require.Equal(t, a.Action.Comment, s.data.Actions[i].Action.Comment)
			require.Equal(t, 0, s.data.Actions[i].Processed)
			require.Equal(t, a.EncryptionMeta.Kind, s.data.Actions[i].EncryptionMeta.Kind)
			require.Equal(t, fmt.Sprintf("%s/api/vault/store/%s/%s", s.vaultURL, s.vaultClientUUID, s.data.Actions[i].UUID), s.data.Actions[i].EncryptionMeta.VaultURL)
			require.NotEqual(t, a.Action.Data, s.data.Actions[i].Action.Data)
		}
	}
}
func TestGetActions(t *testing.T) {
	tests := []struct {
		inputState      func() StateInterface
		expectedActions []*EncryptedAction
	}{
		{
			inputState: func() StateInterface {
				s, err := New(&Options{})
				require.Nil(t, err)
				return s
			},
			expectedActions: []*EncryptedAction{},
		},
		{
			inputState: func() StateInterface {
				s, err := New(&Options{})
				require.Nil(t, err)
				s.(*State).data.Actions = []*EncryptedAction{
					{
						Action: Action{
							Kind:         "mail",
							ProcessAfter: 20,
							Data:         "encrypted",
						},
						UUID:      "test",
						Processed: 1,
					},
					{
						Action: Action{
							Kind:         "mail",
							ProcessAfter: 20,
							Comment:      "test",
							Data:         "encrypted2",
						},
						UUID:      "test2",
						Processed: 0,
					},
				}
				return s
			},
			expectedActions: []*EncryptedAction{
				{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 20,
						Data:         "encrypted",
					},
					UUID:      "test",
					Processed: 1,
				},
				{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 20,
						Comment:      "test",
						Data:         "encrypted2",
					},
					UUID:      "test2",
					Processed: 0,
				},
			},
		},
	}
	for _, test := range tests {
		s := test.inputState()
		actions := s.GetActions()
		require.Equal(t, test.expectedActions, actions)
	}
}
func TestGetAction(t *testing.T) {
	tests := []struct {
		inputState     func() StateInterface
		inputUUID      string
		expectedAction *EncryptedAction
		expectedIndex  int
	}{
		{
			inputState: func() StateInterface {
				s, err := New(&Options{})
				require.Nil(t, err)
				return s
			},
			inputUUID:      "test3",
			expectedAction: nil,
			expectedIndex:  -1,
		},
		{
			inputState: func() StateInterface {
				s, err := New(&Options{})
				require.Nil(t, err)
				s.(*State).data.Actions = []*EncryptedAction{
					{
						Action: Action{
							Kind:         "mail",
							ProcessAfter: 20,
							Comment:      "test",
							Data:         "encrypted",
						},
						UUID:      "test",
						Processed: 1,
					},
					{
						Action: Action{
							Kind:         "mail",
							ProcessAfter: 20,
							Comment:      "test",
							Data:         "encrypted2",
						},
						UUID:      "test2",
						Processed: 0,
					},
				}
				return s
			},
			inputUUID:      "test3",
			expectedAction: nil,
			expectedIndex:  -1,
		},
		{
			inputState: func() StateInterface {
				s, err := New(&Options{})
				require.Nil(t, err)
				s.(*State).data.Actions = []*EncryptedAction{
					{
						Action: Action{
							Kind:         "mail",
							ProcessAfter: 20,
							Comment:      "test",
							Data:         "encrypted",
						},
						UUID:      "test",
						Processed: 0,
					},
					{
						Action: Action{
							Kind:         "mail",
							ProcessAfter: 20,
							Comment:      "test",
							Data:         "encrypted2",
						},
						UUID:      "test2",
						Processed: 0,
					},
				}
				return s
			},
			inputUUID: "test2",
			expectedAction: &EncryptedAction{
				Action: Action{
					Kind:         "mail",
					ProcessAfter: 20,
					Comment:      "test",
					Data:         "encrypted2",
				},
				UUID:      "test2",
				Processed: 0,
			},
			expectedIndex: 1,
		},
	}
	for _, test := range tests {
		s := test.inputState()
		a, i := s.GetAction(test.inputUUID)
		require.Equal(t, test.expectedAction, a)
		require.Equal(t, test.expectedIndex, i)
	}
}
func TestDeleteAction(t *testing.T) {
	tests := []struct {
		inputState      func() StateInterface
		inputUUID       string
		expectedActions []*EncryptedAction
		expectedError   error
	}{
		{
			inputState: func() StateInterface {
				s, err := New(&Options{})
				require.Nil(t, err)
				return s
			},
			inputUUID:       "test3",
			expectedActions: []*EncryptedAction{},
			expectedError:   fmt.Errorf("missing action with uuid test3"),
		},
		{
			inputState: func() StateInterface {
				s, err := New(&Options{SavePath: "test_state.json"})
				require.Nil(t, err)
				s.(*State).data.Actions = []*EncryptedAction{
					{
						Action: Action{
							Kind:         "mail",
							ProcessAfter: 20,
							Comment:      "test",
							Data:         "encrypted",
						},
						UUID:      "test",
						Processed: 1,
					},
					{
						Action: Action{
							Kind:         "mail",
							ProcessAfter: 20,
							Comment:      "test",
							Data:         "encrypted2",
						},
						UUID:      "test2",
						Processed: 0,
					},
				}
				return s
			},
			inputUUID: "test3",
			expectedActions: []*EncryptedAction{
				{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 20,
						Comment:      "test",
						Data:         "encrypted",
					},
					UUID:      "test",
					Processed: 1,
				},
				{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 20,
						Comment:      "test",
						Data:         "encrypted2",
					},
					UUID:      "test2",
					Processed: 0,
				},
			},
			expectedError: fmt.Errorf("missing action with uuid test3"),
		},
		{
			inputState: func() StateInterface {
				s, err := New(&Options{SavePath: "test_state.json"})
				require.Nil(t, err)
				s.(*State).data.Actions = []*EncryptedAction{
					{
						Action: Action{
							Kind:         "mail",
							ProcessAfter: 20,
							Comment:      "test",
							Data:         "encrypted",
						},
						UUID:      "test",
						Processed: 1,
					},
					{
						Action: Action{
							Kind:         "mail",
							ProcessAfter: 20,
							Comment:      "test",
							Data:         "encrypted2",
						},
						UUID:      "test2",
						Processed: 0,
					},
				}
				return s
			},
			inputUUID: "test2",
			expectedActions: []*EncryptedAction{
				{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 20,
						Comment:      "test",
						Data:         "encrypted",
					},
					UUID:      "test",
					Processed: 1,
				},
			},
		},
	}
	for _, test := range tests {
		os.Remove("test_state.json")
		defer os.Remove("test_state.json")
		s := test.inputState()
		err := s.DeleteAction(test.inputUUID)
		require.Equal(t, test.expectedActions, s.(*State).data.Actions)
		require.Equal(t, test.expectedError, err)
	}
}

func TestMarkActionAsProcessed(t *testing.T) {
	tests := []struct {
		inputState      func() StateInterface
		inputUUID       string
		expectedActions []*EncryptedAction
		expectedError   bool
		fakeHTTPServer  func() *httptest.Server
	}{
		{
			inputState: func() StateInterface {
				s, err := New(&Options{})
				require.Nil(t, err)
				return s
			},
			inputUUID:       "test3",
			expectedActions: []*EncryptedAction{},
			expectedError:   true,
		},
		{
			inputState: func() StateInterface {
				s, err := New(&Options{SavePath: "test_state.json"})
				require.Nil(t, err)
				s.(*State).data.Actions = []*EncryptedAction{
					{
						Action: Action{
							Kind:         "mail",
							ProcessAfter: 20,
							Comment:      "test",
							Data:         "encrypted",
						},
						UUID:      "test",
						Processed: 0,
					},
					{
						Action: Action{
							Kind:         "mail",
							ProcessAfter: 20,
							Comment:      "test",
							Data:         "encrypted2",
						},
						UUID:      "test2",
						Processed: 0,
					},
				}
				return s
			},
			inputUUID: "test3",
			expectedActions: []*EncryptedAction{
				{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 20,
						Comment:      "test",
						Data:         "encrypted",
					},
					UUID:      "test",
					Processed: 0,
				},
				{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 20,
						Comment:      "test",
						Data:         "encrypted2",
					},
					UUID:      "test2",
					Processed: 0,
				},
			},
			expectedError: true,
		},
		{
			inputState: func() StateInterface {
				s, err := New(&Options{SavePath: "test_state.json", VaultClientUUID: "client-random-uuid"})
				require.Nil(t, err)
				s.(*State).data.Actions = []*EncryptedAction{
					{
						Action: Action{
							Kind:         "mail",
							ProcessAfter: 20,
							Comment:      "test",
							Data:         "encrypted",
						},
						UUID:      "test",
						Processed: 0,
					},
					{
						Action: Action{
							Kind:         "mail",
							ProcessAfter: 20,
							Comment:      "test",
							Data:         "encrypted2",
						},
						UUID:      "test2",
						Processed: 0,
						EncryptionMeta: EncryptionMeta{
							VaultURL: "http\r",
						},
					},
				}
				return s
			},
			inputUUID: "test2",
			expectedActions: []*EncryptedAction{
				{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 20,
						Comment:      "test",
						Data:         "encrypted",
					},
					UUID:      "test",
					Processed: 0,
				},
				{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 20,
						Comment:      "test",
						Data:         "encrypted2",
					},
					UUID:      "test2",
					Processed: 1,
					EncryptionMeta: EncryptionMeta{
						VaultURL: "http\r",
					},
				},
			},
			expectedError: true,
		},
		{
			inputState: func() StateInterface {
				s, err := New(&Options{SavePath: "test_state.json", VaultClientUUID: "client-random-uuid"})
				require.Nil(t, err)
				s.(*State).data.Actions = []*EncryptedAction{
					{
						Action: Action{
							Kind:         "mail",
							ProcessAfter: 20,
							Comment:      "test",
							Data:         "encrypted",
						},
						UUID:      "test",
						Processed: 0,
					},
					{
						Action: Action{
							Kind:         "mail",
							ProcessAfter: 20,
							Comment:      "test",
							Data:         "encrypted2",
						},
						UUID:      "test2",
						Processed: 0,
						EncryptionMeta: EncryptionMeta{
							VaultURL: "http://non-existing",
						},
					},
				}
				return s
			},
			inputUUID: "test2",
			expectedActions: []*EncryptedAction{
				{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 20,
						Comment:      "test",
						Data:         "encrypted",
					},
					UUID:      "test",
					Processed: 0,
				},
				{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 20,
						Comment:      "test",
						Data:         "encrypted2",
					},
					UUID:      "test2",
					Processed: 1,
					EncryptionMeta: EncryptionMeta{
						VaultURL: "http://non-existing",
					},
				},
			},
			expectedError: true,
		},
		{
			inputState: func() StateInterface {
				s, err := New(&Options{SavePath: "test_state.json", VaultClientUUID: "client-random-uuid"})
				require.Nil(t, err)
				s.(*State).data.Actions = []*EncryptedAction{
					{
						Action: Action{
							Kind:         "mail",
							ProcessAfter: 20,
							Comment:      "test",
							Data:         "encrypted",
						},
						UUID:      "test",
						Processed: 0,
					},
					{
						Action: Action{
							Kind:         "mail",
							ProcessAfter: 20,
							Comment:      "test",
							Data:         "encrypted2",
						},
						UUID:           "test2",
						Processed:      0,
						EncryptionMeta: EncryptionMeta{},
					},
				}
				return s
			},
			inputUUID: "test2",
			expectedActions: []*EncryptedAction{
				{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 20,
						Comment:      "test",
						Data:         "encrypted",
					},
					UUID:      "test",
					Processed: 0,
				},
				{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 20,
						Comment:      "test",
						Data:         "encrypted2",
					},
					UUID:           "test2",
					Processed:      1,
					EncryptionMeta: EncryptionMeta{},
				},
			},
			fakeHTTPServer: func() *httptest.Server {
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					require.Equal(t, "/api/vault/store/client-random-uuid/test2", r.URL.Path)
					w.WriteHeader(http.StatusBadRequest)
				}))
				return s
			},
			expectedError: true,
		},
		{
			inputState: func() StateInterface {
				s, err := New(&Options{SavePath: "test_state.json", VaultClientUUID: "client-random-uuid"})
				require.Nil(t, err)
				s.(*State).data.Actions = []*EncryptedAction{
					{
						Action: Action{
							Kind:         "mail",
							ProcessAfter: 20,
							Comment:      "test",
							Data:         "encrypted",
						},
						UUID:      "test",
						Processed: 0,
					},
					{
						Action: Action{
							Kind:         "mail",
							ProcessAfter: 20,
							Comment:      "test",
							Data:         "encrypted2",
						},
						UUID:           "test2",
						Processed:      0,
						EncryptionMeta: EncryptionMeta{},
					},
				}
				return s
			},
			inputUUID: "test2",
			expectedActions: []*EncryptedAction{
				{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 20,
						Comment:      "test",
						Data:         "encrypted",
					},
					UUID:      "test",
					Processed: 0,
				},
				{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 20,
						Comment:      "test",
						Data:         "encrypted2",
					},
					UUID:           "test2",
					Processed:      2,
					EncryptionMeta: EncryptionMeta{},
				},
			},
			fakeHTTPServer: func() *httptest.Server {
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					require.Equal(t, "/api/vault/store/client-random-uuid/test2", r.URL.Path)
					w.WriteHeader(http.StatusOK)
				}))
				return s
			},
		},
	}
	for _, test := range tests {
		os.Remove("test_state.json")
		defer os.Remove("test_state.json")
		s := test.inputState()

		var fakeServer *httptest.Server
		if test.fakeHTTPServer != nil {
			fakeServer = test.fakeHTTPServer()
			defer fakeServer.Close()
			s.(*State).vaultURL = fakeServer.URL
			for _, a := range s.(*State).data.Actions {
				a.EncryptionMeta.VaultURL = fmt.Sprintf("%s/api/vault/store/%s/%s", s.(*State).vaultURL, s.(*State).vaultClientUUID, a.UUID)
			}
			for _, a := range test.expectedActions {
				a.EncryptionMeta.VaultURL = fmt.Sprintf("%s/api/vault/store/%s/%s", s.(*State).vaultURL, s.(*State).vaultClientUUID, a.UUID)
			}

		}

		err := s.MarkActionAsProcessed(test.inputUUID)

		require.Equal(t, test.expectedActions, s.(*State).data.Actions)
		if test.expectedError {
			require.Error(t, err)
		} else {
			require.Nil(t, err)
		}
	}
}

func TestDecryptAction(t *testing.T) {
	tests := []struct {
		inputActionUUID string
		inputState      func() *State
		expectedError   bool
		expectedAction  *Action
		mockCryptFunc   func(string) (crypt.CryptInterface, error)
		fakeHTTPServer  func() *httptest.Server
	}{
		{
			inputActionUUID: "test",
			inputState: func() *State {
				c, err := crypt.New("AGE-SECRET-KEY-1CUGTTN4UQCDCFQAY7QM8C4RM4KGE7LN47D5SUU9MQVHEPDPWR04Q5NN5D8")
				require.Nil(t, err)
				encryptedData, err := c.Encrypt(`{"message":"test","destination":["a@a.com","b@com"],"subject":"test2"}`)
				require.Nil(t, err)
				action := &EncryptedAction{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 10,
						Comment:      "a",
						Data:         encryptedData,
					},
					Processed: 0,
					UUID:      "action-random-uuid",
					EncryptionMeta: EncryptionMeta{
						Kind:     "X25519",
						VaultURL: "",
					},
				}
				s := &State{
					data: &data{
						LastSeen: time.Now(),
						Actions: []*EncryptedAction{
							action,
						},
					},
					vaultURL:        "",
					vaultClientUUID: "client-random-uuid",
					savePath:        "test_state.json",
				}
				return s
			},
			expectedError: true,
		},
		{
			inputActionUUID: "action-random-uuid",
			inputState: func() *State {
				c, err := crypt.New("AGE-SECRET-KEY-1CUGTTN4UQCDCFQAY7QM8C4RM4KGE7LN47D5SUU9MQVHEPDPWR04Q5NN5D8")
				require.Nil(t, err)
				encryptedData, err := c.Encrypt(`{"message":"test","destination":["a@a.com","b@com"],"subject":"test2"}`)
				require.Nil(t, err)
				action := &EncryptedAction{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 10,
						Comment:      "a",
						Data:         encryptedData,
					},
					Processed: 0,
					UUID:      "action-random-uuid",
					EncryptionMeta: EncryptionMeta{
						Kind:     "X25519",
						VaultURL: "",
					},
				}
				s := &State{
					data: &data{
						LastSeen: time.Now(),
						Actions: []*EncryptedAction{
							action,
						},
					},
					vaultURL:        "",
					vaultClientUUID: "client-random-uuid",
					savePath:        "test_state.json",
				}
				return s
			},
			expectedError: true,
		},
		{
			inputActionUUID: "action-random-uuid",
			inputState: func() *State {
				c, err := crypt.New("AGE-SECRET-KEY-1CUGTTN4UQCDCFQAY7QM8C4RM4KGE7LN47D5SUU9MQVHEPDPWR04Q5NN5D8")
				require.Nil(t, err)
				encryptedData, err := c.Encrypt(`{"message":"test","destination":["a@a.com","b@com"],"subject":"test2"}`)
				require.Nil(t, err)
				action := &EncryptedAction{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 10,
						Comment:      "a",
						Data:         encryptedData,
					},
					Processed: 0,
					UUID:      "action-random-uuid",
					EncryptionMeta: EncryptionMeta{
						Kind:     "X25519",
						VaultURL: "",
					},
				}
				s := &State{
					data: &data{
						LastSeen: time.Now(),
						Actions: []*EncryptedAction{
							action,
						},
					},
					vaultURL:        "",
					vaultClientUUID: "client-random-uuid",
					savePath:        "test_state.json",
				}
				return s
			},
			fakeHTTPServer: func() *httptest.Server {
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					require.Equal(t, "/api/vault/store/client-random-uuid/action-random-uuid", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}))
				return s
			},
			expectedError: true,
		},
		{
			inputActionUUID: "action-random-uuid",
			inputState: func() *State {
				c, err := crypt.New("AGE-SECRET-KEY-1CUGTTN4UQCDCFQAY7QM8C4RM4KGE7LN47D5SUU9MQVHEPDPWR04Q5NN5D8")
				require.Nil(t, err)
				encryptedData, err := c.Encrypt(`{"message":"test","destination":["a@a.com","b@com"],"subject":"test2"}`)
				require.Nil(t, err)
				action := &EncryptedAction{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 10,
						Comment:      "a",
						Data:         encryptedData,
					},
					Processed: 0,
					UUID:      "action-random-uuid",
					EncryptionMeta: EncryptionMeta{
						Kind:     "X25519",
						VaultURL: "",
					},
				}
				s := &State{
					data: &data{
						LastSeen: time.Now(),
						Actions: []*EncryptedAction{
							action,
						},
					},
					vaultURL:        "",
					vaultClientUUID: "client-random-uuid",
					savePath:        "test_state.json",
				}
				return s
			},
			fakeHTTPServer: func() *httptest.Server {
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					require.Equal(t, "/api/vault/store/client-random-uuid/action-random-uuid", r.URL.Path)
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"broken json`))
				}))
				return s
			},
			expectedError: true,
		},
		{
			inputActionUUID: "action-random-uuid",
			inputState: func() *State {
				c, err := crypt.New("AGE-SECRET-KEY-1CUGTTN4UQCDCFQAY7QM8C4RM4KGE7LN47D5SUU9MQVHEPDPWR04Q5NN5D8")
				require.Nil(t, err)
				encryptedData, err := c.Encrypt(`{"message":"test","destination":["a@a.com","b@com"],"subject":"test2"}`)
				require.Nil(t, err)
				action := &EncryptedAction{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 10,
						Comment:      "a",
						Data:         encryptedData,
					},
					Processed: 0,
					UUID:      "action-random-uuid",
					EncryptionMeta: EncryptionMeta{
						Kind:     "X25519",
						VaultURL: "",
					},
				}
				s := &State{
					data: &data{
						LastSeen: time.Now(),
						Actions: []*EncryptedAction{
							action,
						},
					},
					vaultURL:        "",
					vaultClientUUID: "client-random-uuid",
					savePath:        "test_state.json",
				}
				return s
			},
			fakeHTTPServer: func() *httptest.Server {
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					require.Equal(t, "/api/vault/store/client-random-uuid/action-random-uuid", r.URL.Path)
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"key": "AGE-SECRET-KEY-1CUGTTN4UQCDCFQAY7QM8C4RM4KGE7LN47D5SUU9MQVHEPDPWR04Q5NN5D8", "process_after": 10}`))
				}))
				return s
			},
			mockCryptFunc: func(string) (crypt.CryptInterface, error) {
				return nil, fmt.Errorf("mockCryptFunc error")
			},
			expectedError: true,
		},
		{
			inputActionUUID: "action-random-uuid",
			inputState: func() *State {
				c, err := crypt.New("AGE-SECRET-KEY-1CUGTTN4UQCDCFQAY7QM8C4RM4KGE7LN47D5SUU9MQVHEPDPWR04Q5NN5D8")
				require.Nil(t, err)
				encryptedData, err := c.Encrypt(`{"message":"test","destination":["a@a.com","b@com"],"subject":"test2"}`)
				require.Nil(t, err)
				action := &EncryptedAction{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 10,
						Comment:      "a",
						Data:         encryptedData,
					},
					Processed: 0,
					UUID:      "action-random-uuid",
					EncryptionMeta: EncryptionMeta{
						Kind:     "X25519",
						VaultURL: "",
					},
				}
				s := &State{
					data: &data{
						LastSeen: time.Now(),
						Actions: []*EncryptedAction{
							action,
						},
					},
					vaultURL:        "",
					vaultClientUUID: "client-random-uuid",
					savePath:        "test_state.json",
				}
				return s
			},
			fakeHTTPServer: func() *httptest.Server {
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					require.Equal(t, "/api/vault/store/client-random-uuid/action-random-uuid", r.URL.Path)
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"key": "AGE-SECRET-KEY-1WCXTESPDAL64QQLNE6SEHHSFQVHZ2KV7KR2XCLGQ0UFSUUJXP5AS84HFG0", "process_after": 10}`))
				}))
				return s
			},
			expectedError: true,
		},
		{
			inputActionUUID: "action-random-uuid",
			inputState: func() *State {
				c, err := crypt.New("AGE-SECRET-KEY-1CUGTTN4UQCDCFQAY7QM8C4RM4KGE7LN47D5SUU9MQVHEPDPWR04Q5NN5D8")
				require.Nil(t, err)
				encryptedData, err := c.Encrypt(`{"message":"test","destination":["a@a.com","b@com"],"subject":"test2"}`)
				require.Nil(t, err)
				action := &EncryptedAction{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 10,
						Comment:      "a",
						Data:         encryptedData,
					},
					Processed: 0,
					UUID:      "action-random-uuid",
					EncryptionMeta: EncryptionMeta{
						Kind:     "X25519",
						VaultURL: "",
					},
				}
				s := &State{
					data: &data{
						LastSeen: time.Now(),
						Actions: []*EncryptedAction{
							action,
						},
					},
					vaultURL:        "",
					vaultClientUUID: "client-random-uuid",
					savePath:        "test_state.json",
				}
				return s
			},
			fakeHTTPServer: func() *httptest.Server {
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					require.Equal(t, "/api/vault/store/client-random-uuid/action-random-uuid", r.URL.Path)
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"key": "AGE-SECRET-KEY-1CUGTTN4UQCDCFQAY7QM8C4RM4KGE7LN47D5SUU9MQVHEPDPWR04Q5NN5D8", "process_after": 10}`))
				}))
				return s
			},
			expectedAction: &Action{
				Kind:         "mail",
				ProcessAfter: 10,
				Comment:      "a",
				Data:         `{"message":"test","destination":["a@a.com","b@com"],"subject":"test2"}`,
			},
		},
	}
	for _, test := range tests {
		os.Remove("test_state.json")
		defer os.Remove("test_state.json")

		cryptNew = crypt.New
		if test.mockCryptFunc != nil {
			cryptNew = test.mockCryptFunc
			defer func() {
				cryptNew = crypt.New
			}()

		}

		s := test.inputState()

		var fakeServer *httptest.Server
		if test.fakeHTTPServer != nil {
			fakeServer = test.fakeHTTPServer()
			defer fakeServer.Close()
			s.vaultURL = fakeServer.URL
			for _, a := range s.data.Actions {
				a.EncryptionMeta.VaultURL = fmt.Sprintf("%s/api/vault/store/%s/%s", s.vaultURL, s.vaultClientUUID, a.UUID)
			}

		}

		action, err := s.DecryptAction(test.inputActionUUID)
		if test.expectedError {
			require.Error(t, err)
		} else {
			require.Nil(t, err)
		}
		require.Equal(t, test.expectedAction, action)
	}
}

func TestSave(t *testing.T) {
	tests := []struct {
		inputActions []*EncryptedAction
		expectedData string
		mockOsCreate func(string) (io.WriteCloser, error)
		shouldPanic  bool
	}{
		{
			inputActions: []*EncryptedAction{
				{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 20,
						Comment:      "test",
						Data:         "encrypted",
					},
					UUID:      "test",
					Processed: 1,
				},
			},
			mockOsCreate: func(string) (io.WriteCloser, error) { return nil, fmt.Errorf("mockOsCreate error") },
			shouldPanic:  true,
		},
		{
			inputActions: []*EncryptedAction{},
			mockOsCreate: func(string) (io.WriteCloser, error) {
				fw := &failWriter{}
				fw.On("Write", mock.Anything).Return(0, fmt.Errorf("failWriter error"))
				fw.On("Close").Return(nil)
				return &failFile{fw}, nil
			},
			shouldPanic: true,
		},
		{
			inputActions: []*EncryptedAction{
				{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 20,
						Comment:      "test",
						Data:         "encrypted",
					},
					UUID:      "test",
					Processed: 1,
				},
				{
					Action: Action{
						Kind:         "mail",
						ProcessAfter: 20,
						Comment:      "test",
						Data:         "encrypted2",
					},
					UUID:      "test2",
					Processed: 0,
				},
			},
			expectedData: `{"last_seen":"2025-03-26T14:55:40.119447+01:00","actions":[{"kind":"mail","process_after":20,"min_interval":0,"comment":"test","data":"encrypted","uuid":"test","processed":1,"last_run":"0001-01-01T00:00:00Z","encryption":{"kind":"","vault_url":""}},{"kind":"mail","process_after":20,"min_interval":0,"comment":"test","data":"encrypted2","uuid":"test2","processed":0,"last_run":"0001-01-01T00:00:00Z","encryption":{"kind":"","vault_url":""}}]}` + "\n",
		},
	}
	oldOsCreate := osCreate
	for _, test := range tests {
		osCreate = oldOsCreate
		defer func() {
			osCreate = oldOsCreate
		}()
		if test.mockOsCreate != nil {
			osCreate = test.mockOsCreate
		}

		os.Remove("test_state.json")
		defer os.Remove("test_state.json")

		mockTime, err := time.Parse("2006-01-02T15:04:05.999999-07:00", "2025-03-26T14:55:40.119447+01:00")
		require.Nil(t, err)

		s := &State{
			data: &data{
				LastSeen: mockTime,
			},
			savePath: "test_state.json",
		}
		s.data.Actions = test.inputActions

		if test.shouldPanic {
			require.Panics(t, s.save)
		} else {
			s.save()
			data, err := os.ReadFile("test_state.json")
			require.Nil(t, err)
			require.Equal(t, test.expectedData, string(data))
		}
	}
}
