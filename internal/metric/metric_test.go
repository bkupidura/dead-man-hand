package metric

import (
	"io/ioutil"
	"net/http/httptest"
	"reflect"
	"regexp"
	"testing"
	"time"

	"dmh/internal/state"

	"github.com/prometheus/client_golang/prometheus/promhttp"
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

func TestInitialize(t *testing.T) {
	tests := []struct {
		inputOpts             func() *Options
		expectedPromCollector func() *promCollector
	}{
		{
			inputOpts: func() *Options {
				s := new(mockState)
				return &Options{State: s}
			},
			expectedPromCollector: func() *promCollector {
				s := new(mockState)
				return &promCollector{chStop: make(chan bool), s: s}
			},
		},
	}

	for _, test := range tests {
		p := Initialize(test.inputOpts())
		p.chStop <- true
		expectedP := test.expectedPromCollector()
		require.Equal(t, expectedP.s, p.s)
		require.Equal(t, reflect.TypeOf(expectedP.chStop), reflect.TypeOf(p.chStop))
	}
}

func TestCollect(t *testing.T) {
	tests := []struct {
		inputPromCollector func() *promCollector
		expectedRegexp     []*regexp.Regexp
	}{
		{
			inputPromCollector: func() *promCollector {
				return &promCollector{chStop: make(chan bool), s: nil}
			},
			expectedRegexp: []*regexp.Regexp{},
		},
		{
			inputPromCollector: func() *promCollector {
				s := new(mockState)
				s.On("GetActions").Return([]*state.EncryptedAction{
					{},
					{},
					{Processed: 2},
				})
				return &promCollector{chStop: make(chan bool), s: s}
			},
			expectedRegexp: []*regexp.Regexp{
				regexp.MustCompile(`dmh_actions{processed="0"} 2`),
				regexp.MustCompile(`dmh_actions{processed="1"} 0`),
				regexp.MustCompile(`dmh_actions{processed="2"} 1`),
			},
		},
		{
			inputPromCollector: func() *promCollector {
				s := new(mockState)
				s.On("GetActions").Return([]*state.EncryptedAction{
					{Processed: 1},
					{Processed: 0},
					{Processed: 2},
				})
				return &promCollector{chStop: make(chan bool), s: s}
			},
			expectedRegexp: []*regexp.Regexp{
				regexp.MustCompile(`dmh_actions{processed="0"} 1`),
				regexp.MustCompile(`dmh_actions{processed="1"} 1`),
				regexp.MustCompile(`dmh_actions{processed="2"} 1`),
			},
		},
	}
	collectInterval = 1
	defer func() {
		collectInterval = 10
	}()

	for _, test := range tests {
		p := test.inputPromCollector()
		go p.collect()

		time.Sleep(time.Duration(collectInterval*2) * time.Second)
		p.chStop <- true

		req := httptest.NewRequest("GET", "/metrics", nil)
		w := httptest.NewRecorder()

		handler := promhttp.Handler()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		body, err := ioutil.ReadAll(resp.Body)
		require.Nil(t, err)

		for _, r := range test.expectedRegexp {
			require.True(t, r.MatchString(string(body)))
		}
	}
}
