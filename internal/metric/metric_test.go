package metric

import (
	"fmt"
	"io"
	"net/http/httptest"
	"reflect"
	"regexp"
	"testing"
	"time"

	"github.com/google/uuid"

	"dmh/internal/state"

	"github.com/prometheus/client_golang/prometheus"
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

func (m *mockState) UpdateActionLastRun(uuid string) error {
	args := m.Called(uuid)
	return args.Error(0)
}

func (m *mockState) GetActionLastRun(uuid string) (time.Time, error) {
	args := m.Called(uuid)
	return args.Get(0).(time.Time), args.Error(1)
}

func TestInitialize(t *testing.T) {
	tests := []struct {
		inputOpts             func() *Options
		expectedPromCollector func() *promCollector
	}{
		{
			inputOpts: func() *Options {
				reg := prometheus.NewRegistry()
				s := new(mockState)
				return &Options{State: s, Registry: reg}
			},
			expectedPromCollector: func() *promCollector {
				s := new(mockState)
				return &promCollector{chStop: make(chan bool), s: s}
			},
		},
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
		require.NotNil(t, p.dmhActions)
		require.NotNil(t, p.dmhMissingSecretsTotal)
		require.IsType(t, &prometheus.GaugeVec{}, p.dmhActions)
		require.IsType(t, &prometheus.CounterVec{}, p.dmhMissingSecretsTotal)
	}
}

func TestCollect(t *testing.T) {
	tests := []struct {
		inputOptions   func() *Options
		expectedRegexp []*regexp.Regexp
	}{
		{
			inputOptions: func() *Options {
				reg := prometheus.NewRegistry()
				return &Options{State: nil, Registry: reg}
			},
			expectedRegexp: []*regexp.Regexp{},
		},
		{
			inputOptions: func() *Options {
				reg := prometheus.NewRegistry()
				s := new(mockState)
				s.On("GetActions").Return([]*state.EncryptedAction{
					{},
					{},
					{Processed: 2},
				})
				return &Options{State: s, Registry: reg}
			},
			expectedRegexp: []*regexp.Regexp{
				regexp.MustCompile(`dmh_actions{processed="0"} 2`),
				regexp.MustCompile(`dmh_actions{processed="1"} 0`),
				regexp.MustCompile(`dmh_actions{processed="2"} 1`),
			},
		},
		{
			inputOptions: func() *Options {
				reg := prometheus.NewRegistry()
				s := new(mockState)
				s.On("GetActions").Return([]*state.EncryptedAction{
					{Processed: 1},
					{Processed: 0},
					{Processed: 2},
				})
				return &Options{State: s, Registry: reg}
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
		opts := test.inputOptions()
		p := Initialize(opts)
		go p.collect()
		time.Sleep(time.Duration(collectInterval*2) * time.Second)
		p.chStop <- true

		req := httptest.NewRequest("GET", "/metrics", nil)
		w := httptest.NewRecorder()
		handler := promhttp.HandlerFor(opts.Registry.(prometheus.Gatherer), promhttp.HandlerOpts{})
		handler.ServeHTTP(w, req)

		resp := w.Result()
		body, err := io.ReadAll(resp.Body)
		require.Nil(t, err)

		for _, r := range test.expectedRegexp {
			require.True(t, r.MatchString(string(body)))
		}
	}
}
func TestUpdateDMHMissingSecrets(t *testing.T) {
	tests := []struct {
		InputIncrements []int
		expectedTotal   float64
	}{
		{InputIncrements: []int{1}, expectedTotal: 1},
		{InputIncrements: []int{2, 3}, expectedTotal: 5},
		{InputIncrements: []int{0}, expectedTotal: 0},
		{InputIncrements: []int{4, 1, 2}, expectedTotal: 7},
	}

	for _, test := range tests {
		opts := &Options{State: nil, Registry: prometheus.NewRegistry()}
		p := Initialize(opts)
		actionUUID := uuid.NewString()
		for _, inc := range test.InputIncrements {
			p.UpdateDMHMissingSecrets(actionUUID, inc)
		}

		req := httptest.NewRequest("GET", "/metrics", nil)
		w := httptest.NewRecorder()
		handler := promhttp.HandlerFor(opts.Registry.(prometheus.Gatherer), promhttp.HandlerOpts{})
		handler.ServeHTTP(w, req)

		resp := w.Result()
		body, err := io.ReadAll(resp.Body)
		require.Nil(t, err)

		require.Regexp(t,
			regexp.MustCompile(fmt.Sprintf(`dmh_missing_secrets_total{action="%s"} %v`, actionUUID, test.expectedTotal)),
			string(body),
		)
	}
}
