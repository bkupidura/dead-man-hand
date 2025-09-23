package metric

import (
	"fmt"
	"io"
	"net/http"
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
		expectedPromCollector func() *PromCollector
	}{
		{
			inputOpts: func() *Options {
				reg := prometheus.NewRegistry()
				s := new(mockState)
				return &Options{State: s, Registry: reg}
			},
			expectedPromCollector: func() *PromCollector {
				s := new(mockState)
				return &PromCollector{chStop: make(chan bool), s: s}
			},
		},
		{
			inputOpts: func() *Options {
				s := new(mockState)
				return &Options{State: s}
			},
			expectedPromCollector: func() *PromCollector {
				s := new(mockState)
				return &PromCollector{chStop: make(chan bool), s: s}
			},
		},
	}

	for _, test := range tests {
		p := Initialize(test.inputOpts())
		p.chStop <- true
		p.chSlowStop <- true
		expectedP := test.expectedPromCollector()
		require.Equal(t, expectedP.s, p.s)
		require.Equal(t, reflect.TypeOf(expectedP.chStop), reflect.TypeOf(p.chStop))
		require.NotNil(t, p.dmhActions)
		require.NotNil(t, p.dmhMissingSecretsTotal)
		require.NotNil(t, p.dmhActionErrorsTotal)
		require.IsType(t, &prometheus.GaugeVec{}, p.dmhActions)
		require.IsType(t, &prometheus.CounterVec{}, p.dmhMissingSecretsTotal)
		require.IsType(t, &prometheus.CounterVec{}, p.dmhActionErrorsTotal)
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

		time.Sleep(time.Duration(collectInterval*2) * time.Second)
		p.chStop <- true
		p.chSlowStop <- true

		req := httptest.NewRequest("GET", "/metrics", nil)
		w := httptest.NewRecorder()
		handler := promhttp.HandlerFor(opts.Registry.(prometheus.Gatherer), promhttp.HandlerOpts{})
		handler.ServeHTTP(w, req)

		resp := w.Result()
		body, err := io.ReadAll(resp.Body)
		require.Nil(t, err)

		for _, r := range test.expectedRegexp {
			require.Regexp(t, r, string(body))
		}
	}
}

func TestCollectSlow(t *testing.T) {
	tests := []struct {
		inputOptions      func() *Options
		expectedRegexp    []*regexp.Regexp
		notExpectedRegexp []*regexp.Regexp
	}{
		{
			inputOptions: func() *Options {
				reg := prometheus.NewRegistry()
				server200 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(200)
				}))
				s := new(mockState)
				s.On("GetActions").Return([]*state.EncryptedAction{
					{Processed: 0, UUID: "uuid1", EncryptionMeta: state.EncryptionMeta{VaultURL: server200.URL}},
				})
				return &Options{State: s, Registry: reg}
			},
			expectedRegexp: []*regexp.Regexp{},
			notExpectedRegexp: []*regexp.Regexp{
				regexp.MustCompile(`dmh_missing_secrets_total{action="uuid1"}`),
			},
		},
		{
			inputOptions: func() *Options {
				reg := prometheus.NewRegistry()
				server423 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(423)
				}))
				s := new(mockState)
				s.On("GetActions").Return([]*state.EncryptedAction{
					{Processed: 0, UUID: "uuid1", EncryptionMeta: state.EncryptionMeta{VaultURL: server423.URL}},
				})
				return &Options{State: s, Registry: reg}
			},
			expectedRegexp: []*regexp.Regexp{},
			notExpectedRegexp: []*regexp.Regexp{
				regexp.MustCompile(`dmh_missing_secrets_total{action="uuid1"}`),
			},
		},
		{
			inputOptions: func() *Options {
				reg := prometheus.NewRegistry()
				s := new(mockState)
				s.On("GetActions").Return([]*state.EncryptedAction{
					{Processed: 0, UUID: "uuid1", EncryptionMeta: state.EncryptionMeta{VaultURL: ""}},
				})
				return &Options{State: s, Registry: reg}
			},
			expectedRegexp: []*regexp.Regexp{
				regexp.MustCompile(`dmh_missing_secrets_total{action="uuid1"} 1`),
			},
			notExpectedRegexp: []*regexp.Regexp{},
		},
		{
			inputOptions: func() *Options {
				reg := prometheus.NewRegistry()
				s := new(mockState)
				s.On("GetActions").Return([]*state.EncryptedAction{
					{Processed: 0, UUID: "uuid1", EncryptionMeta: state.EncryptionMeta{VaultURL: "http://invalid-url"}},
				})
				return &Options{State: s, Registry: reg}
			},
			expectedRegexp: []*regexp.Regexp{
				regexp.MustCompile(`dmh_missing_secrets_total{action="uuid1"} 1`),
			},
			notExpectedRegexp: []*regexp.Regexp{},
		},
		{
			inputOptions: func() *Options {
				reg := prometheus.NewRegistry()
				server500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(500)
				}))
				s := new(mockState)
				s.On("GetActions").Return([]*state.EncryptedAction{
					{Processed: 0, UUID: "uuid1", EncryptionMeta: state.EncryptionMeta{VaultURL: server500.URL}},
				})
				return &Options{State: s, Registry: reg}
			},
			expectedRegexp: []*regexp.Regexp{
				regexp.MustCompile(`dmh_missing_secrets_total{action="uuid1"} 1`),
			},
			notExpectedRegexp: []*regexp.Regexp{},
		},
		{
			inputOptions: func() *Options {
				reg := prometheus.NewRegistry()
				server404 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(404)
				}))
				s := new(mockState)
				s.On("GetActions").Return([]*state.EncryptedAction{
					{Processed: 0, UUID: "uuid1", EncryptionMeta: state.EncryptionMeta{VaultURL: server404.URL}},
				})
				return &Options{State: s, Registry: reg}
			},
			expectedRegexp: []*regexp.Regexp{
				regexp.MustCompile(`dmh_missing_secrets_total{action="uuid1"} 1`),
			},
			notExpectedRegexp: []*regexp.Regexp{},
		},
		{
			inputOptions: func() *Options {
				reg := prometheus.NewRegistry()
				server200 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(200)
				}))
				server423 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(423)
				}))
				server500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(500)
				}))
				s := new(mockState)
				s.On("GetActions").Return([]*state.EncryptedAction{
					{Processed: 0, UUID: "uuid1", EncryptionMeta: state.EncryptionMeta{VaultURL: ""}},
					{Processed: 1, UUID: "uuid2", EncryptionMeta: state.EncryptionMeta{VaultURL: server423.URL}},
					{Processed: 0, UUID: "uuid3", EncryptionMeta: state.EncryptionMeta{VaultURL: server200.URL}},
					{Processed: 0, UUID: "uuid4", EncryptionMeta: state.EncryptionMeta{VaultURL: server500.URL}},
					{Processed: 2, UUID: "uuid5", EncryptionMeta: state.EncryptionMeta{VaultURL: "http://invalid-url"}},
					{Processed: 0, UUID: "uuid6", EncryptionMeta: state.EncryptionMeta{VaultURL: "http://invalid-url"}},
				})
				return &Options{State: s, Registry: reg}
			},
			expectedRegexp: []*regexp.Regexp{
				regexp.MustCompile(`dmh_missing_secrets_total{action="uuid1"} 1`),
				regexp.MustCompile(`dmh_missing_secrets_total{action="uuid4"} 1`),
				regexp.MustCompile(`dmh_missing_secrets_total{action="uuid6"} 1`),
			},
			notExpectedRegexp: []*regexp.Regexp{
				regexp.MustCompile(`dmh_missing_secrets_total{action="uuid2"}`),
				regexp.MustCompile(`dmh_missing_secrets_total{action="uuid3"}`),
				regexp.MustCompile(`dmh_missing_secrets_total{action="uuid5"}`),
			},
		},
	}
	collectSlowInterval = 2
	collectSlowUnit = time.Second
	defer func() {
		collectSlowInterval = 12
		collectSlowUnit = time.Hour
	}()

	for _, test := range tests {
		opts := test.inputOptions()
		p := Initialize(opts)

		time.Sleep(time.Duration(collectSlowInterval+1) * time.Second)
		p.chStop <- true
		p.chSlowStop <- true

		req := httptest.NewRequest("GET", "/metrics", nil)
		w := httptest.NewRecorder()
		handler := promhttp.HandlerFor(opts.Registry.(prometheus.Gatherer), promhttp.HandlerOpts{})
		handler.ServeHTTP(w, req)

		resp := w.Result()
		body, err := io.ReadAll(resp.Body)
		require.Nil(t, err)

		for _, r := range test.expectedRegexp {
			require.Regexp(t, r, string(body))
		}
		if test.notExpectedRegexp != nil {
			for _, r := range test.notExpectedRegexp {
				require.NotRegexp(t, r, string(body))
			}
		}
	}
}

func TestDMHActionErrorsTotal(t *testing.T) {
	tests := []struct {
		inputActionUUID string
		inputErrorLabel string
		inputIncrements []int
		expected        float64
	}{
		{uuid.NewString(), "timeout", []int{1, 2}, 3},
		{uuid.NewString(), "not_found", []int{5}, 5},
		{uuid.NewString(), "internal", []int{0, 0, 1}, 1},
	}

	for _, test := range tests {
		opts := &Options{State: nil, Registry: prometheus.NewRegistry()}
		p := Initialize(opts)

		for _, inc := range test.inputIncrements {
			p.UpdateDMHActionErrors(test.inputActionUUID, test.inputErrorLabel, inc)
		}

		req := httptest.NewRequest("GET", "/metrics", nil)
		w := httptest.NewRecorder()

		handler := promhttp.HandlerFor(opts.Registry.(prometheus.Gatherer), promhttp.HandlerOpts{})
		handler.ServeHTTP(w, req)

		resp := w.Result()
		body, err := io.ReadAll(resp.Body)
		require.Nil(t, err)

		require.Regexp(t,
			regexp.MustCompile(fmt.Sprintf(`dmh_action_errors_total{action=\"%s\",error=\"%s\"} %v`, test.inputActionUUID, test.inputErrorLabel, test.expected)),
			string(body),
		)
	}
}
