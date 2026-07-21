package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"dmh/internal/auth"
	"dmh/internal/metric"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/require"
)

// plainResponseWriter implements only http.ResponseWriter, not http.Flusher.
type plainResponseWriter struct {
	header http.Header
}

func (p *plainResponseWriter) Header() http.Header         { return p.header }
func (p *plainResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (p *plainResponseWriter) WriteHeader(int)             {}

func TestStatusRecorderWriteHeader(t *testing.T) {
	tests := []struct {
		inputCode int
	}{
		{inputCode: http.StatusOK},
		{inputCode: http.StatusUnauthorized},
		{inputCode: http.StatusInternalServerError},
	}
	for _, test := range tests {
		w := httptest.NewRecorder()
		rec := &statusRecorder{ResponseWriter: w}

		rec.WriteHeader(test.inputCode)

		require.Equal(t, test.inputCode, rec.status)
		require.Equal(t, test.inputCode, w.Code)
	}
}

func TestStatusRecorderWrite(t *testing.T) {
	tests := []struct {
		inputPreWriteHeader int // 0 means WriteHeader was never called first
		expectedStatus      int
	}{
		{
			inputPreWriteHeader: 0,
			expectedStatus:      http.StatusOK,
		},
		{
			inputPreWriteHeader: http.StatusCreated,
			expectedStatus:      http.StatusCreated,
		},
	}
	for _, test := range tests {
		w := httptest.NewRecorder()
		rec := &statusRecorder{ResponseWriter: w}
		if test.inputPreWriteHeader != 0 {
			rec.WriteHeader(test.inputPreWriteHeader)
		}

		n, err := rec.Write([]byte("body"))

		require.Nil(t, err)
		require.Equal(t, 4, n)
		require.Equal(t, test.expectedStatus, rec.status)
		require.Equal(t, "body", w.Body.String())
	}
}

func TestStatusRecorderFlush(t *testing.T) {
	fw := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: fw}
	require.NotPanics(t, rec.Flush)
	require.True(t, fw.Flushed)

	rec2 := &statusRecorder{ResponseWriter: &plainResponseWriter{header: http.Header{}}}
	require.NotPanics(t, rec2.Flush)
}

func TestMetricsMiddleware(t *testing.T) {
	tests := []struct {
		inputSeedIdentity bool
		inputNilMetric    bool
		inputNext         http.HandlerFunc
		expectedStatus    int
		expectedContain   []string
		expectedExclude   []string
	}{
		{
			inputSeedIdentity: false,
			inputNext: func(w http.ResponseWriter, r *http.Request) {
				require.Nil(t, auth.IdentityFromContext(r.Context()))
				w.WriteHeader(http.StatusOK)
			},
			expectedStatus:  http.StatusOK,
			expectedContain: []string{`dmh_http_requests_total{code="200",method="GET"} 1`},
			expectedExclude: []string{"dmh_auth_success_total", "dmh_auth_failures_total"},
		},
		{
			inputSeedIdentity: true,
			inputNext: func(w http.ResponseWriter, r *http.Request) {
				auth.IdentityFromContext(r.Context()).Type = auth.AuthTypeBearer
				w.WriteHeader(http.StatusOK)
			},
			expectedStatus:  http.StatusOK,
			expectedContain: []string{`dmh_http_requests_total{code="200",method="GET"} 1`, `dmh_auth_success_total{type="bearer"} 1`},
			expectedExclude: []string{"dmh_auth_failures_total"},
		},
		{
			inputSeedIdentity: true,
			inputNext: func(w http.ResponseWriter, r *http.Request) {
				id := auth.IdentityFromContext(r.Context())
				id.Type = auth.AuthTypeBearer
				id.Reason = "invalid_token"
				w.WriteHeader(http.StatusUnauthorized)
			},
			expectedStatus:  http.StatusUnauthorized,
			expectedContain: []string{`dmh_http_requests_total{code="401",method="GET"} 1`, `dmh_auth_failures_total{reason="invalid_token",type="bearer"} 1`},
			expectedExclude: []string{"dmh_auth_success_total"},
		},
		{
			inputSeedIdentity: false,
			inputNext:         func(w http.ResponseWriter, r *http.Request) {},
			expectedStatus:    http.StatusOK,
			expectedContain:   []string{`dmh_http_requests_total{code="200",method="GET"} 1`},
		},
		{
			inputSeedIdentity: true,
			inputNilMetric:    true,
			inputNext:         func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) },
			expectedStatus:    http.StatusOK,
		},
	}

	for _, test := range tests {
		var p *metric.PromCollector
		var registry *prometheus.Registry
		if !test.inputNilMetric {
			registry = prometheus.NewRegistry()
			p = metric.Initialize(&metric.Options{Registry: registry})
		}

		handler := metricsMiddleware(p)(test.inputNext)

		req := httptest.NewRequest("GET", "/x", nil)
		if test.inputSeedIdentity {
			req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{}))
		}
		w := httptest.NewRecorder()
		require.NotPanics(t, func() { handler.ServeHTTP(w, req) })

		require.Equal(t, test.expectedStatus, w.Code)

		if registry == nil {
			continue
		}
		p.Stop()

		mreq := httptest.NewRequest("GET", "/metrics", nil)
		mw := httptest.NewRecorder()
		promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(mw, mreq)
		body := mw.Body.String()

		for _, s := range test.expectedContain {
			require.Contains(t, body, s)
		}
		for _, s := range test.expectedExclude {
			require.NotContains(t, body, s)
		}
	}
}
