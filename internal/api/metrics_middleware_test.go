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
