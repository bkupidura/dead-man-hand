package api

import (
	"net/http"
	"time"

	"dmh/internal/auth"
	"dmh/internal/metric"
)

// statusRecorder captures the response status code written by the handler.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// Flush forwards to the underlying writer so streaming endpoints (e.g. /metrics)
// keep working through this recorder.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// metricsMiddleware records HTTP and auth metrics.
// It only reads the outcome, never builds it: Identity is seeded upstream by
// auth.SeedIdentity (nil when auth is disabled). The pointer is grabbed before
// next() so the auth chain's in-place writes stay visible even when Authorizer
// denies without calling next.
func metricsMiddleware(p *metric.PromCollector) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p == nil {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()
			id := auth.IdentityFromContext(r.Context())
			rec := &statusRecorder{ResponseWriter: w}

			next.ServeHTTP(rec, r)

			status := rec.status
			if status == 0 {
				status = http.StatusOK
			}
			p.RecordHTTPRequest(r.Method, status, time.Since(start))

			if id == nil {
				return
			}
			if id.Reason == "" {
				p.RecordAuthSuccess(string(id.Type))
			} else {
				p.RecordAuthFailure(string(id.Type), id.Reason)
			}
		})
	}
}
