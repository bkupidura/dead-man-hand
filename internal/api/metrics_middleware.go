package api

import (
	"net/http"
	"time"

	"dmh/internal/auth"
	"dmh/internal/metric"

	"github.com/go-chi/chi/v5/middleware"
)

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
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			next.ServeHTTP(ww, r)

			status := ww.Status()
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
