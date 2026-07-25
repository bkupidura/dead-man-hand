package api

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"dmh/internal/auth"

	"github.com/go-chi/chi/v5/middleware"
)

// apiLogFormatter logs the path only, never the query string or headers, so tokens and signatures never reach logs.
type apiLogFormatter struct{}

func (apiLogFormatter) NewLogEntry(r *http.Request) middleware.LogEntry {
	return &apiLogEntry{
		method: r.Method,
		path:   r.URL.Path,
		remote: r.RemoteAddr,
	}
}

type apiLogEntry struct {
	method   string
	path     string
	remote   string
	identity *auth.Identity
}

// identityFields formats e.identity for the log line, or "" if unset.
func (e *apiLogEntry) identityFields() string {
	if e.identity == nil {
		return ""
	}
	fields := ""
	if e.identity.Name != "" {
		fields += fmt.Sprintf(" identity=%s", e.identity.Name)
	}
	if e.identity.Type != "" {
		fields += fmt.Sprintf(" type=%s", e.identity.Type)
	}
	if e.identity.Reason != "" {
		fields += fmt.Sprintf(" reason=%s", e.identity.Reason)
	}
	return fields
}

// Write logs a single completed request.
func (e *apiLogEntry) Write(status, bytes int, header http.Header, elapsed time.Duration, extra any) {
	msg := fmt.Sprintf("http request %s %s from %s status=%d bytes=%d duration=%s", e.method, e.path, e.remote, status, bytes, elapsed)
	msg += e.identityFields()
	log.Print(msg)
}

// Panic logs the recovered panic, then prints the stack Recoverer would have.
func (e *apiLogEntry) Panic(v any, stack []byte) {
	msg := fmt.Sprintf("http request %s %s from %s panicked: %v", e.method, e.path, e.remote, v)
	msg += e.identityFields()
	log.Print(msg)
	middleware.PrintPrettyStack(v)
}

// logIdentity attaches the request's Identity to the log entry via chi
// GetLogEntry.
func logIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if entry, ok := middleware.GetLogEntry(r).(*apiLogEntry); ok {
			entry.identity = auth.IdentityFromContext(r.Context())
		}
		next.ServeHTTP(w, r)
	})
}
