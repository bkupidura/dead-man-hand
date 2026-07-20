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
	identity string
}

// Write logs a single completed request.
func (e *apiLogEntry) Write(status, bytes int, header http.Header, elapsed time.Duration, extra any) {
	msg := fmt.Sprintf("http request %s %s from %s status=%d bytes=%d duration=%s", e.method, e.path, e.remote, status, bytes, elapsed)
	if e.identity != "" {
		msg += fmt.Sprintf(" identity=%s", e.identity)
	}
	log.Print(msg)
}

// Panic logs the recovered panic, then prints the stack Recoverer would have.
func (e *apiLogEntry) Panic(v any, stack []byte) {
	msg := fmt.Sprintf("http request %s %s from %s panicked: %v", e.method, e.path, e.remote, v)
	if e.identity != "" {
		msg += fmt.Sprintf(" identity=%s", e.identity)
	}
	log.Print(msg)
	middleware.PrintPrettyStack(v)
}

// logIdentity attaches Identity to the log entry via chi's GetLogEntry.
// Runs before Authorizer, so a denied request still logs which token it was.
func logIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if entry, ok := middleware.GetLogEntry(r).(*apiLogEntry); ok {
			if id := auth.IdentityFromContext(r.Context()); id != nil {
				entry.identity = id.Name
			}
		}
		next.ServeHTTP(w, r)
	})
}
