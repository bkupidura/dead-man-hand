package api

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"dmh/internal/auth"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/require"
)

func TestApiLogFormatterNewLogEntry(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/action/store?e=abc&s=secret", nil)
	entry := apiLogFormatter{}.NewLogEntry(req)
	apiEntry, ok := entry.(*apiLogEntry)
	require.True(t, ok)
	require.Equal(t, "GET", apiEntry.method)
	require.Equal(t, "/api/action/store", apiEntry.path)
	require.Equal(t, "", apiEntry.identity)
}

func TestApiLogEntryWrite(t *testing.T) {
	tests := []struct {
		inputEntry      *apiLogEntry
		inputStatus     int
		expectedContain []string
		expectedExclude []string
	}{
		{
			inputEntry:      &apiLogEntry{method: "GET", path: "/api/action/store", remote: "1.2.3.4"},
			inputStatus:     http.StatusOK,
			expectedContain: []string{"GET /api/action/store", "from 1.2.3.4", "status=200"},
			expectedExclude: []string{"identity="},
		},
		{
			inputEntry:      &apiLogEntry{method: "GET", path: "/api/action/store", remote: "1.2.3.4"},
			inputStatus:     http.StatusUnauthorized,
			expectedContain: []string{"status=401"},
			expectedExclude: []string{"identity="},
		},
		{
			inputEntry:      &apiLogEntry{method: "GET", path: "/api/action/store", remote: "1.2.3.4", identity: "admin"},
			inputStatus:     http.StatusUnauthorized,
			expectedContain: []string{"status=401", "identity=admin"},
		},
		{
			inputEntry:      &apiLogEntry{method: "GET", path: "/api/action/store", remote: "1.2.3.4", identity: "admin"},
			inputStatus:     http.StatusOK,
			expectedContain: []string{"status=200", "identity=admin"},
		},
	}
	for _, test := range tests {
		buf := &bytes.Buffer{}
		log.SetOutput(buf)
		defer log.SetOutput(os.Stderr)

		test.inputEntry.Write(test.inputStatus, 10, http.Header{}, time.Millisecond, nil)

		for _, s := range test.expectedContain {
			require.Contains(t, buf.String(), s)
		}
		for _, s := range test.expectedExclude {
			require.NotContains(t, buf.String(), s)
		}
	}
}

func TestApiLogEntryPanic(t *testing.T) {
	entry := &apiLogEntry{method: "GET", path: "/api/action/store", remote: "1.2.3.4", identity: "admin"}

	buf := &bytes.Buffer{}
	log.SetOutput(buf)
	defer log.SetOutput(os.Stderr)

	require.NotPanics(t, func() { entry.Panic("boom", []byte("stack")) })
	require.Contains(t, buf.String(), "panicked: boom")
	require.Contains(t, buf.String(), "identity=admin")
}

func TestLogIdentity(t *testing.T) {
	tests := []struct {
		inputIdentity    *auth.Identity
		expectedIdentity string
	}{
		{
			expectedIdentity: "",
		},
		{
			inputIdentity:    &auth.Identity{Name: "admin", Scopes: []string{"api"}},
			expectedIdentity: "admin",
		},
	}
	for _, test := range tests {
		entry := &apiLogEntry{method: "GET", path: "/x"}

		req := httptest.NewRequest("GET", "/x", nil)
		req = middleware.WithLogEntry(req, entry)
		if test.inputIdentity != nil {
			req = req.WithContext(auth.ContextWithIdentity(req.Context(), test.inputIdentity))
		}

		var called bool
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

		logIdentity(next).ServeHTTP(httptest.NewRecorder(), req)

		require.True(t, called)
		require.Equal(t, test.expectedIdentity, entry.identity)
	}
}

func TestLogIdentityNoEntry(t *testing.T) {
	// No log entry in context (eg. Logger not wired up): must not panic, must still call next.
	req := httptest.NewRequest("GET", "/x", nil)
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{Name: "admin"}))

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	require.NotPanics(t, func() {
		logIdentity(next).ServeHTTP(httptest.NewRecorder(), req)
	})
	require.True(t, called)
}
