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
	require.Nil(t, apiEntry.identity)
}

func TestApiLogEntryIdentityFields(t *testing.T) {
	tests := []struct {
		inputIdentity *auth.Identity
		expectedField string
	}{
		{
			inputIdentity: nil,
			expectedField: "",
		},
		{
			inputIdentity: &auth.Identity{},
			expectedField: "",
		},
		{
			inputIdentity: &auth.Identity{Name: "admin"},
			expectedField: " identity=admin",
		},
		{
			inputIdentity: &auth.Identity{Type: auth.AuthTypeBearer},
			expectedField: " type=bearer",
		},
		{
			inputIdentity: &auth.Identity{Reason: "invalid_token"},
			expectedField: " reason=invalid_token",
		},
		{
			inputIdentity: &auth.Identity{Name: "admin", Type: auth.AuthTypeBearer},
			expectedField: " identity=admin type=bearer",
		},
		{
			inputIdentity: &auth.Identity{Type: auth.AuthTypeBearer, Reason: "invalid_token"},
			expectedField: " type=bearer reason=invalid_token",
		},
		{
			inputIdentity: &auth.Identity{Name: "admin", Type: auth.AuthTypeBearer, Reason: "insufficient_scope"},
			expectedField: " identity=admin type=bearer reason=insufficient_scope",
		},
	}
	for _, test := range tests {
		entry := &apiLogEntry{identity: test.inputIdentity}
		require.Equal(t, test.expectedField, entry.identityFields())
	}
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
			expectedExclude: []string{"identity=", "type=", "reason="},
		},
		{
			inputEntry:      &apiLogEntry{method: "GET", path: "/api/action/store", remote: "1.2.3.4"},
			inputStatus:     http.StatusUnauthorized,
			expectedContain: []string{"status=401"},
			expectedExclude: []string{"identity=", "type=", "reason="},
		},
		{
			inputEntry:      &apiLogEntry{method: "GET", path: "/api/action/store", remote: "1.2.3.4", identity: &auth.Identity{Name: "admin", Type: auth.AuthTypeBearer}},
			inputStatus:     http.StatusOK,
			expectedContain: []string{"status=200", "identity=admin", "type=bearer"},
			expectedExclude: []string{"reason="},
		},
		{
			inputEntry:      &apiLogEntry{method: "GET", path: "/api/action/store", remote: "1.2.3.4", identity: &auth.Identity{Type: auth.AuthTypeBearer, Reason: "invalid_token"}},
			inputStatus:     http.StatusUnauthorized,
			expectedContain: []string{"status=401", "type=bearer", "reason=invalid_token"},
			expectedExclude: []string{"identity="},
		},
		{
			inputEntry:      &apiLogEntry{method: "GET", path: "/api/action/store", remote: "1.2.3.4", identity: &auth.Identity{Name: "admin", Type: auth.AuthTypeBearer, Reason: "insufficient_scope"}},
			inputStatus:     http.StatusUnauthorized,
			expectedContain: []string{"status=401", "identity=admin", "type=bearer", "reason=insufficient_scope"},
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
	entry := &apiLogEntry{method: "GET", path: "/api/action/store", remote: "1.2.3.4", identity: &auth.Identity{Name: "admin"}}

	buf := &bytes.Buffer{}
	log.SetOutput(buf)
	defer log.SetOutput(os.Stderr)

	require.NotPanics(t, func() { entry.Panic("boom", []byte("stack")) })
	require.Contains(t, buf.String(), "panicked: boom")
	require.Contains(t, buf.String(), "identity=admin")
}

func TestApiLogEntryWriteReflectsLaterIdentityMutation(t *testing.T) {
	identity := &auth.Identity{Name: "admin", Type: auth.AuthTypeBearer}
	entry := &apiLogEntry{method: "GET", path: "/api/action/store", remote: "1.2.3.4", identity: identity}

	identity.Reason = "insufficient_scope"

	buf := &bytes.Buffer{}
	log.SetOutput(buf)
	defer log.SetOutput(os.Stderr)

	entry.Write(http.StatusUnauthorized, 10, http.Header{}, time.Millisecond, nil)

	require.Contains(t, buf.String(), "identity=admin")
	require.Contains(t, buf.String(), "reason=insufficient_scope")
}

func TestLogIdentity(t *testing.T) {
	tests := []struct {
		inputIdentity *auth.Identity
	}{
		{},
		{
			inputIdentity: &auth.Identity{Name: "admin", Scopes: []string{"api"}},
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
		if test.inputIdentity == nil {
			require.Nil(t, entry.identity)
		} else {
			require.Same(t, test.inputIdentity, entry.identity)
		}
	}
}

func TestLogIdentityNoEntry(t *testing.T) {
	req := httptest.NewRequest("GET", "/x", nil)
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{Name: "admin"}))

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	require.NotPanics(t, func() {
		logIdentity(next).ServeHTTP(httptest.NewRecorder(), req)
	})
	require.True(t, called)
}
