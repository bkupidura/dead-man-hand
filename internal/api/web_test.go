package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAliveWebHandler(t *testing.T) {
	req, err := http.NewRequest("GET", "/alive", nil)
	require.Nil(t, err)
	w := httptest.NewRecorder()

	handler := aliveWebHandler()

	handler(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"))
	require.Contains(t, w.Body.String(), `<button id="alive">`)
	require.Contains(t, w.Body.String(), `fetch("/alive", {method: "POST"})`)
}
