//go:build integration
// +build integration

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"dmh/internal/api"
	"dmh/internal/crypt"
	"dmh/internal/metric"
	"dmh/internal/state"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// Token hashes are used in test configs.
const (
	userBearerToken    = "example-bearer-token"
	vaultBearerToken   = "test-token"
	sigAuthBearerToken = "sig-auth-test-token"
)

// authRequest sends HTTP request with bearer token.
func authRequest(method string, url string, token string, body []byte) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewBuffer(body)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return http.DefaultClient.Do(req)
}

// syncBuffer is goroutine safe bytes.Buffer for capturing logs.
type syncBuffer struct {
	mtx sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	return b.buf.String()
}

func TestDMH(t *testing.T) {
	stateFile := "integration_test_state.json"
	vaultFile := "integration_test_vault.json"
	configFile := "integration_test_config.yaml"
	clientUUID := "integration-test-client-uuid"
	requiredEnvs := map[string]string{"DMH_CONFIG_FILE": configFile, "DMH_COMPONENTS": "dmh,vault"}

	getActionsInterval = 1
	getActionsIntervalUnit = time.Second

	f, err := os.Create(stateFile)
	defer os.Remove(stateFile)
	require.Nil(t, err)
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf(`{"last_seen":"2025-03-26T14:55:40.119447+01:00","actions":[{"kind":"json_post","process_after":1,"min_interval":0,"comment":"missing-encryption-key-from-vault","data":"YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBMUktTQjM0bFJOTDhWa05JcHdLUzM4dlBXRVQ2eklSdmdrenh4ejRJVHlJClRMWWJnZ1JaKzdTSG5QeFREZVRYdXRjWjFRa3ZLRE9ZY2NkRVo2TytrdGMKLS0tIDNoMWtzeXpiQ1JWKy9ZbHhqeHJuMjYxR2NlblZkZlIwRWRzOUJCNDZPNXcK+D+heGeg32Eym2D3wQU0evdTvRzmGvbw8cf5ukIwYyKINpu4raClZKgn5sfb4pkgqxYR+TaF4oBW3D9Jt0cZMRn5mL7pOWxDgvLMkhES3hk6U0Nfu+9SKODtipqPQubJw4gHDrw3INYjK5jVNYVcITjXzHbBMTiaZD7jNCmPH20Xrw==","uuid":"bf577b9d-26f4-4168-b8e4-0e1d692559ed","processed":0,"last_run":"0001-01-01T00:00:00Z","encryption":{"kind":"X25519","vault_url":"http://127.0.0.1:8080/api/vault/store/%s/bf577b9d-26f4-4168-b8e4-0e1d692559ed"}},{"uuid":"9acc344e-a65b-4675-9723-5664c0e73c76","kind":"json_post","data":"YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSAvb2JISGVZS3lEcmlsenlaeUFnbHRDYjJTK1FLSVdLSWkvYjhwSjRXeEg4CmxNT0YrVCtjNUZRWi9HS2d4MFFiN3AwVDlRc0k1eVJsbXBqWHhMRFhTWE0KLS0tIE12NktMSlVGVC9LMlpTRGFjZ2FRVXhpcEJjdmwyUExCL2tGaGJtZFhyc1UKfx25yewZmc6eVeuX7ufIN2vmFR/hXldbY1LW1UwNMH/AqPToZ2ZKTYdqhA7+ZtF8mOyduvsLVX1siaatb0VC4kmGdIr2DiPlVyCbcGNwTgNqjPs5RNkcqQB9DITQPfGdmGRh3OP3t16FFT91zVWDRDRVbFnSEKfeusg33wDHlsd1E99RrVPAK5TpT6wGykDCCW66Xwh8YNYkFb4s2f0PSIsE/r7bxR4mq1VNbBuV0eRo5uz9WAiR7NyH","process_after":1,"comment":"","processed":0, "encryption": {"kind":"X25519","vault_url":"http://127.0.0.1:8080/api/vault/store/%s/9acc344e-a65b-4675-9723-5664c0e73c76"}},{"uuid":"7df7c024-d0a8-4183-83fa-373ea4a7735a","kind":"json_post","data":"YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBJSmIxTlBZZ1dqZlVqY2RBTjg1YjRlWEVCNjFXMFVac0EwdWczVXYxblZ3CmFPNjl5THJ6Q0ZxaGdxU2RmZlBUdXdwVjJ2ajNoSUxPSitxYStFSVBMOTQKLS0tIExpQVFsZ1p6Vy9TWVllY1NUYmt4M1BrZGV6Yk5mUkNhQURFRUhaU3BCazgKeLCm87tFZiyWy1pBgfmZnrNK/BygpARjcOz30EeA7pUnS3bAleWKsOoO+mOrYUXt4FxvS8s7botqWYvqJBU18ctHRZshxQLaz5q240EsOsBWGvxZN1rn1SonO5DsBxxrPvJJmbyI47lXpaScrnSE1eotvgt0zWDc58kkgMGgBxiMYjqQXdFylwp5WU+Q9JThCakt+QsQP9X5MRvPfPWOg9a9Kw==","process_after":10,"comment":"test","processed":2, "encryption": {"kind":"X25519","vault_url":"http://127.0.0.1:8080/api/vault/store/%s/7df7c024-d0a8-4183-83fa-373ea4a7735a"}}]}`, clientUUID, clientUUID, clientUUID))
	require.Nil(t, err)

	f, err = os.Create(vaultFile)
	defer os.Remove(vaultFile)
	require.Nil(t, err)
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf(`{"%s":{"last_seen": "2025-03-26T14:55:40.119447+01:00", "secrets": {"9acc344e-a65b-4675-9723-5664c0e73c76": {"key": "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBGMDl6R0dQOGQxWUFOS21URENNRklBWVp0R2xMdzM0OGgwTDlOMmJieWxnCnJ4WS9IOUlBYmNvZDNqbm5Ua3d2R2hsemNmL2doQWZ6RjVDS0NUZ0RjTzAKLS0tIEE3UVoyYXh0MjJramFieWZab3Fmc1BSZThISGhkaTVzWmM4L1NQSUlYQ0EKcwoFDL1JXgWw0MQWaoUCRXkZJvghmbKUdDzTkXnsLWKSwvUUOMdHD+of/AUFy7MAuGQ5Pju28/Yfj/w9vAtBPCTC5mmbdTM3/0NLizGH11RZKh2dA2h1LdHRwxLxWvhhO9eBPortK0Tw+Q==", "process_after": 1, "encryption": {"kind": "X25519"}}}}}`, clientUUID))
	require.Nil(t, err)

	f, err = os.Create(configFile)
	defer os.Remove(configFile)
	require.Nil(t, err)
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf(`
    components:
      - dmh
      - vault
    auth:
      anonymous_scope:
        - metrics
      bearer:
        token:
          - name: user
            hash: 6e529315274fd842da9323d9af0805bbef21bd90d2cb30b3cab8fab882d20067
            scope:
              - api:action
              - api:alive
          - name: vault-client
            hash: 4c5dc9b7708905f77f5e5d16316b5dfb425e68cb326dcd55a860e90a7707031e
            scope:
              - api:vault
          - name: sig-auth-test
            hash: 91d8f5e25c6eca5e85822c8860e886773162fb982946b59f0400e8a26e66e7a2
            scope:
              - api:action
              - alive
      signed_url:
        secret: integration-test-signed-url-secret
    vault:
      key: AGE-SECRET-KEY-1GEUMZFAZD42WGZFGATTTJHV4SURK8LU507QVCAKXKJP6UTFMJTCS0E3QJ4
      file: %s
    state:
      file: %s
    action:
      process_unit: second
    remote_vault:
      url: http://127.0.0.1:8080
      client_uuid: %s
      token: test-token
    execute:
      plugin:
        bulksms:
          routing_group: standard
          token:
            id: test-id
            secret: test-secret
        mail:
          server: 127.0.0.1
          from: dmh@example.com
    `, vaultFile, stateFile, clientUUID))
	require.Nil(t, err)

	for k, v := range requiredEnvs {
		err := os.Setenv(k, v)
		require.Nil(t, err)
		defer os.Unsetenv(k)
	}

	hitEndpoint := map[string]int{
		"/alive":                 0,
		"/test":                  0,
		"/action/once":           0,
		"/action/test":           0,
		"/action/min_interval":   0,
		"/action/fail":           0,
		"/action/never_executed": 0,
		"/action/missing_key":    0,
		"/action/sig_auth":       0,
	}
	// Lets start fake server which can be used by Actions.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.Nil(t, err)

		hitEndpoint[r.URL.RequestURI()] += 1

		if r.URL.RequestURI() == "/alive" {
			require.Equal(t, `{"field1":"alive-test"}`, string(body))
			require.Equal(t, "alive", r.Header.Get("type"))
		} else if r.URL.RequestURI() == "/test" {
			require.Equal(t, `{"key1":"value1","key2":true}`, string(body))
			require.Equal(t, "test", r.Header.Get("header1"))
			require.Equal(t, "test2", r.Header.Get("header2"))
		} else if r.URL.RequestURI() == "/action/once" {
			require.Equal(t, `{"key1":"value1"}`, string(body))
		} else if r.URL.RequestURI() == "/action/test" {
			require.Equal(t, `{"key1":"value1","key2":"action/test"}`, string(body))
			require.Equal(t, "test1", r.Header.Get("header3"))
			require.Equal(t, "test2", r.Header.Get("header4"))
		} else if r.URL.RequestURI() == "/action/min_interval" {
			require.Equal(t, `{"key1":"value1","key2":"action/min_interval"}`, string(body))
			require.Equal(t, "test1", r.Header.Get("header3"))
			require.Equal(t, "test2", r.Header.Get("header4"))
		} else if r.URL.RequestURI() == "/action/sig_auth" {
			require.Regexp(t, `^\{"link":"https://dmh\.example\.com/alive\?e=[0-9a-z]+\\u0026s=[A-Za-z0-9_-]+"\}$`, string(body))
		} else if r.URL.RequestURI() == "/action/fail" {
			require.Equal(t, `{"key1":"fail"}`, string(body))
			w.WriteHeader(http.StatusInternalServerError)
			return
		} else {
			require.FailNow(t, fmt.Sprintf("unexpected request to %s", r.URL))
		}
		w.WriteHeader(http.StatusOK)
	})
	s := httptest.NewUnstartedServer(handler)
	l, err := net.Listen("tcp", "127.0.0.1:9090")
	require.Nil(t, err)
	s.Listener = l
	s.Start()
	defer s.Close()

	go main()
	time.Sleep(1 * time.Second)

	// Lets add new alive Action
	action := &state.Action{
		Kind:         "json_post",
		ProcessAfter: 1,
		MinInterval:  4,
		Comment:      "alive",
		Data:         `{"url":"http://127.0.0.1:9090/alive","data":{"field1":"alive-test"},"headers":{"type":"alive"},"success_code":[200]}`,
	}

	actionJson, err := json.Marshal(action)
	require.Nil(t, err)

	resp, err := authRequest("POST", "http://127.0.0.1:8080/api/action/store", userBearerToken, actionJson)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Lets give alive probe some time to run
	time.Sleep(3 * time.Second)

	// Lets check that request without token is rejected
	resp, err = http.Get("http://127.0.0.1:8080/api/action/store")
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Lets check that request with unknown token is rejected
	resp, err = authRequest("GET", "http://127.0.0.1:8080/api/action/store", "unknown-token", nil)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Lets check that request with valid token but without covering scope is rejected
	resp, err = authRequest("GET", "http://127.0.0.1:8080/api/action/store", vaultBearerToken, nil)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Fetch secrets uuids we know
	for _, test := range []struct {
		inputSecretUUID string
		expectedCode    int
	}{
		{
			inputSecretUUID: "9acc344e-a65b-4675-9723-5664c0e73c76",
			expectedCode:    http.StatusNotFound,
		},
		{
			inputSecretUUID: "7df7c024-d0a8-4183-83fa-373ea4a7735a",
			expectedCode:    http.StatusNotFound,
		},
	} {
		resp, err := authRequest("GET", fmt.Sprintf("http://127.0.0.1:8080/api/vault/store/%s/%s", clientUUID, test.inputSecretUUID), vaultBearerToken, nil)
		require.Nil(t, err)
		defer resp.Body.Close()
		require.Equal(t, test.expectedCode, resp.StatusCode)

	}

	// Lets test /api/action/test
	action = &state.Action{
		Kind:         "json_post",
		ProcessAfter: 10,
		Data:         `{"url":"http://127.0.0.1:9090/action/test","data":{"key1":"value1", "key2": "action/test"}, "headers": {"header3": "test1", "header4": "test2"}, "success_code":[200]}`,
	}

	actionJson, err = json.Marshal(action)
	require.Nil(t, err)

	resp, err = authRequest("POST", "http://127.0.0.1:8080/api/action/test", userBearerToken, actionJson)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Lets test /api/action/test with a dummy action.
	action = &state.Action{
		Kind:         "dummy",
		ProcessAfter: 10,
		Data:         `{"message":"integration test dummy action"}`,
	}

	actionJson, err = json.Marshal(action)
	require.Nil(t, err)

	resp, err = authRequest("POST", "http://127.0.0.1:8080/api/action/test", userBearerToken, actionJson)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Lets test that {sig_auth:alive} is rendered into a real signed link when the
	// creating token scope covers /alive.
	action = &state.Action{
		Kind:         "json_post",
		ProcessAfter: 10,
		Data:         `{"url":"http://127.0.0.1:9090/action/sig_auth","data":{"link":"https://dmh.example.com/{sig_auth:alive}"},"success_code":[200]}`,
	}

	actionJson, err = json.Marshal(action)
	require.Nil(t, err)

	resp, err = authRequest("POST", "http://127.0.0.1:8080/api/action/test", sigAuthBearerToken, actionJson)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Lets test that {sig_auth:metrics} is rejected, sig-auth-test token does not cover /metrics.
	action = &state.Action{
		Kind:         "json_post",
		ProcessAfter: 10,
		Data:         `{"url":"http://127.0.0.1:9090/action/sig_auth","data":{"link":"https://dmh.example.com/{sig_auth:metrics}"},"success_code":[200]}`,
	}

	actionJson, err = json.Marshal(action)
	require.Nil(t, err)

	resp, err = authRequest("POST", "http://127.0.0.1:8080/api/action/test", sigAuthBearerToken, actionJson)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	// Lets add new Action
	action = &state.Action{
		Kind:         "json_post",
		ProcessAfter: 10,
		Comment:      "comment",
		Data:         `{"url":"http://127.0.0.1:9090/action/once","data":{"key1":"value1"},"success_code":[200]}`,
	}

	actionJson, err = json.Marshal(action)
	require.Nil(t, err)

	resp, err = authRequest("POST", "http://127.0.0.1:8080/api/action/store", userBearerToken, actionJson)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Lets add new Action with min_interval
	action = &state.Action{
		Kind:         "json_post",
		ProcessAfter: 1,
		MinInterval:  4,
		Comment:      "min_interval",
		Data:         `{"url":"http://127.0.0.1:9090/action/min_interval","data":{"key1":"value1","key2":"action/min_interval"},"headers":{"header3":"test1","header4":"test2"},"success_code":[200]}`,
	}

	actionJson, err = json.Marshal(action)
	require.Nil(t, err)

	resp, err = authRequest("POST", "http://127.0.0.1:8080/api/action/store", userBearerToken, actionJson)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Lets add new Action which will always fail on execution
	action = &state.Action{
		Kind:         "json_post",
		ProcessAfter: 1,
		MinInterval:  4,
		Comment:      "fail",
		Data:         `{"url":"http://127.0.0.1:9090/action/fail","data":{"key1":"fail"},"success_code":[200]}`,
	}

	actionJson, err = json.Marshal(action)
	require.Nil(t, err)

	resp, err = authRequest("POST", "http://127.0.0.1:8080/api/action/store", userBearerToken, actionJson)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Lets wait for min_interval action to run 2x.
	time.Sleep(6 * time.Second)

	// Lets update LastSeen
	resp, err = authRequest("GET", "http://127.0.0.1:8080/api/alive", userBearerToken, nil)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Lets add new Action
	action = &state.Action{
		Kind:         "json_post",
		ProcessAfter: 30,
		Comment:      "never_executed",
		Data:         `{"url":"http://127.0.0.1:9090/action/never_executed","data":{"key1":"value1","key2":"action/min_interval"},"headers":{"header3":"test1","header4":"test2"},"success_code":[200]}`,
	}

	actionJson, err = json.Marshal(action)
	require.Nil(t, err)

	resp, err = authRequest("POST", "http://127.0.0.1:8080/api/action/store", userBearerToken, actionJson)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Lets fetch all actions
	var actions []*state.EncryptedAction
	resp, err = authRequest("GET", "http://127.0.0.1:8080/api/action/store", userBearerToken, nil)
	require.Nil(t, err)
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&actions)
	require.Nil(t, err)

	require.Equal(t, 8, len(actions))
	addedActionEncrypted := actions[2]
	require.NotEqual(t, action.Data, addedActionEncrypted.Data)
	require.Equal(t, fmt.Sprintf("http://127.0.0.1:8080/api/vault/store/%s/%s", clientUUID, addedActionEncrypted.UUID), addedActionEncrypted.EncryptionMeta.VaultURL)

	// Validate all actions
	for i, test := range []struct {
		expectUUID         string
		expectKind         string
		expectProcessAfter int
		expectMinInterval  int
		expectComment      string
		expectProcessed    int
	}{
		{
			expectUUID:         "bf577b9d-26f4-4168-b8e4-0e1d692559ed",
			expectKind:         "json_post",
			expectProcessAfter: 1,
			expectComment:      "missing-encryption-key-from-vault",
			expectProcessed:    0,
		},
		{
			expectUUID:         "9acc344e-a65b-4675-9723-5664c0e73c76",
			expectKind:         "json_post",
			expectProcessAfter: 1,
			expectComment:      "",
			expectProcessed:    2,
		},
		{
			expectUUID:         "7df7c024-d0a8-4183-83fa-373ea4a7735a",
			expectKind:         "json_post",
			expectProcessAfter: 10,
			expectComment:      "test",
			expectProcessed:    2,
		},
		{
			expectKind:         "json_post",
			expectProcessAfter: 1,
			expectMinInterval:  4,
			expectComment:      "alive",
			expectProcessed:    0,
		},
		{
			expectKind:         "json_post",
			expectProcessAfter: 10,
			expectComment:      "comment",
			expectProcessed:    2,
		},
		{
			expectKind:         "json_post",
			expectProcessAfter: 1,
			expectMinInterval:  4,
			expectComment:      "min_interval",
			expectProcessed:    0,
		},
		{
			expectKind:         "json_post",
			expectProcessAfter: 1,
			expectMinInterval:  4,
			expectComment:      "fail",
			expectProcessed:    0,
		},
		{
			expectKind:         "json_post",
			expectProcessAfter: 30,
			expectComment:      "never_executed",
			expectProcessed:    0,
		},
	} {
		if test.expectUUID != "" {
			require.Equal(t, test.expectUUID, actions[i].UUID)
		}
		require.Equal(t, test.expectKind, actions[i].Kind)
		require.Equal(t, test.expectProcessAfter, actions[i].ProcessAfter)
		require.Equal(t, test.expectMinInterval, actions[i].MinInterval)
		require.Equal(t, test.expectComment, actions[i].Comment)
		require.Equal(t, test.expectProcessed, actions[i].Processed)
	}

	// Lets check if every action has proper vault url
	for _, action := range actions {
		require.Equal(t, fmt.Sprintf("http://127.0.0.1:8080/api/vault/store/%s/%s", clientUUID, action.UUID), action.EncryptionMeta.VaultURL)
	}

	// Lets check that vault locked all secrets as we updated LastSeen.
	for _, action := range actions {
		resp, err = authRequest("GET", fmt.Sprintf("http://127.0.0.1:8080/api/vault/store/%s/%s", clientUUID, action.UUID), vaultBearerToken, nil)
		require.Nil(t, err)
		defer resp.Body.Close()

		if action.Processed == 2 || action.UUID == "bf577b9d-26f4-4168-b8e4-0e1d692559ed" {
			require.Equal(t, http.StatusNotFound, resp.StatusCode)
		} else {
			require.Equal(t, http.StatusLocked, resp.StatusCode)
		}
	}

	// Lets fetch single action
	resp, err = authRequest("GET", fmt.Sprintf("http://127.0.0.1:8080/api/action/store/%s", actions[1].UUID), userBearerToken, nil)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var encryptedAction state.EncryptedAction
	err = json.NewDecoder(resp.Body).Decode(&encryptedAction)
	require.Nil(t, err)
	require.Equal(t, "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSAvb2JISGVZS3lEcmlsenlaeUFnbHRDYjJTK1FLSVdLSWkvYjhwSjRXeEg4CmxNT0YrVCtjNUZRWi9HS2d4MFFiN3AwVDlRc0k1eVJsbXBqWHhMRFhTWE0KLS0tIE12NktMSlVGVC9LMlpTRGFjZ2FRVXhpcEJjdmwyUExCL2tGaGJtZFhyc1UKfx25yewZmc6eVeuX7ufIN2vmFR/hXldbY1LW1UwNMH/AqPToZ2ZKTYdqhA7+ZtF8mOyduvsLVX1siaatb0VC4kmGdIr2DiPlVyCbcGNwTgNqjPs5RNkcqQB9DITQPfGdmGRh3OP3t16FFT91zVWDRDRVbFnSEKfeusg33wDHlsd1E99RrVPAK5TpT6wGykDCCW66Xwh8YNYkFb4s2f0PSIsE/r7bxR4mq1VNbBuV0eRo5uz9WAiR7NyH", encryptedAction.Data)
	require.Equal(t, actions[1].UUID, encryptedAction.UUID)

	// Lets delete single action
	resp, err = authRequest("DELETE", fmt.Sprintf("http://127.0.0.1:8080/api/action/store/%s", actions[0].UUID), userBearerToken, nil)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Lets confirm that it was deleted
	resp, err = authRequest("GET", fmt.Sprintf("http://127.0.0.1:8080/api/action/store/%s", actions[0].UUID), userBearerToken, nil)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)

	// Lets ensure that all fakeServer endpoints were visited
	require.Equal(t, 9, len(hitEndpoint))
	for k, v := range map[string]int{
		"/alive":                 2,
		"/test":                  1,
		"/action/once":           1,
		"/action/test":           1,
		"/action/min_interval":   2,
		"/action/never_executed": 0,
		"/action/missing_key":    0,
		"/action/sig_auth":       1,
	} {
		require.Equal(t, v, hitEndpoint[k])
	}
	// Failing action is retried on every dispatcher tick, exact count depends on timing.
	require.GreaterOrEqual(t, hitEndpoint["/action/fail"], 1)

	// Lets confirm vault secret lock status
	time.Sleep(3 * time.Second)

	resp, err = authRequest("GET", "http://127.0.0.1:8080/api/action/store", userBearerToken, nil)
	require.Nil(t, err)
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&actions)
	require.Nil(t, err)

	require.Equal(t, 7, len(actions))

	for _, action := range actions {
		resp, err = authRequest("GET", fmt.Sprintf("http://127.0.0.1:8080/api/vault/store/%s/%s", clientUUID, action.UUID), vaultBearerToken, nil)
		require.Nil(t, err)
		defer resp.Body.Close()

		if action.Processed == 2 || action.UUID == "bf577b9d-26f4-4168-b8e4-0e1d692559ed" {
			require.Equal(t, http.StatusNotFound, resp.StatusCode)
		} else if action.MinInterval > 0 {
			require.Equal(t, http.StatusOK, resp.StatusCode)
		} else if action.Processed == 0 {
			require.Equal(t, http.StatusLocked, resp.StatusCode)
		}

		if (action.Processed == 0 && action.MinInterval == 0) || action.Processed == 2 {
			resp, err = authRequest("DELETE", fmt.Sprintf("http://127.0.0.1:8080/api/vault/store/%s/%s", clientUUID, action.UUID), vaultBearerToken, nil)
			require.Nil(t, err)
			defer resp.Body.Close()
			if action.Processed == 0 {
				require.Equal(t, http.StatusLocked, resp.StatusCode)
			} else {
				require.Equal(t, http.StatusNotFound, resp.StatusCode)
			}
		}
	}

	resp, err = http.Get("http://127.0.0.1:8080/metrics")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.Nil(t, err)

	require.Contains(t, string(body), `dmh_actions{processed="0"} 4`)
	require.Contains(t, string(body), `dmh_actions{processed="1"} 0`)
	require.Contains(t, string(body), `dmh_actions{processed="2"} 3`)
	require.Contains(t, string(body), `dmh_action_errors_total{action="bf577b9d-26f4-4168-b8e4-0e1d692559ed",error="DecryptAction"} 10`)
	require.Regexp(t, `dmh_action_errors_total{action="[a-f0-9-]+",error="Run"} [0-9]+`, string(body))

	// Human /alive page requires a credential when auth is enabled.
	resp, err = http.Get("http://127.0.0.1:8080/alive")
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Bearer token without "alive" scope (user only has api:action, api:alive) is not enough.
	resp, err = authRequest("GET", "http://127.0.0.1:8080/alive", userBearerToken, nil)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Signed URL grants access to exactly /alive without any bearer token.
	signedAliveURL := "http://127.0.0.1:8080" + crypt.SignURL("integration-test-signed-url-secret", "/alive", time.Now().Add(time.Hour))
	resp, err = http.Get(signedAliveURL)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err = io.ReadAll(resp.Body)
	require.Nil(t, err)
	require.Contains(t, string(body), `<button id="alive">`)

	// POST on the same signed URL confirms aliveness end-to-end, through the in-process vault.
	resp, err = http.Post(signedAliveURL, "", nil)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Signature signed with a different secret does not authorize.
	wrongSecretURL := "http://127.0.0.1:8080" + crypt.SignURL("wrong-secret", "/alive", time.Now().Add(time.Hour))
	resp, err = http.Get(wrongSecretURL)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Expired signature does not authorize.
	expiredURL := "http://127.0.0.1:8080" + crypt.SignURL("integration-test-signed-url-secret", "/alive", time.Now().Add(-time.Hour))
	resp, err = http.Get(expiredURL)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestDMHAuthDisabled(t *testing.T) {
	stateFile := "integration_test_auth_disabled_state.json"
	vaultFile := "integration_test_auth_disabled_vault.json"
	configFile := "integration_test_auth_disabled_config.yaml"

	f, err := os.Create(configFile)
	defer os.Remove(configFile)
	require.Nil(t, err)
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf(`
    components:
      - dmh
      - vault
      - unknown
    auth:
      enabled: false
    action:
      process_unit: minute
    state:
      file: %s
    remote_vault:
      url: http://127.0.0.1:18081
      client_uuid: auth-disabled-client
    vault:
      key: AGE-SECRET-KEY-1GEUMZFAZD42WGZFGATTTJHV4SURK8LU507QVCAKXKJP6UTFMJTCS0E3QJ4
      file: %s
    `, stateFile, vaultFile))
	require.Nil(t, err)
	defer os.Remove(vaultFile)
	defer os.Remove(stateFile)

	err = os.Setenv("DMH_CONFIG_FILE", configFile)
	require.Nil(t, err)
	defer os.Unsetenv("DMH_CONFIG_FILE")

	oldHTTPPort := api.HTTPPort
	api.HTTPPort = 18081
	defer func() { api.HTTPPort = oldHTTPPort }()

	oldMetricInitialize := metricInitialize
	metricInitialize = func(opts *metric.Options) *metric.PromCollector {
		opts.Registry = prometheus.NewRegistry()
		return metric.Initialize(opts)
	}
	defer func() { metricInitialize = oldMetricInitialize }()

	logBuf := &syncBuffer{}
	log.SetOutput(logBuf)
	defer log.SetOutput(os.Stderr)

	go main()
	time.Sleep(1 * time.Second)

	require.Contains(t, logBuf.String(), "authentication is DISABLED")

	// Without token, API endpoints reply from handlers and not with 401.
	resp, err := http.Get("http://127.0.0.1:18081/healthz")
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp, err = http.Get("http://127.0.0.1:18081/api/vault/store/client-uuid/secret-uuid")
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)

	// Human /alive page is open without any credential when auth is disabled.
	resp, err = http.Get("http://127.0.0.1:18081/alive")
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.Nil(t, err)
	require.Contains(t, string(body), `<button id="alive">`)

	// POST confirms aliveness end-to-end, through the in-process vault, no credential needed.
	resp, err = http.Post("http://127.0.0.1:18081/alive", "", nil)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestDMHAuthMissing(t *testing.T) {
	vaultFile := "integration_test_auth_missing_vault.json"
	configFile := "integration_test_auth_missing_config.yaml"

	f, err := os.Create(configFile)
	defer os.Remove(configFile)
	require.Nil(t, err)
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf(`
    components:
      - vault
    vault:
      key: AGE-SECRET-KEY-1GEUMZFAZD42WGZFGATTTJHV4SURK8LU507QVCAKXKJP6UTFMJTCS0E3QJ4
      file: %s
    `, vaultFile))
	require.Nil(t, err)
	defer os.Remove(vaultFile)

	err = os.Setenv("DMH_CONFIG_FILE", configFile)
	require.Nil(t, err)
	defer os.Unsetenv("DMH_CONFIG_FILE")

	oldHTTPPort := api.HTTPPort
	api.HTTPPort = 18082
	defer func() { api.HTTPPort = oldHTTPPort }()

	oldMetricInitialize := metricInitialize
	metricInitialize = func(opts *metric.Options) *metric.PromCollector {
		opts.Registry = prometheus.NewRegistry()
		return metric.Initialize(opts)
	}
	defer func() { metricInitialize = oldMetricInitialize }()

	logBuf := &syncBuffer{}
	log.SetOutput(logBuf)
	defer log.SetOutput(os.Stderr)

	require.Panics(t, main)
	require.Contains(t, logBuf.String(), "auth.bearer.token is not configured")
}

func TestDMHMissingConfigFile(t *testing.T) {
	err := os.Setenv("DMH_CONFIG_FILE", "integration-non-existing.yaml")
	require.Nil(t, err)
	defer os.Unsetenv("DMH_CONFIG_FILE")

	logBuf := &syncBuffer{}
	log.SetOutput(logBuf)
	defer log.SetOutput(os.Stderr)

	require.Panics(t, main)
	require.Contains(t, logBuf.String(), "error loading config")
}

func TestDMHAuthInvalid(t *testing.T) {
	vaultFile := "integration_test_auth_invalid_vault.json"
	configFile := "integration_test_auth_invalid_config.yaml"
	defer os.Remove(vaultFile)
	defer os.Remove(configFile)

	err := os.Setenv("DMH_CONFIG_FILE", configFile)
	require.Nil(t, err)
	defer os.Unsetenv("DMH_CONFIG_FILE")

	oldMetricInitialize := metricInitialize
	metricInitialize = func(opts *metric.Options) *metric.PromCollector {
		opts.Registry = prometheus.NewRegistry()
		return metric.Initialize(opts)
	}
	defer func() { metricInitialize = oldMetricInitialize }()

	tests := []struct {
		inputAuthConfig string
	}{
		{
			inputAuthConfig: `
      bearer:
        token:
          - name: admin
            hash: not-a-hash
            scope:
              - api`,
		},
		{
			inputAuthConfig: `
      bearer:
        token: 10`,
		},
	}
	for _, test := range tests {
		f, err := os.Create(configFile)
		require.Nil(t, err)
		_, err = f.WriteString(fmt.Sprintf(`
    components:
      - vault
    auth:%s
    vault:
      key: AGE-SECRET-KEY-1GEUMZFAZD42WGZFGATTTJHV4SURK8LU507QVCAKXKJP6UTFMJTCS0E3QJ4
      file: %s
    `, test.inputAuthConfig, vaultFile))
		require.Nil(t, err)
		f.Close()

		require.Panics(t, main)
	}
}
