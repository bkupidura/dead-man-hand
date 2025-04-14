package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"dmh/internal/state"

	"github.com/stretchr/testify/require"
)

func TestDMH(t *testing.T) {
	stateFile := "integration_test_state.json"
	vaultFile := "integration_test_vault.json"
	configFile := "integration_test_config.yaml"
	clientUUID := "integration-test-client-uuid"
	requiredEnvs := map[string]string{"DMH_CONFIG_FILE": configFile}

	processMessagesInterval = 1
	aliveIntervalUnit = time.Second
	processAfterIntervalUnit = time.Second
	processMessagesIntervalUnit = time.Second

	f, err := os.Create(stateFile)
	defer os.Remove(stateFile)
	require.Nil(t, err)
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf(`{"last_seen":"2025-03-26T14:55:40.119447+01:00","actions":[{"uuid":"9acc344e-a65b-4675-9723-5664c0e73c76","kind":"json_post","data":"YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSAvb2JISGVZS3lEcmlsenlaeUFnbHRDYjJTK1FLSVdLSWkvYjhwSjRXeEg4CmxNT0YrVCtjNUZRWi9HS2d4MFFiN3AwVDlRc0k1eVJsbXBqWHhMRFhTWE0KLS0tIE12NktMSlVGVC9LMlpTRGFjZ2FRVXhpcEJjdmwyUExCL2tGaGJtZFhyc1UKfx25yewZmc6eVeuX7ufIN2vmFR/hXldbY1LW1UwNMH/AqPToZ2ZKTYdqhA7+ZtF8mOyduvsLVX1siaatb0VC4kmGdIr2DiPlVyCbcGNwTgNqjPs5RNkcqQB9DITQPfGdmGRh3OP3t16FFT91zVWDRDRVbFnSEKfeusg33wDHlsd1E99RrVPAK5TpT6wGykDCCW66Xwh8YNYkFb4s2f0PSIsE/r7bxR4mq1VNbBuV0eRo5uz9WAiR7NyH","process_after":1,"comment":"","processed":0, "encryption": {"kind":"X25519","vault_url":"http://127.0.0.1:8080/api/vault/store/%s/9acc344e-a65b-4675-9723-5664c0e73c76"}},{"uuid":"7df7c024-d0a8-4183-83fa-373ea4a7735a","kind":"json_post","data":"YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBJSmIxTlBZZ1dqZlVqY2RBTjg1YjRlWEVCNjFXMFVac0EwdWczVXYxblZ3CmFPNjl5THJ6Q0ZxaGdxU2RmZlBUdXdwVjJ2ajNoSUxPSitxYStFSVBMOTQKLS0tIExpQVFsZ1p6Vy9TWVllY1NUYmt4M1BrZGV6Yk5mUkNhQURFRUhaU3BCazgKeLCm87tFZiyWy1pBgfmZnrNK/BygpARjcOz30EeA7pUnS3bAleWKsOoO+mOrYUXt4FxvS8s7botqWYvqJBU18ctHRZshxQLaz5q240EsOsBWGvxZN1rn1SonO5DsBxxrPvJJmbyI47lXpaScrnSE1eotvgt0zWDc58kkgMGgBxiMYjqQXdFylwp5WU+Q9JThCakt+QsQP9X5MRvPfPWOg9a9Kw==","process_after":10,"comment":"test","processed":2, "encryption": {"kind":"X25519","vault_url":"http://127.0.0.1:8080/api/vault/store/%s/7df7c024-d0a8-4183-83fa-373ea4a7735a"}}]}`, clientUUID, clientUUID))
	require.Nil(t, err)

	f, err = os.Create(vaultFile)
	defer os.Remove(vaultFile)
	require.Nil(t, err)
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf(`{"%s":{"last_seen": "2025-03-26T14:55:40.119447+01:00", "secrets": {"9acc344e-a65b-4675-9723-5664c0e73c76": {"key": "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBGMDl6R0dQOGQxWUFOS21URENNRklBWVp0R2xMdzM0OGgwTDlOMmJieWxnCnJ4WS9IOUlBYmNvZDNqbm5Ua3d2R2hsemNmL2doQWZ6RjVDS0NUZ0RjTzAKLS0tIEE3UVoyYXh0MjJramFieWZab3Fmc1BSZThISGhkaTVzWmM4L1NQSUlYQ0EKcwoFDL1JXgWw0MQWaoUCRXkZJvghmbKUdDzTkXnsLWKSwvUUOMdHD+of/AUFy7MAuGQ5Pju28/Yfj/w9vAtBPCTC5mmbdTM3/0NLizGH11RZKh2dA2h1LdHRwxLxWvhhO9eBPortK0Tw+Q==", "process_after": 1, "encryption": {"kind": "X25519"}}, "7df7c024-d0a8-4183-83fa-373ea4a7735a": {"key": "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBGMDl6R0dQOGQxWUFOS21URENNRklBWVp0R2xMdzM0OGgwTDlOMmJieWxnCnJ4WS9IOUlBYmNvZDNqbm5Ua3d2R2hsemNmL2doQWZ6RjVDS0NUZ0RjTzAKLS0tIEE3UVoyYXh0MjJramFieWZab3Fmc1BSZThISGhkaTVzWmM4L1NQSUlYQ0EKcwoFDL1JXgWw0MQWaoUCRXkZJvghmbKUdDzTkXnsLWKSwvUUOMdHD+of/AUFy7MAuGQ5Pju28/Yfj/w9vAtBPCTC5mmbdTM3/0NLizGH11RZKh2dA2h1LdHRwxLxWvhhO9eBPortK0Tw+Q==", "process_after": 10, "encryption": {"kind": "X25519"}}}}}`, clientUUID))
	require.Nil(t, err)

	f, err = os.Create(configFile)
	defer os.Remove(configFile)
	require.Nil(t, err)
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf(`
    components:
      - dmh
      - vault
    vault:
      key: AGE-SECRET-KEY-1GEUMZFAZD42WGZFGATTTJHV4SURK8LU507QVCAKXKJP6UTFMJTCS0E3QJ4
      file: %s
    state:
      file: %s
    remote_vault:
      url: http://127.0.0.1:8080
      client_uuid: %s
    alive:
      - every: 2
        kind: json_post
        data:
          url: http://127.0.0.1:9090/alive
          headers:
            type: alive
          data:
            field1: alive-test
          success_code:
            - 200
    `, vaultFile, stateFile, clientUUID))
	require.Nil(t, err)

	for k, v := range requiredEnvs {
		err := os.Setenv(k, v)
		require.Nil(t, err)
	}

	// Lets start fake server which can be used by Actions.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.Nil(t, err)

		if r.URL.RequestURI() == "/alive" {
			require.Equal(t, `{"field1":"alive-test"}`, string(body))
			require.Equal(t, "alive", r.Header.Get("type"))
		} else if r.URL.RequestURI() == "/test" {
			require.Equal(t, `{"key1":"value1","key2":true}`, string(body))
			require.Equal(t, "test", r.Header.Get("header1"))
			require.Equal(t, "test2", r.Header.Get("header2"))
		} else if r.URL.RequestURI() == "/action/test" {
			require.Equal(t, `{"key1":"value1","key2":"action/test"}`, string(body))
			require.Equal(t, "test1", r.Header.Get("header3"))
			require.Equal(t, "test2", r.Header.Get("header4"))
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
	time.Sleep(3 * time.Second)

	// Fetch all secrets from vault, LastSeen is out-of-sync, so everything is released.
	// First secret was already deleted by execution of 9acc344e-a65b-4675-9723-5664c0e73c76 action.
	for _, test := range []struct {
		inputSecretUUID string
		expectedKey     string
		expectedCode    int
	}{
		{
			inputSecretUUID: "9acc344e-a65b-4675-9723-5664c0e73c76",
			expectedCode:    http.StatusNotFound,
		},
		{
			inputSecretUUID: "7df7c024-d0a8-4183-83fa-373ea4a7735a",
			expectedKey:     "AGE-SECRET-KEY-1GEUMZFAZD42WGZFGATTTJHV4SURK8LU507QVCAKXKJP6UTFMJTCS0E3QJ4",
			expectedCode:    http.StatusOK,
		},
	} {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:8080/api/vault/store/%s/%s", clientUUID, test.inputSecretUUID))
		require.Nil(t, err)
		defer resp.Body.Close()
		require.Equal(t, test.expectedCode, resp.StatusCode)
		if test.expectedKey != "" {
			var vaultData state.VaultData
			err = json.NewDecoder(resp.Body).Decode(&vaultData)
			require.Nil(t, err)
			require.Equal(t, test.expectedKey, vaultData.Key)
		}

	}

	// Lets update LastSeen
	resp, err := http.Get("http://127.0.0.1:8080/api/alive")
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Lets test /api/action/test
	action := &state.Action{
		Kind:         "json_post",
		ProcessAfter: 10,
		Data:         `{"url":"http://127.0.0.1:9090/action/test","data":{"key1":"value1", "key2": "action/test"}, "headers": {"header3": "test1", "header4": "test2"}, "success_code":[200]}`,
	}

	actionJson, err := json.Marshal(action)
	require.Nil(t, err)

	resp, err = http.Post("http://127.0.0.1:8080/api/action/test", "application/json", bytes.NewBuffer(actionJson))
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Lets add new Action
	action = &state.Action{
		Kind:         "json_post",
		ProcessAfter: 10,
		Comment:      "comment",
		Data:         `{"url":"http://127.0.0.1:9090/test","data":{"key1":"value1"},"success_code":[200]}`,
	}

	actionJson, err = json.Marshal(action)
	require.Nil(t, err)

	resp, err = http.Post("http://127.0.0.1:8080/api/action/store", "application/json", bytes.NewBuffer(actionJson))
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Lets fetch all actions
	var actions []*state.EncryptedAction
	resp, err = http.Get("http://127.0.0.1:8080/api/action/store")
	require.Nil(t, err)
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&actions)
	require.Nil(t, err)

	require.Equal(t, 3, len(actions))
	addedActionEncrypted := actions[2]
	require.NotEqual(t, action.Data, addedActionEncrypted.Data)
	require.Equal(t, fmt.Sprintf("http://127.0.0.1:8080/api/vault/store/%s/%s", clientUUID, addedActionEncrypted.UUID), addedActionEncrypted.EncryptionMeta.VaultURL)

	// Validate all actions
	for i, test := range []struct {
		expectUUID         string
		expectKind         string
		expectProcessAfter int
		expectComment      string
		expectProcessed    int
	}{
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
			expectProcessAfter: 10,
			expectComment:      "comment",
			expectProcessed:    0,
		},
	} {
		if test.expectUUID != "" {
			require.Equal(t, test.expectUUID, actions[i].UUID)
		}
		require.Equal(t, test.expectKind, actions[i].Kind)
		require.Equal(t, test.expectProcessAfter, actions[i].ProcessAfter)
		require.Equal(t, test.expectComment, actions[i].Comment)
		require.Equal(t, test.expectProcessed, actions[i].Processed)
	}

	// Lets check that vault locked all secrets as we updated LastSeen.
	for _, action := range actions {
		resp, err = http.Get(fmt.Sprintf("http://127.0.0.1:8080/api/vault/store/%s/%s", clientUUID, action.UUID))
		require.Nil(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusNotFound, resp.StatusCode)
	}

	// Lets fetch single action
	resp, err = http.Get(fmt.Sprintf("http://127.0.0.1:8080/api/action/store/%s", actions[0].UUID))
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var encryptedAction state.EncryptedAction
	err = json.NewDecoder(resp.Body).Decode(&encryptedAction)
	require.Nil(t, err)
	require.Equal(t, "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSAvb2JISGVZS3lEcmlsenlaeUFnbHRDYjJTK1FLSVdLSWkvYjhwSjRXeEg4CmxNT0YrVCtjNUZRWi9HS2d4MFFiN3AwVDlRc0k1eVJsbXBqWHhMRFhTWE0KLS0tIE12NktMSlVGVC9LMlpTRGFjZ2FRVXhpcEJjdmwyUExCL2tGaGJtZFhyc1UKfx25yewZmc6eVeuX7ufIN2vmFR/hXldbY1LW1UwNMH/AqPToZ2ZKTYdqhA7+ZtF8mOyduvsLVX1siaatb0VC4kmGdIr2DiPlVyCbcGNwTgNqjPs5RNkcqQB9DITQPfGdmGRh3OP3t16FFT91zVWDRDRVbFnSEKfeusg33wDHlsd1E99RrVPAK5TpT6wGykDCCW66Xwh8YNYkFb4s2f0PSIsE/r7bxR4mq1VNbBuV0eRo5uz9WAiR7NyH", encryptedAction.Data)
	require.Equal(t, actions[0].UUID, encryptedAction.UUID)

	// Lets delete single action
	req, err := http.NewRequest("DELETE", fmt.Sprintf("http://127.0.0.1:8080/api/action/store/%s", actions[0].UUID), nil)
	require.Nil(t, err)
	client := &http.Client{}
	resp, err = client.Do(req)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Lets confirm that it was deleted
	resp, err = http.Get(fmt.Sprintf("http://127.0.0.1:8080/api/action/store/%s", actions[0].UUID))
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}
